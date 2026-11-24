package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// status is a job's outcome. ready means the reader accepted the bundle and
// the engine produced a document; rejected means the hostile-input reader
// refused it (never a renderer's opinion); FailedLimit means a resource
// boundary stopped the job; FailedCrash means the child died another way
// (panic, wrong exit code). no other outcome exists, so web can map every
// upload to exactly one state (contract §5.4).
type Status string

const (
	StatusReady       Status = "READY"
	StatusRejected    Status = "REJECTED"
	StatusFailedLimit Status = "FAILED_LIMIT"
	StatusFailedCrash Status = "FAILED_CRASH"
)

// defaults from contract §5.2: a 30 MB bundle analyzes in ~7.5 s with ~420 MB
// peak RSS, so the worst 64 MiB case extrapolates to ~17 s. the wall clock is
// set 3.5× beyond that; the memory shape is the container cgroup's job (one
// request per container), which the child cannot state anyway.
const (
	DefaultTimeout = 60 * time.Second
	maxStderrBytes = 4096
	memoryLimitEnv = "1GiB"
)

// result is one completed job. stderr carries at most maxStderrBytes of
// truncated diagnostics and the child's design keeps bundle bytes out of it.
type Result struct {
	Status   Status
	Document []byte
	Reason   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// runner is the parent half: it starts one child per job in a private
// directory with no inherited environment and classifies the exit.
type Runner struct {
	// ChildPath is the analyzer child binary. parent and child are the same
	// binary in this repository; outside callers may point the child anywhere.
	ChildPath string
	// timeout bounds each job; zero means DefaultTimeout.
	Timeout time.Duration
}

// NewRunner points the runner at a child binary. A relative path is resolved
// here: run starts the child in a private working directory, so "bin/x" would
// otherwise mean "/tmp/deprehendo-analyzer-*/bin/x" and every job would fail with
// "no such file or directory" after a successful startup stat.
func NewRunner(childPath string) *Runner {
	if childPath != "" && !filepath.IsAbs(childPath) {
		if abs, err := filepath.Abs(childPath); err == nil {
			childPath = abs
		}
	}
	return &Runner{ChildPath: childPath, Timeout: DefaultTimeout}
}

// run executes one job: bundle bytes in, one document or one classified
// status out. the parent itself never parses the bundle (§5.4: no second
// parser) and holds no bundle data after the child returns.
func (r *Runner) Run(ctx context.Context, bundle []byte) (Result, error) {
	if r.ChildPath == "" {
		return Result{}, fmt.Errorf("analyzer: no child binary")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	jobctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	private, err := os.MkdirTemp("", "deprehendo-analyzer-*")
	if err != nil {
		return Result{}, fmt.Errorf("analyzer: private dir: %w", err)
	}
	defer os.RemoveAll(private)

	cmd := exec.CommandContext(jobctx, r.ChildPath)
	cmd.Dir = private
	// no inherited environment: the child learns nothing about the machine
	// beyond what it must to bound its own GC (§5.4).
	cmd.Env = []string{"GOMEMLIMIT=" + memoryLimitEnv}
	cmd.Stdin = bytes.NewReader(bundle)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	// WaitDelay keeps a wedged child holding the pipes from outliving the
	// context kill.
	cmd.WaitDelay = 5 * time.Second
	runerr := cmd.Run()
	result := Result{Duration: time.Since(start), ExitCode: exitCode(cmd), Stderr: truncateStderr(stderr.String()), Document: stdout.Bytes()}
	if runerr != nil {
		// wall clock: a context deadline produces "signal: killed" (or the
		// WaitDelay cleanup). both are the boundary doing its job.
		if jobctx.Err() != nil || strings.Contains(fmt.Sprint(runerr), "signal:") {
			result.Status = StatusFailedLimit
			result.Reason = fmt.Sprintf("job exceeded a resource boundary (%s)", runerr)
			return result, nil
		}
		// the child's classified rejections come back as exit codes.
		switch exitCode(cmd) {
		case ExitRejected:
			result.Status = StatusRejected
			result.Reason = rejectionClass(result.Stderr)
			return result, nil
		case ExitLimited:
			result.Status = StatusFailedLimit
			result.Reason = "child could not install its own resource limits"
			return result, nil
		}
		result.Status = StatusFailedCrash
		result.Reason = runerr.Error()
		return result, nil
	}
	if exit := exitCode(cmd); exit != ExitOK {
		result.Status = StatusFailedCrash
		result.Reason = fmt.Sprintf("child exited %d", exit)
		return result, nil
	}
	if len(result.Document) == 0 {
		result.Status = StatusFailedCrash
		result.Reason = "child exited 0 with no document"
		return result, nil
	}
	result.Status = StatusReady
	result.Reason = ""
	result.Stderr = ""
	result.Document = stdout.Bytes()
	return result, nil
}

// exitCode reads the child's exit status without panicking when the process
// was killed before recording one.
func exitCode(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}

// rejectionClass reduces a reader rejection to its first line, which already
// names the rule that refused the bundle ("incident: ... checksum mismatch").
// diagnostics stay bounded and never grow with the hostile input.
func rejectionClass(stderr string) string {
	first := stderr
	if index := strings.IndexByte(stderr, '\n'); index >= 0 {
		first = stderr[:index]
	}
	first = strings.TrimSpace(first)
	if first == "" {
		return "the reader refused the bundle without a message"
	}
	return first
}

// truncateStderr bounds diagnostics so a midnight-sized panic cannot turn the
// parent's log into the child's memory again.
func truncateStderr(s string) string {
	if len(s) > maxStderrBytes {
		return s[:maxStderrBytes] + "…(truncated)"
	}
	return s
}
