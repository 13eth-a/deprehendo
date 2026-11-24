package simulator

// the fake GitHub actions runner harness (phase 5 item 5.41).
//
// `deprehendo-sim github <scenario>` materializes a runner installation, starts a
// real Runner.Listener process, and lets it run the scenario: spawn a worker,
// spawn the job process tree, write diagnostic logs, hold a broker-shaped TCP
// connection, and then fail in the scenario's own way. every process is a real
// kernel process named after the runner binary it runs from, so
//
//	deprehendo-agent github watch
//
// and the recorder see the same observations a genuine runner produces. the
// harness never needs GitHub, credentials, or network access, which keeps the
// fast feedback loop (5.41) intact.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"deprehendo/internal/events"
	"deprehendo/internal/platform"
	"deprehendo/internal/simhelper"
)

const (
	defaultGitHubDuration = 10 * time.Second
	githubReadyTimeout    = 8 * time.Second
)

// RunGitHubCLI is the `github` subcommand of deprehendo-sim.
func RunGitHubCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printGitHubUsage(stdout)
		return 0
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		printGitHubUsage(stdout)
		return 0
	}
	scenario := args[0]
	if simhelper.GitHubDescription(scenario) == "" {
		fmt.Fprintf(stderr, "deprehendo-sim github: unknown scenario %q\n\n", scenario)
		printGitHubUsage(stderr)
		return 2
	}

	fs := flag.NewFlagSet("deprehendo-sim github "+scenario, flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "installation root (default: a new temporary directory, removed on exit)")
	duration := fs.Duration("duration", defaultGitHubDuration, "scenario lifetime")
	keep := fs.Bool("keep", false, "keep the generated installation directory")
	jsonmode := fs.Bool("json", false, "emit newline-delimited JSON events on stdout")
	verbose := fs.Bool("verbose", false, "include extra detail")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "deprehendo-sim github: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *duration <= 0 || *duration > 10*time.Minute {
		fmt.Fprintln(stderr, "deprehendo-sim github: --duration must be positive and at most 10m")
		return 2
	}

	cfg := Config{
		Duration: *duration, Verbose: *verbose, JSON: *jsonmode,
		Events: events.New(scenario, stdout, stdout, *jsonmode),
	}
	temporary := false
	if *root == "" {
		dir, err := os.MkdirTemp("", "deprehendo-github-"+scenario+"-")
		if err != nil {
			fmt.Fprintf(stderr, "deprehendo-sim github: %v\n", err)
			return 1
		}
		*root = dir
		temporary = true
	}
	if *keep {
		temporary = false
	}
	runner, err := MaterializeGitHubRunner(*root, scenario)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-sim github: %v\n", err)
		return 1
	}
	if temporary {
		defer os.RemoveAll(*root)
	}

	cfg.Say(fmt.Sprintf("Fake GitHub Actions runner (%s)", scenario))
	cfg.Say(fmt.Sprintf("Installation root: %s", runner.Root))
	cfg.Emit("started", map[string]any{
		"scenario": scenario, "root": runner.Root, "duration_ms": duration.Milliseconds(),
	})

	listener, err := spawn(runner.ListenerPath, []string{
		"_ghrunner", "--root", runner.Root, "--scenario", scenario, "--hold", duration.String(),
	}, "Runner.Listener", true)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-sim github: %v\n", err)
		return 1
	}
	cfg.Emit("listener_started", map[string]any{"listener_pid": listener.PID()})
	cfg.Say(fmt.Sprintf("Listener PID: %d", listener.PID()))

	// ctrl+C must reap the runner, not orphan it: the listener leads its own
	// process group, so a terminal interrupt never reaches it directly.
	signalctx, stopsignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopsignals()

	ctx, cancel := context.WithTimeout(context.Background(), *duration+githubReadyTimeout)
	defer cancel()

	// wait until the harness publishes its state (idle/running), so the
	// caller knows the runner is observable before recording is attached.
	state, ready := waitForGitHubState(ctx, runner.Root)
	if !ready {
		cfg.Emit("not_ready", map[string]any{"timeout_ms": githubReadyTimeout.Milliseconds()})
		cfg.Say("Harness did not publish state; cleaning up.")
	} else {
		cfg.Emit("ready", map[string]any{
			"listener_pid": state.Listener, "worker_pid": state.Worker,
			"job_root_pid": state.JobRoot, "phase": state.Phase,
		})
		if state.Worker > 0 {
			cfg.Say(fmt.Sprintf("Worker PID: %d", state.Worker))
		}
	}

	// report the runner's later phase changes. the ready event can only show
	// the phase the caller attached in (an idle runner before its job), so
	// this stream is what tells an operator or a test that the worker and job
	// tree actually appeared.
	stopphases := make(chan struct{})
	if ready {
		go watchGitHubPhases(runner.Root, state.Phase, cfg, stopphases)
	}

	done := make(chan waitRes, 1)
	go func() {
		code, kind, err := reap(listener.Cmd)
		done <- waitRes{code: code, kind: kind, err: err}
	}()

	timer := time.NewTimer(*duration + githubReadyTimeout)
	defer timer.Stop()
	reason := "duration_elapsed"
	var waitErr error
	select {
	case res := <-done:
		waitErr = res.err
		reason = "listener_exited"
		cfg.Emit("listener_exited", map[string]any{"exit_code": res.code, "exit_kind": res.kind})
	case <-timer.C:
		reason = "duration_elapsed"
	case <-signalctx.Done():
		reason = "interrupted"
	}

	close(stopphases)

	// cleanup is unconditional and ordered: the listener group first (it owns
	// nothing else once killed), then any published worker/job group that a
	// scenario deliberately orphaned.
	final, _ := simhelper.ReadGitHubState(runner.Root)
	_ = spawnGroupKill(listener, syscall.SIGKILL)
	killQuiet(final.Worker)
	killQuiet(final.JobRoot)
	if _, ok := doneOrTimeout(done, 2*time.Second); !ok {
		_ = listener.Cmd.Process.Kill()
	}

	cfg.Emit("exited", map[string]any{"code": 0, "reason": reason, "scenario": scenario})
	cfg.Say("Harness stopped; all processes reaped.")
	if waitErr != nil && !errors.Is(waitErr, os.ErrProcessDone) {
		// A signaled listener is expected for the self-kill scenario.
		if scenario != simhelper.GitHubRunnerSelfKill {
			fmt.Fprintf(stderr, "deprehendo-sim github: listener wait: %v\n", waitErr)
			return 1
		}
	}
	return 0
}

// GitHubRunner describes a materialized fake installation.
type GitHubRunner struct {
	Root         string
	ListenerPath string
	WorkerPath   string
	JobPath      string
	Scenario     string
}

// MaterializeGitHubRunner writes a runner installation layout and copies the
// sim binary into the three role paths. the binaries are real executables with
// the right names, so /proc (or ps) resolves them exactly like a real runner.
func MaterializeGitHubRunner(root, scenario string) (GitHubRunner, error) {
	runner := GitHubRunner{
		Root:         root,
		ListenerPath: filepath.Join(root, "bin", "Runner.Listener"),
		WorkerPath:   filepath.Join(root, "bin", "Runner.Worker"),
		JobPath:      filepath.Join(root, "_work", "job"),
		Scenario:     scenario,
	}
	for _, dir := range []string{
		filepath.Join(root, "bin"),
		filepath.Join(root, "_diag"),
		filepath.Join(root, "_work"),
		filepath.Join(root, "2.320.0"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return GitHubRunner{}, err
		}
	}
	binary, err := SimBinary()
	if err != nil {
		return GitHubRunner{}, fmt.Errorf("locate sim binary: %w", err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		return GitHubRunner{}, fmt.Errorf("read sim binary: %w", err)
	}
	for _, path := range []string{runner.ListenerPath, runner.WorkerPath, runner.JobPath} {
		if err := os.WriteFile(path, data, 0o755); err != nil {
			return GitHubRunner{}, err
		}
	}
	ephemeral := scenario == simhelper.GitHubNormalEphemeral
	name := "linux-prod-03"
	if ephemeral {
		name = "ci-ephemeral-07"
	}
	config := fmt.Sprintf("{\"agentId\":7,\"agentName\":%q,\"ephemeral\":%t,\"workFolder\":\"_work\"}\n", name, ephemeral)
	if err := os.WriteFile(filepath.Join(root, ".runner"), []byte(config), 0o600); err != nil {
		return GitHubRunner{}, err
	}
	if err := os.WriteFile(filepath.Join(root, "config.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		return GitHubRunner{}, err
	}
	return runner, nil
}

func printGitHubUsage(w io.Writer) {
	fmt.Fprint(w, "Usage:\n  deprehendo-sim github <scenario> [--root DIR] [--duration DUR] [--keep] [--json]\n\n")
	fmt.Fprintln(w, "Fake GitHub Actions runner scenarios:")
	for _, name := range simhelper.GitHubScenarios() {
		fmt.Fprintf(w, "  %-24s %s\n", name, simhelper.GitHubDescription(name))
	}
	fmt.Fprintln(w, "\nThe harness writes a real installation (bin/Runner.Listener, bin/Runner.Worker,")
	fmt.Fprintln(w, ".runner, config.sh, _diag/) and real processes, so `deprehendo-agent start")
	fmt.Fprintln(w, "--github-runner-pids <listener>` can record it without GitHub access.")
}

func waitForGitHubState(ctx context.Context, root string) (simhelper.GitHubState, bool) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(githubReadyTimeout)
	defer deadline.Stop()
	for {
		if state, err := simhelper.ReadGitHubState(root); err == nil && state.Listener > 0 {
			// "assigned" is a transient phase: the worker has not published its
			// job tree yet, so a caller attaching now could miss the tree.
			if state.Phase == "idle" || state.Phase == "running" {
				return state, true
			}
		}
		select {
		case <-ctx.Done():
			return simhelper.GitHubState{}, false
		case <-deadline.C:
			return simhelper.GitHubState{}, false
		case <-ticker.C:
		}
	}
}

// watchGitHubPhases emits one event per observed phase transition until the
// caller closes stop. it polls the harness state file, so it never races the
// listener's own writes.
func watchGitHubPhases(root, initial string, cfg Config, stop <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	last := initial
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		state, err := simhelper.ReadGitHubState(root)
		if err != nil || state.Phase == last {
			continue
		}
		last = state.Phase
		cfg.Emit("phase", map[string]any{
			"phase": state.Phase, "worker_pid": state.Worker, "job_root_pid": state.JobRoot,
		})
	}
}

// killQuiet kills a process group if the PID was published.
func killQuiet(pid int) {
	if pid <= 0 {
		return
	}
	_ = platform.KillGroup(pid, syscall.SIGKILL)
}

func doneOrTimeout(done chan waitRes, timeout time.Duration) (waitRes, bool) {
	select {
	case res := <-done:
		return res, true
	case <-time.After(timeout):
		return waitRes{}, false
	}
}
