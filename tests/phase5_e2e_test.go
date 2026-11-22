package tests

// phase 5 end-to-end correlation (5.43): the fake runner from item 5.41 drives
// the shipped recorder and the shipped report, so the whole GitHub path runs
// without GitHub access:
//
//	runner installation → Runner.Listener → Runner.Worker → job process tree
//	    → recorder snapshots → provider section → GitHub-aware report
//
// the test asserts correlation and honesty, not a scripted story: the runner
// identity, the worker→runner binding, the job process tree and the job's
// unknown identity are all facts of the capture, and a healthy runner must not
// produce a failure-shaped claim.
//
// A real self-hosted runner (5.42) can replace the harness without changing
// anything else: point RUNOPSY_E2E_GITHUB_RUNNER_ROOT at an installation whose
// Runner.Listener is already running. that path is skipped when unset because
// it needs a disposable runner and a real workflow.
//
// gated behind RUNOPSY_E2E_GITHUB because each case runs a live recorder.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/diagnosis"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github"
	"runopsy/internal/simhelper"
)

func TestPhase5GitHubEndToEnd(t *testing.T) {
	if os.Getenv("RUNOPSY_E2E_GITHUB") == "" {
		t.Skip("set RUNOPSY_E2E_GITHUB=1 to run fake-runner -> recorder -> GitHub-aware report")
	}
	if testing.Short() {
		t.Skip("live fake runner and recorder")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("requires Linux or macOS, got %s", runtime.GOOS)
	}
	t.Run("healthy-job", testPhase5HealthyJob)
	t.Run("assignment-stall", testPhase5AssignmentStall)
	t.Run("worker-oom", testPhase5WorkerOOM)
}

// githubE2E owns one fake runner process and one recorder attached to its
// listener.
type githubE2E struct {
	t       *testing.T
	dir     string
	root    string
	socket  string
	incDir  string
	sim     *exec.Cmd
	simOut  *recorderOutput
	agent   *exec.Cmd
	out     *recorderOutput
	done    chan error
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	state   simhelper.GitHubState
}

// startGitHubE2E launches the fake runner, waits for it to be observable, then
// attaches the recorder with --github-runner-pids. because the harness idles
// for a couple of seconds before the job arrives, the assignment happens on
// camera instead of before the first snapshot.
func startGitHubE2E(t *testing.T, scenario string) *githubE2E {
	t.Helper()
	base, err := os.MkdirTemp("", "runopsy-phase5-")
	if err != nil {
		t.Fatal(err)
	}
	h := &githubE2E{
		t:      t,
		dir:    base,
		root:   filepath.Join(base, "runner"),
		socket: filepath.Join(base, "agent.sock"),
		incDir: filepath.Join(base, "incidents"),
		simOut: &recorderOutput{},
		out:    &recorderOutput{},
		done:   make(chan error, 1),
	}
	if err := os.Mkdir(h.incDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.stop)

	h.ctx, h.cancel = context.WithTimeout(context.Background(), 120*time.Second)
	h.sim = exec.CommandContext(h.ctx, simPath, "github", scenario,
		"--root", h.root, "--duration", "45s", "--json")
	h.sim.Stdout, h.sim.Stderr = h.simOut, h.simOut
	if err := h.sim.Start(); err != nil {
		t.Fatalf("start fake runner: %v", err)
	}
	simdone := make(chan error, 1)
	go func() { simdone <- h.sim.Wait() }()
	t.Cleanup(func() {
		_ = h.sim.Process.Signal(syscall.SIGTERM)
		select {
		case <-simdone:
		case <-time.After(10 * time.Second):
			_ = h.sim.Process.Kill()
			<-simdone
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		state, err := simhelper.ReadGitHubState(h.root)
		if err == nil && state.Listener > 0 && state.Phase == "idle" {
			h.state = state
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if h.state.Listener == 0 {
		t.Fatalf("fake runner never reached idle: %s", h.simOut.String())
	}

	h.agent = exec.CommandContext(h.ctx, agentPath, "start",
		"--socket", h.socket,
		"--incident-dir", h.incDir,
		"--interval", "100ms",
		"--window", "30s",
		"--capture-pre", "10s",
		"--capture-post", "2s",
		"--max-incidents", "1",
		"--github-runner-pids", strconv.Itoa(h.state.Listener),
		"--provider-identifiers",
	)
	h.agent.Stdout, h.agent.Stderr = h.out, h.out
	if err := h.agent.Start(); err != nil {
		t.Fatalf("start recorder: %v", err)
	}
	go func() { h.done <- h.agent.Wait() }()

	for sampledeadline := time.Now().Add(30 * time.Second); time.Now().Before(sampledeadline); {
		var buf bytes.Buffer
		if err := agent.ReadControl(h.ctx, h.socket, "status", &buf); err == nil {
			var status agent.Status
			if json.Unmarshal(buf.Bytes(), &status) == nil && status.Samples >= 5 {
				return h
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("recorder never sampled: %s", h.out.String())
	return nil
}

func (h *githubE2E) stop() {
	if h == nil || h.stopped {
		return
	}
	h.stopped = true
	if h.agent != nil && h.agent.Process != nil {
		_ = h.agent.Process.Signal(syscall.SIGINT)
		select {
		case <-h.done:
		case <-time.After(15 * time.Second):
			_ = h.agent.Process.Kill()
			<-h.done
		}
	}
	h.cancel()
	_ = os.RemoveAll(h.dir)
}

// trigger captures the incident and returns the saved bundle path.
func (h *githubE2E) trigger() string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentPath, "trigger", "--socket", h.socket).CombinedOutput()
	if err != nil {
		h.t.Fatalf("manual trigger: %v\n%s\nrecorder log:\n%s", err, out, h.out.String())
	}
	return h.waitBundle(40 * time.Second)
}

func (h *githubE2E) waitBundle(within time.Duration) string {
	h.t.Helper()
	return waitForBundle(h.t, h.incDir, within)
}

// waitForPhase polls until the harness reports the phase, so a case can time
// the trigger against the scenario rather than sleeping blindly.
func (h *githubE2E) waitForPhase(phase string, within time.Duration) simhelper.GitHubState {
	h.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if state, err := simhelper.ReadGitHubState(h.root); err == nil && state.Phase == phase {
			return state
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatalf("fake runner never reached phase %q: %s", phase, h.simOut.String())
	return simhelper.GitHubState{}
}

// providerSection decodes the one stored provider section from the shipped
// timeline --report --json output.
type providerSectionOutput struct {
	Providers []struct {
		Provider string           `json:"Provider"`
		Section  evidence.Section `json:"Section"`
	} `json:"providers"`
	Diagnosis *diagnosis.Report `json:"diagnosis"`
}

func githubSection(t *testing.T, bundle string) (evidence.Section, *diagnosis.Report) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentPath, "timeline", bundle, "--report", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("timeline %s: %v\n%s", bundle, err, out)
	}
	var report providerSectionOutput
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("timeline returned invalid JSON: %v\n%s", err, out)
	}
	if len(report.Providers) != 1 {
		t.Fatalf("bundle carries %d provider sections, want 1 (output: %s)", len(report.Providers), out)
	}
	section := report.Providers[0].Section
	if section.Provider != "github-actions" {
		t.Fatalf("provider section = %q", section.Provider)
	}
	if section.Health.State != evidence.HealthAvailable {
		t.Fatalf("provider health = %s (%v), want AVAILABLE", section.Health.State, section.Health.Reasons)
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("stored provider section is invalid: %v", err)
	}
	return section, report.Diagnosis
}

func sectionEventTypes(section evidence.Section) []string {
	out := make([]string, 0, len(section.Events))
	for _, event := range section.Events {
		out = append(out, event.Type)
	}
	return out
}

func hasSectionEvent(section evidence.Section, eventType string) bool {
	for _, event := range section.Events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

// registerGitHub installs the provider vocabulary in this test process, which
// is what a stored section validates against. the shipped binaries do the same
// at start-up (cmd/runopsy-agent/github.go).
var registerGitHubOnce sync.Once

func registerGitHub(t *testing.T) {
	t.Helper()
	var failed error
	registerGitHubOnce.Do(func() {
		failed = provider.Default.Register(github.GitHubProvider{})
	})
	if failed != nil {
		t.Fatalf("register provider: %v", failed)
	}
}

func testPhase5HealthyJob(t *testing.T) {
	registerGitHub(t)
	h := startGitHubE2E(t, simhelper.GitHubHealthyJob)
	running := h.waitForPhase("running", 20*time.Second)
	if running.Worker <= 0 || running.JobRoot <= 0 {
		t.Fatalf("running state = %+v, want a worker and job root", running)
	}
	bundle := h.trigger()
	section, report := githubSection(t, bundle)

	// runner identity came from the installation, not from a PID. the host may
	// also carry a real runner (for example on a self-hosted CI runner), so pick
	// the one whose listener is the fake runner this test started.
	var matched []evidence.Runner
	for _, r := range section.Runners {
		for _, sup := range r.Supervisors {
			if sup.PID == h.state.Listener {
				matched = append(matched, r)
			}
		}
	}
	if len(matched) != 1 {
		t.Fatalf("runners for listener %d = %d, want 1 (all runners: %+v)", h.state.Listener, len(matched), section.Runners)
	}
	runner := matched[0]
	if runner.Name.State != evidence.Known || runner.Name.Value != "linux-prod-03" {
		t.Errorf("runner name = %+v, want the configured linux-prod-03", runner.Name)
	}
	if runner.Version.State != evidence.Known || runner.Version.Value != "2.320.0" {
		t.Errorf("runner version = %+v, want 2.320.0 from the installation", runner.Version)
	}
	if runner.Lifecycle != evidence.LifecyclePersistent {
		t.Errorf("lifecycle = %s, want PERSISTENT", runner.Lifecycle)
	}

	// worker → listener → runner, and the job tree the worker owns.
	if len(section.Workers) != 1 {
		t.Fatalf("workers = %d, want 1: %+v", len(section.Workers), section.Workers)
	}
	worker := section.Workers[0]
	if worker.Runner != runner.Ref {
		t.Errorf("worker bound to %q, want the listener's runner %q", worker.Runner, runner.Ref)
	}
	if worker.Process.PID != running.Worker {
		t.Errorf("worker PID = %d, want the observed %d", worker.Process.PID, running.Worker)
	}
	roles := map[evidence.Role]int{}
	for _, role := range section.ProcessRoles {
		roles[role.Role]++
	}
	if roles[evidence.RoleJobRoot] == 0 || roles[evidence.RoleJobProcess] == 0 {
		t.Errorf("job tree roles = %v, want JOB_ROOT and JOB_PROCESS", roles)
	}

	// the assignment bound to exactly that worker, and the job's identity is
	// honestly unknown: no API call and no invented fields (5.9/5.10).
	if len(section.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(section.Jobs))
	}
	job := section.Jobs[0]
	if job.Runner != runner.Ref {
		t.Errorf("job bound to runner=%q, want %q", job.Runner, runner.Ref)
	}
	if worker.Job != job.Ref {
		t.Errorf("worker carries job=%q, want %q", worker.Job, job.Ref)
	}
	for name, state := range map[string]evidence.State{
		"repository": job.Repository.State, "workflow": job.Workflow.State,
		"job name": job.Name.State, "run": job.RunID.State, "attempt": job.Attempt.State,
	} {
		if state != evidence.Unknown {
			t.Errorf("%s state = %s, want UNKNOWN without GitHub API enrichment", name, state)
		}
	}
	assigned := false
	for _, event := range section.Events {
		if event.Type != "GITHUB_JOB_ASSIGNED" {
			continue
		}
		assigned = true
		if event.Worker != worker.Ref || event.Job != job.Ref {
			t.Errorf("assignment event bound to worker=%q job=%q, want %q/%q",
				event.Worker, event.Job, worker.Ref, job.Ref)
		}
	}
	if !assigned {
		t.Fatalf("no GITHUB_JOB_ASSIGNED event (events: %v)", sectionEventTypes(section))
	}

	// A healthy job must not look like a failure (5.40).
	for _, banned := range []string{
		"GITHUB_JOB_PROGRESS_STOPPED", "GITHUB_COMMUNICATION_STALLED",
		"GITHUB_JOB_CANCELLATION", "GITHUB_JOB_TIMEOUT", "GITHUB_RUNNER_STOPPED",
	} {
		if hasSectionEvent(section, banned) {
			t.Errorf("healthy job produced %s", banned)
		}
	}
	if len(section.Conflicts) != 0 {
		t.Errorf("healthy job produced conflicts: %+v", section.Conflicts)
	}
	if report != nil {
		for _, match := range report.Matches {
			if strings.HasPrefix(string(match.SignatureID), "GITHUB_") {
				t.Errorf("healthy job matched provider signature %s", match.SignatureID)
			}
		}
	}

	// the report pairs the provider context with the systems diagnosis (5.26)
	// and speaks in job terms rather than bare PIDs (5.27/5.28).
	text := timelineText(t, bundle)
	for _, want := range []string{"GitHub Actions", "Runner        linux-prod-03", "Job           UNKNOWN"} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "GitHub Actions") > strings.Index(text, "Underlying systems diagnosis") {
		t.Errorf("provider context must precede the systems diagnosis:\n%s", text)
	}
	// an installation path is never written to the bundle (5.36).
	raw, err := json.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), h.root) {
		t.Fatalf("provider section leaks the installation path %q", h.root)
	}
}

func testPhase5AssignmentStall(t *testing.T) {
	registerGitHub(t)
	h := startGitHubE2E(t, simhelper.GitHubAssignmentStall)
	// the assignment is logged; no worker ever appears.
	assigned := h.waitForPhase("assigned", 20*time.Second)
	if assigned.Worker != 0 {
		t.Fatalf("assignment stall spawned a worker: %+v", assigned)
	}
	bundle := h.trigger()
	section, report := githubSection(t, bundle)

	if len(section.Workers) != 0 || len(section.Jobs) != 0 {
		t.Fatalf("workers/jobs invented without a process: %d/%d", len(section.Workers), len(section.Jobs))
	}
	records := 0
	for _, event := range section.Events {
		if event.Type != "GITHUB_JOB_ASSIGNED" {
			continue
		}
		records++
		if event.Source != evidence.SourceRunnerLog {
			t.Errorf("assignment source = %s, want RUNNER_LOG", event.Source)
		}
		if event.Worker != "" || event.Job != "" {
			t.Errorf("assignment guessed worker/job: %q/%q", event.Worker, event.Job)
		}
	}
	if records == 0 {
		t.Fatalf("no assignment recorded (events: %v)", sectionEventTypes(section))
	}
	// the runner is alive and available: the stall is in the job handoff, not
	// the runner's own health. no signature may explain it yet (5.25).
	if section.Health.State != evidence.HealthAvailable {
		t.Errorf("health = %s, want AVAILABLE", section.Health.State)
	}
	if report != nil && !report.Unknown {
		t.Fatalf("assignment stall diagnosed as %+v; no provider signature is implemented for it yet", report.Matches)
	}
}

func testPhase5WorkerOOM(t *testing.T) {
	registerGitHub(t)
	h := startGitHubE2E(t, simhelper.GitHubWorkerOOM)
	h.waitForPhase("running", 20*time.Second)
	// the harness kills the worker and its job; the listener survives, so
	// this is a job-side failure rather than a runner death.
	killed := h.waitForPhase("worker-killed", 20*time.Second)
	if killed.Worker <= 0 {
		t.Fatalf("worker-killed state = %+v", killed)
	}
	time.Sleep(600 * time.Millisecond)
	bundle := h.trigger()
	section, report := githubSection(t, bundle)

	if !hasSectionEvent(section, "GITHUB_WORKER_EXITED") {
		t.Errorf("worker disappearance not recorded (events: %v)", sectionEventTypes(section))
	}
	if len(section.Workers) != 1 || section.Workers[0].Exited.IsZero() {
		t.Errorf("worker exit not recorded: %+v", section.Workers)
	}
	// the listener was never restarted or lost, so the runner-level facts stay
	// clean and no communication stall may be claimed from a dead worker.
	if hasSectionEvent(section, "GITHUB_RUNNER_STOPPED") {
		t.Error("runner reported stopped while its listener was alive")
	}
	if hasSectionEvent(section, "GITHUB_COMMUNICATION_STALLED") {
		t.Error("worker death produced a runner communication stall")
	}
	for _, conflict := range section.Conflicts {
		if conflict.Question == "TERMINATION_INTENT" {
			t.Errorf("unexplained worker death claimed a termination intent: %+v", conflict)
		}
	}
	// v1 has no kernel OOM record, so nothing may claim OOM_KILL (phase 2
	// honesty rule applied to the provider path).
	if report != nil {
		for _, match := range report.Matches {
			if match.SignatureID == diagnosis.SignatureOOMKill {
				t.Errorf("OOM_KILL diagnosed without a kernel OOM record")
			}
		}
	}
}

// timelineText runs the human report an operator reads.
func timelineText(t *testing.T, bundle string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentPath, "timeline", bundle, "--report").CombinedOutput()
	if err != nil {
		t.Fatalf("timeline %s: %v\n%s", bundle, err, out)
	}
	return string(out)
}
