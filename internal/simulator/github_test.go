package simulator

// tests for the fake GitHub runner harness (phase 5 item 5.41). the harness is
// the reason provider tests do not need GitHub: it materializes a real runner
// installation, starts real processes named like the runner's, and fails in
// each scenario's own way. these tests pin the two things a harness can get
// wrong and still look fine in a log: the choreography it claims, and the
// processes it must not leave behind.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"runopsy/internal/platform"
	"runopsy/internal/simhelper"
)

// TestGitHubHarnessPlans pins the choreography table. every advertised
// scenario must have a plan and a help line, and the plans must differ where
// the scenarios differ: an assignment-stall never spawns a worker, a worker
// scenario waits long enough for a recorder to attach, and the OOM case takes
// the job down with the worker while the orphan case does not.
func TestGitHubHarnessPlans(t *testing.T) {
	scenarios := simhelper.GitHubScenarios()
	if len(scenarios) != 9 {
		t.Fatalf("harness advertises %d scenarios, want the 9 from the Phase 5 plan", len(scenarios))
	}
	seen := map[string]bool{}
	for _, name := range scenarios {
		if seen[name] {
			t.Errorf("scenario %q listed twice", name)
		}
		seen[name] = true
		if simhelper.GitHubDescription(name) == "" {
			t.Errorf("%s has no help description", name)
		}
		if _, err := simhelper.PlanFor(name); err != nil {
			t.Errorf("%s has no plan: %v", name, err)
		}
	}
	if _, err := simhelper.PlanFor("not-a-scenario"); err == nil {
		t.Error("an unknown scenario produced a plan")
	}

	assignment, err := simhelper.PlanFor(simhelper.GitHubAssignmentStall)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.Worker || assignment.JobTree || !assignment.AssignOnly {
		t.Errorf("assignment-stall plan = %+v, want an assignment with no worker", assignment)
	}
	healthy, err := simhelper.PlanFor(simhelper.GitHubHealthyJob)
	if err != nil {
		t.Fatal(err)
	}
	if !healthy.Worker || !healthy.JobTree || healthy.JobAfter <= 0 {
		t.Errorf("healthy-job plan = %+v, want a worker tree after an idle delay", healthy)
	}
	oom, err := simhelper.PlanFor(simhelper.GitHubWorkerOOM)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := simhelper.PlanFor(simhelper.GitHubOrphanJob)
	if err != nil {
		t.Fatal(err)
	}
	if !oom.KillTree {
		t.Error("worker-oom must take the job tree down with the worker")
	}
	if orphan.KillTree {
		t.Error("orphan-job must leave the job tree alive")
	}
	selfKill, err := simhelper.PlanFor(simhelper.GitHubRunnerSelfKill)
	if err != nil {
		t.Fatal(err)
	}
	if selfKill.SelfKill <= 0 {
		t.Error("runner-self-kill never terminates the listener")
	}
	ephemeral, err := simhelper.PlanFor(simhelper.GitHubNormalEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	if ephemeral.ListenerStop <= 0 || ephemeral.WorkerExit <= 0 {
		t.Errorf("ephemeral plan = %+v, want a completed job and an early listener stop", ephemeral)
	}
}

// TestGitHubHarnessMaterializesInstallation proves the on-disk half is a real
// runner layout: the three role binaries are executable files under a
// bin/_work/_diag/version structure, and .runner carries only the allowlisted
// keys (so a fixture can never smuggle a secret into the provider).
func TestGitHubHarnessMaterializesInstallation(t *testing.T) {
	simBinary(t)
	root := t.TempDir()
	runner, err := MaterializeGitHubRunner(root, simhelper.GitHubHealthyJob)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range simhelper.InstallationFiles(root) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("installation is missing %s: %v", path, err)
		}
		if !info.Mode().IsRegular() {
			t.Errorf("%s is not a regular file", path)
		}
	}
	for _, path := range []string{runner.ListenerPath, runner.WorkerPath, runner.JobPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable", path)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "_diag")); err != nil {
		t.Errorf("installation has no diagnostic directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "2.320.0")); err != nil {
		t.Errorf("installation has no version directory: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".runner"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf(".runner is not JSON: %v", err)
	}
	allowed := map[string]bool{"agentId": true, "agentName": true, "ephemeral": true, "workFolder": true}
	for key := range config {
		if !allowed[key] {
			t.Errorf(".runner carries unlisted key %q", key)
		}
	}
	if config["agentName"] != "linux-prod-03" {
		t.Errorf(".runner agentName = %v", config["agentName"])
	}
}

func TestGitHubCLIRejectsUnknownScenario(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunGitHubCLI([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), `unknown scenario "bogus"`) {
		t.Errorf("stderr = %q", errb.String())
	}
	var help bytes.Buffer
	if code := RunGitHubCLI(nil, &help, &errb); code != 0 {
		t.Fatalf("bare `github` exit code = %d, want 0", code)
	}
	for _, name := range simhelper.GitHubScenarios() {
		if !strings.Contains(help.String(), name) {
			t.Errorf("help output missing scenario %q", name)
		}
	}
	if code := RunGitHubCLI([]string{"healthy-idle", "--duration", "0s"}, &out, &errb); code != 2 {
		t.Fatalf("zero duration exit code = %d, want 2", code)
	}
}

// runGitHubHarness drives the harness in JSON mode with an explicit root so
// the test can inspect the installation afterwards.
func runGitHubHarness(t *testing.T, scenario string, duration time.Duration) ([]githubEvent, simhelper.GitHubState, string) {
	t.Helper()
	simBinary(t)
	root := t.TempDir()
	var out, errb bytes.Buffer
	code := RunGitHubCLI([]string{scenario, "--root", root, "--duration", duration.String(), "--json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("harness %s exit = %d\nstderr: %s\nstdout: %s", scenario, code, errb.String(), out.String())
	}
	var got []githubEvent
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		var event githubEvent
		if err := dec.Decode(&event); err != nil {
			t.Fatalf("decode harness event: %v\nraw: %s", err, out.String())
		}
		got = append(got, event)
	}
	state, err := simhelper.ReadGitHubState(root)
	if err != nil {
		t.Fatalf("harness published no state: %v", err)
	}
	return got, state, root
}

type githubEvent struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

func (e githubEvent) number(key string) int {
	value, _ := e.Data[key].(float64)
	return int(value)
}

// TestGitHubHarnessHealthyJob runs the load-bearing scenario end to end: a
// listener idles, a job is assigned, a worker and job tree appear, and
// everything is reaped when the listener exits on its own.
func TestGitHubHarnessHealthyJob(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real runner processes")
	}
	events, state, root := runGitHubHarness(t, simhelper.GitHubHealthyJob, 6*time.Second)

	var ready *githubEvent
	var running *githubEvent
	for i := range events {
		switch {
		case events[i].Type == "ready":
			ready = &events[i]
		case events[i].Type == "phase" && events[i].Data["phase"] == "running":
			running = &events[i]
		}
	}
	if ready == nil {
		t.Fatalf("harness never published readiness: %+v", events)
	}
	// readiness is what a caller can attach to, so it must arrive while the
	// runner is still idle (before the assignment). otherwise the job is
	// already running before recording starts.
	if ready.Data["phase"] != "idle" {
		t.Errorf("ready phase = %v, want idle", ready.Data["phase"])
	}
	if running == nil {
		t.Fatalf("harness never reported a running job: %+v", events)
	}
	if got := running.number("worker_pid"); got <= 0 {
		t.Errorf("running phase reported worker_pid=%d", got)
	}
	if got := running.number("job_root_pid"); got <= 0 {
		t.Errorf("running phase reported job_root_pid=%d", got)
	}
	if state.Worker <= 0 || state.JobRoot <= 0 {
		t.Fatalf("final state = %+v, want a worker and job root", state)
	}
	if state.Phase != "stopped" {
		t.Errorf("final phase = %q, want stopped", state.Phase)
	}
	requireProcessesGone(t, state.Listener, state.Worker, state.JobRoot)

	// the installation must show the runner's own diagnostic artifacts: a
	// listener log with the startup record and a worker log with the job.
	requireLogContains(t, root, "Runner_*.log", "Listening for Jobs")
	requireLogContains(t, root, "Runner_*.log", "INFO JobDispatcher] Job request 1 for plan 6f1c job 0d2e received.")
	requireLogContains(t, root, "Worker_*.log", "Job message received")
}

// TestGitHubHarnessAssignmentStall is the 5.20 shape: the assignment is
// logged, the listener stays alive for the whole run, and no worker ever
// appears, so a provider must leave the assignment unbound.
func TestGitHubHarnessAssignmentStall(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real runner processes")
	}
	events, state, root := runGitHubHarness(t, simhelper.GitHubAssignmentStall, 5*time.Second)
	if state.Worker != 0 || state.JobRoot != 0 {
		t.Fatalf("assignment stall spawned processes: worker=%d job=%d", state.Worker, state.JobRoot)
	}
	for _, event := range events {
		if event.Type == "ready" && event.number("worker_pid") != 0 {
			t.Errorf("ready reported a worker for the stall scenario: %+v", event.Data)
		}
	}
	requireProcessesGone(t, state.Listener)
	requireLogContains(t, root, "Runner_*.log", "INFO JobDispatcher] Job request 1 for plan 6f1c job 0d2e received.")
}

// TestGitHubHarnessInterruptReapsRunner proves ctrl+C is safe: the harness is
// told to stop before its duration ends and must still kill the runner
// process group it started, leaving nothing behind.
func TestGitHubHarnessInterruptReapsRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real runner processes")
	}
	binary := simBinary(t)
	root := t.TempDir()
	cmd := exec.Command(binary, "github", simhelper.GitHubHealthyIdle, "--root", root, "--duration", "60s", "--json")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var state simhelper.GitHubState
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := simhelper.ReadGitHubState(root); err == nil && st.Listener > 0 && st.Phase == "idle" {
			state = st
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if state.Listener == 0 {
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("harness never became ready: %s", out.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal harness: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("interrupted harness exited with %v\n%s", err, out.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("interrupted harness did not stop\n%s", out.String())
	}
	if !strings.Contains(out.String(), `"interrupted"`) {
		t.Errorf("harness did not report the interrupt as its stop reason:\n%s", out.String())
	}
	requireProcessesGone(t, state.Listener)
}

func requireProcessesGone(t *testing.T, pids ...int) {
	t.Helper()
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if !goneOrZombie(pid, 5*time.Second) {
			p, ok, _ := platform.Find(pid)
			t.Errorf("harness left pid %d behind (%+v, alive=%t)", pid, p, ok)
		}
	}
}

func requireLogContains(t *testing.T, root, pattern, want string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "_diag", pattern))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no %s under %s/_diag", pattern, root)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), want) {
			return
		}
	}
	t.Errorf("no %s contains %q", pattern, want)
}
