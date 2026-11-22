package simulator

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

type simRunResult struct {
	code   int
	kind   string // "exited" | "signal"
	stdout []byte
	stderr []byte
}

// runSim executes the test-built sim binary with the given arguments and
// reports the observed exit status the way the OS reported it to us.
func runSim(t *testing.T, args ...string) simRunResult {
	t.Helper()
	if simBinaryPath == "" {
		t.Skip("sim binary not built")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, simBinaryPath, args...)
	cmd.WaitDelay = time.Second
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("run %v timed out: %v\nstdout: %s\nstderr: %s", args, ctx.Err(), so.String(), se.String())
	}
	code, kind := 0, "exited"
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				kind = "signal"
				code = 128 + int(ws.Signal())
			} else if ws.Exited() {
				code = ws.ExitStatus()
			}
		}
	} else if err != nil {
		t.Fatalf("run %v: %v\nstderr: %s", args, err, se.String())
	}
	return simRunResult{code: code, kind: kind, stdout: so.Bytes(), stderr: se.Bytes()}
}

func TestExitScenarioChosenExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process")
	}
	res := runSim(t, "exit", "--code", "7", "--json")
	if res.kind != "exited" || res.code != 7 {
		t.Errorf("exit --code 7 gave kind=%s code=%d, want exited/7", res.kind, res.code)
	}
	evs := decodeEvents(t, bytes.NewBuffer(res.stdout))
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if rc, _ := exited[0].Data["code"].(float64); int(rc) != 7 {
		t.Errorf("event exit code = %v, want 7", exited[0].Data["code"])
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "exit_code_requested" {
		t.Errorf("exit reason = %v, want exit_code_requested", exited[0].Data["reason"])
	}
}

func TestSignalScenarioTerminatedByTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process")
	}
	// the self-TERMed process must land in the kernel's 128+N status (143), not
	// a graceful exit: that is the whole point of the reset before the raise.
	res := runSim(t, "signal", "--signal", "TERM", "--hold", "300ms", "--json")
	if res.kind != "signal" || res.code != 143 {
		t.Errorf("signal TERM gave kind=%s code=%d, want signal/143", res.kind, res.code)
	}
	evs := decodeEvents(t, bytes.NewBuffer(res.stdout))
	sent := eventsOf(evs, "signal_sent")
	if len(sent) != 1 {
		t.Fatalf("signal_sent events = %d, want 1", len(sent))
	}
	if name, _ := sent[0].Data["signal"].(string); name != "TERM" {
		t.Errorf("signal_sent name = %v, want TERM", sent[0].Data["signal"])
	}
	if got := eventsOf(evs, "exited"); len(got) != 0 {
		t.Errorf("exited events = %d, want 0 (a TERMed process cannot emit its death)",
			len(got))
	}
}

func TestSignalScenarioKilled(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process")
	}
	res := runSim(t, "signal", "--signal", "KILL", "--hold", "200ms", "--json")
	if res.kind != "signal" || res.code != 137 {
		t.Errorf("signal KILL gave kind=%s code=%d, want signal/137", res.kind, res.code)
	}
}

func TestSignalScenarioINTReachesDefaultDisposition(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process")
	}
	// after the scenario's signal.Reset the CLI's graceful handler no longer
	// applies: a self-INT is an unsupervised SIGINT, so 130.
	res := runSim(t, "signal", "--signal", "INT", "--hold", "200ms", "--json")
	if res.kind != "signal" || res.code != 130 {
		t.Errorf("signal INT gave kind=%s code=%d, want signal/130", res.kind, res.code)
	}
}

func TestSignalScenarioStopResumedByWatcher(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process")
	}
	// STOP must freeze, then the _cont helper resumes the process; it exits 0.
	// without the watcher this test would hang, so a passing run doubles as
	// bounded-runtime proof.
	start := time.Now()
	res := runSim(t, "signal", "--signal", "STOP", "--hold", "300ms", "--resume-after", "30ms", "--json")
	if elapsed := time.Since(start); elapsed < 330*time.Millisecond {
		t.Fatalf("STOP run completed in %s before hold plus resume delay elapsed", elapsed)
	}

	if res.kind != "exited" || res.code != 0 {
		t.Errorf("signal STOP resume gave kind=%s code=%d, want exited/0", res.kind, res.code)
	}
	evs := decodeEvents(t, bytes.NewBuffer(res.stdout))
	if got := eventsOf(evs, "signal_sent"); len(got) != 1 {
		t.Errorf("signal_sent events = %d, want 1", len(got))
	}
	if got := eventsOf(evs, "resumed"); len(got) != 1 {
		t.Errorf("resumed events = %d, want 1 (the watcher's SIGCONT)", len(got))
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "signal_delivered" {
		t.Errorf("exit reason = %v, want signal_delivered", exited[0].Data["reason"])
	}
}

func TestSignalScenarioContDelivered(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process")
	}
	// CONT on a running process is a no-op to the kernel, but the run must
	// still complete cleanly with the signal recorded.
	res := runSim(t, "signal", "--signal", "CONT", "--hold", "200ms", "--json")
	if res.kind != "exited" || res.code != 0 {
		t.Errorf("signal CONT gave kind=%s code=%d, want exited/0", res.kind, res.code)
	}
	evs := decodeEvents(t, bytes.NewBuffer(res.stdout))
	sent := eventsOf(evs, "signal_sent")
	if len(sent) != 1 {
		t.Fatalf("signal_sent events = %d, want 1", len(sent))
	}
	if name, _ := sent[0].Data["signal"].(string); name != "CONT" {
		t.Errorf("signal_sent name = %v, want CONT", sent[0].Data["signal"])
	}
	if got := eventsOf(evs, "resumed"); len(got) != 0 {
		t.Errorf("resumed events = %d, want 0 (nothing was frozen)", len(got))
	}
}
