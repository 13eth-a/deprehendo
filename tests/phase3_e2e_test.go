package tests

// phase 3 end-to-end fault evaluation: a live simulator fault is recorded by
// the real agent, persisted as a bundle by the phase 2 trigger rules, and
// classified by the offline deterministic analyzer. these are separate from
// the internal/diagnosis corpus tests because they exercise the collector,
// redactor, bundle writer and reader as well as the signature rules.
//
// gated behind RUNOPSY_E2E_DIAGNOSIS because the CPU-spin rule requires a real
// 60s sustained-CPU window, so the suite takes about a minute and a half.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/diagnosis"
)

func TestPhase3DiagnosisEndToEnd(t *testing.T) {
	if os.Getenv("RUNOPSY_E2E_DIAGNOSIS") == "" {
		t.Skip("set RUNOPSY_E2E_DIAGNOSIS=1 to run simulator -> recorder -> analyzer fault evaluation")
	}
	if testing.Short() {
		t.Skip("live fault-injection diagnosis")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("requires Linux or macOS, got %s", runtime.GOOS)
	}
	t.Run("frozen-worker", testDiagnosisFrozenWorker)
	t.Run("watched-exit-is-unknown", testDiagnosisWatchedExitUnknown)
	if runtime.GOOS == "linux" {
		// process CPU ticks and PSI are Linux-only, and CPU_SPIN depends on
		// both; on macOS the collector reports unavailable CPU telemetry.
		t.Run("cpu-spin", testDiagnosisCPUSpin)
	}
}

// diagnosisHarness owns one live recorder process pointed at a scratch
// incident directory. the simulator is started separately so each case can
// choose its own trigger.
type diagnosisHarness struct {
	t           *testing.T
	dir         string
	socket      string
	incidentDir string
	cmd         *exec.Cmd
	out         *recorderOutput
	done        chan error
	ctx         context.Context
	cancel      context.CancelFunc
	stopped     bool
	simBin      string
	simName     string
}

func startDiagnosisRecorder(t *testing.T, timeout time.Duration, extra ...string) *diagnosisHarness {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "runopsy-phase3-")
	if err != nil {
		t.Fatal(err)
	}
	h := &diagnosisHarness{
		t:           t,
		dir:         base,
		socket:      filepath.Join(base, "agent.sock"),
		incidentDir: filepath.Join(base, "incidents"),
		out:         &recorderOutput{},
		done:        make(chan error, 1),
	}
	t.Cleanup(h.stop)
	if err := os.Mkdir(h.incidentDir, 0700); err != nil {
		t.Fatal(err)
	}
	// watch a private copy under a name unique to this test process: a plain
	// --watch-name runopsy-sim would also capture simulators started by other
	// packages' tests running in parallel, and their exits would leak into this
	// incident's process group. linux truncates comm to 15 bytes, so the name
	// stays short.
	h.simName = fmt.Sprintf("rph3-%d", os.Getpid())
	h.simBin = filepath.Join(base, h.simName)
	binary, err := os.ReadFile(simPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.simBin, binary, 0755); err != nil {
		t.Fatal(err)
	}
	h.ctx, h.cancel = context.WithTimeout(context.Background(), timeout)
	args := []string{"start",
		"--socket", h.socket,
		"--incident-dir", h.incidentDir,
		"--interval", "100ms",
		"--watch-name", h.simName,
		"--max-incidents", "1",
	}
	args = append(args, extra...)
	h.cmd = exec.CommandContext(h.ctx, agentPath, args...)
	h.cmd.Stdout, h.cmd.Stderr = h.out, h.out
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start recorder: %v", err)
	}
	go func() { h.done <- h.cmd.Wait() }()

	for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); {
		var out bytes.Buffer
		if err := agent.ReadControl(h.ctx, h.socket, "status", &out); err == nil {
			var status agent.Status
			if json.Unmarshal(out.Bytes(), &status) == nil && status.Samples >= 3 {
				return h
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("recorder never sampled: %s", h.out.String())
	return nil
}

func (h *diagnosisHarness) stop() {
	if h == nil || h.cmd == nil || h.cmd.Process == nil || h.stopped {
		return
	}
	h.stopped = true
	_ = h.cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
	h.cancel()
	_ = os.RemoveAll(h.dir)
}

// runSimulator starts one scenario and returns its PID. the cleanup path
// interrupts the simulator so a failed assertion cannot leak workers.
func (h *diagnosisHarness) runSimulator(args ...string) *exec.Cmd {
	h.t.Helper()
	simctx, cancel := context.WithTimeout(h.ctx, 120*time.Second)
	cmd := exec.CommandContext(simctx, h.simBin, append(args, "--json")...)
	var out recorderOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		cancel()
		h.t.Fatalf("start simulator %v: %v", args, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	h.t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		cancel()
	})
	return cmd
}

func (h *diagnosisHarness) waitBundle(within time.Duration) string {
	h.t.Helper()
	path := waitForBundle(h.t, h.incidentDir, within)
	return path
}

// analyzeBundle runs the shipped analyze binary exactly as an operator would
// and decodes the JSON report.
func analyzeBundle(t *testing.T, bundle string) *diagnosis.Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentPath, "analyze", bundle, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("analyze %s: %v\n%s", bundle, err, out)
	}
	var report diagnosis.Report
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("analyze %s returned invalid JSON: %v\n%s", bundle, err, out)
	}
	return &report
}

func requirePrimary(t *testing.T, report *diagnosis.Report, want diagnosis.SignatureID) diagnosis.SignatureMatch {
	t.Helper()
	if report.Unknown || len(report.Matches) == 0 {
		t.Fatalf("diagnosis = UNKNOWN, want %s (strong observations: %+v)", want, report.StrongObservations)
	}
	top := report.Matches[0]
	if top.SignatureID != want {
		t.Fatalf("primary diagnosis = %s, want %s (all matches: %+v)", top.SignatureID, want, report.Matches)
	}
	if top.Confidence < report.MinConfidence || top.Confidence > 1 {
		t.Fatalf("%s confidence = %v, want within [%v,1]", want, top.Confidence, report.MinConfidence)
	}
	if len(top.Supporting) == 0 {
		t.Fatalf("%s matched without supporting evidence", want)
	}
	return top
}

func testDiagnosisFrozenWorker(t *testing.T) {
	// the analyzer can only see what was captured, so the post-trigger window
	// must itself exceed the 5s minimum stopped span; the worker therefore
	// stays frozen well past capture end.
	h := startDiagnosisRecorder(t, 60*time.Second,
		"--window", "20s",
		"--trigger-on-stop",
		"--capture-pre", "10s",
		"--capture-post", "7s",
	)
	h.runSimulator("frozen-worker", "--freeze-after", "1200ms", "--freeze-for", "15s", "--grace", "300ms")
	bundle := h.waitBundle(40 * time.Second)
	report := analyzeBundle(t, bundle)
	match := requirePrimary(t, report, diagnosis.SignatureFrozenProcess)
	if !strings.Contains(string(match.Supporting[0].Code), "PROCESS_STOPPED") {
		t.Errorf("first supporting evidence = %s, want a stopped-state observation", match.Supporting[0].Code)
	}
}

func testDiagnosisWatchedExitUnknown(t *testing.T) {
	h := startDiagnosisRecorder(t, 45*time.Second,
		"--window", "15s",
		"--trigger-on-process-exit",
		"--capture-pre", "6s",
		"--capture-post", "1s",
	)
	h.runSimulator("exit", "--code", "7", "--hold", "1200ms")
	bundle := h.waitBundle(30 * time.Second)
	report := analyzeBundle(t, bundle)
	if !report.Unknown || len(report.Matches) != 0 {
		t.Fatalf("clean watched exit produced %+v, want UNKNOWN with no matches", report.Matches)
	}
	// an observed exit is still a strong observation even when no signature
	// explains it, so the report must not be empty.
	if len(report.StrongObservations) == 0 {
		t.Fatal("UNKNOWN report carried no strong observations")
	}
}

func testDiagnosisCPUSpin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("CPU_SPIN needs Linux process tick and PSI collectors")
	}
	// the rule needs 60s of sustained CPU, so the capture window must reach
	// back at least that far before the manual trigger.
	h := startDiagnosisRecorder(t, 150*time.Second,
		"--window", "90s",
		"--capture-pre", "75s",
		"--capture-post", "1s",
	)
	h.runSimulator("cpu-spin", "--workers", "1", "--duration", "70s")
	time.Sleep(64 * time.Second)
	out, err := exec.CommandContext(h.ctx, agentPath, "trigger", "--socket", h.socket).CombinedOutput()
	if err != nil {
		t.Fatalf("manual trigger: %v\n%s\nrecorder log:\n%s", err, out, h.out.String())
	}
	bundle := h.waitBundle(40 * time.Second)
	report := analyzeBundle(t, bundle)
	for _, match := range report.Matches {
		if match.SignatureID == diagnosis.SignatureCPUSpin {
			t.Fatal("v1 lacks application progress evidence and must not diagnose CPU_SPIN")
		}
	}
	for _, rejected := range report.Rejections {
		if rejected.SignatureID == diagnosis.SignatureCPUSpin && len(rejected.Supporting) > 0 && len(rejected.MissingEvidence) > 0 {
			return
		}
	}
	t.Fatalf("CPU hypothesis must retain observed CPU evidence and explain missing progress telemetry; rejections=%+v", report.Rejections)
}
