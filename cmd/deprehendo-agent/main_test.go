package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/agent"
	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

func TestCommands(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"version"}, 0, "Deprehendo Agent " + version},
		{[]string{"version", "unexpected"}, 2, "unexpected arguments"},
		{[]string{"github", "doctor", "unexpected"}, 2, "unexpected arguments"},
		{[]string{"status", "--socket", "/nonexistent-deprehendo-test.sock"}, 1, "agent unavailable"},
		{[]string{"trigger", "--socket", "/nonexistent-deprehendo-test.sock"}, 1, "agent unavailable"},
		{[]string{"inspect"}, 2, "requires exactly one"},
		{[]string{"inspect", "/nonexistent-deprehendo-test.deprehendo"}, 1, "inspect:"},
		{[]string{"status", "--json", "--socket", "/nonexistent-deprehendo-test.sock"}, 1, "agent unavailable"},
		{[]string{"status", "--help"}, 0, "Usage of status"},
		{[]string{"--help"}, 0, "Usage:"},
		{[]string{"unknown"}, 2, "unknown command"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != tc.code {
				t.Fatalf("run(%v) = %d, want %d; stderr=%s", tc.args, code, tc.code, stderr.String())
			}
			if !strings.Contains(stdout.String()+stderr.String(), tc.want) {
				t.Fatalf("output missing %q: stdout=%q stderr=%q", tc.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestVersionReportsEmbeddedAnalysisVersions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version = %d: %s", code, stderr.String())
	}
	for _, want := range []string{
		"Deprehendo Agent " + incident.AgentVersion,
		"Analyzer " + diagnosis.AnalyzerVersion,
		fmt.Sprintf("Signature set %d", diagnosis.SignatureSetVersion),
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("version output missing %q: %s", want, stdout.String())
		}
	}
}

func TestStartRejectsInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"start", "--interval", "0s"},
		{"start", "--window", "-1s"},
		{"start", "--log-level", "verbose"},
		{"start", "--window", "2562047h47m16.854775807s", "--interval", "1ns"},
		{"start", "--watch-tree"},
		{"start", "--watch-pid", "-1"},
		{"start", "--watch-fs", ""},
		{"start", "--capture-pre", "-1s"},
		{"start", "--capture-post", "2h"},
		{"start", "--max-incidents", "-1"},
		{"start", "--max-incident-age", "-1s"},
		{"start", "--trigger-memory-percent", "101"},
		{"start", "--trigger-disk-free-percent", "-1"},
		{"start", "--trigger-duration", "-1s"},
		{"start", "--trigger-on-stop"},
		{"start", "--trigger-on-stop", "--watch-pid", "1", "--collect-processes=false"},
		// 6.21: an unknown tracing mode is a usage error, resolved before
		// anything is started.
		{"start", "--tracing", "solar-flare"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("run(%v) = %d, want 2; stderr=%s", args, code, stderr.String())
		}
	}
}

// TestStartTracingIsConfiguredBeforeAnyCollection pins 6.21/6.46 at the CLI
// boundary: the mode is resolved from the flag or the environment before any
// collection starts, and the debug-recording path is accepted as a start flag.
func TestStartTracingIsConfiguredBeforeAnyCollection(t *testing.T) {
	t.Setenv("DEPREHENDO_TRACING", "disabled")
	var stdout, stderr bytes.Buffer
	// A disabled mode still needs a valid run; it must get past tracing setup
	// and stop at the next configuration error rather than failing on tracing.
	code := run([]string{"start", "--trace-debug-output", filepath.Join(t.TempDir(), "trace.bin"), "--watch-fs", ""}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("start = %d, want 2; stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "tracing") {
		t.Fatalf("a valid tracing configuration reported an error: %s", stderr.String())
	}

	cfg, err := traceConfig("", "")
	if err != nil {
		t.Fatalf("traceConfig from env: %v", err)
	}
	if cfg.Mode.Enabled() {
		t.Fatalf("DEPREHENDO_TRACING=disabled resolved to %q", cfg.Mode)
	}
	cfg, err = traceConfig("proc", "")
	if err != nil {
		t.Fatalf("traceConfig from flag: %v", err)
	}
	if cfg.Mode.String() != "proc" {
		t.Fatalf("explicit flag did not override the environment: %q", cfg.Mode)
	}
}

func TestRuntimeRejectsUnsafeCapacity(t *testing.T) {
	for _, capacity := range []int{0, -1, 1 << 21} {
		if _, err := agent.New(agent.Options{Interval: time.Second, Capacity: capacity}); err == nil {
			t.Errorf("agent.New capacity %d unexpectedly succeeded", capacity)
		}
	}
}

func TestRuntimeSamplesAndDumpsLatestProcessView(t *testing.T) {
	r, err := agent.New(agent.Options{Interval: time.Second, Capacity: 16})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	r.SampleOnce()
	status := r.Status()
	if status.Samples != 1 || status.ProcessCount == 0 || status.LastSample.IsZero() || status.StartedAt.Before(started) {
		t.Fatalf("incomplete one-shot status: %+v", status)
	}
	var dump bytes.Buffer
	if err := r.Dump(&dump); err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if !strings.Contains(dump.String(), `"processes"`) || !strings.Contains(dump.String(), `"timestamp"`) || !strings.Contains(dump.String(), `"metrics"`) {
		t.Fatalf("unexpected dump: %s", dump.String())
	}
	if status.Uptime <= 0 || status.BufferUsed != 1 || status.BufferCapacity != 16 || len(status.CollectorMetrics) == 0 {
		t.Fatalf("status missing uptime/buffer/collector telemetry: %+v", status)
	}
}

func TestRuntimeRunStopsOnCancellation(t *testing.T) {
	r, err := agent.New(agent.Options{Interval: 250 * time.Millisecond, Capacity: 16})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	deadline := time.Now().Add(45 * time.Second)
	for r.Status().Samples < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := r.Status().Samples; got < 2 {
		t.Fatalf("samples = %d after %s, want an initial and at least one scheduled sample", got, time.Until(deadline))
	}
}

func TestDumpContainsSelfProcess(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("unsupported process snapshot platform %s", runtime.GOOS)
	}
	r, err := agent.New(agent.Options{Interval: time.Second, Capacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	r.SampleOnce()
	var dump bytes.Buffer
	if err := r.Dump(&dump); err != nil {
		t.Fatal(err)
	}
	processes, err := platform.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) == 0 {
		t.Fatal("process snapshot is unexpectedly empty")
	}
	selffound := false
	for _, process := range processes {
		if process.PID == runtimePid() {
			selffound = true
			if process.Threads <= 0 && runtime.GOOS == "linux" {
				t.Errorf("Linux process snapshot should include thread count: %+v", process)
			}
		}
	}
	if !selffound {
		t.Error("dump is missing the test process")
	}
}

func runtimePid() int { return os.Getpid() }

func testBundle(t *testing.T) string {
	t.Helper()
	at := time.Date(2026, 10, 25, 19, 48, 12, 0, time.UTC)
	i := &incident.Incident{
		SchemaVersion: incident.SchemaVersion,
		ID:            "inc_0123456789abcdef0123456789abcdef",
		CreatedAt:     at.Add(31 * time.Second),
		TriggeredAt:   at,
		CaptureStart:  at.Add(-time.Minute),
		CaptureEnd:    at.Add(30 * time.Second),
		Window:        incident.CaptureWindow{PreTrigger: time.Minute, PostTrigger: 30 * time.Second},
		Trigger:       incident.Trigger{Type: "process_stopped", PID: 4218},
		Metadata:      incident.Metadata{AgentVersion: incident.AgentVersion, Host: incident.LocalHost()},
		Events:        []incident.Event{{Timestamp: at, Type: incident.IncidentTriggered, PID: 4218}},
	}
	var encoded bytes.Buffer
	if err := incident.Encode(&encoded, i, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), i.ID+".deprehendo")
	if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectSummaryAndTimeline(t *testing.T) {
	path := testBundle(t)
	for _, args := range [][]string{{path, "--timeline"}, {"--timeline", path}} {
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"inspect"}, args...), &stdout, &stderr); code != 0 {
			t.Fatalf("inspect %v = %d: %s", args, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"INCIDENT", "inc_0123456789abcdef0123456789abcdef", "Triggered", "process_stopped (pid 4218)", "Integrity            OK", "TIMELINE", "19:48:12", "INCIDENT_TRIGGERED", "process_stopped"} {
			if !strings.Contains(out, want) {
				t.Errorf("inspect output missing %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "FROZEN_PROCESS") {
			t.Errorf("inspect emitted a diagnosis:\n%s", out)
		}
	}
}
