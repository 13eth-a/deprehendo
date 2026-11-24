package tests

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

	"deprehendo/internal/agent"
	"deprehendo/internal/incident"
)

func incidentBundles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "inc_") && strings.HasSuffix(entry.Name(), ".deprehendo") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths
}

// privateSim copies the test-built simulator into dir under a name unique to
// this test process, and returns its path and process name. watching the shared
// name deprehendo-sim also matches simulators that other packages' tests run in
// parallel (internal/simulator builds and runs its own deprehendo-sim, including a
// stopped frozen worker), so a test could trigger on, and then inspect, a
// process it never started. linux truncates comm to 15 bytes, so the name
// stays short. same approach as the phase 3 harness.
func privateSim(t *testing.T, dir, tag string) (path, name string) {
	t.Helper()
	name = fmt.Sprintf("%s-%d", tag, os.Getpid())
	path = filepath.Join(dir, name)
	binary, err := os.ReadFile(simPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, binary, 0755); err != nil {
		t.Fatal(err)
	}
	return path, name
}

func waitForBundle(t *testing.T, dir string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if paths := incidentBundles(t, dir); len(paths) > 0 {
			return paths[0]
		}
		time.Sleep(50 * time.Millisecond)
	}
	entries, _ := os.ReadDir(dir)
	t.Fatalf("no incident bundle appeared within %s (entries=%v)", within, entries)
	return ""
}

// TestPhase2IncidentEndToEnd runs the full pipeline: the simulator stops a
// worker, the recorder observes it, the automatic stopped-process rule freezes
// the capture window, the bundle is saved, and an offline inspect --timeline
// reads it back. A second, manual trigger proves the recorder keeps running
// after persistence.
func TestPhase2IncidentEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("full simulator/recorder/bundle pipeline")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("requires Linux or macOS, got %s", runtime.GOOS)
	}
	base, err := os.MkdirTemp("/tmp", "deprehendo-phase2-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	socket := filepath.Join(base, "agent.sock")
	incidentdir := filepath.Join(base, "incidents")
	if err := os.Mkdir(incidentdir, 0700); err != nil {
		t.Fatal(err)
	}
	simbin, simname := privateSim(t, base, "rph2")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	agentcmd := exec.CommandContext(ctx, agentPath, "start",
		"--socket", socket,
		"--incident-dir", incidentdir,
		"--interval", "100ms",
		"--window", "20s",
		"--watch-name", simname,
		"--trigger-on-stop",
		"--capture-pre", "15s",
		"--capture-post", "1s",
		"--max-incidents", "1",
		"--collect-network=false",
		"--collect-pressure=false",
		"--collect-cgroups=false",
	)
	var agentOut recorderOutput
	agentcmd.Stdout, agentcmd.Stderr = &agentOut, &agentOut
	if err := agentcmd.Start(); err != nil {
		t.Fatal(err)
	}
	agentdone := make(chan error, 1)
	go func() { agentdone <- agentcmd.Wait() }()
	agentstopped := false
	defer func() {
		if !agentstopped {
			_ = agentcmd.Process.Kill()
			<-agentdone
		}
	}()

	ready := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		var out bytes.Buffer
		if err := agent.ReadControl(ctx, socket, "status", &out); err == nil {
			var status agent.Status
			if json.Unmarshal(out.Bytes(), &status) == nil && status.Samples >= 3 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("agent never sampled: %s", agentOut.String())
	}

	simctx, simcancel := context.WithTimeout(ctx, 20*time.Second)
	simcmd := exec.CommandContext(simctx, simbin, "frozen-worker", "--freeze-after", "1200ms", "--freeze-for", "4s", "--grace", "300ms", "--json")
	var simOut recorderOutput
	simcmd.Stdout, simcmd.Stderr = &simOut, &simOut
	if err := simcmd.Start(); err != nil {
		simcancel()
		t.Fatal(err)
	}
	simdone := make(chan error, 1)
	go func() { simdone <- simcmd.Wait() }()
	simstopped := false
	defer func() {
		if !simstopped {
			simcancel()
			_ = simcmd.Process.Kill()
			<-simdone
		}
	}()

	bundlepath := waitForBundle(t, incidentdir, 25*time.Second)
	bundle, err := incident.ReadFile(bundlepath)
	if err != nil {
		t.Fatalf("automatic bundle invalid: %v\n%s", err, agentOut.String())
	}
	if bundle.Incident.Trigger.Type != "process_stopped" {
		t.Fatalf("trigger = %+v, want process_stopped", bundle.Incident.Trigger)
	}
	if len(bundle.Incident.Snapshots) == 0 {
		t.Fatal("bundle has no snapshots")
	}
	stoppedevidence, postevidence := false, false
	trig := bundle.Incident.Trigger
	var seen []string // what each snapshot recorded for the trigger PID, for the failure message
	for _, snapshot := range bundle.Incident.Snapshots {
		if snapshot.Timestamp.After(bundle.Incident.TriggeredAt) {
			postevidence = true
		}
		for _, process := range snapshot.Processes {
			if process.PID != trig.PID {
				continue
			}
			seen = append(seen, fmt.Sprintf("%s start=%d state=%q", snapshot.Timestamp.Format("15:04:05.000"), process.StartTicks, process.State))
			// same definition as the trigger rule: T (stopped) or t (tracing stop).
			if process.StartTicks == trig.StartTicks && (strings.HasPrefix(process.State, "T") || strings.HasPrefix(process.State, "t")) {
				stoppedevidence = true
			}
		}
	}
	if !stoppedevidence {
		t.Fatalf("bundle does not contain the stopped watched process\ntrigger: %+v at %s\n%d snapshots; trigger PID seen in %d:\n  %s\nagent log:\n%s\nsimulator log:\n%s",
			trig, bundle.Incident.TriggeredAt.Format("15:04:05.000"), len(bundle.Incident.Snapshots), len(seen),
			strings.Join(seen, "\n  "), agentOut.String(), simOut.String())
	}
	if !postevidence {
		t.Fatal("bundle has no post-trigger evidence")
	}
	if len(bundle.Incident.Events) == 0 {
		t.Fatal("bundle has no event timeline")
	}

	inspectout, err := exec.CommandContext(ctx, agentPath, "inspect", bundlepath, "--timeline").CombinedOutput()
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, inspectout)
	}
	for _, want := range []string{"Integrity", "TIMELINE", "INCIDENT_TRIGGERED", "process_stopped"} {
		if !strings.Contains(string(inspectout), want) {
			t.Errorf("inspect output missing %q:\n%s", want, inspectout)
		}
	}

	_ = simcmd.Process.Signal(syscall.SIGTERM)
	<-simdone
	simstopped = true
	simcancel()

	// the watched process disappears after the stopped-state capture and can
	// legitimately create a second automatic incident. wait for that capture
	// to finish before issuing the manual trigger; otherwise this test races
	// the single-active-incident policy it is meant to verify.
	var status agent.IncidentStatus
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		status, err = agent.IncidentStatusControl(ctx, socket)
		if err == nil && (status.State == incident.Complete || status.State == incident.Idle) {
			break
		}
		if err == nil && status.State == incident.Failed {
			t.Fatalf("automatic capture failed after process exit: %+v", status)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status.State != incident.Complete && status.State != incident.Idle {
		t.Fatalf("capture was not idle after simulator exit: %+v", status)
	}

	triggerout, err := exec.CommandContext(ctx, agentPath, "trigger", "--socket", socket).CombinedOutput()
	if err != nil {
		t.Fatalf("manual trigger: %v\n%s\nagent log:\n%s", err, triggerout, agentOut.String())
	}
	for _, want := range []string{"Incident triggered", "Capturing 1s post-trigger evidence...", "Saved: " + incidentdir} {
		if !strings.Contains(string(triggerout), want) {
			t.Errorf("trigger output missing %q:\n%s", want, triggerout)
		}
	}
	// retention keeps one bundle: the manual incident displaces the automatic
	// one that this test already read and validated.
	paths := incidentBundles(t, incidentdir)
	if len(paths) != 1 || paths[0] == bundlepath {
		t.Fatalf("bundles after manual trigger = %v, want only the new manual bundle", paths)
	}
	if _, err := os.Lstat(bundlepath); !os.IsNotExist(err) {
		t.Fatalf("retention did not prune the older bundle: %v", err)
	}
	manual, err := incident.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("manual bundle invalid: %v", err)
	}
	if manual.Incident.Trigger.Type != "manual" {
		t.Fatalf("manual trigger = %+v", manual.Incident.Trigger)
	}

	if err := agentcmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := <-agentdone; err != nil {
		t.Fatalf("agent shutdown: %v\n%s", err, agentOut.String())
	}
	agentstopped = true
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("control socket left after shutdown: %v", err)
	}
	for _, want := range []string{"incident triggered", "incident saved"} {
		if !strings.Contains(agentOut.String(), want) {
			t.Errorf("agent log missing %q:\n%s", want, agentOut.String())
		}
	}
}
