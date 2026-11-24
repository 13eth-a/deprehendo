package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

func incidentDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// controlSocket keeps the unix socket path short enough for macOS sockaddr_un.
func controlSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "deprehendo-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}

func waitIncident(t *testing.T, capture *incident.Capture, id string) incident.CaptureStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status := capture.Status()
		if status.ID == id && (status.State == incident.Complete || status.State == incident.Failed) {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("incident %s did not finish: %+v", id, capture.Status())
	return incident.CaptureStatus{}
}

func TestControlManualTriggerAndIncidentStatus(t *testing.T) {
	dir := incidentDir(t)
	capture, err := incident.NewCapture(incident.CaptureOptions{
		Window: incident.CaptureWindow{PreTrigger: time.Second, PostTrigger: 80 * time.Millisecond},
		Writer: incident.FileWriter{Directory: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = capture.Close(ctx)
	})
	r, err := New(Options{Interval: time.Second, Capacity: 3, Capture: capture,
		DisableProcesses: true, DisableNetwork: true, DisablePressure: true, DisableCgroups: true})
	if err != nil {
		t.Fatal(err)
	}
	socket := controlSocket(t)
	server, err := r.ServeControl(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	response, err := TriggerControlWithNote(context.Background(), socket, "worker stalled")
	if err != nil {
		t.Fatal(err)
	}
	if response.Note != "worker stalled" {
		t.Fatalf("trigger note = %q", response.Note)
	}
	if !strings.HasPrefix(response.ID, "inc_") || response.State != incident.CapturingPost {
		t.Fatalf("trigger response = %+v", response)
	}
	if response.Window.PostTrigger != 80*time.Millisecond {
		t.Fatalf("window = %+v", response.Window)
	}
	if _, err := TriggerControl(context.Background(), socket); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("duplicate trigger = %v, want active-incident error", err)
	}
	status, err := IncidentStatusControl(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	if status.ID != response.ID {
		t.Fatalf("status = %+v", status)
	}

	final := waitIncident(t, capture, response.ID)
	if final.State != incident.Complete || final.Path == "" {
		t.Fatalf("capture did not save: %+v", final)
	}
	bundle, err := incident.ReadFile(final.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Incident.Trigger.Type != "manual" || bundle.Incident.ID != response.ID || bundle.Incident.Trigger.Note != "worker stalled" || !bundle.Incident.Privacy.UserNote {
		t.Fatalf("bundle = %+v", bundle.Incident)
	}
	status, err = IncidentStatusControl(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != incident.Complete || status.Path != final.Path {
		t.Fatalf("final status = %+v", status)
	}
	next, err := TriggerControl(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := IncidentStatusControlFor(context.Background(), socket, response.ID)
	if err != nil || previous.State != incident.Complete || previous.Path != final.Path {
		t.Fatalf("previous result lost after %s: %+v %v", next.ID, previous, err)
	}
	if _, err := IncidentStatusControlFor(context.Background(), socket, "inc_unknown"); err == nil {
		t.Fatal("unknown result succeeded")
	}
}

func TestControlWithoutCaptureRejectsTrigger(t *testing.T) {
	r, err := New(Options{Interval: time.Second, Capacity: 2, DisableProcesses: true, DisableNetwork: true, DisablePressure: true, DisableCgroups: true})
	if err != nil {
		t.Fatal(err)
	}
	socket := controlSocket(t)
	server, err := r.ServeControl(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := TriggerControl(context.Background(), socket); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("trigger without capture = %v", err)
	}
	if _, err := IncidentStatusControl(context.Background(), socket); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("status without capture = %v", err)
	}
}

func TestIncidentPipelineTriggersOnStoppedProcess(t *testing.T) {
	dir := incidentDir(t)
	capture, err := incident.NewCapture(incident.CaptureOptions{
		Window: incident.CaptureWindow{PreTrigger: 2 * time.Second},
		Writer: incident.FileWriter{Directory: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = capture.Close(ctx)
	})
	pipeline := NewIncidentPipeline(capture, nil, &incident.StoppedProcessRule{Enabled: true})
	defer pipeline.Close()
	// 7.46: the saved hook runs once, after the bundle exists, and gets the
	// same path the capture reports.
	saved := make(chan string, 2)
	pipeline.OnSaved = func(id, path string) {
		if id == "" || path == "" {
			t.Errorf("OnSaved(%q, %q) is missing a value", id, path)
		}
		saved <- path
	}

	at := time.Now().UTC().Add(-1500 * time.Millisecond)
	process := func(state string) collector.Snapshot {
		return collector.Snapshot{
			Timestamp: at,
			System:    &collector.SystemSnapshot{ProcessCountAvailable: true, ProcessCount: 1},
			Processes: []collector.ProcessSnapshot{{Process: platform.Process{PID: 99, PPID: 1, StartTicks: 5, State: state, Name: "worker"}}},
		}
	}
	pipeline.Observe(process("R"))
	if got := capture.Status().State; got != incident.Idle {
		t.Fatalf("running process triggered capture: %s", got)
	}
	at = at.Add(time.Second)
	pipeline.Observe(process("T"))
	deadline := time.Now().Add(5 * time.Second)
	for capture.Status().State != incident.Complete && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	status := capture.Status()
	if status.State != incident.Complete || status.Path == "" {
		t.Fatalf("capture did not complete: %+v", status)
	}
	bundle, err := incident.ReadFile(status.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Incident.Trigger.Type != "process_stopped" || bundle.Incident.Trigger.PID != 99 || bundle.Incident.Trigger.StartTicks != 5 {
		t.Fatalf("trigger = %+v", bundle.Incident.Trigger)
	}
	if len(bundle.Incident.Snapshots) != 2 {
		t.Fatalf("captured %d snapshots, want both pre and trigger samples", len(bundle.Incident.Snapshots))
	}

	select {
	case got := <-saved:
		if got != status.Path {
			t.Fatalf("OnSaved path = %q, want %q", got, status.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnSaved was never called for a complete incident")
	}
	select {
	case path := <-saved:
		t.Fatalf("OnSaved fired twice (second path %q)", path)
	case <-time.After(100 * time.Millisecond):
	}
}
