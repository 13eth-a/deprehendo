package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"deprehendo/internal/agent"
	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

func TestIncidentRecorderSimulatorPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("live simulator/recorder pipeline")
	}
	h := startRecorder(t, "normal", "--duration", "5s")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// A generous pre-window keeps the pre-trigger assertion robust when the
	// race detector or a busy host stretches individual collection cycles.
	// the post window must be longer than a slow race-enabled collection cycle,
	// otherwise the capture deadline can win before a post-trigger sample lands.
	capture, err := incident.NewCapture(incident.CaptureOptions{Window: incident.CaptureWindow{PreTrigger: 10 * time.Second, PostTrigger: 2 * time.Second}, Writer: incident.FileWriter{Directory: dir}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = capture.Close(ctx)
	})
	rt, err := agent.New(agent.Options{Interval: 50 * time.Millisecond, Capacity: 40, Window: 2 * time.Second, Filter: collector.Filter{PIDs: []int{h.cmd.Process.Pid}}, OnSnapshot: capture.Observe})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	for rt.Status().Samples < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rt.Status().Samples < 2 {
		t.Fatal("recorder never sampled")
	}
	id, err := capture.Trigger(incident.Trigger{Type: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	for capture.Status().State == incident.CapturingPost || capture.Status().State == incident.Finalizing {
		if time.Now().After(deadline) {
			t.Fatal("capture did not finalize", capture.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	status := capture.Status()
	if status.State != incident.Complete {
		t.Fatal(status)
	}
	bundle, err := incident.ReadFile(status.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Incident.ID != id || len(bundle.Incident.Snapshots) < 2 {
		t.Fatal("timeline missing")
	}
	before, after := false, false
	for _, s := range bundle.Incident.Snapshots {
		if s.Timestamp.Before(bundle.Incident.TriggeredAt) {
			before = true
		} else {
			after = true
		}
	}
	if !before || !after {
		t.Fatalf("pre/post evidence missing: before=%t after=%t", before, after)
	}
	count := rt.Status().Samples
	for resume := time.Now().Add(10 * time.Second); rt.Status().Samples <= count && time.Now().Before(resume); {
		time.Sleep(20 * time.Millisecond)
	}
	if rt.Status().Samples <= count {
		t.Fatal("recording stopped after persistence")
	}
}
