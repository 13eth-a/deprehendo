package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

func TestWatchedProcessExitCLIIntegration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	capture, pipeline, err := setupIncidentCapture(captureSettings{Directory: dir, Pre: time.Second, Post: 0, OnExit: true}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer pipeline.Close()
	at := time.Now().UTC()
	process := collector.ProcessSnapshot{Process: platform.Process{PID: 145, StartTicks: 17, State: "S", Name: "watched"}}
	sample := func(ts time.Time, rows ...collector.ProcessSnapshot) collector.Snapshot {
		return collector.Snapshot{Timestamp: ts, System: &collector.SystemSnapshot{ProcessCountAvailable: true}, Processes: rows}
	}
	pipeline.Observe(sample(at, process))
	pipeline.Observe(sample(at.Add(time.Second)))
	deadline := time.Now().Add(5 * time.Second)
	for capture.Status().State != incident.Complete && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := capture.Status()
	if status.State != incident.Complete {
		t.Fatalf("exit capture did not finish: %+v", status)
	}
	bundle, err := incident.ReadFile(status.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Incident.Trigger.Type != "process_exit" || bundle.Incident.Trigger.PID != 145 || bundle.Incident.Trigger.StartTicks != 17 {
		t.Fatalf("trigger=%+v", bundle.Incident.Trigger)
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"inspect", status.Path, "--timeline"}, &out, &stderr); code != 0 {
		t.Fatalf("inspect=%d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "process_exit (pid 145)") && !strings.Contains(out.String(), "process_exit") {
		t.Fatalf("timeline omitted trigger: %s", out.String())
	}
	listed, err := incident.List(filepath.Dir(status.Path))
	if err != nil || len(listed) != 1 {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := capture.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIncidentDirectoryExclusiveWhileAgentRuns(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	release, err := lockIncidentDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if other, err := lockIncidentDirectory(dir); err == nil {
		other()
		t.Fatal("second agent acquired the directory")
	}
	release()
	next, err := lockIncidentDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	next()
}
