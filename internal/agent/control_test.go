package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeCollectorSelection(t *testing.T) {
	r, err := New(Options{
		Interval: time.Second, Capacity: 3,
		DisableProcesses: true, DisableNetwork: true,
		DisablePressure: true, DisableCgroups: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.SampleOnce()
	status := r.Status()
	if len(status.CollectorMetrics) != 1 || status.CollectorMetrics["system"].Cycles != 1 {
		t.Fatalf("disabled collectors were polled: %+v", status.CollectorMetrics)
	}
	history := r.History()
	if len(history) != 1 || len(history[0].Processes) != 0 || len(history[0].Connections) != 0 || history[0].Pressure != nil || history[0].Cgroup != nil {
		t.Fatalf("disabled sections present: %+v", history)
	}
}

func TestControlServesRetainedDataAndCleansSocket(t *testing.T) {
	r, err := New(Options{Interval: time.Second, Capacity: 3})
	if err != nil {
		t.Fatal(err)
	}
	// keep socket paths short enough for macOS sockaddr_un.
	dir, err := os.MkdirTemp("/tmp", "runopsy-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent.sock")
	server, err := r.ServeControl(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	if other, err := r.ServeControl(socket); err == nil {
		other.Close()
		t.Fatal("second server replaced live socket")
	}
	r.SampleOnce()
	for _, view := range []string{"status", "snapshot", "history"} {
		var out bytes.Buffer
		if err := ReadControl(context.Background(), socket, view, &out); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("%s invalid JSON: %s", view, out.String())
		}
	}
	var history bytes.Buffer
	if err := ReadControl(context.Background(), socket, "history", &history); err != nil {
		t.Fatal(err)
	}
	var snapshots []map[string]any
	if err := json.Unmarshal(history.Bytes(), &snapshots); err != nil || len(snapshots) != 1 {
		t.Fatalf("history %s err=%v", history.String(), err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket remains: %v", err)
	}
}
