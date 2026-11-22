package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/collector"
)

func TestAgentCLIRecordsInspectableTimelineAndCleansUp(t *testing.T) {
	if testing.Short() {
		t.Skip("foreground CLI lifecycle")
	}
	dir, err := os.MkdirTemp("/tmp", "runopsy-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentPath, "start", "--socket", socket, "--interval", "200ms", "--window", "2s", "--watch-pid", strconv.Itoa(os.Getpid()), "--collect-network=false", "--collect-pressure=false", "--collect-cgroups=false")
	var log recorderOutput
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := false
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
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
		t.Fatalf("agent failed to sample: %s", log.String())
	}
	for _, command := range []string{"status", "dump"} {
		out, err := exec.CommandContext(ctx, agentPath, command, "--socket", socket, "--json").CombinedOutput()
		if err != nil || !json.Valid(out) {
			t.Fatalf("%s: %v %s", command, err, out)
		}
	}
	out, err := exec.CommandContext(ctx, agentPath, "dump", "--socket", socket, "--history").CombinedOutput()
	var history []collector.Snapshot
	if err != nil || json.Unmarshal(out, &history) != nil || len(history) == 0 || len(history) > 10 {
		t.Fatalf("history: %v %s", err, out)
	}
	for i, s := range history {
		if len(s.Connections) != 0 || s.Pressure != nil || s.Cgroup != nil {
			t.Fatalf("disabled sections present in CLI history: %+v", s)
		}
		for _, metric := range s.Metrics {
			if metric.Name == "connections" || metric.Name == "socket-owners" || metric.Name == "pressure" || metric.Name == "cgroups" || metric.Name == "process-cgroups" {
				t.Fatalf("disabled collector ran: %+v", metric)
			}
		}
		if i > 0 && !s.Timestamp.After(history[i-1].Timestamp) {
			t.Fatal("history not chronological")
		}
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("shutdown: %v %s", err, log.String())
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket left after Ctrl+C: %v", err)
	}
}
