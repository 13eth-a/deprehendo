package tests

import (
	"bytes"
	"context"
	"encoding/json"
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

// waitForBundleOfProcess waits for a saved bundle that actually carries the
// exit of pid, instead of whichever bundle was written first. every case here
// watches the same process name, so a leftover process from an earlier case can
// exit first and trigger a bundle that has nothing to do with this case's
// simulator; picking paths[0] then inspected the wrong incident (H10).
func waitForBundleOfProcess(t *testing.T, dir string, pid int, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, path := range incidentBundles(t, dir) {
			bundle, err := incident.ReadFile(path)
			if err != nil {
				continue
			}
			for _, e := range bundle.Incident.Events {
				if e.PID == pid && (e.Type == incident.ProcessExited || e.Type == incident.TraceProcessExit) {
					return path
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	entries, _ := os.ReadDir(dir)
	t.Fatalf("no bundle carrying the exit of pid %d appeared within %s (entries=%v)", pid, within, entries)
	return ""
}

// real CLI matrix: inject, record, trigger, publish, then inspect offline.
func TestPhase2AcceptanceMatrix(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("Linux incident acceptance matrix")
	}
	cases := []struct {
		name, trigger string
		sim, flags    []string
	}{
		{"normal", "manual", []string{"normal", "--duration", "12s"}, nil},
		{"cpu-spin", "manual", []string{"cpu-spin", "--workers", "2", "--duration", "12s"}, nil},
		{"memory-pressure", "memory_threshold", []string{"memory-pressure", "--rate", "4MB", "--interval", "150ms", "--limit", "128MB", "--duration", "12s"}, []string{"--trigger-memory-percent", "0.01", "--trigger-duration", "1400ms"}},
		{"frozen-worker", "process_stopped", []string{"frozen-worker", "--freeze-after", "700ms", "--freeze-for", "4s", "--grace", "500ms"}, []string{"--trigger-on-stop"}},
		{"orphan-process", "manual", []string{"orphan-process", "--tasks", "1", "--grace", "1500ms"}, nil},
		{"process-exit", "process_exit", []string{"exit", "--code", "7", "--hold", "1800ms"}, []string{"--trigger-on-process-exit"}},
		{"socket-stall", "manual", []string{"socket-stall", "--stall-after", "1", "--ping-interval", "50ms", "--stall-threshold", "200ms", "--stall-duration", "5s"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, err := os.MkdirTemp("/tmp", "deprehendo-matrix-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(base)
			dir := filepath.Join(base, "incidents")
			socket := filepath.Join(base, "agent.sock")
			simbin, simname := privateSim(t, base, "rpm2")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := []string{"start", "--socket", socket, "--incident-dir", dir, "--interval", "100ms", "--window", "10s", "--capture-pre", "5s", "--capture-post", "1s", "--watch-name", simname}
			args = append(args, tc.flags...)
			recorder := exec.CommandContext(ctx, agentPath, args...)
			var log recorderOutput
			recorder.Stdout = &log
			recorder.Stderr = &log
			if err := recorder.Start(); err != nil {
				t.Fatal(err)
			}
			recorderdone := make(chan error, 1)
			go func() { recorderdone <- recorder.Wait() }()
			defer func() {
				_ = recorder.Process.Signal(syscall.SIGINT)
				select {
				case <-recorderdone:
				case <-time.After(5 * time.Second):
					_ = recorder.Process.Kill()
					<-recorderdone
				}
			}()
			ready := false
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				var out bytes.Buffer
				if agent.ReadControl(ctx, socket, "status", &out) == nil {
					var status agent.Status
					if json.Unmarshal(out.Bytes(), &status) == nil && status.Samples >= 2 {
						ready = true
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatalf("recorder not ready: %s", log.String())
			}
			sim := exec.CommandContext(ctx, simbin, append(tc.sim, "--json")...)
			var simLog recorderOutput
			sim.Stdout = &simLog
			sim.Stderr = &simLog
			if err := sim.Start(); err != nil {
				t.Fatal(err)
			}
			simdone := make(chan error, 1)
			go func() { simdone <- sim.Wait() }()
			defer func() {
				_ = sim.Process.Signal(syscall.SIGTERM)
				select {
				case <-simdone:
				case <-time.After(3 * time.Second):
					_ = sim.Process.Kill()
					<-simdone
				}
			}()
			if tc.trigger == "manual" {
				delay := 700 * time.Millisecond
				if tc.name == "orphan-process" {
					delay = 2200 * time.Millisecond
				}
				time.Sleep(delay)
				out, err := exec.CommandContext(ctx, agentPath, "trigger", "--socket", socket, "--note", "acceptance "+tc.name).CombinedOutput()
				if err != nil {
					t.Fatalf("manual trigger: %v %s\n%s", err, out, log.String())
				}
			}
			path := waitForBundle(t, dir, 12*time.Second)
			if tc.name == "process-exit" {
				// the exit of this case's simulator is the evidence the
				// assertions below need, so wait for the bundle that holds it
				// rather than a bundle a leftover process triggered.
				path = waitForBundleOfProcess(t, dir, sim.Process.Pid, 12*time.Second)
			}
			bundle, err := incident.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			i := bundle.Incident
			if i.Trigger.Type != tc.trigger || len(i.Snapshots) < 2 {
				t.Fatalf("bad capture trigger=%+v snapshots=%d", i.Trigger, len(i.Snapshots))
			}
			before, after, condition := false, false, false
			var minRSS, maxRSS uint64
			for _, s := range i.Snapshots {
				before = before || s.Timestamp.Before(i.TriggeredAt)
				after = after || s.Timestamp.After(i.TriggeredAt)
				for _, p := range s.Processes {
					if tc.name == "frozen-worker" && strings.HasPrefix(p.State, "T") {
						condition = true
					}
					if p.PID == sim.Process.Pid {
						if tc.name == "normal" || tc.name == "orphan-process" {
							condition = true
						}
						if tc.name == "cpu-spin" && p.CPUPercent > 1 {
							condition = true
						}
						if p.RSSBytes > 0 && (minRSS == 0 || p.RSSBytes < minRSS) {
							minRSS = p.RSSBytes
						}
						if p.RSSBytes > maxRSS {
							maxRSS = p.RSSBytes
						}
					}
				}
				if tc.name == "socket-stall" {
					for _, c := range s.Connections {
						if c.PID == sim.Process.Pid && c.State == "ESTABLISHED" {
							condition = true
						}
					}
				}
			}
			if tc.name == "memory-pressure" {
				condition = maxRSS > minRSS+(4<<20)
			}
			if tc.name == "process-exit" {
				for _, e := range i.Events {
					// either source of the same fact: with the tracer on
					// PATH, the §9.1 merge lets TRACE_PROCESS_EXIT own the
					// duplicated entry (consume the differ's exit) or, if
					// the trace copy arrives after the window, the raw
					// differ exit survives. both are evidence the process
					// exited; asserting only one type made this pass/flake
					// depending on tracer arrival (adversarial H10).
					if (e.Type == incident.ProcessExited || e.Type == incident.TraceProcessExit) && e.PID == sim.Process.Pid {
						condition = true
					}
				}
			}
			if !before || !after || !condition {
				t.Fatalf("evidence missing before=%v after=%v condition=%v\n%s\n%s", before, after, condition, log.String(), simLog.String())
			}
			for _, inspectargs := range [][]string{{"validate", path}, {"inspect", path, "--timeline"}, {"inspect", path, "--snapshot", "0"}, {"inspect", path, "--privacy"}, {"extract", "--output", filepath.Join(base, "extracted"), path}, {"incidents", "list", "--incident-dir", dir}} {
				out, err := exec.CommandContext(ctx, agentPath, inspectargs...).CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %v %s", inspectargs, err, out)
				}
			}
			count := len(i.Snapshots)
			stat, _ := os.Stat(path)
			t.Logf("scenario=%s trigger=%s snapshots=%d events=%d bytes=%d", tc.name, i.Trigger.Type, count, len(i.Events), stat.Size())
		})
	}
}
