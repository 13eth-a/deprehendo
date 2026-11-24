package simulator

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"deprehendo/internal/events"
	"deprehendo/internal/platform"
)

func TestProcessRunnerHardKillCleansChildren(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	bin := simBinary(t)
	for _, tc := range []struct {
		name, ready string
		args        []string
	}{
		{"frozen", "worker_frozen", []string{"frozen-worker", "--freeze-after", "150ms", "--freeze-for", "30s"}},
		{"orphan", "tree_recorded", []string{"orphan-process", "--grace", "30s"}},
		{"tree", "tree_recorded", []string{"process-tree", "--settle", "30s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, append(tc.args, "--json")...)
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			var groups []int
			defer func() {
				for _, pid := range groups {
					_ = platform.KillGroup(pid, syscall.SIGKILL)
				}
			}()
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			scan := bufio.NewScanner(out)
			ready := false
			for scan.Scan() {
				var ev events.Event
				if err := json.Unmarshal(scan.Bytes(), &ev); err != nil {
					t.Fatal(err)
				}
				if ev.Type == "worker_spawned" || ev.Type == "helper_spawned" {
					key := "worker_pid"
					if ev.Type == "helper_spawned" {
						key = "helper_pid"
					}
					if pid, ok := ev.Data[key].(float64); ok {
						groups = append(groups, int(pid))
					}
				}
				if ev.Type == tc.ready {
					ready = true
					break
				}
			}
			if !ready {
				t.Fatalf("did not observe %s: %v", tc.ready, scan.Err())
			}
			children, err := platform.Children(cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			for _, child := range children {
				if child.PID == child.PGID {
					groups = append(groups, child.PGID)
				}
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			// leave the runner unreaped while checking cleanup: kill(pid, 0)
			// still succeeds for a zombie, but its helpers must detect death.
			for _, pgid := range groups {
				if !groupGoneOrZombie(pgid, 3*time.Second) {
					t.Errorf("group %d survived runner SIGKILL", pgid)
				}
			}
		})
	}
}

func TestFrozenWorkerDurationClipsLongPhases(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	cfg, out := newTestConfig(t, 10*time.Millisecond)
	start := time.Now()
	if err := (&FrozenWorker{}).Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("10ms run took %s", elapsed)
	}
	assertWorkerGone(t, workerPID(t, decodeEvents(t, out)))
}

func TestProcessScenariosRejectUnexpectedWorkerExit(t *testing.T) {
	prev := simBinaryOverride
	simBinaryOverride = "/usr/bin/true"
	defer func() { simBinaryOverride = prev }()
	for _, scenario := range []Scenario{&FrozenWorker{}, &OrphanProcess{}, &ProcessTree{}} {
		t.Run(scenario.Name(), func(t *testing.T) {
			cfg, _ := newTestConfig(t, time.Second)
			if err := scenario.Run(context.Background(), cfg); err == nil {
				t.Fatal("unexpected worker exit reported as success")
			}
		})
	}
}
