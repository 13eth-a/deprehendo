package collector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"deprehendo/internal/platform"
)

// liveSources adapt the same platform collectors the agent binary uses.
type liveProcess struct{}

func (liveProcess) CollectProcesses() ([]platform.Process, error) { return platform.Processes() }

type liveNetwork struct{}

func (liveNetwork) CollectConnections() ([]platform.TCPRecord, error) { return platform.Connections() }

type liveOwners struct{}

func (liveOwners) CollectSocketOwners() (map[uint64]platform.SocketOwner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("socket owners unsupported on this platform")
	}
	return platform.SocketOwners(platform.DefaultProcRoot)
}

// TestSchedulerObservesSpawnedProcess is the compact integration check for
// the scheduler on a live machine: a real child process must appear in the
// sampled snapshot, keep its identity across samples, and drop out when it
// exits. this anchors part of the phase 1 observation matrix without the
// full simulator runs (owned by the 1.24 integration slice).
func TestSchedulerObservesSpawnedProcess(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("no live scheduler platform on %s", runtime.GOOS)
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	childpid := cmd.Process.Pid

	sched, err := NewScheduler(20*time.Millisecond, 8, Sources{
		Retention: 5 * time.Second,
		Process:   liveProcess{},
		Network:   liveNetwork{},
		Owners:    liveOwners{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// wait for the child to be observable; process enumeration is inherently
	// eventually-consistent.
	deadline := time.Now().Add(5 * time.Second)
	observed := false
	var node Snapshot
	for time.Now().Before(deadline) {
		node = sched.Collect(context.Background())
		if _, ok := BuildProcessTree(node.Processes).Find(childpid); ok {
			observed = true
			break
		}
	}
	if !observed {
		t.Fatalf("spawned pid %d never surfaced in the process snapshot", childpid)
	}
	childnode := BuildProcessTree(node.Processes)
	found, _ := childnode.Find(childpid)
	if found.Snapshot.PPID != os.Getpid() {
		t.Fatalf("child ppid = %d, want %d", found.Snapshot.PPID, os.Getpid())
	}
	if runtime.GOOS == "linux" {
		if found.Snapshot.StartTicks <= 0 {
			t.Fatalf("linux child start ticks = %d, want > 0", found.Snapshot.StartTicks)
		}
		if found.Snapshot.Threads < 1 {
			t.Fatalf("linux child threads = %d, want >= 1", found.Snapshot.Threads)
		}
	}

	// two consecutive samples under the same identity must not lose the
	// process and must produce a non-negative CPU percent.
	second := sched.Collect(context.Background())
	node2, ok := BuildProcessTree(second.Processes).Find(childpid)
	if !ok {
		t.Fatalf("child disappeared between consecutive samples")
	}
	if node2.Snapshot.CPUPercent < 0 {
		t.Fatalf("cpu percent = %f, want >= 0", node2.Snapshot.CPUPercent)
	}

	// after the child exits, the next sample must stop listing it.
	_ = syscall.Kill(childpid, syscall.SIGKILL)
	_ = cmd.Wait()
	var exited bool
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		after := sched.Collect(context.Background())
		if _, ok := BuildProcessTree(after.Processes).Find(childpid); !ok {
			exited = true
			break
		}
	}
	if !exited {
		t.Fatalf("exited pid %d still present in the snapshot", childpid)
	}

	// Self-monitoring: buffer retained the cycles, per-collector telemetry
	// exists for the enabled collectors.
	status := sched.Status()
	if status.Samples < 3 || status.BufferUsed == 0 {
		t.Fatalf("scheduler status health: %+v", status)
	}
	if m, ok := status.Collectors["processes"]; !ok || m.Errors != 0 {
		t.Fatalf("process telemetry = %+v", m)
	}
}
