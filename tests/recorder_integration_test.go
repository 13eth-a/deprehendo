package tests

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"deprehendo/internal/agent"
	"deprehendo/internal/collector"
)

// recorderHarness runs one simulator scenario and samples the real recorder
// (platform collectors included) around it. assertions stay platform-aware:
// macOS exposes process identity/RSS but not CPU ticks, PSI, cgroups, or the
// TCP table, which report partial failures there.
type recorderHarness struct {
	t      *testing.T
	rt     *agent.Runtime
	cmd    *exec.Cmd
	done   chan error
	output *recorderOutput
}

func startRecorder(t *testing.T, args ...string) *recorderHarness {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("recorder integration requires Linux or macOS, got %s", runtime.GOOS)
	}
	cmd := exec.Command(simPath, append(args, "--json")...)
	var output recorderOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start deprehendo-sim %v: %v", args, err)
	}
	rt, err := agent.New(agent.Options{
		Interval: 25 * time.Millisecond,
		Capacity: 400,
		Filter:   collector.Filter{PIDs: []int{cmd.Process.Pid}, Descendants: true},
	})
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("initialize recorder: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	h := &recorderHarness{t: t, rt: rt, cmd: cmd, done: done, output: &output}
	t.Cleanup(h.stop)
	return h
}

// stop interrupts the scenario the way an operator would, then verifies the
// process actually terminated rather than leaking children into later tests.
func (h *recorderHarness) stop() {
	if h == nil || h.cmd.Process == nil {
		return
	}
	_ = h.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
}

func (h *recorderHarness) sample() collector.Snapshot {
	h.t.Helper()
	h.rt.SampleOnce()
	history := h.rt.History()
	if len(history) == 0 {
		h.t.Fatal("recorder produced no snapshot")
	}
	return history[len(history)-1]
}

// until samples until cond is satisfied or the timeout expires, returning the
// matching snapshot. failure output includes the scenario's own log so an
// observation bug is separable from a scenario bug.
func (h *recorderHarness) until(timeout time.Duration, want string, cond func(collector.Snapshot) bool) collector.Snapshot {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	var last collector.Snapshot
	for time.Now().Before(deadline) {
		last = h.sample()
		if cond(last) {
			return last
		}
		time.Sleep(40 * time.Millisecond)
	}
	h.t.Fatalf("recorder never observed %s within %s\nlast snapshot: %+v\nscenario output: %s", want, timeout, last, h.output.String())
	return last
}

func simPID(h *recorderHarness) int { return h.cmd.Process.Pid }

// simNode finds the sampled simulator process (owned by this test) in a
// snapshot, proving the filter kept the watched tree.
func simNode(h *recorderHarness, snapshot collector.Snapshot) (collector.ProcessSnapshot, bool) {
	for _, process := range snapshot.Processes {
		if process.PID == simPID(h) {
			return process, true
		}
	}
	return collector.ProcessSnapshot{}, false
}

func descendantNodes(h *recorderHarness, snapshot collector.Snapshot) []collector.ProcessSnapshot {
	tree := collector.BuildProcessTree(snapshot.Processes)
	descendants := tree.Descendants(simPID(h))
	nodes := make([]collector.ProcessSnapshot, 0, len(descendants))
	for _, pid := range descendants {
		if node, ok := tree.Find(pid); ok {
			nodes = append(nodes, node.Snapshot)
		}
	}
	return nodes
}

// TestRecorderObservesNormalScenario is the baseline: the recorder must see a
// healthy watched process together with host load, CPU count, memory (linux),
// and disk capacity.
func TestRecorderObservesNormalScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live recorder and simulator")
	}
	h := startRecorder(t, "normal", "--duration", "5s")
	snapshot := h.until(5*time.Second, "the normal scenario process", func(s collector.Snapshot) bool {
		process, ok := simNode(h, s)
		return ok && process.RSSBytes > 0
	})

	process, ok := simNode(h, snapshot)
	if !ok {
		t.Fatal("watched process missing from snapshot")
	}
	if process.State == "" {
		t.Fatal("process state empty")
	}
	if snapshot.System == nil {
		t.Fatal("system section missing")
	}
	if snapshot.System.CPUCount < 1 || snapshot.System.DiskTotal == 0 {
		t.Fatalf("host section incomplete: %+v", snapshot.System)
	}
	if snapshot.System.LoadAverage < 0 {
		t.Fatalf("negative load average: %+v", snapshot.System)
	}
	if runtime.GOOS == "linux" {
		if snapshot.System.MemoryTotal == 0 || snapshot.System.MemoryUsed == 0 {
			t.Fatalf("linux memory section incomplete: %+v", snapshot.System)
		}
		if process.OpenFDs <= 0 {
			t.Fatalf("watched process fd count = %d, want > 0 with an active filter", process.OpenFDs)
		}
	}
	// the filter must retain only the watched tree.
	for _, retained := range snapshot.Processes {
		if retained.PID == simPID(h) {
			continue
		}
		isdescendant := false
		for _, desc := range descendantNodes(h, snapshot) {
			if desc.PID == retained.PID {
				isdescendant = true
				break
			}
		}
		if !isdescendant {
			t.Fatalf("unwatched pid %d leaked into the filtered snapshot", retained.PID)
		}
	}
}

// TestRecorderObservesCPUSpin checks the CPU spike is visible in per-process
// accounting. linux is the platform with clock ticks; macOS has no per-process
// CPU percentage, so the assertion there is only that the process remains R/S.
func TestRecorderObservesCPUSpin(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live recorder and simulator")
	}
	h := startRecorder(t, "cpu-spin", "--workers", "2", "--duration", "5s")
	if runtime.GOOS != "linux" {
		t.Skip("per-process CPU ticks are Linux-only; macOS recorder reports 0 percent")
	}
	h.until(5*time.Second, "a busy cpu-spin process", func(s collector.Snapshot) bool {
		process, ok := simNode(h, s)
		return ok && process.CPUPercent > 10
	})
}

// TestRecorderObservesMemoryPressure checks that growing RSS is visible.
func TestRecorderObservesMemoryPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live recorder and simulator")
	}
	h := startRecorder(t, "memory-pressure", "--rate", "8MB", "--interval", "100ms", "--limit", "64MB", "--duration", "5s")
	first := h.until(5*time.Second, "the memory-pressure process", func(s collector.Snapshot) bool {
		process, ok := simNode(h, s)
		return ok && process.RSSBytes > 0
	})
	baseline, _ := simNode(h, first)
	h.until(5*time.Second, "RSS growth", func(s collector.Snapshot) bool {
		process, ok := simNode(h, s)
		return ok && process.RSSBytes > baseline.RSSBytes+4<<20
	})
}

// TestRecorderObservesFrozenWorker checks a stopped child remains present with
// the stopped state, the evidence phase 1 exists to capture.
func TestRecorderObservesFrozenWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live recorder and simulator")
	}
	// A race-enabled process-table scan can take over a second on macOS; keep
	// the worker stopped long enough that sampling cannot miss the window.
	h := startRecorder(t, "frozen-worker", "--freeze-after", "300ms", "--freeze-for", "4s", "--grace", "200ms")
	h.until(15*time.Second, "a stopped descendant", func(s collector.Snapshot) bool {
		for _, node := range descendantNodes(h, s) {
			if strings.HasPrefix(node.State, "T") {
				return true
			}
		}
		return false
	})
}

// TestRecorderObservesProcessTree checks the watched tree retains real
// descendants (worker + task hierarchy) rather than a flat process list.
func TestRecorderObservesProcessTree(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live recorder and simulator")
	}
	h := startRecorder(t, "process-tree", "--settle", "300ms", "--between", "200ms", "--duration", "4s")
	snapshot := h.until(5*time.Second, "tree descendants", func(s collector.Snapshot) bool {
		return len(descendantNodes(h, s)) > 0
	})
	// every retained descendant must also carry a coherent PPID chain: the
	// recorder must not invent a hierarchy.
	tree := collector.BuildProcessTree(snapshot.Processes)
	for _, child := range tree.Descendants(simPID(h)) {
		node, ok := tree.Find(child)
		if !ok {
			continue
		}
		if node.Snapshot.PPID <= 0 {
			t.Fatalf("descendant pid %d has no parent", child)
		}
	}
}

// TestRecorderObservesSocketStall checks the kernel TCP table shows the
// stalled connection and attributes it to the watched process.
func TestRecorderObservesSocketStall(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live recorder and simulator")
	}
	if runtime.GOOS != "linux" {
		t.Skip("TCP table collection is Linux-only; macOS reports a partial failure instead")
	}
	h := startRecorder(t, "socket-stall", "--ping-interval", "20ms", "--stall-threshold", "80ms", "--stall-duration", "1500ms", "--stall-after", "1")
	h.until(5*time.Second, "an established socket owned by the simulator", func(s collector.Snapshot) bool {
		if !strings.Contains(h.output.String(), `"type":"stall_detected"`) {
			return false
		}
		for _, conn := range s.Connections {
			if conn.PID == simPID(h) && conn.State == "ESTABLISHED" {
				return true
			}
		}
		return false
	})
}

// the simulator may still be writing when a failed assertion prints its log.
type recorderOutput struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *recorderOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *recorderOutput) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

func TestRecorderObservesOrphanReparenting(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("live Linux reparenting")
	}
	h := startRecorder(t, "orphan-process", "--tasks", "1", "--grace", "1500ms")
	// orphans cease to be descendants. keep matching by name to observe them
	// after reparenting rather than interpreting filter exclusion as death.
	rt, err := agent.New(agent.Options{Interval: 20 * time.Millisecond, Capacity: 200, Filter: collector.Filter{Name: "deprehendo-sim"}})
	if err != nil {
		t.Fatal(err)
	}
	h.rt = rt
	var original collector.ProcessSnapshot
	h.until(5*time.Second, "grandchild before orphaning", func(s collector.Snapshot) bool {
		tree := collector.BuildProcessTree(s.Processes)
		for _, child := range tree.Descendants(simPID(h)) {
			node, ok := tree.Find(child)
			if ok && node.Snapshot.PPID != simPID(h) {
				original = node.Snapshot
				return true
			}
		}
		return false
	})
	h.until(5*time.Second, "same process with changed PPID", func(s collector.Snapshot) bool {
		for _, p := range s.Processes {
			if p.PID == original.PID && p.StartTicks == original.StartTicks && p.PPID != original.PPID && !strings.HasPrefix(p.State, "Z") {
				return true
			}
		}
		return false
	})
}

func TestRecorderObservesExitAndFatalSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("live termination observations")
	}
	for _, args := range [][]string{{"exit", "--code", "7", "--hold", "1200ms"}, {"signal", "--signal", "TERM", "--hold", "1200ms"}} {
		t.Run(args[0], func(t *testing.T) {
			h := startRecorder(t, args...)
			h.until(5*time.Second, "process before termination", func(s collector.Snapshot) bool { _, ok := simNode(h, s); return ok })
			h.until(5*time.Second, "process disappearance", func(s collector.Snapshot) bool { _, ok := simNode(h, s); return !ok })
		})
	}
}
