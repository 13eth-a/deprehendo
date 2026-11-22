package collector

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"runopsy/internal/platform"
)

type processFunc func() ([]platform.Process, error)

func (f processFunc) CollectProcesses() ([]platform.Process, error) { return f() }

type pressureFunc func() (map[platform.Resource]platform.PressureSnapshot, error)

func (f pressureFunc) CollectPressure() (map[platform.Resource]platform.PressureSnapshot, error) {
	return f()
}

type cgroupFunc func() (platform.CgroupSnapshot, error)

func (f cgroupFunc) CollectCgroup() (platform.CgroupSnapshot, error) { return f() }

func TestSchedulerSerializesConcurrentCollectAndCancelsWaiter(t *testing.T) {
	entered := make(chan struct{}, 20)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	s, err := NewScheduler(time.Second, 32, Sources{Process: processFunc(func() ([]platform.Process, error) {
		n := active.Add(1)
		for prev := maximum.Load(); n > prev && !maximum.CompareAndSwap(prev, n); prev = maximum.Load() {
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		return []platform.Process{{PID: 1}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.Collect(context.Background()) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if got := s.Collect(ctx); !got.Timestamp.IsZero() {
		t.Fatal("canceled waiter collected a snapshot")
	}
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); s.Collect(context.Background()) }()
	}
	close(release)
	wg.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("%d collectors overlapped", got)
	}
	if got := s.Status().Samples; got != 9 {
		t.Fatalf("samples=%d, want 9", got)
	}
}

func TestSchedulerCanceledBeforeStartDoesNotPoll(t *testing.T) {
	var calls int
	s, _ := NewScheduler(time.Second, 2, Sources{Process: processFunc(func() ([]platform.Process, error) { calls++; return nil, nil })})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Collect(ctx)
	if calls != 0 || s.Status().Samples != 0 {
		t.Fatal("canceled collection polled or retained a sample")
	}
}

type cancelingProcess struct{}

func (cancelingProcess) CollectProcesses() ([]platform.Process, error) { return nil, nil }
func (cancelingProcess) CollectProcessesContext(ctx context.Context) ([]platform.Process, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSchedulerCancellationDoesNotRetainFailedShutdownSample(t *testing.T) {
	s, err := NewScheduler(time.Second, 4, Sources{Process: cancelingProcess{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if sample := s.Collect(ctx); !sample.Timestamp.IsZero() {
		t.Fatal("cancelled cycle returned a completed snapshot")
	}
	if status := s.Status(); status.Samples != 0 || status.CollectorErr != 0 || status.BufferUsed != 0 {
		t.Fatalf("shutdown polluted health/history: %+v", status)
	}
}

func TestSchedulerSnapshotsOwnAllMutablePayload(t *testing.T) {
	pressure := map[platform.Resource]platform.PressureSnapshot{platform.PressureCPU: {HasFull: true}}
	s, _ := NewScheduler(time.Second, 2, Sources{
		Process:  &stubProcess{procs: []platform.Process{{PID: 7, Name: "worker"}}},
		System:   &stubSystem{},
		Pressure: pressureFunc(func() (map[platform.Resource]platform.PressureSnapshot, error) { return pressure, nil }),
		Cgroup:   cgroupFunc(func() (platform.CgroupSnapshot, error) { return platform.CgroupSnapshot{Path: "/runner"}, nil }),
	})
	first := s.Collect(context.Background())
	pressure[platform.PressureCPU] = platform.PressureSnapshot{}
	first.Processes[0].PID = 999
	first.System.MemoryTotal = 0
	first.Pressure[platform.PressureCPU] = platform.PressureSnapshot{}
	first.Cgroup.Path = "bad"
	first.Metrics[0].Name = "bad"
	latest, ok := s.Latest()
	if !ok || latest.Processes[0].PID != 7 || latest.System.MemoryTotal != 16000 || !latest.Pressure[platform.PressureCPU].HasFull || latest.Cgroup.Path != "/runner" || latest.Metrics[0].Name != "system" {
		t.Fatalf("retained snapshot aliased producer or caller: %+v", latest)
	}
	latest.Processes[0].PID = 0
	history := s.History()
	history[0].System.MemoryTotal = 0
	latest, _ = s.Latest()
	if latest.Processes[0].PID != 7 || latest.System.MemoryTotal != 16000 {
		t.Fatal("query result aliased retained snapshot")
	}
}

func TestSchedulerExpiresByAgeWithoutNewSamples(t *testing.T) {
	s, _ := NewScheduler(time.Second, 10, Sources{Retention: 20 * time.Millisecond})
	s.Collect(context.Background())
	if len(s.History()) != 1 {
		t.Fatal("new sample missing")
	}
	time.Sleep(35 * time.Millisecond)
	if _, ok := s.Latest(); ok {
		t.Fatal("aged latest sample retained")
	}
	if len(s.History()) != 0 || s.Status().BufferUsed != 0 {
		t.Fatal("query did not expire old history")
	}
}

func TestSchedulerByteBudgetAndOversizedSample(t *testing.T) {
	process := &stubProcess{procs: []platform.Process{{PID: 1, Name: "small"}}}
	capbytes := int64(unsafe.Sizeof(Snapshot{}))*10 + 1800
	s, err := NewScheduler(time.Second, 10, Sources{Process: process, MaxHistoryBytes: capbytes})
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		s.Collect(context.Background())
	}
	before := s.Status()
	if before.BufferBytes > capbytes || before.BufferUsed >= 10 || before.BufferUsed == 0 {
		t.Fatalf("byte budget not enforced: %+v", before)
	}
	process.procs[0].Name = strings.Repeat("x", 8192)
	s.Collect(context.Background())
	after := s.Status()
	if after.BufferBytes > capbytes || after.DroppedSnapshots != 1 || after.BufferUsed != before.BufferUsed {
		t.Fatalf("oversized sample erased history or bypassed budget: %+v", after)
	}
}

func TestSchedulerLastSuccessSurvivesFailure(t *testing.T) {
	process := &stubProcess{procs: []platform.Process{{PID: 1, StartTicks: 10, CPUTicks: 1}}}
	s, _ := NewScheduler(time.Second, 4, Sources{Process: process})
	s.Collect(context.Background())
	good := s.Status()
	process.procs = nil
	process.err = errors.New("proc unavailable")
	s.Collect(context.Background())
	bad := s.Status()
	if good.LastSuccessfulSample.IsZero() || !bad.LastSuccessfulSample.Equal(good.LastSuccessfulSample) || !bad.Collectors["processes"].LastSuccess.Equal(good.Collectors["processes"].LastSuccess) {
		t.Fatal("failed sample advanced last successful sample")
	}
	process.err = nil
	process.procs = []platform.Process{{PID: 1, StartTicks: 10, CPUTicks: 2}}
	if next := s.Collect(context.Background()); next.Processes[0].CPUPercent <= 0 {
		t.Fatal("transient process error discarded CPU baseline")
	}
}

func TestCPUTrackerUnsignedCounterBoundary(t *testing.T) {
	var tracker CPUTracker
	now := time.Now()
	tracker.Observe([]platform.Process{{PID: 1, StartTicks: 1, CPUTicks: 1<<63 - 10}}, now)
	got := tracker.Observe([]platform.Process{{PID: 1, StartTicks: 1, CPUTicks: 1<<63 + 10}}, now.Add(time.Second))
	if got[0].CPUPercent != 20 {
		t.Fatalf("cpu=%v, want 20", got[0].CPUPercent)
	}
}

func TestFilterAbsentRootDoesNotSelectOrphans(t *testing.T) {
	if got := (Filter{PIDs: []int{99}, Descendants: true}).Select([]ProcessSnapshot{sample(100, 99)}); len(got) != 0 {
		t.Fatalf("absent root selected %+v", got)
	}
}

func TestSchedulerCountsMissedCadenceWithoutCatchup(t *testing.T) {
	var calls atomic.Int32
	s, _ := NewScheduler(10*time.Millisecond, 20, Sources{Process: processFunc(func() ([]platform.Process, error) { calls.Add(1); time.Sleep(35 * time.Millisecond); return nil, nil })})
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.Status(); got.MissedSamples < 6 || calls.Load() > 3 {
		t.Fatalf("missed cadence/calls incorrect: %+v calls %d", got, calls.Load())
	}
}

func TestConnectionJSONPreservesDescriptorZero(t *testing.T) {
	connections := connectSnapshots([]platform.TCPRecord{{Inode: 5}}, map[uint64]platform.SocketOwner{5: {PID: 42, FD: 0}}, nil)
	data, err := json.Marshal(connections[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["fd"]) != "0" {
		t.Fatalf("descriptor zero omitted from snapshot: %s", data)
	}
}

func BenchmarkSnapshotJSON(b *testing.B) {
	snapshot := Snapshot{Timestamp: time.Now(), Processes: benchmarkProcesses(1000)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(snapshot); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkSnapshotClone(b *testing.B) {
	snapshot := Snapshot{Timestamp: time.Now(), Processes: benchmarkProcesses(1000)}
	b.ReportAllocs()
	for b.Loop() {
		_ = cloneSnapshot(snapshot)
	}
}
func benchmarkProcesses(n int) []ProcessSnapshot {
	out := make([]ProcessSnapshot, n)
	for i := range out {
		out[i] = ProcessSnapshot{Process: platform.Process{PID: i + 1, PPID: i, Name: "worker", State: "S", StartTicks: 10, CPUTicks: 500}}
	}
	return out
}
func BenchmarkProcessTree(b *testing.B) {
	processes := benchmarkProcesses(1000)
	b.ReportAllocs()
	for b.Loop() {
		_ = BuildProcessTree(processes)
	}
}
func BenchmarkCPUTracker(b *testing.B) {
	processes := make([]platform.Process, 1000)
	for i := range processes {
		processes[i] = platform.Process{PID: i + 1, CPUTicks: 500}
	}
	var tracker CPUTracker
	b.ReportAllocs()
	for b.Loop() {
		_ = tracker.Observe(processes, time.Now())
	}
}
func BenchmarkRingAppend(b *testing.B) {
	ring := NewRing[Snapshot](600)
	b.ReportAllocs()
	for b.Loop() {
		ring.Add(Snapshot{Timestamp: time.Now()})
	}
}
