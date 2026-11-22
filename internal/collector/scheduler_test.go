package collector

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"runopsy/internal/platform"
)

func loopback(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

type stubProcess struct {
	procs []platform.Process
	err   error
	calls int
}

func (s *stubProcess) CollectProcesses() ([]platform.Process, error) {
	s.calls++
	return s.procs, s.err
}

type stubNetwork struct {
	err error
}

func (s *stubNetwork) CollectConnections() ([]platform.TCPRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []platform.TCPRecord{{
		LocalAddr: loopback(127, 0, 0, 1),
		LocalPort: 8080,
		State:     "LISTEN",
		Inode:     5,
	}}, nil
}

type stubSystem struct {
	err error
}

func (s *stubSystem) CollectSystem() (SystemSnapshot, error) {
	return SystemSnapshot{MemoryTotal: 16000}, s.err
}

type stubCgroup struct {
	err error
}

func (s *stubCgroup) CollectCgroup() (platform.CgroupSnapshot, error) {
	return platform.CgroupSnapshot{}, s.err
}

func TestSchedulerKeepsPartialResultsOnCollectorFailure(t *testing.T) {
	process := &stubProcess{procs: []platform.Process{{PID: 9, PPID: 1}}}
	sched, err := NewScheduler(time.Second, 4, Sources{
		System:   &stubSystem{},
		Process:  process,
		Network:  &stubNetwork{err: errors.New("tcp table unavailable")},
		Pressure: failingPressure(),
		Cgroup:   &stubCgroup{},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := sched.Collect(context.Background())

	if len(snapshot.Processes) != 1 || snapshot.Processes[0].PID != 9 {
		t.Fatalf("process section lost: %+v", snapshot.Processes)
	}
	if snapshot.System == nil || snapshot.System.MemoryTotal != 16000 || snapshot.System.ProcessCount != 1 {
		t.Fatalf("system section lost or overwritten: %+v", snapshot.System)
	}
	if len(snapshot.Connections) != 0 {
		t.Fatalf("failed network collector must contribute no rows: %+v", snapshot.Connections)
	}
	var failed []string
	for _, e := range snapshot.Errors {
		failed = append(failed, e.Collector)
	}
	if len(failed) != 2 || failed[0] != "connections" || failed[1] != "pressure" {
		t.Fatalf("snapshot errors = %+v, want connections then pressure", snapshot.Errors)
	}
	status := sched.Status()
	if status.CollectorErr != 2 {
		t.Fatalf("collector error total = %d, want 2", status.CollectorErr)
	}
	if m, ok := status.Collectors["processes"]; !ok || m.Errors != 0 || m.Cycles != 1 {
		t.Fatalf("processes metric = %+v", m)
	}
	if m, ok := status.Collectors["connections"]; !ok || m.Errors != 1 {
		t.Fatalf("connections metric = %+v", m)
	}
	if m, ok := status.Collectors["system"]; !ok || m.Total < m.Last || m.Average <= 0 {
		t.Fatalf("system timing metric = %+v; total=%s last=%s average=%s", m, m.Total, m.Last, m.Average)
	}
	if len(snapshot.Metrics) != 5 {
		t.Fatalf("per-cycle metrics = %+v, want system/processes/connections/pressure/cgroups", snapshot.Metrics)
	}
	wantmetrics := []struct {
		name string
		err  bool
	}{{"system", false}, {"processes", false}, {"connections", true}, {"pressure", true}, {"cgroups", false}}
	for i, want := range wantmetrics {
		got := snapshot.Metrics[i]
		if got.Name != want.name || got.Error != want.err || got.Duration < 0 {
			t.Errorf("cycle metric[%d] = %+v, want name=%q error=%v nonnegative duration", i, got, want.name, want.err)
		}
	}
	// status returns detached metric values. changing the copy must not
	// change the scheduler's internal cumulative timing.
	metric := status.Collectors["system"]
	metric.Cycles = 999
	status.Collectors["system"] = metric
	if got := sched.Status().Collectors["system"].Cycles; got != 1 {
		t.Fatalf("mutating status changed scheduler counter: cycles=%d", got)
	}
}

func TestSchedulerAppliesWatchFilterWithoutLosingHostCount(t *testing.T) {
	process := &stubProcess{procs: []platform.Process{
		{PID: 100, PPID: 1, Name: "Runner.Listener", StartTicks: 5},
		{PID: 101, PPID: 100, Name: "node", StartTicks: 6},
		{PID: 200, PPID: 1, Name: "other", StartTicks: 7},
	}}
	sched, err := NewScheduler(time.Second, 4, Sources{
		Process: process,
		Filter:  Filter{PIDs: []int{100}, Descendants: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := sched.Collect(context.Background())
	if len(snapshot.Processes) != 2 || snapshot.Processes[0].PID != 100 || snapshot.Processes[1].PID != 101 {
		t.Fatalf("filtered processes = %+v, want pids 100 and 101", snapshot.Processes)
	}
	if snapshot.System == nil || snapshot.System.ProcessCount != 3 {
		t.Fatalf("host process count = %+v, want 3 sampled processes even when watching", snapshot.System)
	}
}

func TestSchedulerNilCollectorsAreSkippedSilently(t *testing.T) {
	sched, err := NewScheduler(time.Second, 4, Sources{
		Process: &stubProcess{procs: []platform.Process{{PID: 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := sched.Collect(context.Background())
	if snapshot.System == nil || snapshot.System.ProcessCount != 1 || snapshot.System.CPUCount == 0 {
		t.Fatalf("host counts not filled: %+v", snapshot.System)
	}
	if len(snapshot.Errors) != 0 {
		t.Fatalf("skipped collectors must not be reported as errors: %+v", snapshot.Errors)
	}
	status := sched.Status()
	if _, ok := status.Collectors["connections"]; ok {
		t.Fatal("nil network collector must not produce telemetry")
	}
}

func TestSchedulerAttributionAndUnknownOwners(t *testing.T) {
	owners := map[uint64]platform.SocketOwner{5: {PID: 123, FD: 3}}
	connections := connectSnapshots([]platform.TCPRecord{
		{LocalAddr: loopback(10, 0, 0, 4), LocalPort: 51922, RemoteAddr: loopback(10, 0, 0, 9), RemotePort: 443, State: "ESTABLISHED", Inode: 5},
		{LocalAddr: loopback(10, 0, 0, 4), LocalPort: 51923, RemoteAddr: loopback(10, 0, 0, 9), RemotePort: 443, State: "ESTABLISHED", Inode: 77},
	}, owners, nil)
	if connections[0].PID != 123 || connections[0].FD != 3 {
		t.Fatalf("owned connection = %+v, want pid 123 fd 3", connections[0])
	}
	if connections[1].PID != 0 || connections[1].FD != -1 {
		t.Fatalf("unowned connection = %+v, want pid 0 fd -1", connections[1])
	}
}

func TestSchedulerRetainsHistoryInOrder(t *testing.T) {
	process := &stubProcess{procs: []platform.Process{{PID: 1}}}
	sched, _ := NewScheduler(10*time.Millisecond, 3, Sources{Process: process})
	for i := 0; i < 5; i++ {
		sched.Collect(context.Background())
	}
	history := sched.History()
	if len(history) != 3 {
		t.Fatalf("history = %d items, want capacity 3", len(history))
	}
	for i := 1; i < len(history); i++ {
		if history[i].Timestamp.Before(history[i-1].Timestamp) {
			t.Fatalf("history out of chronological order at %d", i)
		}
	}
	// wait to release the scheduler's short interval; the metric history
	// stays available after all cycles.
	if status := sched.Status(); status.Samples != 5 {
		t.Fatalf("samples = %d, want 5", status.Samples)
	}
}

func TestSchedulerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewScheduler(0, 3, Sources{}); err == nil {
		t.Fatal("zero interval accepted")
	}
	if _, err := NewScheduler(time.Second, 0, Sources{}); err == nil {
		t.Fatal("zero capacity accepted")
	}
}

func failingPressure() PressureProducer {
	return failingPressureStub{}
}

type failingPressureStub struct{}

func (failingPressureStub) CollectPressure() (map[platform.Resource]platform.PressureSnapshot, error) {
	return nil, errors.New("psi unavailable")
}
