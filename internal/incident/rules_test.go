package incident

import (
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
)

func systemSample(at time.Time, usedPercent, freePercent float64) collector.Snapshot {
	const total = uint64(1000)
	return collector.Snapshot{Timestamp: at, System: &collector.SystemSnapshot{
		MemoryStatsAvailable:  true,
		MemoryTotal:           total,
		MemoryUsed:            uint64(float64(total) * usedPercent / 100),
		DiskStatsAvailable:    true,
		DiskTotal:             total,
		DiskFree:              uint64(float64(total) * freePercent / 100),
		ProcessCountAvailable: true,
		ProcessCount:          1,
	}}
}

func processSample(at time.Time, state string) collector.Snapshot {
	return collector.Snapshot{Timestamp: at, System: &collector.SystemSnapshot{ProcessCountAvailable: true, ProcessCount: 1},
		Processes: []collector.ProcessSnapshot{{Process: platform.Process{PID: 42, PPID: 1, StartTicks: 7, State: state, Name: "worker"}}}}
}

func TestResourceRulesMemoryDebounce(t *testing.T) {
	r := &ResourceRules{Memory: &ThresholdRule{Value: 95, Duration: 2 * time.Second}}
	at := time.Now().UTC()
	if got := r.Observe(systemSample(at, 94, 50)); got != nil {
		t.Fatalf("triggered below threshold: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(time.Second), 96, 50)); got != nil {
		t.Fatalf("triggered before duration: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(2*time.Second), 96, 50)); got != nil {
		t.Fatalf("triggered one sample before duration: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(3*time.Second), 96, 50)); got == nil || got.Type != "memory_threshold" {
		t.Fatalf("missing debounced trigger: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(4*time.Second), 99, 50)); got != nil {
		t.Fatalf("repeat trigger during one episode: %+v", got)
	}
	// dropping below the threshold starts a fresh episode with no history.
	if got := r.Observe(systemSample(at.Add(5*time.Second), 50, 50)); got != nil {
		t.Fatalf("trigger while recovering: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(6*time.Second), 96, 50)); got != nil {
		t.Fatalf("old duration reused after reset: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(8*time.Second), 96, 50)); got == nil {
		t.Fatal("missing trigger after a fresh continuous episode")
	}
}

func TestResourceRulesUnavailableSensorResets(t *testing.T) {
	r := &ResourceRules{Memory: &ThresholdRule{Value: 95, Duration: time.Second}}
	at := time.Now().UTC()
	r.Observe(systemSample(at, 99, 50))
	missing := collector.Snapshot{Timestamp: at.Add(time.Second), System: &collector.SystemSnapshot{}}
	if got := r.Observe(missing); got != nil {
		t.Fatalf("triggered without memory data: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(2*time.Second), 99, 50)); got != nil {
		t.Fatalf("duration survived an unavailable sample: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(3*time.Second), 99, 50)); got == nil {
		t.Fatal("missing trigger after a fresh available episode")
	}
}

func TestResourceRulesDiskFreeIsInvertedAndBounded(t *testing.T) {
	r := &ResourceRules{DiskFree: &ThresholdRule{Value: 2, Duration: 0}}
	at := time.Now().UTC()
	if got := r.Observe(systemSample(at, 10, 3)); got != nil {
		t.Fatalf("triggered with enough free space: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(time.Second), 10, 2)); got == nil || got.Type != "disk_threshold" {
		t.Fatalf("missing low-disk trigger: %+v", got)
	}
	// invalid or disabled rules never fire.
	for _, rule := range []*ThresholdRule{nil, {Value: 0}, {Value: 101}, {Value: -1}} {
		disabled := &ResourceRules{DiskFree: rule}
		if got := disabled.Observe(systemSample(at.Add(2*time.Second), 10, 0)); got != nil {
			t.Fatalf("invalid rule fired: %+v (%+v)", got, rule)
		}
	}
}

func TestStoppedProcessRuleFiresOncePerEpisode(t *testing.T) {
	var r StoppedProcessRule
	if got := r.Observe(processSample(time.Now().UTC(), "T")); got != nil {
		t.Fatal("disabled rule fired")
	}
	r.Enabled = true
	at := time.Now().UTC()
	if got := r.Observe(processSample(at, "S")); got != nil {
		t.Fatalf("running process triggered: %+v", got)
	}
	got := r.Observe(processSample(at.Add(time.Second), "T"))
	if got == nil || got.Type != "process_stopped" || got.PID != 42 || got.StartTicks != 7 {
		t.Fatalf("missing stopped trigger: %+v", got)
	}
	if got := r.Observe(processSample(at.Add(2*time.Second), "T")); got != nil {
		t.Fatalf("repeat stopped trigger: %+v", got)
	}
	// A recycled PID with a different start time is a different identity.
	reused := processSample(at.Add(3*time.Second), "T")
	reused.Processes[0].StartTicks = 8
	if got := r.Observe(reused); got == nil {
		t.Fatal("new process identity was suppressed")
	}
	// running again resets the episode; a new stop is evidence again.
	r.Observe(processSample(at.Add(4*time.Second), "S"))
	if got := r.Observe(processSample(at.Add(5*time.Second), "t")); got == nil {
		t.Fatal("lowercase stopped state did not trigger")
	}
}

func TestStoppedProcessRuleIgnoresUnavailableProcessSection(t *testing.T) {
	r := StoppedProcessRule{Enabled: true}
	at := time.Now().UTC()
	if got := r.Observe(processSample(at, "T")); got == nil {
		t.Fatal("initial stopped observation did not trigger")
	}
	unavailable := processSample(at.Add(time.Second), "T")
	unavailable.Processes = nil
	unavailable.Errors = []collector.CollectionError{{Collector: "processes", Err: "denied"}}
	if got := r.Observe(unavailable); got != nil {
		t.Fatalf("unavailable process section triggered: %+v", got)
	}
	if got := r.Observe(processSample(at.Add(2*time.Second), "T")); got == nil {
		t.Fatal("stopped episode did not restart after unavailability")
	}
	// A failed section must also not be mistaken for the process running again.
	r.Observe(unavailable)
	if got := r.Observe(processSample(at.Add(3*time.Second), "T")); got != nil {
		t.Fatal("stale unavailable observation restarted the stop episode")
	}
}
