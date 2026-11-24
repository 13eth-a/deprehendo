package incident

import (
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/platform"
)

func exitRuleSample(at time.Time, processes ...collector.ProcessSnapshot) collector.Snapshot {
	return collector.Snapshot{
		Timestamp: at,
		System:    &collector.SystemSnapshot{ProcessCountAvailable: true},
		Processes: processes,
	}
}

func TestWatchedProcessExitRuleRequiresSuccessfulContinuousObservation(t *testing.T) {
	at := time.Now().UTC()
	proc := collector.ProcessSnapshot{Process: platform.Process{PID: 71, StartTicks: 9, State: "S"}}
	rule := WatchedProcessExitRule{Enabled: true}
	if got := rule.Observe(exitRuleSample(at, proc)); got != nil {
		t.Fatalf("baseline emitted %v", got)
	}
	unavailable := exitRuleSample(at.Add(time.Second))
	unavailable.System.ProcessCountAvailable = false
	unavailable.Errors = []collector.CollectionError{{Collector: "processes", Err: "denied"}}
	if got := rule.Observe(unavailable); got != nil {
		t.Fatalf("unavailable emitted %v", got)
	}
	if got := rule.Observe(exitRuleSample(at.Add(2 * time.Second))); got != nil {
		t.Fatalf("exit inferred across unavailable sample: %v", got)
	}
	if got := rule.Observe(exitRuleSample(at.Add(3*time.Second), proc)); got != nil {
		t.Fatalf("new baseline emitted %v", got)
	}
	got := rule.Observe(exitRuleSample(at.Add(4 * time.Second)))
	if got == nil || got.Type != "process_exit" || got.PID != 71 || got.StartTicks != 9 {
		t.Fatalf("exit = %+v", got)
	}
	if got := rule.Observe(exitRuleSample(at.Add(5 * time.Second))); got != nil {
		t.Fatalf("duplicate exit emitted %v", got)
	}
}

func TestProcessAvailabilityCanUseCollectorMetrics(t *testing.T) {
	at := time.Now().UTC()
	p := collector.ProcessSnapshot{Process: platform.Process{PID: 3, StartTicks: 4}}
	var differ Differ
	first := collector.Snapshot{Timestamp: at, Metrics: []collector.CollectorTiming{{Name: "processes"}}, Processes: []collector.ProcessSnapshot{p}}
	if events := differ.Observe(first); len(events) != 0 {
		t.Fatalf("initial metrics-backed observation emitted %v", events)
	}
	second := collector.Snapshot{Timestamp: at.Add(time.Second), Metrics: []collector.CollectorTiming{{Name: "processes"}}}
	events := differ.Observe(second)
	found := false
	for _, event := range events {
		if event.Type == ProcessExited {
			found = true
		}
	}
	if !found {
		t.Fatalf("successful process metrics did not establish disappearance: %v", events)
	}
}
