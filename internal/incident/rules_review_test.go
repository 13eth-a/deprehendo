package incident

import (
	"deprehendo/internal/collector"
	"deprehendo/internal/platform"
	"testing"
	"time"
)

func TestDifferMetricErrorOverridesHostAvailability(t *testing.T) {
	at := time.Now()
	var d Differ
	d.Observe(sample(at, 10))
	failed := sample(at.Add(time.Second), 10)
	failed.Processes = nil
	failed.Metrics = append(failed.Metrics, collector.CollectorTiming{Name: "processes", Error: true})
	for _, event := range d.Observe(failed) {
		if event.Type == ProcessExited {
			t.Fatal("failed telemetry inferred exit")
		}
	}
	recovered := sample(at.Add(2*time.Second), 10)
	if got := d.Observe(recovered); len(got) != 0 {
		t.Fatalf("baseline lost on failure: %v", got)
	}
}
func TestDebounceStaleSamplesCannotRearmOrMoveClock(t *testing.T) {
	at := time.Now()
	d := Debounce{Duration: time.Second}
	if d.Observe(at, true, true) || !d.Observe(at.Add(time.Second), true, true) {
		t.Fatal("initial episode")
	}
	if d.Observe(at, false, false) || d.Observe(at.Add(2*time.Second), true, true) {
		t.Fatal("stale sample rearmed episode")
	}
	d.Observe(at.Add(3*time.Second), false, true)
	if d.Observe(at.Add(2*time.Second), true, true) || d.Observe(at.Add(4*time.Second), true, true) {
		t.Fatal("stale sample shifted debounce start")
	}
	if !d.Observe(at.Add(5*time.Second), true, true) {
		t.Fatal("fresh episode missing")
	}
}
func TestResourceRulesUpdateBothSensorsWhenMemoryTriggers(t *testing.T) {
	at := time.Now()
	r := ResourceRules{Memory: &ThresholdRule{Value: 95}, DiskFree: &ThresholdRule{Value: 2, Duration: 2 * time.Second}}
	r.Observe(systemSample(at, 50, 1))
	unavailable := systemSample(at.Add(time.Second), 99, 1)
	unavailable.System.DiskStatsAvailable = false
	if got := r.Observe(unavailable); got == nil || got.Type != "memory_threshold" {
		t.Fatal("memory trigger missing")
	}
	if got := r.Observe(systemSample(at.Add(2*time.Second), 99, 1)); got != nil {
		t.Fatalf("disk debounce survived unavailable sensor: %+v", got)
	}
	if got := r.Observe(systemSample(at.Add(4*time.Second), 99, 1)); got == nil || got.Type != "disk_threshold" {
		t.Fatalf("disk episode not tracked: %+v", got)
	}
}
func TestExitRulesDoNotInferDeathAcrossUnavailableSample(t *testing.T) {
	for _, rule := range []SnapshotRule{&ProcessExitRule{Enabled: true}, &WatchedProcessExitRule{Enabled: true}} {
		at := time.Now()
		rule.Observe(sample(at, 10))
		bad := sample(at.Add(time.Second), 10)
		bad.Processes = nil
		bad.Errors = []collector.CollectionError{{Collector: "processes"}}
		if rule.Observe(bad) != nil {
			t.Fatal("unavailable sample triggered")
		}
		good := sample(at.Add(2*time.Second), 10)
		good.Processes = nil
		if rule.Observe(good) != nil {
			t.Fatal("unknown interval inferred process exit")
		}
	}
}
func TestExitRuleSelectsDeterministicIdentity(t *testing.T) {
	for range 30 {
		var rule = WatchedProcessExitRule{Enabled: true}
		at := time.Now()
		s := sample(at, 10)
		s.Processes = append(s.Processes, collector.ProcessSnapshot{Process: platform.Process{PID: 7, StartTicks: 11}})
		rule.Observe(s)
		s.Timestamp = at.Add(time.Second)
		s.Processes = nil
		got := rule.Observe(s)
		if got == nil || got.PID != 7 {
			t.Fatalf("nondeterministic exit: %+v", got)
		}
	}
}
func TestDifferDeduplicatesCollectorErrors(t *testing.T) {
	var d Differ
	s := sample(time.Now(), 10)
	s.Errors = []collector.CollectionError{{Collector: "processes", Err: "one"}, {Collector: "processes", Err: "two"}}
	events := d.Observe(s)
	if len(events) != 1 || events[0].Type != CollectorError {
		t.Fatalf("duplicate errors: %+v", events)
	}
}
