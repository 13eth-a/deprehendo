package collector

import (
	"testing"
	"time"

	"deprehendo/internal/platform"
)

func TestCPUTrackerFirstSampleIsZero(t *testing.T) {
	var tracker CPUTracker
	now := time.Now()
	snapshots := tracker.Observe([]platform.Process{{PID: 42, CPUTicks: 500}}, now)
	if len(snapshots) != 1 || snapshots[0].CPUPercent != 0 {
		t.Fatalf("first sample = %+v, want zero percent", snapshots)
	}
}

func TestCPUTrackerDeltaOverWallClock(t *testing.T) {
	var tracker CPUTracker
	t1 := time.Now()
	tracker.Observe([]platform.Process{{PID: 42, StartTicks: 7, CPUTicks: 500}}, t1)
	t2 := t1.Add(time.Second)
	snapshots := tracker.Observe([]platform.Process{{
		PID: 42, CPUTicks: 600, StartTicks: 7,
	}}, t2)
	if got := snapshots[0].CPUPercent; got < 99.999 || got > 100.001 {
		t.Fatalf("cpu percent = %f, want 100 (100 ticks over 1s at USER_HZ=100)", got)
	}
}

func TestCPUTrackerMultiThreadedExceedsHundred(t *testing.T) {
	// 400 ticks in 1s at USER_HZ=100 means four busy cores legally exceed
	// 100 percent; do not clamp.
	if got := CPUPercentFor(400, time.Second); got != 400 {
		t.Fatalf("cpu percent = %f, want 400", got)
	}
	if got := CPUPercentFor(400, 0); got != 0 {
		t.Fatalf("zero elapsed must yield 0, got %f", got)
	}
}

func TestCPUTrackerPIDReuseStartsFresh(t *testing.T) {
	var tracker CPUTracker
	t1 := time.Now()
	tracker.Observe([]platform.Process{{
		PID: 7, StartTicks: 100, CPUTicks: 1000,
	}}, t1)
	// same PID, but a different start ticks value: a new process reused
	// the PID. its counter is lower than the previous holder's, which a
	// PID-only tracker would report as a negative/huge nonsense delta.
	snapshots := tracker.Observe([]platform.Process{{
		PID: 7, StartTicks: 500, CPUTicks: 10,
	}}, t1.Add(time.Second))
	if snapshots[0].CPUPercent != 0 {
		t.Fatalf("reused PID = %f percent, want 0 for the first sample", snapshots[0].CPUPercent)
	}
	// the reused PID is now tracked under its own identity and accumulates
	// deltas from its own baseline.
	snapshots = tracker.Observe([]platform.Process{{
		PID: 7, StartTicks: 500, CPUTicks: 110,
	}}, t1.Add(2*time.Second))
	if got := snapshots[0].CPUPercent; got < 99.999 || got > 100.001 {
		t.Fatalf("reused PID second delta = %f, want 100", got)
	}
}

func TestCPUTrackerForgetsExitedProcesses(t *testing.T) {
	var tracker CPUTracker
	t1 := time.Now()
	tracker.Observe([]platform.Process{
		{PID: 1, CPUTicks: 100},
		{PID: 2, CPUTicks: 200},
	}, t1)
	t2 := t1.Add(time.Second)
	snapshots := tracker.Observe([]platform.Process{{PID: 2, CPUTicks: 300}}, t2)
	if len(snapshots) != 1 || snapshots[0].PID != 2 {
		t.Fatalf("snapshots = %+v, want only pid 2", snapshots)
	}
	// A process absent from the immediately preceding table starts fresh,
	// even if it later returns under the same identity.
	snapshots = tracker.Observe([]platform.Process{{PID: 1, StartTicks: 8, CPUTicks: 150}}, t2.Add(time.Second))
	if got := snapshots[0].CPUPercent; got != 0 {
		t.Fatalf("returning process percent = %f, want first-sample zero", got)
	}
}

func TestCPUTrackerNegativeTickNoiseClamped(t *testing.T) {
	var tracker CPUTracker
	// A counter anomaly (torn read, container accounting quirk) must not
	// surface as a negative percent.
	t1 := time.Now()
	tracker.Observe([]platform.Process{{PID: 3, CPUTicks: 500}}, t1)
	snapshots := tracker.Observe([]platform.Process{{PID: 3, CPUTicks: 10}}, t1.Add(time.Second))
	if snapshots[0].CPUPercent != 0 {
		t.Fatalf("negative delta produced %f percent, want 0", snapshots[0].CPUPercent)
	}
}
