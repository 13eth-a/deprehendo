package simulator

import (
	"context"
	"testing"
	"time"
)

func TestCPUSpinRunsToDuration(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, 600*time.Millisecond)

	sc := &CPUSpin{Workers: 2}
	start := time.Now()
	if err := sc.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond || elapsed > 5*time.Second {
		t.Errorf("elapsed = %s, want close to 600ms", elapsed)
	}

	evs := decodeEvents(t, out)
	if len(eventsOf(evs, "started")) != 1 {
		t.Errorf("missing started event")
	}
	reports := eventsOf(evs, "work_report")
	if len(reports) < 2 {
		t.Errorf("work_report events = %d, want at least 2 for a 600ms run", len(reports))
	}
	units, _ := reports[len(reports)-1].Data["units"].(float64)
	if units <= 0 {
		t.Errorf("final work_report units = %v, want > 0 (workers must actually burn CPU)", units)
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "duration_elapsed" {
		t.Errorf("exit reason = %v, want duration_elapsed", reason)
	}
	checkGoroutines(t, baseline)
}

func TestCPUSpinDefaultsToOneWorkerPerCore(t *testing.T) {
	cfg, out := newTestConfig(t, 100*time.Millisecond)
	if err := (&CPUSpin{}).Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	evs := decodeEvents(t, out)
	started := eventsOf(evs, "started")[0]
	if workers, _ := started.Data["workers"].(float64); workers <= 0 {
		t.Errorf("default workers = %v, want NumCPU (>0)", started.Data["workers"])
	}
}

func TestCPUSpinStopsOnCancel(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if err := (&CPUSpin{Workers: 2}).Run(ctx, cfg); err != nil {
		t.Fatalf("Run returned %v, want nil after cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s to react to cancellation", elapsed)
	}

	exited := eventsOf(decodeEvents(t, out), "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "interrupted" {
		t.Errorf("exit reason = %v, want interrupted", reason)
	}
	checkGoroutines(t, baseline)
}
