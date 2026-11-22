package simulator

import (
	"bytes"
	"context"
	"testing"
	"time"

	"runopsy/internal/events"
)

func newTestConfig(t *testing.T, duration time.Duration) (Config, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	em := events.New("test", &out, nil, true)
	return Config{Duration: duration, JSON: true, Events: em}, &out
}

func eventsOf(evs []events.Event, typ string) []events.Event {
	var got []events.Event
	for _, ev := range evs {
		if ev.Type == typ {
			got = append(got, ev)
		}
	}
	return got
}

func TestNormalExitsZeroAfterDuration(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, 300*time.Millisecond)

	start := time.Now()
	if err := (&Normal{}).Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < 250*time.Millisecond {
		t.Errorf("exited after %s, expected to run the full 300ms duration", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("exited after %s, expected close to 300ms", elapsed)
	}

	evs := decodeEvents(t, out)
	started := eventsOf(evs, "started")
	if len(started) != 1 {
		t.Fatalf("got %d started events, want 1", len(started))
	}
	if started[0].Data["state"] != "running" {
		t.Errorf("started.state = %v, want running", started[0].Data["state"])
	}

	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("got %d exited events, want 1", len(exited))
	}
	if code, _ := exited[0].Data["code"].(float64); code != 0 {
		t.Errorf("exit code = %v, want 0", exited[0].Data["code"])
	}
	if reason := exited[0].Data["reason"]; reason != "duration_elapsed" {
		t.Errorf("exit reason = %v, want duration_elapsed", reason)
	}
	checkGoroutines(t, baseline)
}

func TestNormalStopsOnCancel(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if err := (&Normal{}).Run(ctx, cfg); err != nil {
		t.Fatalf("Run returned %v, want nil after cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s to react to cancellation", elapsed)
	}

	evs := decodeEvents(t, out)
	if len(eventsOf(evs, "stop_requested")) != 1 {
		t.Errorf("missing stop_requested event: %+v", evs)
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("got %d exited events, want 1", len(exited))
	}
	if reason := exited[0].Data["reason"]; reason != "interrupted" {
		t.Errorf("exit reason = %v, want interrupted", reason)
	}
	checkGoroutines(t, baseline)
}
