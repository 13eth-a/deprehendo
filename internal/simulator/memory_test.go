package simulator

import (
	"context"
	"testing"
	"time"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"1024", 1024, false},
		{"1KB", 1024, false},
		{"2.5KB", 2560, false},
		{"50MB", 50 * 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{" 128mib ", 128 * 1024 * 1024, false},
		{"10B", 10, false},
		{"", 0, true},
		{"MB", 0, true},
		{"50XB", 0, true},
		{"-5MB", 0, true},
	}
	for _, tc := range tests {
		got, err := parseBytes(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseBytes(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBytes(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestMemoryPressureReachesLimit(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, time.Minute)

	sc := &MemoryPressure{Rate: "2MB", Interval: 10 * time.Millisecond, Limit: "10MB"}
	start := time.Now()
	if err := sc.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("elapsed = %s; 5 steps x 10ms should be quick", elapsed)
	}

	evs := decodeEvents(t, out)
	allocs := eventsOf(evs, "memory_allocated")
	if len(allocs) < 5 {
		t.Fatalf("memory_allocated events = %d, want at least 5 (2MB steps to 10MB)", len(allocs))
	}
	final, _ := allocs[len(allocs)-1].Data["total_bytes"].(float64)
	if final != 10*1024*1024 {
		t.Errorf("final total_bytes = %v, want 10MB worth", allocs[len(allocs)-1].Data["total_bytes"])
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "limit_reached" {
		t.Errorf("exit reason = %v, want limit_reached", reason)
	}
	checkGoroutines(t, baseline)
}

func TestMemoryPressureStopsOnCancel(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, time.Minute)

	sc := &MemoryPressure{Rate: "50MB", Interval: 10 * time.Millisecond, Limit: "10GB"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()

	if err := sc.Run(ctx, cfg); err != nil {
		t.Fatalf("Run returned %v, want nil after cancellation", err)
	}
	if evs := decodeEvents(t, out); len(eventsOf(evs, "exited")) != 1 {
		t.Fatalf("missing exited event: %+v", evs)
	}
	checkGoroutines(t, baseline)
}

func TestMemoryPressureRejectsBadSizes(t *testing.T) {
	cfg, out := newTestConfig(t, 0)
	sc := &MemoryPressure{Rate: "50MB", Interval: time.Millisecond, Limit: "lots"}
	err := sc.Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected an error for a bad --limit")
	}
	if !contains(err.Error(), "--limit") {
		t.Errorf("error %v should name --limit", err)
	}
	if evs := decodeEvents(t, out); len(evs) != 0 {
		t.Errorf("emitted %d events before validating flags", len(evs))
	}

	sc = &MemoryPressure{Rate: "zero", Limit: "1MB", Interval: time.Millisecond}
	err = sc.Run(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "--rate") {
		t.Fatalf("expected --rate validation error, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestMemoryPressureRateDoesNotRaiseLimit(t *testing.T) {
	cfg, out := newTestConfig(t, time.Second)
	sc := &MemoryPressure{Rate: "2MB", Interval: time.Millisecond, Limit: "1KB"}
	if err := sc.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range eventsOf(decodeEvents(t, out), "memory_allocated") {
		if got := ev.Data["total_bytes"].(float64); got != 1024 {
			t.Fatalf("retained %v bytes despite 1KB limit", got)
		}
	}
}
