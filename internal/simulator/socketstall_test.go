package simulator

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"runopsy/internal/events"
)

func TestConnStateTransitions(t *testing.T) {
	tests := []struct {
		from, to connState
		legal    bool
	}{
		{stateConnecting, stateHealthy, true},
		{stateConnecting, stateStalled, false},
		{stateConnecting, stateClosed, true},
		{stateHealthy, stateStalled, true},
		{stateHealthy, stateRecovered, false},
		{stateHealthy, stateClosed, true},
		{stateStalled, stateRecovered, true},
		{stateStalled, stateHealthy, false},
		{stateStalled, stateClosed, true},
		{stateRecovered, stateClosed, true},
		{stateRecovered, stateStalled, false},
		{stateClosed, stateHealthy, false},
		{stateClosed, stateClosed, false},
	}

	for _, tc := range tests {
		tr := newTransitioner(tc.from)
		from, err := tr.Transition(tc.to)
		if tc.legal {
			if err != nil {
				t.Errorf("%s -> %s: unexpected error: %v", tc.from, tc.to, err)
				continue
			}
			if from != tc.from {
				t.Errorf("%s -> %s: reported previous state %s", tc.from, tc.to, from)
			}
			if got := tr.State(); got != tc.to {
				t.Errorf("%s -> %s: state is %s", tc.from, tc.to, got)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s -> %s: expected an error for an illegal transition", tc.from, tc.to)
		}
		if got := tr.State(); got != tc.from {
			t.Errorf("%s -> %s: illegal transition changed state to %s", tc.from, tc.to, got)
		}
	}
}

func shortSocketStall() *SocketStall {
	return &SocketStall{
		pingInterval:   20 * time.Millisecond,
		stallThreshold: 150 * time.Millisecond,
		stallDuration:  300 * time.Millisecond,
		stallAfter:     2,
	}
}

func stateSequence(evs []events.Event) []string {
	var got []string
	for _, ev := range eventsOf(evs, "conn_state") {
		to, _ := ev.Data["to"].(string)
		got = append(got, to)
	}
	return got
}

func TestSocketStallFullCycle(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, 0)

	start := time.Now()
	if err := shortSocketStall().Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("cycle took %s; expected it to finish on its own", elapsed)
	}

	evs := decodeEvents(t, out)

	got := stateSequence(evs)
	want := []string{"HEALTHY", "STALLED", "RECOVERED", "CLOSED"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("state sequence = %v, want %v", got, want)
	}

	if n := len(eventsOf(evs, "stall_detected")); n != 1 {
		t.Fatalf("stall_detected events = %d, want 1", n)
	}
	if n := len(eventsOf(evs, "recovered")); n != 1 {
		t.Fatalf("recovered events = %d, want 1", n)
	}

	pongs := eventsOf(evs, "pong_received")
	if len(pongs) < 3 {
		t.Fatalf("pong_received events = %d, want at least 3 (two before the stall, one after)", len(pongs))
	}
	// progress must be proven on both sides of the stall on the same socket.
	stallidx, recoveredidx := -1, -1
	for i, ev := range evs {
		switch ev.Type {
		case "stall_detected":
			stallidx = i
		case "recovered":
			recoveredidx = i
		}
	}
	if stallidx < 0 || recoveredidx < 0 || recoveredidx < stallidx {
		t.Fatalf("recovery did not follow the stall: stall=%d recovered=%d", stallidx, recoveredidx)
	}

	stallev := eventsOf(evs, "stall_detected")[0]
	if progress, _ := stallev.Data["progress"].(string); progress != "none" {
		t.Errorf("stall progress = %q, want none", progress)
	}
	if socket, _ := stallev.Data["socket"].(string); socket != "open" {
		t.Errorf("stall socket = %q, want open", socket)
	}
	if silent, _ := stallev.Data["silent_ms"].(float64); silent < 100 {
		t.Errorf("silent_ms = %v, want at least the 150ms threshold", silent)
	}

	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "cycle_complete" {
		t.Errorf("exit reason = %q, want cycle_complete", reason)
	}
	checkGoroutines(t, baseline)
}

func TestSocketStallCancelDuringStall(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, time.Hour)

	sc := shortSocketStall()
	sc.stallDuration = 30 * time.Second // never recovers on its own

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if err := sc.Run(ctx, cfg); err != nil {
		t.Fatalf("Run returned %v, want nil after cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s to react to cancellation", elapsed)
	}

	evs := decodeEvents(t, out)
	states := stateSequence(evs)
	want := []string{"HEALTHY", "STALLED", "CLOSED"}
	if strings.Join(states, ",") != strings.Join(want, ",") {
		t.Fatalf("state sequence = %v, want %v", states, want)
	}
	if n := len(eventsOf(evs, "recovered")); n != 0 {
		t.Errorf("recovered events = %d, want 0 when canceled mid-stall", n)
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "interrupted" {
		t.Errorf("exit reason = %q, want interrupted", reason)
	}
	checkGoroutines(t, baseline)
}

func TestSocketStallRejectsInvertedThresholds(t *testing.T) {
	cfg, out := newTestConfig(t, 0)
	sc := &SocketStall{
		pingInterval:   500 * time.Millisecond,
		stallThreshold: 100 * time.Millisecond,
	}
	err := sc.Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected an error when the threshold is shorter than the ping interval")
	}
	if !strings.Contains(err.Error(), "stall-threshold") {
		t.Errorf("error = %v, want it to name stall-threshold", err)
	}
	if evs := decodeEvents(t, out); len(evs) != 0 {
		t.Errorf("emitted %d events before validating flags: %+v", len(evs), evs)
	}
}

func TestSocketStallDurationCapStopsCleanly(t *testing.T) {
	baseline := goroutines()
	cfg, out := newTestConfig(t, 250*time.Millisecond)
	sc := shortSocketStall()
	sc.stallDuration = 30 * time.Second // the cap, not recovery, must end the run

	start := time.Now()
	if err := sc.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s to honour --duration", elapsed)
	}

	evs := decodeEvents(t, out)
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "duration_elapsed" {
		t.Errorf("exit reason = %q, want duration_elapsed", reason)
	}
	states := stateSequence(evs)
	if len(states) == 0 || states[len(states)-1] != "CLOSED" {
		t.Errorf("final state = %v, want CLOSED", states)
	}
	checkGoroutines(t, baseline)
}

func TestSocketStallDefaultDurationTerminates(t *testing.T) {
	// guards the "budget" rule: no --duration must still produce a bounded run.
	// 20ms pings, 60ms threshold, 100ms stall, 1 ping before stalling.
	baseline := goroutines()
	cfg, out := newTestConfig(t, 0)
	sc := &SocketStall{
		pingInterval:   20 * time.Millisecond,
		stallThreshold: 60 * time.Millisecond,
		stallDuration:  100 * time.Millisecond,
		stallAfter:     1,
	}
	done := make(chan error, 1)
	go func() { done <- sc.Run(context.Background(), cfg) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not terminate without --duration")
	}
	if len(eventsOf(decodeEvents(t, out), "exited")) != 1 {
		t.Error("missing exited event")
	}
	checkGoroutines(t, baseline)
}

func TestSocketStallCancellationInterruptsLongRead(t *testing.T) {
	cfg, out := newTestConfig(t, 90*time.Millisecond)
	sc := shortSocketStall()
	sc.stallThreshold = time.Hour
	sc.stallDuration = 2 * time.Hour
	finished := make(chan error, 1)
	go func() { finished <- sc.Run(context.Background(), cfg) }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("duration cap did not interrupt socket read")
	}
	if got := len(eventsOf(decodeEvents(t, out), "stall_detected")); got != 0 {
		t.Fatalf("recorded %d stalls after cancellation", got)
	}
}

func TestStallServerConcurrentCloseStopsRecoveryTimer(t *testing.T) {
	cfg, _ := newTestConfig(t, 0)
	srv, err := newStallServer(cfg, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv.Start(context.Background())
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping\nping\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		srv.mu.Lock()
		stalled := srv.stalled
		srv.mu.Unlock()
		if stalled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not stall")
		}
		time.Sleep(time.Millisecond)
	}
	finished := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); srv.Close() }()
		}
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close waited for hour-long recovery timer")
	}
}

func TestSocketStallRejectsUndetectableStall(t *testing.T) {
	for _, duration := range []time.Duration{50 * time.Millisecond, 150 * time.Millisecond} {
		cfg, out := newTestConfig(t, 0)
		sc := shortSocketStall()
		sc.stallDuration = duration
		err := sc.Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "stall-duration") {
			t.Fatalf("duration %s: error = %v, want stall-duration validation", duration, err)
		}
		if evs := decodeEvents(t, out); len(evs) != 0 {
			t.Fatalf("emitted events before validating stall-duration: %+v", evs)
		}
	}
}
