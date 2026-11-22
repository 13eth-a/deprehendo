package simulator

import (
	"context"
	"testing"
	"time"

	"runopsy/internal/events"
	"runopsy/internal/platform"
)

// workerPID pulls the worker's pid out of the event stream.
func workerPID(t *testing.T, evs []events.Event) int {
	t.Helper()
	spawned := eventsOf(evs, "worker_spawned")
	if len(spawned) != 1 {
		t.Fatalf("worker_spawned events = %d, want 1", len(spawned))
	}
	pid, ok := spawned[0].Data["worker_pid"].(float64)
	if !ok {
		t.Fatalf("worker_spawned has no numeric worker_pid: %v", spawned[0].Data)
	}
	return int(pid)
}

// eventIndex returns the first index of the event with the given type, or -1.
func eventIndex(evs []events.Event, typ string) int {
	for i, e := range evs {
		if e.Type == typ {
			return i
		}
	}
	return -1
}

// assertWorkerGone fails if the worker process is still visible (alive or a
// zombie the runner failed to reap).
func assertWorkerGone(t *testing.T, pid int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		_, ok, err := platform.Find(pid)
		if err != nil || !ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("worker pid %d still visible after 2.5s", pid)
}

func TestFrozenWorkerFullCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, 0)
	fw := &FrozenWorker{
		FreezeAfter: 300 * time.Millisecond,
		FreezeFor:   500 * time.Millisecond,
		Grace:       300 * time.Millisecond,
	}
	start := time.Now()
	if err := fw.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("cycle finished in %s, want >= 900ms", elapsed)
	}

	evs := decodeEvents(t, out)
	if got := eventsOf(evs, "worker_frozen"); len(got) != 1 {
		t.Errorf("worker_frozen events = %d, want 1", len(got))
	}
	if got := eventsOf(evs, "worker_resumed"); len(got) != 1 {
		t.Errorf("worker_resumed events = %d, want 1", len(got))
	}
	killed := eventsOf(evs, "worker_killed")
	if len(killed) != 1 {
		t.Fatalf("worker_killed events = %d, want 1", len(killed))
	}
	if code, _ := killed[0].Data["exit_code"].(float64); int(code) != 137 {
		t.Errorf("worker exit_code = %v, want 137 (SIGKILL)", killed[0].Data["exit_code"])
	}
	if kind, _ := killed[0].Data["exit_kind"].(string); kind != "signal" {
		t.Errorf("worker exit_kind = %v, want signal", killed[0].Data["exit_kind"])
	}

	// event order: frozen strictly before resumed.
	frozen := eventIndex(evs, "worker_frozen")
	resumed := eventIndex(evs, "worker_resumed")
	if frozen >= resumed {
		t.Errorf("worker_frozen at %d not before worker_resumed at %d", frozen, resumed)
	}

	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "cycle_complete" {
		t.Errorf("exit reason = %v, want cycle_complete", exited[0].Data["reason"])
	}

	assertWorkerGone(t, workerPID(t, evs))
	checkGoroutines(t, baseline)
}

func TestFrozenWorkerStoppedStateObserved(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)

	cfg, out := newTestConfig(t, 0)
	fw := &FrozenWorker{
		FreezeAfter: 300 * time.Millisecond,
		FreezeFor:   1 * time.Second,
		Grace:       200 * time.Millisecond,
	}
	if err := fw.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	evs := decodeEvents(t, out)
	sawstopped := false
	for _, e := range eventsOf(evs, "worker_state") {
		if e.Data["kind"] == "stopped" {
			sawstopped = true
		}
	}
	if !sawstopped {
		t.Errorf("no worker_state event with kind=stopped; the freeze must be observable in the process table")
	}
}

func TestFrozenWorkerNoResumeGoesStraightToKill(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)

	cfg, out := newTestConfig(t, 0)
	fw := &FrozenWorker{
		FreezeAfter: 300 * time.Millisecond,
		FreezeFor:   300 * time.Millisecond,
		NoResume:    true,
	}
	if err := fw.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	evs := decodeEvents(t, out)
	if got := eventsOf(evs, "worker_resumed"); len(got) != 0 {
		t.Errorf("worker_resumed events = %d, want 0 with --no-resume", len(got))
	}
	if got := eventsOf(evs, "worker_frozen"); len(got) != 1 {
		t.Errorf("worker_frozen events = %d, want 1", len(got))
	}
	assertWorkerGone(t, workerPID(t, evs))
}

func TestFrozenWorkerCancelWhileFrozen(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// leave startup headroom for race-instrumented child exec, but cancel
		// well before the worker's natural resume.
		time.Sleep(1500 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if err := (&FrozenWorker{
		FreezeAfter: 300 * time.Millisecond,
		FreezeFor:   10 * time.Second,
	}).Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s to react to cancellation", elapsed)
	}

	evs := decodeEvents(t, out)
	if got := eventsOf(evs, "worker_resumed"); len(got) != 0 {
		t.Errorf("worker_resumed events = %d, want 0 when cancelled while frozen", len(got))
	}
	if got := eventsOf(evs, "worker_frozen"); len(got) != 1 {
		t.Errorf("worker_frozen events = %d, want 1 before the cancel", len(got))
	}
	killed := eventsOf(evs, "worker_killed")
	if len(killed) != 1 {
		t.Fatalf("worker_killed events = %d, want 1 after cancellation", len(killed))
	}
	if code, _ := killed[0].Data["exit_code"].(float64); int(code) != 137 {
		t.Errorf("worker exit_code = %v, want 137", killed[0].Data["exit_code"])
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "interrupted" {
		t.Errorf("exit reason = %v, want interrupted", exited[0].Data["reason"])
	}

	assertWorkerGone(t, workerPID(t, evs))
	checkGoroutines(t, baseline)
}
