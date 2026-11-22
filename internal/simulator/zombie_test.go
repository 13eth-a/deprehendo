package simulator

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestZombieFullCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, 0)
	start := time.Now()
	if err := (&ZombieWorker{Grace: 400 * time.Millisecond, Window: 400 * time.Millisecond}).Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("cycle took %s", elapsed)
	}

	evs := decodeEvents(t, out)
	spawned := eventsOf(evs, "leaf_spawned")
	if len(spawned) != 1 {
		t.Fatalf("leaf_spawned events = %d, want 1", len(spawned))
	}
	pid, ok := spawned[0].Data["leaf_pid"].(float64)
	if !ok {
		t.Fatalf("leaf_spawned has no numeric leaf_pid: %v", spawned[0].Data)
	}
	leafpid := int(pid)

	kill := eventsOf(evs, "leaf_killed")
	if len(kill) != 1 {
		t.Fatalf("leaf_killed events = %d, want 1", len(kill))
	}
	if unreaped, _ := kill[0].Data["unreaped"].(bool); !unreaped {
		t.Errorf("kill was not marked unreaped")
	}

	corpse := eventsOf(evs, "zombie_observed")
	if len(corpse) != 1 {
		t.Fatalf("zombie_observed events = %d, want 1", len(corpse))
	}
	if cp, _ := corpse[0].Data["leaf_pid"].(float64); int(cp) != leafpid {
		t.Errorf("zombie leaf_pid = %v, want %d", corpse[0].Data["leaf_pid"], leafpid)
	}
	// ps adds flags such as "+" (foreground group) to the state when run from a
	// terminal, so the test checks the zombie code, as the rest of the package does.
	if state, _ := corpse[0].Data["state"].(string); !strings.HasPrefix(state, "Z") {
		t.Errorf("observed state = %q, want a zombie (Z...)", state)
	}
	// the exit-status decode is Linux-only (/proc stat); elsewhere the field
	// stays empty and honest (a zombie state with the status not captured).
	if state, _ := corpse[0].Data["exit_status"].(string); state != "" && state != "signal:9" {
		t.Errorf("exit_status = %q, want empty or signal:9", state)
	}

	exited := eventsOf(evs, "exited")
	if len(exited) != 1 || exited[0].Data["reason"] != "cycle_complete" {
		t.Errorf("exited = %v, want cycle_complete", exited)
	}
	assertWorkerGone(t, leafpid)
	checkGoroutines(t, baseline)
}

func TestZombieCancelMidWindowCleansUp(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(700 * time.Millisecond)
		cancel()
	}()
	if err := (&ZombieWorker{Grace: 200 * time.Millisecond, Window: 10 * time.Second}).Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	evs := decodeEvents(t, out)
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 || exited[0].Data["reason"] != "interrupted" {
		t.Fatalf("exited = %v, want interrupted", exited)
	}
	if cleaned := eventsOf(evs, "tree_cleaned"); len(cleaned) != 1 {
		t.Fatalf("tree_cleaned events = %d, want 1", len(cleaned))
	}
	// cancellation may land before or after the kill; in either case the
	// leaf ends reaped, never as a leftover corpse.
	if corpse := eventsOf(evs, "zombie_observed"); len(corpse) > 1 {
		t.Errorf("zombie_observed events = %d, want at most 1", len(corpse))
	}
	spawned := eventsOf(evs, "leaf_spawned")
	pid, ok := spawned[0].Data["leaf_pid"].(float64)
	if !ok {
		t.Fatalf("leaf_spawned has no numeric leaf_pid: %v", spawned[0].Data)
	}
	assertWorkerGone(t, int(pid))
	checkGoroutines(t, baseline)
}

func TestZombieShortDurationStillTearsDown(t *testing.T) {
	// A duration shorter than the grace is clipped, not bypassed: the run
	// must still deliver a complete teardown, not a leaked corpse.
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, 150*time.Millisecond)
	if err := (&ZombieWorker{Grace: 10 * time.Second, Window: 10 * time.Second}).Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	evs := decodeEvents(t, out)
	for _, typ := range []string{"leaf_killed", "zombie_observed"} {
		if got := eventsOf(evs, typ); len(got) != 0 {
			t.Errorf("unexpected %s events before the grace: %d", typ, len(got))
		}
	}
	// teardown itself is mandatory. the kill/reap it performs is what keeps
	// the clipped run from leaking a corpse.
	if cleaned := eventsOf(evs, "tree_cleaned"); len(cleaned) != 1 {
		t.Fatalf("tree_cleaned events = %d, want 1", len(cleaned))
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 || exited[0].Data["reason"] != "duration_elapsed" {
		t.Errorf("exited = %v, want duration_elapsed", exited)
	}
	checkGoroutines(t, baseline)
}
