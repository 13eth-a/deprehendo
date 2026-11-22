package simulator

import (
	"context"
	"testing"
	"time"
)

func TestProcessTreeCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, 0)
	pt := &ProcessTree{Settle: 500 * time.Millisecond, Between: 400 * time.Millisecond}
	start := time.Now()
	if err := pt.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("cycle took %s", elapsed)
	}

	evs := decodeEvents(t, out)

	recorded := eventsOf(evs, "tree_recorded")
	if len(recorded) != 1 {
		t.Fatalf("tree_recorded events = %d, want 1", len(recorded))
	}
	workerpid := int(recorded[0].Data["worker_pid"].(float64))
	if pgid, _ := recorded[0].Data["worker_pgid"].(float64); int(pgid) != workerpid {
		t.Errorf("worker_pgid = %v, want %d (Setpgid child is its own leader)", recorded[0].Data["worker_pgid"], workerpid)
	}

	// two branch kills, worker first (group), helper second (single process).
	kills := eventsOf(evs, "branch_killed")
	if len(kills) != 2 {
		t.Fatalf("branch_killed events = %d, want 2", len(kills))
	}
	if branch, _ := kills[0].Data["branch"].(string); branch != "worker" {
		t.Errorf("first branch_killed = %v, want worker", kills[0].Data["branch"])
	}
	if mode, _ := kills[0].Data["mode"].(string); mode != "process_group" {
		t.Errorf("worker branch kill mode = %v, want process_group", kills[0].Data["mode"])
	}
	if mode, _ := kills[1].Data["mode"].(string); mode != "single_process" {
		t.Errorf("helper branch kill mode = %v, want single_process", kills[1].Data["mode"])
	}

	// the survey is the point of the scenario: the group kill took the tasks
	// while the helper branch stayed untouched until its own kill.
	survey := eventsOf(evs, "branch_survey")
	if len(survey) != 2 {
		t.Fatalf("branch_survey events = %d, want 2 (group and pid kill)", len(survey))
	}
	if mode, _ := survey[0].Data["mode"].(string); mode != "process_group" {
		t.Errorf("first survey mode = %v, want process_group", survey[0].Data["mode"])
	}
	if gone, _ := survey[0].Data["tasks_gone"].(float64); int(gone) != 2 {
		t.Errorf("group survey tasks_gone = %v, want 2", survey[0].Data["tasks_gone"])
	}
	if alive, _ := survey[0].Data["helper_alive"].(bool); !alive {
		t.Errorf("worker group kill unexpectedly touched helper branch")
	}
	if mode, _ := survey[1].Data["mode"].(string); mode != "single_process" {
		t.Errorf("second survey mode = %v, want single_process", survey[1].Data["mode"])
	}
	if alive, _ := survey[1].Data["tasks_alive"].(float64); int(alive) != 2 {
		t.Errorf("pid-only kill left %v tasks alive, want 2", survey[1].Data["tasks_alive"])
	}
	if reparented, _ := survey[1].Data["tasks_reparented"].(float64); int(reparented) != 2 {
		t.Errorf("pid-only kill reparented %v tasks, want 2", survey[1].Data["tasks_reparented"])
	}

	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "cycle_complete" {
		t.Errorf("exit reason = %v, want cycle_complete", exited[0].Data["reason"])
	}

	// nothing survived: worker, helper, or any task.
	for _, key := range []string{"worker_task_pids", "helper_task_pids"} {
		if taskpids, ok := recorded[0].Data[key].([]any); ok {
			for _, raw := range taskpids {
				pid := int(raw.(float64))
				if !goneOrZombie(pid, 2*time.Second) {
					t.Errorf("task pid %d still visible after the cycle", pid)
				}
			}
		}
	}
	if !goneOrZombie(workerpid, 2*time.Second) {
		t.Errorf("worker pid %d still visible after the cycle", workerpid)
	}
	checkGoroutines(t, baseline)
}

func TestProcessTreeCancelMidCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// cancel after the tree is recorded but before the first branch kill.
		time.Sleep(700 * time.Millisecond)
		cancel()
	}()
	if err := (&ProcessTree{Settle: 5 * time.Second}).Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	evs := decodeEvents(t, out)
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 {
		t.Fatalf("exited events = %d, want 1", len(exited))
	}
	if reason, _ := exited[0].Data["reason"].(string); reason != "interrupted" {
		t.Errorf("exit reason = %v, want interrupted", exited[0].Data["reason"])
	}
	cleaned := eventsOf(evs, "tree_cleaned")
	if len(cleaned) != 1 {
		t.Fatalf("tree_cleaned events = %d, want 1 after cancellation", len(cleaned))
	}
	if still, _ := cleaned[0].Data["still_alive"].(float64); int(still) != 0 {
		t.Errorf("tree_cleaned still_alive = %v, want 0", cleaned[0].Data["still_alive"])
	}
	checkGoroutines(t, baseline)
}
