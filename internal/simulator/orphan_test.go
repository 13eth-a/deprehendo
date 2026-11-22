package simulator

import (
	"context"
	"testing"
	"time"
)

func TestOrphanProcessCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real children")
	}
	simBinary(t)
	baseline := goroutines()

	cfg, out := newTestConfig(t, 0)
	start := time.Now()
	if err := (&OrphanProcess{Tasks: 2, Grace: 400 * time.Millisecond}).Run(context.Background(), cfg); err != nil {
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
	taskpids, ok := recorded[0].Data["task_pids"].([]any)
	if !ok || len(taskpids) != 2 {
		t.Fatalf("tree_recorded task_pids = %v, want two PIDs", recorded[0].Data["task_pids"])
	}
	workerpid := int(recorded[0].Data["worker_pid"].(float64))

	reaped := eventsOf(evs, "worker_reaped")
	if len(reaped) != 1 {
		t.Fatalf("worker_reaped events = %d, want 1", len(reaped))
	}
	if code, _ := reaped[0].Data["exit_code"].(float64); int(code) != 137 {
		t.Errorf("worker exit_code = %v, want 137", reaped[0].Data["exit_code"])
	}

	reports := eventsOf(evs, "orphan_report")
	if len(reports) != 2 {
		t.Fatalf("orphan_report events = %d, want 2", len(reports))
	}
	for _, r := range reports {
		if alive, _ := r.Data["alive"].(bool); !alive {
			t.Errorf("orphan %v did not survive the worker kill", r.Data["task_pid"])
		}
		if observed, _ := r.Data["observed"].(bool); !observed {
			t.Errorf("orphan %v not observable after worker kill", r.Data["task_pid"])
		}
		if ppidafter, _ := r.Data["ppid_after"].(float64); int(ppidafter) == workerpid {
			t.Errorf("orphan %v still reports dead worker as parent", r.Data["task_pid"])
		}
		if pgid, _ := r.Data["pgid"].(float64); int(pgid) != workerpid {
			t.Errorf("orphan %v pgid=%v, want %d", r.Data["task_pid"], r.Data["pgid"], workerpid)
		}
	}
	summary := eventsOf(evs, "orphan_summary")
	if len(summary) != 1 {
		t.Fatalf("orphan_summary events = %d, want 1", len(summary))
	}
	if alive, _ := summary[0].Data["tasks_alive"].(float64); int(alive) != 2 {
		t.Errorf("tasks_alive = %v, want 2", summary[0].Data["tasks_alive"])
	}
	if reparented, _ := summary[0].Data["tasks_reparented"].(float64); int(reparented) != 2 {
		t.Errorf("tasks_reparented = %v, want 2", summary[0].Data["tasks_reparented"])
	}

	cleaned := eventsOf(evs, "tree_cleaned")
	if len(cleaned) != 1 {
		t.Fatalf("tree_cleaned events = %d, want 1", len(cleaned))
	}
	if still, _ := cleaned[0].Data["still_alive"].(float64); int(still) != 0 {
		t.Errorf("still_alive = %v, want 0", cleaned[0].Data["still_alive"])
	}
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 || exited[0].Data["reason"] != "cycle_complete" {
		t.Errorf("exited = %v, want cycle_complete", exited)
	}
	assertWorkerGone(t, workerpid)
	checkGoroutines(t, baseline)
}

func TestOrphanProcessCancelCleansChildren(t *testing.T) {
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
	if err := (&OrphanProcess{Tasks: 2, Grace: 5 * time.Second}).Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	evs := decodeEvents(t, out)
	exited := eventsOf(evs, "exited")
	if len(exited) != 1 || exited[0].Data["reason"] != "interrupted" {
		t.Fatalf("exited = %v, want interrupted", exited)
	}
	cleaned := eventsOf(evs, "tree_cleaned")
	if len(cleaned) != 1 {
		t.Fatalf("tree_cleaned events = %d, want 1", len(cleaned))
	}
	if still, _ := cleaned[0].Data["still_alive"].(float64); int(still) != 0 {
		t.Errorf("still_alive = %v after cancellation, want 0", cleaned[0].Data["still_alive"])
	}
	checkGoroutines(t, baseline)
}
