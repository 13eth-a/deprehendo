package main

import (
	"testing"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

func TestIntentCoversWindowAndContradiction(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	intent := provider.GenericEvent{
		Kind:      provider.GenericTerminationIntended,
		Intent:    provider.IntentCancelled,
		Process:   &evidence.ProcessRef{PID: 42, StartTicks: 900},
		Timestamp: at,
	}
	interp := provider.Interpretation{Generic: []provider.GenericEvent{intent}}

	covers := intentCovers([]provider.Interpretation{interp})
	if len(covers) != 1 {
		t.Fatalf("covers = %d, want 1", len(covers))
	}
	c := covers[0]
	if !c.From.Equal(at.Add(-time.Second)) || !c.Until.Equal(at.Add(30*time.Second)) {
		t.Fatalf("window = [%v, %v], want 1 s before to 30 s grace after", c.From, c.Until)
	}

	// T4: a TERMINATION_INTENT conflict in the section removes the cover.
	contradicted := interp
	contradicted.Section.Conflicts = []evidence.Conflict{{Question: "TERMINATION_INTENT"}}
	if got := intentCovers([]provider.Interpretation{contradicted}); len(got) != 0 {
		t.Fatalf("contradicted intent kept %d covers, want 0", len(got))
	}
}

// A stated SUCCEEDED job covers its worker and job tree, so the normal end of
// a job is not a process-group kill. A stated failure covers nothing.
func TestIntentCoversJobSucceededCoversWorkerTree(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	section := evidence.Section{ProcessRoles: []evidence.ProcessRole{
		{Process: evidence.ProcessRef{PID: 10, StartTicks: 1}, Role: evidence.RoleSupervisor, Runner: "runner-a"},
		{Process: evidence.ProcessRef{PID: 11, StartTicks: 2}, Role: evidence.RoleWorker, Runner: "runner-a", Worker: "worker-1"},
		{Process: evidence.ProcessRef{PID: 12, StartTicks: 3}, Role: evidence.RoleJobRoot, Runner: "runner-a", Worker: "worker-1"},
		{Process: evidence.ProcessRef{PID: 13, StartTicks: 4}, Role: evidence.RoleJobProcess, Runner: "runner-a", Worker: "worker-1"},
	}}
	intent := provider.GenericEvent{
		Kind:      provider.GenericTerminationIntended,
		Intent:    provider.IntentJobSucceeded,
		Runner:    "runner-a",
		Worker:    "worker-1",
		Timestamp: at,
	}
	covers := intentCovers([]provider.Interpretation{{Section: section, Generic: []provider.GenericEvent{intent}}})
	if len(covers) != 1 {
		t.Fatalf("covers = %d, want 1", len(covers))
	}
	got := map[int]bool{}
	for _, p := range covers[0].Processes {
		got[p.PID] = true
	}
	for _, pid := range []int{11, 12, 13} {
		if !got[pid] {
			t.Errorf("pid %d not covered by a stated success: %v", pid, got)
		}
	}
	if got[10] {
		t.Errorf("supervisor covered by a job success: %v", got)
	}
}

// the runner writes the SUCCEEDED line only after the worker has exited, so a
// normal exit can precede the line by many seconds. the cover must reach back
// past that exit.
func TestIntentCoversJobSucceededReachesBackToWorkerExit(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	section := evidence.Section{ProcessRoles: []evidence.ProcessRole{
		{Process: evidence.ProcessRef{PID: 11, StartTicks: 2}, Role: evidence.RoleWorker, Runner: "runner-a", Worker: "worker-1"},
	}}
	intent := provider.GenericEvent{
		Kind:      provider.GenericTerminationIntended,
		Intent:    provider.IntentJobSucceeded,
		Runner:    "runner-a",
		Worker:    "worker-1",
		Timestamp: at,
	}
	covers := intentCovers([]provider.Interpretation{{Section: section, Generic: []provider.GenericEvent{intent}}})
	if len(covers) != 1 {
		t.Fatalf("covers = %d, want 1", len(covers))
	}
	exitedat := at.Add(-20 * time.Second)
	if exitedat.Before(covers[0].From) || exitedat.After(covers[0].Until) {
		t.Fatalf("worker exit at %v outside cover [%v, %v]", exitedat, covers[0].From, covers[0].Until)
	}
}

// §10A.5: a runner-level CANCELLED covers the runner's worker and job tree,
// limited to the intent's worker, but not the supervisor or another runner.
func TestIntentCoversResolvesRunnerJobTree(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	intent := provider.GenericEvent{
		Kind:      provider.GenericTerminationIntended,
		Intent:    provider.IntentCancelled,
		Runner:    "runner-a",
		Worker:    "worker-1",
		Timestamp: at,
	}
	section := evidence.Section{ProcessRoles: []evidence.ProcessRole{
		{Process: evidence.ProcessRef{PID: 10, StartTicks: 1}, Role: evidence.RoleSupervisor, Runner: "runner-a"},
		{Process: evidence.ProcessRef{PID: 11, StartTicks: 2}, Role: evidence.RoleWorker, Runner: "runner-a", Worker: "worker-1"},
		{Process: evidence.ProcessRef{PID: 12, StartTicks: 3}, Role: evidence.RoleJobRoot, Runner: "runner-a", Worker: "worker-1"},
		{Process: evidence.ProcessRef{PID: 13, StartTicks: 4}, Role: evidence.RoleJobProcess, Runner: "runner-a", Worker: "worker-1"},
		{Process: evidence.ProcessRef{PID: 14, StartTicks: 5}, Role: evidence.RoleJobProcess, Runner: "runner-a", Worker: "worker-2"},
		{Process: evidence.ProcessRef{PID: 20, StartTicks: 6}, Role: evidence.RoleJobRoot, Runner: "runner-b", Worker: "worker-3"},
	}}
	covers := intentCovers([]provider.Interpretation{{Section: section, Generic: []provider.GenericEvent{intent}}})
	if len(covers) != 1 {
		t.Fatalf("covers = %d, want 1", len(covers))
	}
	got := map[int]bool{}
	for _, p := range covers[0].Processes {
		got[p.PID] = true
	}
	for _, pid := range []int{11, 12, 13} {
		if !got[pid] {
			t.Errorf("pid %d not covered: %v", pid, got)
		}
	}
	for _, pid := range []int{10, 14, 20} {
		if got[pid] {
			t.Errorf("pid %d wrongly covered: %v", pid, got)
		}
	}

	// A shutdown covers the runner's whole tree: the supervisor that received
	// it, its worker and that worker's job processes (B3: a runner self-update
	// took its tree down and the uncovered job exits looked like a group kill).
	intent.Intent = provider.IntentServiceShutdown
	covers = intentCovers([]provider.Interpretation{{Section: section, Generic: []provider.GenericEvent{intent}}})
	if len(covers) != 1 {
		t.Fatalf("shutdown covers = %d, want 1", len(covers))
	}
	got = map[int]bool{}
	for _, p := range covers[0].Processes {
		got[p.PID] = true
	}
	for _, pid := range []int{10, 11, 12, 13} {
		if !got[pid] {
			t.Errorf("shutdown did not cover pid %d: %v", pid, got)
		}
	}
	for _, pid := range []int{14, 20} {
		if got[pid] {
			t.Errorf("shutdown covered another worker's or runner's process %d: %v", pid, got)
		}
	}
}
