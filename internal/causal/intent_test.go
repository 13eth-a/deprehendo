package causal

import (
	"testing"
	"time"
)

// TestIntentCoverMakesCoveredExitContext asserts 5.25 / T3: a process exit
// inside an intent's window is CONTEXT, not a failure anchor.
func TestIntentCoverMakesCoveredExitContext(t *testing.T) {
	base := baseStart()
	exit := baseEvent(EventProcessExited, base.Add(5*time.Second), processSubject(42, 900), map[string]any{"exit_state": "signalled"})
	exit.PID, exit.StartTicks = 42, 900
	g := graphFrom(t, []Event{exit})
	g.SetIntentCovers([]IntentCover{{
		Processes: []ProcessIdentity{{PID: 42, StartTicks: 900}},
		From:      base.Add(4 * time.Second),
		Until:     base.Add(35 * time.Second),
	}})
	if anchors := g.failureAnchors(); len(anchors) != 0 {
		t.Fatalf("covered exit produced %d failure anchors, want 0", len(anchors))
	}
}

// TestIntentCoverCoversGroupTermination: a cancelled job's worker tree is
// killed as one process group. when every member of that group is covered by
// the cancel intent, the derived PROCESS_GROUP_TERMINATED is context too, not a
// failure anchor.
func TestIntentCoverCoversGroupTermination(t *testing.T) {
	base := baseStart()
	var exits []Event
	for _, pid := range []int{42, 43} {
		e := baseEvent(EventProcessExited, base.Add(5*time.Second), processSubject(pid, 900), map[string]any{"exit_state": "signalled"})
		e.PID, e.StartTicks, e.PGID = pid, 900, 77
		exits = append(exits, e)
	}
	g := graphFrom(t, exits)
	g.SetIntentCovers([]IntentCover{{
		Processes: []ProcessIdentity{{PID: 42, StartTicks: 900}, {PID: 43, StartTicks: 900}},
		From:      base.Add(4 * time.Second),
		Until:     base.Add(35 * time.Second),
	}})
	if anchors := g.failureAnchors(); len(anchors) != 0 {
		t.Fatalf("covered group produced %d failure anchors, want 0", len(anchors))
	}
}

// TestIntentCoverExpiresAfterWindow asserts the same exit 31 s after the
// intent, outside the cancellation grace window, keeps its failure anchor.
func TestIntentCoverExpiresAfterWindow(t *testing.T) {
	base := baseStart()
	intent := base
	exit := baseEvent(EventProcessExited, intent.Add(31*time.Second), processSubject(42, 900), map[string]any{"exit_state": "signalled"})
	exit.PID, exit.StartTicks = 42, 900
	g := graphFrom(t, []Event{exit})
	g.SetIntentCovers([]IntentCover{{
		Processes: []ProcessIdentity{{PID: 42, StartTicks: 900}},
		From:      intent.Add(-time.Second),
		Until:     intent.Add(30 * time.Second),
	}})
	if anchors := g.failureAnchors(); len(anchors) != 1 {
		t.Fatalf("exit past the window produced %d failure anchors, want 1", len(anchors))
	}
}

// TestRunnerTreeCoverCoversTheUntaggedGroup: a runner self-update (B3,
// 2026-11-02) ends the listener's whole process group, but the section can only
// role-tag the supervisor; the job's processes left behind are never tagged.
// the cover names the supervisor, so its group is intended, while an exit in a
// different group stays a failure anchor.
func TestRunnerTreeCoverCoversTheUntaggedGroup(t *testing.T) {
	base := baseStart()
	supervisor := baseEvent(EventProcessExited, base.Add(40*time.Second), processSubject(240130, 6850539), map[string]any{"exit_state": "signalled"})
	supervisor.PID, supervisor.StartTicks, supervisor.PGID = 240130, 6850539, 240116
	untagged := baseEvent(EventProcessExited, base.Add(41*time.Second), processSubject(250626, 14105993), map[string]any{"exit_state": "signalled"})
	untagged.PID, untagged.StartTicks, untagged.PGID = 250626, 14105993, 240116
	group := baseEvent(EventProcessGroupTerminated, base.Add(41*time.Second), groupSubject(240116), map[string]any{"pgid": 240116})
	group.PGID = 240116
	group.ProcessIDs = []ProcessIdentity{{PID: 240130, StartTicks: 6850539}, {PID: 250626, StartTicks: 14105993}}
	unrelated := baseEvent(EventProcessExited, base.Add(42*time.Second), processSubject(77, 1), map[string]any{"exit_state": "signalled"})
	unrelated.PID, unrelated.StartTicks, unrelated.PGID = 77, 1, 88

	g := graphFrom(t, []Event{supervisor, untagged, group, unrelated})
	g.SetIntentCovers([]IntentCover{{
		Processes:  []ProcessIdentity{{PID: 240130, StartTicks: 6850539}},
		From:       base.Add(39 * time.Second),
		Until:      base.Add(80 * time.Second),
		RunnerTree: true,
	}})
	for _, id := range g.failureAnchors() {
		e := g.Get(id)
		if e.PGID == 240116 {
			t.Errorf("runner update left failure anchor %s on group member %d", e.Type, e.PID)
		}
	}
	if anchors := g.failureAnchors(); len(anchors) != 1 || g.Get(anchors[0]).PGID != 88 {
		t.Fatalf("anchors = %+v, want only the exit in the other group", anchors)
	}
}

// TestIntentCoverIgnoresOtherProcesses asserts a cover never removes an
// anchor for a process it does not name.
func TestIntentCoverIgnoresOtherProcesses(t *testing.T) {
	base := baseStart()
	exit := baseEvent(EventProcessExited, base.Add(5*time.Second), processSubject(77, 1), map[string]any{"exit_state": "signalled"})
	exit.PID, exit.StartTicks = 77, 1
	g := graphFrom(t, []Event{exit})
	g.SetIntentCovers([]IntentCover{{
		Processes: []ProcessIdentity{{PID: 42, StartTicks: 900}},
		From:      base,
		Until:     base.Add(30 * time.Second),
	}})
	if anchors := g.failureAnchors(); len(anchors) != 1 {
		t.Fatalf("uncovered exit produced %d failure anchors, want 1", len(anchors))
	}
}
