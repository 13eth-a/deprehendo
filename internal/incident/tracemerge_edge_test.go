package incident

import (
	"testing"
	"time"
)

// edge cases for the trace/polling merge (6.31, contract §9.1). the existing
// tests cover the basic pairing; these pin the boundaries and the counting
// invariant a diagnosis relies on: a merge may reorder evidence but never
// invents, duplicates or silently drops it.

var mergeT0 = time.Unix(1_800_000_000, 0)

func pollEv(typ string, pid int, start int64, at time.Time) Event {
	return Event{Type: typ, PID: pid, StartTicks: start, Timestamp: at, Provenance: ProvenanceSnapshotDiff}
}

func traceEv(typ string, pid int, start int64, at time.Time) Event {
	return Event{Type: typ, PID: pid, StartTicks: start, Timestamp: at, Provenance: ProvenanceTrace}
}

// countBy tallies merged events by type; used by the counting invariants.
func countBy(evs []Event) map[string]int {
	m := map[string]int{}
	for _, e := range evs {
		m[e.Type]++
	}
	return m
}

// the window is inclusive at its edge and exclusive beyond it.
func TestMergeWindowBoundary(t *testing.T) {
	w := DefaultDedupWindow
	at := mergeT0.Add(10 * time.Second)

	edge := Merge([]Event{pollEv(ProcessExited, 42, 7, at)},
		[]Event{traceEv(TraceProcessExit, 42, 7, at.Add(w))}, w)
	if len(edge) != 1 {
		t.Fatalf("exactly at the window must merge: got %d events", len(edge))
	}

	beyond := Merge([]Event{pollEv(ProcessExited, 42, 7, at)},
		[]Event{traceEv(TraceProcessExit, 42, 7, at.Add(w+time.Nanosecond))}, w)
	if len(beyond) != 2 {
		t.Fatalf("beyond the window must stay separate: got %d events", len(beyond))
	}
}

// one polling event may corroborate at most one tracer event. A second
// tracer exit of the same PID must not reuse the consumed polling record.
func TestMergeConsumesEachPollingEventOnce(t *testing.T) {
	at := mergeT0
	poll := []Event{pollEv(ProcessExited, 42, 7, at)}
	traced := []Event{
		traceEv(TraceProcessExit, 42, 7, at),
		traceEv(TraceProcessExit, 42, 7, at.Add(100*time.Millisecond)),
	}
	out := Merge(poll, traced, 0)
	if len(out) != 2 {
		t.Fatalf("two tracer exits + one polling exit must yield two events, got %d", len(out))
	}
	corroborated := 0
	for _, e := range out {
		if len(e.CorroboratedBy) > 0 {
			corroborated++
		}
	}
	if corroborated != 1 {
		t.Fatalf("exactly one tracer event may be corroborated, got %d", corroborated)
	}
}

// counting invariant: every input is either kept or consumed as corroboration
// by exactly one partner. nothing appears from nowhere, nothing vanishes.
func TestMergeNeverInventsOrLosesEvidence(t *testing.T) {
	at := mergeT0
	poll := []Event{
		pollEv(ProcessStarted, 1, 10, at),
		pollEv(ProcessExited, 1, 10, at.Add(time.Second)),
		pollEv(ProcessExited, 2, 20, at.Add(time.Second)),
		pollEv(ProcessStarted, 3, 30, at.Add(time.Minute)),
	}
	traced := []Event{
		traceEv(TraceProcessExec, 1, 10, at),
		traceEv(TraceProcessExit, 1, 10, at.Add(time.Second)),
		traceEv(TraceProcessExit, 9, 90, at.Add(time.Second)), // unmatched
	}
	out := Merge(poll, traced, 0)
	// 4 polling + 3 traced = 7 inputs. matched pairs: (ProcessStarted 1),
	// (ProcessExited 1). each pair collapses to one output event: 7 - 2 = 5.
	if len(out) != 5 {
		t.Fatalf("want 5 merged events, got %d: %v", len(out), countBy(out))
	}
	got := countBy(out)
	if got[TraceProcessExit] != 2 || got[TraceProcessExec] != 1 {
		t.Fatalf("tracer events must all survive as owners: %v", got)
	}
	if got[ProcessExited] != 1 || got[ProcessStarted] != 1 {
		t.Fatalf("only the unmatched polling exit of pid 2 and pid 3's start may remain: %v", got)
	}
}

// distinct non-zero identities never merge, even with the same PID and an
// overlapping time: that is PID reuse, and it must stay two facts.
func TestMergeNeverPairsAcrossPIDReuse(t *testing.T) {
	at := mergeT0
	out := Merge(
		[]Event{pollEv(ProcessExited, 42, 111, at)},
		[]Event{traceEv(TraceProcessExit, 42, 222, at)}, 0)
	if len(out) != 2 {
		t.Fatalf("reused PID with a different identity merged: %v", countBy(out))
	}
}

// contract §9.1: a zero start time on one side (identity unknown, for
// example a process that exited before the tracer could read /proc) pairs
// only when the known identity's observed lifetime covers the event time
// (§4). with no such evidence the pair stays two facts, with the
// disagreement recorded as a conflict on both events.
func TestMergeUnknownIdentityWithoutCoverageStaysTwoFacts(t *testing.T) {
	at := mergeT0
	out := Merge(
		[]Event{pollEv(ProcessExited, 42, 0, at)},
		[]Event{traceEv(TraceProcessExit, 42, 222, at)}, 0)
	if len(out) != 2 {
		t.Fatalf("unknown-identity pair merged silently: %v", countBy(out))
	}
	for _, e := range out {
		if !hasConflict(e, ConflictIdentityUncovered) {
			t.Fatalf("missing uncovered conflict on %s: %+v", e.Type, e.Conflicts)
		}
	}
}

// the positive control for the same rule: the polling stream proves the
// known identity was seen alive at or before the event (started one second
// earlier, not yet observed to exit), so a zero-start trace exit may merge.
// here the differ exit itself carries the unknown start (identity unreadable
// in its snapshot); the tracer knows the identity.
func TestMergeZeroIdentityPairsUnderObservedCoverage(t *testing.T) {
	at := mergeT0
	polling := []Event{
		pollEv(ProcessStarted, 42, 7, at.Add(-time.Second)),
		pollEv(ProcessExited, 42, 0, at),
	}
	out := Merge(polling, []Event{traceEv(TraceProcessExit, 42, 7, at)}, 0)
	if len(out) != 2 {
		t.Fatalf("covered pair must merge with the poll start kept: %v", countBy(out))
	}
	var m *Event
	for i := range out {
		if out[i].Type == TraceProcessExit {
			m = &out[i]
		}
	}
	if m == nil {
		t.Fatalf("trace exit missing: %+v", out)
	}
	if len(m.CorroboratedBy) == 0 || len(m.Conflicts) != 0 {
		t.Fatalf("merged entry must be corroborated and conflict-free: %+v", *m)
	}
}

// A known identity whose exit was already observed before the trace event is
// dead at the event time: its lifetime does not cover the event, so the
// pairing with an unknown-identity record is refused. the observed exit sits
// outside the dedup window here, so it is not itself a merge candidate.
func TestMergeZeroIdentityRefusedWhenIdentityAlreadyExit(t *testing.T) {
	at := mergeT0
	polling := []Event{
		pollEv(ProcessStarted, 42, 7, at.Add(-4*time.Second)),
		pollEv(ProcessExited, 42, 7, at.Add(-3*time.Second)),
		pollEv(ProcessExited, 42, 0, at),
	}
	out := Merge(polling, []Event{traceEv(TraceProcessExit, 42, 7, at)}, 0)
	if len(out) != 4 {
		t.Fatalf("exited identity must not cover the event: %v", countBy(out))
	}
	var tagged bool
	for _, e := range out {
		tagged = tagged || hasConflict(e, ConflictIdentityUncovered)
	}
	if !tagged {
		t.Fatalf("refusal must be recorded as a conflict")
	}
}

// two identities of the same PID started no later than the event: the
// unknown-side event could belong to either, so nothing merges and the
// ambiguity is the recorded conflict.
func TestMergeUnknownIdentityAmbiguousUnderPIDReuse(t *testing.T) {
	at := mergeT0
	polling := []Event{
		pollEv(ProcessStarted, 42, 7, at.Add(-2*time.Second)),
		pollEv(ProcessExited, 42, 7, at.Add(-time.Second)),
		pollEv(ProcessStarted, 42, 9, at),
		pollEv(ProcessExited, 42, 0, at),
	}
	out := Merge(polling, []Event{traceEv(TraceProcessExit, 42, 222, at)}, 0)
	if len(out) != 5 {
		t.Fatalf("ambiguous unknown identity must stay a separate fact: %v", countBy(out))
	}
	var traceEvents int
	haveambiguous, havemismatch := false, false
	for _, e := range out {
		if e.Type == TraceProcessExit {
			traceEvents++
			haveambiguous = haveambiguous || hasConflict(e, ConflictIdentityAmbiguous)
			havemismatch = havemismatch || hasConflict(e, ConflictIdentityMismatch)
		}
	}
	if traceEvents != 1 || !haveambiguous || !havemismatch {
		t.Fatalf("ambiguity and the earlier identity's mismatch must both be recorded: %+v", out)
	}
}

func hasConflict(e Event, tag string) bool {
	for _, c := range e.Conflicts {
		if c == tag {
			return true
		}
	}
	return false
}

// both sides unknown, but the polling stream saw the PID reused inside the
// window: two identities could own the event, so it stays two facts with
// the ambiguity recorded (§9.1). with one observed identity, or none, the
// PID-and-time pairing still stands.
func TestMergeBothUnknownRefusedWhenPollingSawPIDReuse(t *testing.T) {
	at := mergeT0.Add(20 * time.Second)
	w := DefaultDedupWindow
	reused := []Event{
		pollEv(ProcessStarted, 42, 100, at.Add(-5*time.Second)),
		pollEv(ProcessExited, 42, 100, at.Add(-500*time.Millisecond)),
		pollEv(ProcessStarted, 42, 200, at.Add(300*time.Millisecond)),
		pollEv(ProcessExited, 42, 0, at.Add(100*time.Millisecond)),
	}
	got := Merge(reused, []Event{traceEv(TraceProcessExit, 42, 0, at)}, w)
	// nothing merges: two polling exits and the tracer exit all survive.
	if n := countBy(got)[ProcessExited] + countBy(got)[TraceProcessExit]; n != 3 {
		t.Fatalf("ambiguous pair merged: %d exit facts in %+v", n, got)
	}
	for _, e := range got {
		if e.Type == TraceProcessExit {
			if len(e.CorroboratedBy) != 0 {
				t.Fatalf("tracer exit was corroborated across a PID reuse: %+v", e)
			}
			if !hasConflict(e, ConflictIdentityAmbiguous) {
				t.Fatalf("tracer exit lacks the ambiguity record: %+v", e)
			}
		}
		if e.Type == ProcessExited && e.StartTicks == 0 && !hasConflict(e, ConflictIdentityAmbiguous) {
			t.Fatalf("unknown polling exit lacks the ambiguity record: %+v", e)
		}
	}

	// no reuse observed: the unknown pair merges as before.
	single := []Event{pollEv(ProcessExited, 42, 0, at.Add(100*time.Millisecond))}
	if got := Merge(single, []Event{traceEv(TraceProcessExit, 42, 0, at)}, w); len(got) != 1 {
		t.Fatalf("unknown pair without reuse evidence must merge: %+v", got)
	}
}

// merge sorts its own copies: the caller's slices keep their order.
func TestMergeLeavesInputsUnchanged(t *testing.T) {
	at := mergeT0.Add(30 * time.Second)
	traced := []Event{
		traceEv(TraceProcessExit, 9, 1, at.Add(time.Second)),
		traceEv(TraceProcessExec, 9, 1, at),
	}
	polling := []Event{
		pollEv(ProcessExited, 9, 1, at.Add(time.Second)),
		pollEv(ProcessStarted, 9, 1, at),
	}
	_ = Merge(polling, traced, DefaultDedupWindow)
	if traced[0].Type != TraceProcessExit || polling[0].Type != ProcessExited {
		t.Fatalf("Merge reordered its inputs: traced=%v polling=%v", traced[0].Type, polling[0].Type)
	}
}
