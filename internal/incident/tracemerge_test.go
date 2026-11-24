package incident

import (
	"testing"
	"time"

	"deprehendo/internal/trace"
)

// tracer helpers ------------------------------------------------------------

func traceExec(seq uint64, pid uint32, atMs int64) trace.TraceEvent {
	return trace.TraceEvent{
		SchemaVersion: trace.SchemaVersion,
		Sequence:      seq,
		MonotonicNs:   atMs * 1_000_000,
		WallUnixMs:    atMs,
		Type:          trace.EventEXEC,
		PID:           pid,
	}
}

func traceExit(seq uint64, pid uint32, code int, atMs int64) trace.TraceEvent {
	c := int32(code)
	return trace.TraceEvent{
		SchemaVersion: trace.SchemaVersion,
		Sequence:      seq,
		MonotonicNs:   atMs * 1_000_000,
		WallUnixMs:    atMs,
		Type:          trace.EventEXIT,
		PID:           pid,
		ExitCode:      &c,
	}
}

func pollStarted(atMs int64, pid int, start int64) Event {
	return Event{Timestamp: time.UnixMilli(atMs), Type: ProcessStarted, PID: pid, StartTicks: start}
}

func pollExited(atMs int64, pid int, start int64) Event {
	return Event{Timestamp: time.UnixMilli(atMs), Type: ProcessExited, PID: pid, StartTicks: start, ExitStatus: "signal:9"}
}

func zeroT() time.Time {
	return time.UnixMilli(1767000000000)
}

func TestFromTraceConvertsExecAndExit(t *testing.T) {
	ev := FromTrace(traceExec(1, 42, 1000), ProvenanceTrace)
	if ev.Type != TraceProcessExec || ev.PID != 42 || ev.Provenance != ProvenanceTrace {
		t.Fatalf("exec conversion: %+v", ev)
	}
	if !ev.Timestamp.Equal(time.UnixMilli(1000)) {
		t.Fatalf("timestamp: %v", ev.Timestamp)
	}
	// exit(0) must be preserved as a real status, not confused with unknown.
	got := FromTrace(traceExit(2, 42, 0, 1100), ProvenanceTrace)
	if got.ExitStatus != "exit:0" || got.Type != TraceProcessExit {
		t.Fatalf("exit-0 conversion: %+v", got)
	}
	// A kernel-signaled death arrives as fact+signal with no exit code
	// (cn_proc wait-status semantics; see the rust proc_connector backend).
	signaled := traceExit(3, 42, 0, 1200)
	signaled.ExitCode = nil
	signaled.Signal = 9
	signaled.Fact = trace.SignalDeliveredToExit
	sig := FromTrace(signaled, ProvenanceTrace)
	if sig.ExitStatus != "signal:9" || sig.SignalFact != "EXITED_BY_SIGNAL" {
		t.Fatalf("signaled exit conversion: %+v", sig)
	}
}

// TestFromTraceKeepsSignalSentAddressing: a SIGNAL_SENT's sender and the
// group it addressed survive into the timeline (contract §3.3, §3.4 "Y sent
// S"). before, FromTrace kept only the target PID, so a group send read as
// "PID 0" and no send said who sent it.
func TestFromTraceKeepsSignalSentAddressing(t *testing.T) {
	one := trace.TraceEvent{
		SchemaVersion: trace.SchemaVersion, Sequence: 1, MonotonicNs: 1, WallUnixMs: 1000,
		Type: trace.EventSIGNAL, PID: 4140, Signal: 15, Fact: trace.SignalSent, SenderPID: 4132,
	}
	ev := FromTrace(one, ProvenanceTrace)
	if ev.PID != 4140 || ev.SenderPID != 4132 || ev.TargetPGID != 0 || ev.SignalFact != "SIGNAL_SENT" {
		t.Fatalf("single-target send: %+v", ev)
	}
	group := one
	group.PID, group.PGID = 0, 77
	ev = FromTrace(group, ProvenanceTrace)
	if ev.PID != 0 || ev.TargetPGID != 77 || ev.SenderPID != 4132 {
		t.Fatalf("group send: %+v", ev)
	}
	// A subject's own pgid on a non-SENT event is not an addressed group.
	stop := trace.TraceEvent{
		SchemaVersion: trace.SchemaVersion, Sequence: 2, MonotonicNs: 2, WallUnixMs: 1000,
		Type: trace.EventSTOP, PID: 9, PGID: 9,
	}
	if ev := FromTrace(stop, ProvenanceTrace); ev.TargetPGID != 0 || ev.SenderPID != 0 {
		t.Fatalf("stop event gained addressing: %+v", ev)
	}
}

func TestFromTraceNormalizesUnknownType(t *testing.T) {
	te := traceExec(9, 7, 500)
	te.Type = trace.EventType(99)
	ev := FromTrace(te, ProvenanceTraceReplay)
	if got, want := ev.Type, "TRACE_EVENT_99"; got != want {
		t.Fatalf("unknown type label: got %q want %q (forward-compatible, never dropped)", got, want)
	}
	if !validEvent(ev.Type) {
		t.Fatalf("unknown-type label must remain validation-clean for bundles")
	}
}

func TestMergePrefersTraceEvidenceAndCorroborates(t *testing.T) {
	// the differ sees a poll-wide exit ~1s after the kernel saw the real
	// one. the timeline keeps ONE exit entry: the tracer's, with the differ
	// recorded as corroboration underneath (6.30/6.31).
	base := zeroT()
	traced := []Event{FromTrace(traceExit(5, 42, 0, base.UnixMilli()), ProvenanceTrace)}
	polling := []Event{pollExited(base.Add(time.Second).UnixMilli(), 42, 0)}

	merged := Merge(polling, traced, DefaultDedupWindow)
	if len(merged) != 1 {
		t.Fatalf("dedup failed: %d events, %+v", len(merged), merged)
	}
	m := merged[0]
	if m.Type != TraceProcessExit || m.Provenance != ProvenanceTrace {
		t.Fatalf("tracer copy must own the normalized entry: %+v", m)
	}
	if len(m.CorroboratedBy) != 1 || m.CorroboratedBy[0] != ProvenanceSnapshotDiff {
		t.Fatalf("differ evidence must survive as corroboration: %+v", m.CorroboratedBy)
	}
	// the polling record itself is preserved under the merged entry: it was
	// not deleted (6.30). model that by checking quality classification.
	if q := EvidenceQuality(m); q != "direct_corroborated" {
		t.Fatalf("quality: %q", q)
	}
}

func TestMergeKeepsUnmatchedPollingEvidence(t *testing.T) {
	base := zeroT()
	polling := []Event{pollStarted(base.UnixMilli(), 42, 3), pollExited(base.Add(2*time.Second).UnixMilli(), 99, 4)}
	traced := []Event{FromTrace(traceExec(1, 7, base.Add(5*time.Minute).UnixMilli()), ProvenanceTrace)}
	merged := Merge(polling, traced, DefaultDedupWindow)
	if len(merged) != 3 {
		t.Fatalf("unmatched events must all survive: %d", len(merged))
	}
	types := map[string]int{}
	for _, e := range merged {
		types[e.Type]++
		if e.CorroboratedBy != nil {
			t.Fatalf("no corroboration expected: %+v", e)
		}
	}
	if types[ProcessStarted] != 1 || types[ProcessExited] != 1 || types[TraceProcessExec] != 1 {
		t.Fatalf("mix wrong: %+v", types)
	}
}

func TestMergeRejectsIdentityMismatch(t *testing.T) {
	// when both sides know start ticks, a different-ticks PID (reuse) must
	// NOT dedupe, even within the time window.
	base := zeroT()
	polling := []Event{pollExited(base.UnixMilli(), 42, 1000)}
	traced := []Event{FromTrace(traceExit(1, 42, 3, base.Add(100*time.Millisecond).UnixMilli()), ProvenanceTrace)}
	traced[0].StartTicks = 2000
	merged := Merge(polling, traced, time.Second)
	if len(merged) != 2 {
		t.Fatalf("PID-reuse pair must stay distinct: %+v", merged)
	}
}

func TestMergeOrdersByTimeThenMonotonic(t *testing.T) {
	base := zeroT()
	traced := []Event{
		FromTrace(traceExec(1, 42, base.Add(300*time.Millisecond).UnixMilli()), ProvenanceTrace),
		FromTrace(traceExit(2, 42, 0, base.Add(time.Second).UnixMilli()), ProvenanceTrace),
	}
	// Out-of-window differ events keep their timeline slots; the in-window
	// pair dedupes underneath the tracer entries.
	polling := []Event{
		pollStarted(base.Add(-5*time.Minute).UnixMilli(), 42, 0),
		pollExited(base.Add(-4*time.Minute).UnixMilli(), 42, 0),
		pollStarted(base.UnixMilli(), 42, 0),
	}
	merged := Merge(polling, traced, DefaultDedupWindow)
	if len(merged) != 4 {
		t.Fatalf("merge count: %d (%+v)", len(merged), merged)
	}
	want := []string{ProcessStarted, ProcessExited, TraceProcessExec, TraceProcessExit}
	for i, w := range want {
		if merged[i].Type != w {
			t.Fatalf("order[%d]=%q want %q; %+v", i, merged[i].Type, w, merged)
		}
	}
}

func TestMergeCorroboratesStartsToo(t *testing.T) {
	base := zeroT()
	traced := []Event{FromTrace(traceExec(1, 42, base.UnixMilli()), ProvenanceTrace)}
	polling := []Event{pollStarted(base.Add(500*time.Millisecond).UnixMilli(), 42, 0)}
	merged := Merge(polling, traced, DefaultDedupWindow)
	if len(merged) != 1 || merged[0].Type != TraceProcessExec {
		t.Fatalf("exec dedup: %+v", merged)
	}
	if len(merged[0].CorroboratedBy) != 1 {
		t.Fatalf("missing corroboration: %+v", merged[0].CorroboratedBy)
	}
	if q := EvidenceQuality(merged[0]); q != "direct_corroborated" {
		t.Fatalf("quality: %q", q)
	}
}

func TestEvidenceQualityClasses(t *testing.T) {
	plain := pollStarted(1, 1, 0)
	if q := EvidenceQuality(plain); q != "snapshot_derived" {
		t.Fatalf("plain differ event: %q", q)
	}
	direct := FromTrace(traceExec(1, 1, 1), ProvenanceTrace)
	if q := EvidenceQuality(direct); q != "direct_kernel" {
		t.Fatalf("tracer event: %q", q)
	}
	if q := EvidenceQuality(FromTrace(traceExec(1, 1, 1), ProvenanceTraceReplay)); q != "direct_kernel" {
		t.Fatalf("replayed tracer event must keep direct quality: %q", q)
	}
}
