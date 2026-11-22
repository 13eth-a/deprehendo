package incident

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"runopsy/internal/trace"
)

// phase 6 merger (6.29–6.32): merge the polling-derived event stream with
// the kernel-tracer stream into one timeline.
//
// rules carried over from the phase plan:
//   - provenance is preserved on every event (6.29): polling events keep the
//     empty legacy provenance; tracer events carry ProvenanceTrace;
//   - stronger evidence never deletes weaker evidence (6.30): when a tracer
//     event and a snapshot-differ event describe the same underlying
//     lifecycle observation, the tracer event owns the normalized timeline
//     entry and the differ source is recorded under CorroboratedBy;
//   - the timeline never shows the same exit (or start) twice (6.31);
//   - evidence quality is queryable per event (6.32) via EvidenceQuality.

// provenance values for Event.Provenance.
const (
	// ProvenanceTrace marks direct kernel-tracer evidence.
	ProvenanceTrace = "rust_trace"
	// ProvenanceSnapshotDiff marks snapshot-derived evidence; this value
	// appears only inside CorroboratedBy after merge (the legacy field
	// stays empty for plain differ output).
	ProvenanceSnapshotDiff = "process_snapshot_diff"
	// ProvenanceTraceReplay marks events decoded from a recorded trace file
	// (6.45), used by replay tooling and fixtures.
	ProvenanceTraceReplay = "trace_replay"
)

// Merge-conflict vocabulary (contract §9.1): why a same-PID, same-kind pair
// inside the dedup window was kept as two facts instead of being merged.
// closed set; event validation enforces it.
const (
	// ConflictIdentityMismatch: both sides know a start time and they
	// differ. distinct processes.
	ConflictIdentityMismatch = "merge_identity_mismatch"
	// ConflictIdentityUncovered: one side's identity is unknown and the
	// polling stream provides no coverage evidence for the known
	// identity's observed lifetime at the event time (§4).
	ConflictIdentityUncovered = "merge_identity_uncovered"
	// ConflictIdentityAmbiguous: another identity of the same PID also
	// started no later than the event, so the unknown-side event could
	// belong to more than one process.
	ConflictIdentityAmbiguous = "merge_identity_ambiguous"
)

func validMergeConflict(c string) bool {
	switch c {
	case ConflictIdentityMismatch, ConflictIdentityUncovered, ConflictIdentityAmbiguous:
		return true
	}
	return false
}

// normalized tracer event type constants live in model.go, next to the
// legacy differ vocabulary they merge with.

// DefaultDedupWindow bounds how close a tracer event and a polling event
// must be, on the wall clock, to be considered the same underlying event
// (6.31). one polling sample period is the practical ceiling; the default is
// deliberately generous to tolerate snapshot timestamp rounding.
const DefaultDedupWindow = 2 * time.Second

// FromTrace converts one wire event to a timeline event that carries its
// provenance. unknown trace event types are preserved under a labelled
// normalized name, never dropped.
func FromTrace(te trace.TraceEvent, provenance string) Event {
	e := Event{
		Timestamp:   time.UnixMilli(te.WallUnixMs),
		Type:        "TRACE_" + te.Type.String(),
		PID:         int(te.PID),
		StartTicks:  te.StartTicks,
		Provenance:  provenance,
		MonotonicNs: te.MonotonicNs,
	}
	if te.Signal != 0 {
		e.Signal = int(te.Signal)
		switch te.Fact {
		case trace.SignalSent:
			e.SignalFact = "SIGNAL_SENT"
			e.SenderPID = int(te.SenderPID)
			if te.PID == 0 {
				e.TargetPGID = int(te.PGID)
			}
		case trace.SignalObservedStop:
			e.SignalFact = "OBSERVED_STOP"
		case trace.SignalDeliveredToExit:
			e.SignalFact = "EXITED_BY_SIGNAL"
			e.ExitStatus = "signal:" + strconv.Itoa(int(te.Signal))
		default:
			e.SignalFact = "UNKNOWN"
		}
	} else if te.ExitCode != nil {
		e.ExitStatus = "exit:" + strconv.Itoa(int(*te.ExitCode))
	}
	switch te.Type {
	case trace.EventEXEC:
		e.Type = TraceProcessExec
	case trace.EventEXIT:
		e.Type = TraceProcessExit
	default:
		// te.Type.String() already renders the forward-compatible
		// TRACE_EVENT_<n> label for unknown numbers (6.57): preserved, not
		// dropped, and still validation-clean for bundles.
		e.Type = te.Type.String()
	}
	return e
}

// merge implements contract §9.1: a trace event and a differ event are the
// same underlying lifecycle observation only when their identities are
// compatible (§4); otherwise both are kept and the disagreement is recorded
// as a conflict on both events. the tracer copy still wins ownership when a
// pair merges, the differ source surviving underneath as corroboration
// (6.30/6.31). ordering is by timestamp, then monotonic reading.
//
// §4 identity rule, as far as the merged streams can evaluate it. equal PIDs
// with two known, different start times are different processes. when one
// side carries no start time (a tracer that could not read /proc, or a
// differ record with an unknown identity), the pair matches only when the
// known identity's observed lifetime (what the polling stream itself saw)
// covers the event time: seen alive at or before the event, and no other
// identity for that PID started before it. A zero-and-known pair with no
// coverage evidence is no longer merged on PID and time alone: it is kept as
// two facts with a recorded merge_identity_* conflict. the §9.1 snapshot
// interval (read start / read end bounds) is approximated here by the
// dedup window, because differ events no longer carry their bounding
// snapshot times; the identity rule is the stronger half of §9.1 and is
// enforced exactly.
func Merge(polling, traced []Event, window time.Duration) []Event {
	if window <= 0 {
		window = DefaultDedupWindow
	}
	bytime := func(a, b Event) bool {
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		return a.MonotonicNs < b.MonotonicNs
	}
	// sort copies: the caller's slices (the capture's live trace buffer
	// among them) must not be reordered as a side effect of merging.
	traced = append([]Event(nil), traced...)
	polling = append([]Event(nil), polling...)
	sort.SliceStable(traced, func(i, j int) bool { return bytime(traced[i], traced[j]) })
	sort.SliceStable(polling, func(i, j int) bool { return bytime(polling[i], polling[j]) })

	// identity histories build from the polling stream itself: it is the
	// observation record of who was seen alive and when (§4, "the known
	// identity's observed lifetime").
	hist := observedIdentities(polling)

	// consumed[i] marks differ events already represented by a tracer entry.
	// conflicts are indexed per side: pollConflicts by polling index,
	// traceConflicts by traced index (the two index spaces are distinct).
	consumed := make([]bool, len(polling))
	corro := make(map[int][]string)
	pollconflicts := make(map[int][]string)
	traceconflicts := make(map[int][]string)

	for ti := range traced {
		t := traced[ti]
		var wantType string
		switch t.Type {
		case TraceProcessExec:
			wantType = ProcessStarted
		case TraceProcessExit:
			wantType = ProcessExited
		default:
			continue
		}
		for pi := range polling {
			if consumed[pi] {
				continue
			}
			p := polling[pi]
			if p.Type != wantType || p.PID != t.PID {
				continue
			}
			if p.Timestamp.Sub(t.Timestamp) > window || t.Timestamp.Sub(p.Timestamp) > window {
				continue
			}
			verdict := identityCompatible(t, p, hist, t.Timestamp, window)
			if verdict == "" {
				consumed[pi] = true
				by := append(corro[ti], ProvenanceSnapshotDiff)
				sort.Strings(by)
				corro[ti] = by
				break
			}
			// same PID, same kind, within the window, but the identities do
			// not reconcile: both facts kept, disagreement recorded (§9.1).
			// scanning continues: a later compatible partner still pairs.
			pollconflicts[pi] = appendConflicts(pollconflicts[pi], verdict)
			traceconflicts[ti] = appendConflicts(traceconflicts[ti], verdict)
		}
	}

	out := make([]Event, 0, len(polling)+len(traced))
	for pi := range polling {
		e := polling[pi]
		if !consumed[pi] {
			e.Conflicts = append([]string(nil), pollconflicts[pi]...)
			out = append(out, e)
		}
	}
	for ti := range traced {
		t := traced[ti]
		t.CorroboratedBy = corro[ti]
		t.Conflicts = append([]string(nil), traceconflicts[ti]...)
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return bytime(out[i], out[j]) })
	return out
}

// identLife is one nonzero identity of one PID as the polling stream observed
// it: firstT is the first observation time ("seen alive at or before"), exitT
// the observed exit (zero while still alive or only undetermined).
type identLife struct {
	start  int64
	firstT time.Time
	exitT  time.Time
}

// observedIdentities extracts, from the polling stream itself, which nonzero
// identities of each PID were observed and when. Zero-start records attribute
// to no identity and contribute nothing.
func observedIdentities(polling []Event) map[int][]identLife {
	m := make(map[int][]identLife)
	for i := range polling {
		e := polling[i]
		if e.StartTicks == 0 {
			continue
		}
		switch e.Type {
		case ProcessStarted, ProcessExited, ProcessStateChanged:
		default:
			continue
		}
		lives := m[e.PID]
		idx := -1
		for j := range lives {
			if lives[j].start == e.StartTicks {
				idx = j
				break
			}
		}
		if idx < 0 {
			m[e.PID] = append(m[e.PID], identLife{start: e.StartTicks, firstT: e.Timestamp})
			continue
		}
		l := &m[e.PID][idx]
		if e.Timestamp.Before(l.firstT) {
			l.firstT = e.Timestamp
		}
		if e.Type == ProcessExited && (l.exitT.IsZero() || e.Timestamp.After(l.exitT)) {
			l.exitT = e.Timestamp
		}
	}
	return m
}

// identityCompatible applies the §4 rule to one candidate pair. empty return
// means the pair may merge; a non-empty return is the conflict tag recording
// why it must stay two facts.
func identityCompatible(t, p Event, hist map[int][]identLife, eventT time.Time, window time.Duration) string {
	switch {
	case t.StartTicks == 0 && p.StartTicks == 0:
		// both sides unknown. the pair may stand on PID and time only when
		// the polling stream gives no reason to doubt it: if it observed two
		// or more identities of this PID within one window of the event, the
		// PID was reused there and either identity could own it (§9.1).
		if observedOwners(hist, t.PID, eventT, window) >= 2 {
			return ConflictIdentityAmbiguous
		}
		return ""
	case t.StartTicks != 0 && p.StartTicks != 0:
		if t.StartTicks == p.StartTicks {
			return ""
		}
		return ConflictIdentityMismatch
	default:
		known := t.StartTicks
		if known == 0 {
			known = p.StartTicks
		}
		return observedCovers(hist, t.PID, known, eventT, window)
	}
}

// observedCovers applies §4 to a pair whose known side is `known`: the event
// time must fall inside that identity's observed presence (from its first
// sighting relaxed by one dedup window (first observations are stamped after
// the fact; a differ start lands a sample after the kernel exec it
// corroborates) to its observed exit or open-ended) and no other identity
// of the same PID may plausibly own the event (none observed alive across
// it, none first seen within the window after it). empty string means merge;
// otherwise the conflict tag to record.
func observedCovers(hist map[int][]identLife, pid int, known int64, eventT time.Time, window time.Duration) string {
	covered, ambiguous := false, false
	for _, l := range hist[pid] {
		if l.start == known {
			if !l.firstT.Add(-window).After(eventT) && (l.exitT.IsZero() || !l.exitT.Before(eventT)) {
				covered = true
			}
			continue
		}
		aliveat := !l.firstT.After(eventT) && (l.exitT.IsZero() || !l.exitT.Before(eventT))
		bornsoonafter := l.firstT.After(eventT) && !l.firstT.Add(-window).After(eventT)
		if aliveat || bornsoonafter {
			ambiguous = true
		}
	}
	if ambiguous {
		return ConflictIdentityAmbiguous
	}
	if covered {
		return ""
	}
	return ConflictIdentityUncovered
}

// observedOwners counts the identities of pid the polling stream saw present
// within one window of eventT: first seen no later than eventT+window and not
// observed to exit before eventT-window.
func observedOwners(hist map[int][]identLife, pid int, eventT time.Time, window time.Duration) int {
	n := 0
	for _, l := range hist[pid] {
		if l.firstT.After(eventT.Add(window)) {
			continue
		}
		if !l.exitT.IsZero() && l.exitT.Before(eventT.Add(-window)) {
			continue
		}
		n++
	}
	return n
}

// appendConflicts keeps each conflict tag once, in sorted order, so the
// recorded reason is deterministic.
func appendConflicts(list []string, tag string) []string {
	for _, c := range list {
		if c == tag {
			return list
		}
	}
	list = append(list, tag)
	sort.Strings(list)
	return list
}

// validTraceEvent whitelist-extends validEvent with the forward-compatible
// TRACE_EVENT_* labels produced for unknown tracer event types. tracked
// prefixes, not raw strings: nothing arbitrary enters the whitelists.
func validTraceEvent(t string) bool {
	const prefix = "TRACE_EVENT_"
	if !strings.HasPrefix(t, prefix) {
		return false
	}
	_, err := strconv.Atoi(strings.TrimPrefix(t, prefix))
	return err == nil
}

// EvidenceQuality classifies one merged event's evidence (6.32). it is a
// helper for signatures and reports, not a universal ranking: each consumer
// decides how much a class is worth for its inference.
func EvidenceQuality(e Event) string {
	switch {
	case len(e.CorroboratedBy) > 0:
		// Kernel-direct evidence that an independent source agrees with; the
		// strongest normalized class (6.61 exposes these levels).
		return "direct_corroborated"
	case e.Provenance == ProvenanceTrace || e.Provenance == ProvenanceTraceReplay:
		return "direct_kernel"
	default:
		return "snapshot_derived"
	}
}
