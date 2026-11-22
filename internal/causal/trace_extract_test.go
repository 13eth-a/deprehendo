package causal

import (
	"testing"
	"time"

	"runopsy/internal/incident"
)

// TestTimelineConsumesMergedTraceEvents asserts the merged tracer stream
// (TRACE_PROCESS_* typed events produced by incident.Merge) becomes the same
// causal vocabulary the differ emits: subjects, wait status, group identity
// and provenance all intact. the kernel-direct provenance ref points at the
// bundle event, which is what the direct-vs-inferred report reads (6.33).
func TestTimelineConsumesMergedTraceEvents(t *testing.T) {
	base := baseStart()
	inc := &incident.Incident{
		CaptureStart: base,
		Metadata: incident.Metadata{Processes: []incident.ProcessMetadata{
			{PID: 4242, PGID: 77, Name: "worker"},
		}},
		Events: []incident.Event{
			{Type: incident.TraceProcessExec, Timestamp: base.Add(time.Second), PID: 4242, StartTicks: 900, Provenance: incident.ProvenanceTrace},
			{Type: incident.TraceProcessStopped, Timestamp: base.Add(2 * time.Second), PID: 4242, StartTicks: 900, Provenance: incident.ProvenanceTrace, CorroboratedBy: []string{incident.ProvenanceSnapshotDiff}},
			{Type: incident.TraceProcessResumed, Timestamp: base.Add(3 * time.Second), PID: 4242, StartTicks: 900, Provenance: incident.ProvenanceTrace},
			{Type: incident.TraceProcessExit, Timestamp: base.Add(4 * time.Second), PID: 4242, StartTicks: 900, ExitStatus: "signal:9", Provenance: incident.ProvenanceTrace},
			// facts with causal consumers (phase 6): a single-target send and
			// the kernel's victim-naming OOM record now enter the graph with
			// their identity and bundle provenance intact.
			{Type: incident.TraceSignalSent, Timestamp: base.Add(4 * time.Second), PID: 4242, StartTicks: 900, Signal: 9, SignalFact: "SIGNAL_SENT", Provenance: incident.ProvenanceTrace},
			{Type: incident.TraceOomKill, Timestamp: base.Add(4 * time.Second), PID: 4242, StartTicks: 900, Provenance: incident.ProvenanceTrace},
			{Type: "TRACE_EVENT_4242", Timestamp: base.Add(4 * time.Second), PID: 4242, Provenance: incident.ProvenanceTrace},
		},
	}
	tl := BuildTimeline(inc)
	if err := NewGraph(tl).Validate(); err != nil {
		t.Fatalf("graph with trace events invalid: %v", err)
	}

	want := []struct {
		eventType EventType
		pid       int
		ticks     int64
		subject   string
	}{
		{EventProcessStarted, 4242, 900, "4242@900"},
		{EventProcessStopped, 4242, 900, "4242@900"},
		{EventProcessResumed, 4242, 900, "4242@900"},
		{EventProcessExited, 4242, 900, "4242@900"},
	}
	if n := countType(tl, want[0].eventType) + countType(tl, EventProcessStopped) +
		countType(tl, EventProcessResumed) + countType(tl, EventProcessExited); n != 4 {
		t.Fatalf("trace events mapped into %d causal events, want 4", n)
	}
	for _, w := range want {
		members := graphEventsOf(tl, w.eventType)
		if len(members) != 1 {
			t.Fatalf("type %s appears %d times, want exactly one", w.eventType, len(members))
		}
		e := tl.Events[members[0]]
		if e.PID != w.pid || e.StartTicks != w.ticks {
			t.Errorf("%s identity = pid %d/StartTicks %d, want %d/%d", w.eventType, e.PID, e.StartTicks, w.pid, w.ticks)
		}
		if e.Subject.ID != w.subject || e.Subject.Kind != SubjectProcess {
			t.Errorf("%s subject = %s/%s, want process %s", w.eventType, e.Subject.Kind, e.Subject.ID, w.subject)
		}
	}
	for _, e := range tl.Events {
		if e.Type == EventProcessExited {
			if pid, _ := e.Data["pgid"].(int); pid != 77 {
				t.Errorf("trace exit pgid = %v, want 77 (facts must keep identity)", e.Data["pgid"])
			}
			if state, _ := e.Data["exit_state"].(string); state != "signal:9" {
				t.Errorf("trace exit exit_state = %q, want signal:9", e.Data["exit_state"])
			}
			found := false
			for _, s := range e.Provenance.Sources {
				if s.Kind == "event" && s.Ref == "3" {
					found = true
				}
			}
			if !found {
				t.Errorf("trace exit provenance %+v must cite bundle event index 3", e.Provenance.Sources)
			}
		}
	}
	if n := countType(tl, EventOOM); n != 1 {
		t.Errorf("kernel OOM record mapped into %d OOM_EVENTs, want exactly 1", n)
	}
	if n := countType(tl, EventSignalSent); n != 1 {
		t.Errorf("kernel send mapped into %d SIGNAL_SENT events, want exactly 1", n)
	}
	for _, e := range tl.Events {
		if e.Type != EventOOM {
			continue
		}
		if e.PID != 4242 || e.StartTicks != 900 {
			t.Errorf("OOM record identity = %d@%d, want 4242@900", e.PID, e.StartTicks)
		}
		if record, _ := e.Data["record"].(string); record != "oom_mark_victim" {
			t.Errorf("OOM record marker = %q, want oom_mark_victim", record)
		}
	}
}

// graphEventsOf returns event indices of one type in timeline order (the
// countType analogue for position-sensitive assertions).
func graphEventsOf(tl *Timeline, eventType EventType) []int {
	var out []int
	for i := range tl.Events {
		if tl.Events[i].Type == eventType {
			out = append(out, i)
		}
	}
	return out
}
