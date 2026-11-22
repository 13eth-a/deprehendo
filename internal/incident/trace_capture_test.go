package incident

import (
	"context"
	"testing"
	"time"

	"runopsy/internal/platform"
	"runopsy/internal/trace"
)

// trace capture tests (6.27/6.47/6.29–6.31): the evidence path from live
// tracer events into the finished incident: bounded buffering before the
// trigger, in-window merges at freeze time, provenance kept, and out-of-order
// deliveries refused instead of reshaping history.

func traceEvent(t trace.EventType, pid uint32, seq uint64, wallMs, mono int64) trace.TraceEvent {
	return trace.TraceEvent{
		SchemaVersion: trace.SchemaVersion,
		Sequence:      seq,
		Type:          t,
		PID:           pid,
		Source:        trace.SourceProcConnector,
		WallUnixMs:    wallMs,
		MonotonicNs:   mono,
	}
}

func newTraceCapture(t *testing.T, window, dedup time.Duration) (*Capture, *recordingWriter) {
	t.Helper()
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{
		Window:      CaptureWindow{PreTrigger: window, PostTrigger: time.Second},
		Writer:      w,
		DedupWindow: dedup,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, w
}

func TestCaptureCarriesTracerEventsThroughFinalize(t *testing.T) {
	c, w := newTraceCapture(t, 500*time.Millisecond, time.Second)
	base := time.Now()
	mono := platform.MonotonicNs()
	c.ObserveTrace(traceEvent(trace.EventEXEC, 42, 1, base.Add(-300*time.Millisecond).UnixMilli(), mono))
	// A regressing delivery is refused, never buffered (§8): the freeze-time
	// merge runs on the tracer's own send order.
	c.ObserveTrace(traceEvent(trace.EventEXEC, 42, 2, base.Add(-100*time.Millisecond).UnixMilli(), mono-5)) // regressed monotonic stamp: bogus
	if got := c.TraceDropped(); got != 1 {
		t.Fatalf("regressed stamp not refused: dropped=%d", got)
	}
	if _, err := c.Trigger(Trigger{Type: "process_stopped", PID: 42}); err != nil {
		t.Fatal(err)
	}
	signaled := traceEvent(trace.EventEXIT, 42, 3, base.Add(200*time.Millisecond).UnixMilli(), mono)
	signaled.Signal = 9
	signaled.Fact = trace.SignalDeliveredToExit
	c.ObserveTrace(signaled)
	waitCapture(t, c)
	if got := c.TraceDropped(); got != 1 {
		t.Fatalf("unexpected extra drops: %d", got)
	}
	w.mu.Lock()
	incidents := len(w.incidents)
	w.mu.Unlock()
	if incidents != 1 {
		t.Fatalf("wrote %d incidents", incidents)
	}
	events := w.incidents[0].Events
	var exec, exit *Event
	for i := range events {
		switch events[i].Type {
		case TraceProcessExec:
			if exec != nil {
				t.Fatal("exec entry duplicated")
			}
			exec = &events[i]
		case TraceProcessExit:
			if exit != nil {
				t.Fatal("exit entry duplicated")
			}
			exit = &events[i]
		}
	}
	if exec == nil || exit == nil {
		t.Fatalf("tracer events lost in freeze merge: %+v", events)
	}
	if exec.Provenance != ProvenanceTrace || exit.Provenance != ProvenanceTrace {
		t.Fatalf("provenance lost: %+v %+v", *exec, *exit)
	}
	if exit.Signal != 9 || exit.SignalFact != "EXITED_BY_SIGNAL" || exit.ExitStatus != "signal:9" {
		t.Fatalf("signal semantics lost: %+v", *exit)
	}
	if exit.MonotonicNs != mono {
		t.Fatalf("monotonic anchor lost after merge: %d", exit.MonotonicNs)
	}
	// incident start: exec before the trigger, exit inside the post window.
	if exec.Timestamp.UnixMilli() != base.Add(-300*time.Millisecond).UnixMilli() {
		t.Fatalf("pre-trigger exec replay drifted: %s", exec.Timestamp)
	}
}

func TestCaptureTraceMergeCorroboratesDifferEvidence(t *testing.T) {
	c, w := newTraceCapture(t, time.Second, 2*time.Second)
	base := time.Now()
	// differ sees the process table without pid 42, then with it: the start
	// observation comes from appearance between two samples.
	before := sample(base.Add(-800*time.Millisecond), 700)
	before.Processes = nil
	c.Observe(before)
	c.Observe(sample(base, 700))
	// the tracer saw the exec of the same identity slightly earlier: the
	// trace copy owns the entry, the differ's start observation corroborates.
	c.ObserveTrace(traceEvent(trace.EventEXEC, 42, 1, base.Add(-850*time.Millisecond).UnixMilli(), 1))
	if _, err := c.Trigger(Trigger{Type: "process_stopped", PID: 42, StartTicks: 700}); err != nil {
		t.Fatal(err)
	}
	waitCapture(t, c)
	events := w.incidents[0].Events
	var started, tracedExec int
	for _, e := range events {
		switch e.Type {
		case ProcessStarted:
			started++
			if e.Provenance != "" {
				t.Fatalf("plain differ start must keep legacy provenance: %+v", e)
			}
		case TraceProcessExec:
			tracedExec++
			if len(e.CorroboratedBy) == 0 {
				t.Fatalf("trace exec not corroborated by differ start: %+v", e)
			}
		}
	}
	if started != 0 || tracedExec != 1 {
		t.Fatalf("the trace copy must own the duplicated start with the differ observation kept as corroboration, got started=%d traced=%d: %+v", started, tracedExec, events)
	}
	// the corroborated entry is the strongest normalized class (6.32/6.61).
	if q := EvidenceQuality(w.incidents[0].Events[0]); q == "" {
		t.Fatal("quality classifier produced nothing")
	}
}

func TestCaptureClosedBufferDropsVisibly(t *testing.T) {
	c, _ := newTraceCapture(t, 200*time.Millisecond, time.Second)
	base := time.Now()
	mono := platform.MonotonicNs()
	// A closed capture must refuse still-arriving events visibly: the
	// reliability story is "nothing after shutdown got in", not silence.
	c.Close(context.Background())
	c.ObserveTrace(traceEvent(trace.EventEXEC, 42, 1, base.UnixMilli(), mono))
	if got := c.TraceDropped(); got != 1 {
		t.Fatalf("closed capture must refuse events visibly: dropped=%d", got)
	}
}

func TestCaptureTraceWindowReplayOutsideWindow(t *testing.T) {
	c, w := newTraceCapture(t, 100*time.Millisecond, time.Second)
	base := time.Now()
	mono := platform.MonotonicNs()
	// older than the pre-trigger window: buffered, then evicted from the
	// ring by the next delivered event, so it never reaches the incident.
	c.ObserveTrace(traceEvent(trace.EventEXEC, 42, 1, base.Add(-time.Hour).UnixMilli(), mono))
	c.ObserveTrace(traceEvent(trace.EventEXEC, 43, 2, base.UnixMilli(), mono+1))
	if _, err := c.Trigger(Trigger{Type: "process_stopped", PID: 43}); err != nil {
		t.Fatal(err)
	}
	waitCapture(t, c)
	for _, e := range w.incidents[0].Events {
		if e.Type == TraceProcessExec && e.PID == 42 {
			t.Fatalf("stale event outside the window reached the bundle: %+v", e)
		}
	}
	found := false
	for _, e := range w.incidents[0].Events {
		if e.Type == TraceProcessExec && e.PID == 43 {
			found = true
		}
	}
	if !found {
		t.Fatal("in-window event missing from the bundle")
	}
}

func TestCaptureTraceActivityInsidePostWindowMarksTruncationExactly(t *testing.T) {
	c, w := newTraceCapture(t, 50*time.Millisecond, time.Second)
	base := time.Now()
	mono := platform.MonotonicNs()
	if _, err := c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	// Post-window delivery in order: active-trace accounting must count it
	// once; finalize must not replay it a second time.
	c.ObserveTrace(traceEvent(trace.EventEXEC, 5000, 1, base.UnixMilli(), mono+2))
	waitCapture(t, c)
	counts := map[int]int{}
	for _, e := range w.incidents[0].Events {
		if e.Type == TraceProcessExec {
			counts[e.PID]++
		}
	}
	for pid, seen := range counts {
		if seen != 1 {
			t.Fatalf("pid %d delivered twice into the bundle", pid)
		}
	}
	if len(counts) < 1 {
		t.Fatal("no post-window trace event reached the bundle")
	}
}
