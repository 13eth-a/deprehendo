package tests

// End-to-end failure isolation (6.40): the tracer is unavailable, and the
// recorder must still record, trigger and save a valid bundle that states
// that tracing was unavailable. the bundle must never look like
// a complete trace stream that happened to see nothing.

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/trace"
)

type memoryIncidentWriter struct {
	mu    sync.Mutex
	saved []*incident.Incident
}

func (w *memoryIncidentWriter) Write(_ context.Context, i *incident.Incident) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.saved = append(w.saved, i)
	return "memory", nil
}

func (w *memoryIncidentWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.saved)
}

func (w *memoryIncidentWriter) first() *incident.Incident {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.saved) == 0 {
		return nil
	}
	return w.saved[0]
}

func TestRecorderContinuesWhenTracerIsUnavailable(t *testing.T) {
	writer := &memoryIncidentWriter{}

	// A tracer that cannot start: on linux the binary is missing, on other
	// platforms the supervisor's platform gate refuses first. both are the
	// degraded path (6.52/6.53), not an error.
	manager := trace.NewManager(trace.ManagerConfig{Binary: "/nonexistent/runopsy-trace"})

	capture, err := incident.NewCapture(incident.CaptureOptions{
		Window: incident.CaptureWindow{PreTrigger: 200 * time.Millisecond, PostTrigger: 50 * time.Millisecond},
		Writer: writer,
		TracingSource: func() incident.TraceReliability {
			return incident.TraceReliabilityFromHealth(manager.Health())
		},
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	pipeline := agent.NewIncidentPipeline(capture, slog.New(slog.NewTextHandler(io.Discard, nil)))

	var sampled atomic.Int64
	runtimeagent, err := agent.New(agent.Options{
		Interval:        20 * time.Millisecond,
		Window:          300 * time.Millisecond,
		Capacity:        32,
		DisableNetwork:  true,
		DisablePressure: true,
		DisableCgroups:  true, Capture: capture,
		OnSnapshot: func(s collector.Snapshot) {
			sampled.Add(1)
			pipeline.Observe(s)
		},
	})
	if err != nil {
		t.Fatalf("agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	agentdone := make(chan struct{})
	go func() { _ = runtimeagent.Run(ctx); close(agentdone) }()
	tracerdone := make(chan struct{})
	go func() { _ = manager.Run(ctx); close(tracerdone) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-tracerdone:
		case <-time.After(5 * time.Second):
			t.Error("tracer supervisor did not stop")
		}
		select {
		case <-agentdone:
		case <-time.After(5 * time.Second):
			t.Error("recorder did not stop")
		}
	})

	// the supervisor must publish a degraded state quickly; the recorder is
	// already sampling while it does.
	deadline := time.Now().Add(5 * time.Second)
	for manager.Health().State == "" {
		if !time.Now().Before(deadline) {
			t.Fatal("tracer supervisor never reported a state")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// the recorder must actually be sampling before the trigger, otherwise
	// "no snapshots" would just mean the test raced startup rather than that
	// tracing hurt recording.
	sampledeadline := time.Now().Add(10 * time.Second)
	for sampled.Load() < 3 {
		if !time.Now().Before(sampledeadline) {
			t.Fatalf("recorder produced only %d samples; cannot attribute missing snapshots to the tracer", sampled.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := pipeline.Trigger(incident.Trigger{Type: "manual"}); err != nil {
		t.Fatalf("trigger: %v", err)
	}

	deadline = time.Now().Add(15 * time.Second)
	for writer.count() == 0 {
		if !time.Now().Before(deadline) {
			t.Fatal("incident was never saved; the recorder did not survive the tracer failure")
		}
		time.Sleep(10 * time.Millisecond)
	}

	saved := writer.first()
	if saved == nil {
		t.Fatal("no incident saved")
	}
	if len(saved.Snapshots) == 0 {
		t.Error("saved incident has no snapshots; recording stopped with the tracer")
	}
	if len(saved.Events) == 0 {
		t.Error("saved incident has no events")
	}
	if saved.Tracing == nil {
		t.Fatal("saved incident has no tracing reliability metadata")
	}
	if saved.Tracing.State != string(trace.StateUnavailable) {
		t.Errorf("tracing state = %q, want %q", saved.Tracing.State, trace.StateUnavailable)
	}
	if saved.Tracing.Reason == "" {
		t.Error("tracing degradation carries no reason")
	}
	if saved.Tracing.EventsLost != 0 {
		t.Errorf("no session ever ran, yet %d events are reported lost", saved.Tracing.EventsLost)
	}
	if err := capture.Close(contextWithTimeout(t, 10*time.Second)); err != nil {
		t.Fatalf("capture close: %v", err)
	}
	pipeline.Close()
}

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// TestTraceReliabilityBeforeSupervisorStarts pins the startup race: an
// incident could finalize before the tracer supervisor reports its first
// state. an empty state is not a valid bundle state, so it must degrade to
// "unavailable" with a reason rather than produce an invalid incident.
func TestTraceReliabilityBeforeSupervisorStarts(t *testing.T) {
	got := incident.TraceReliabilityFromHealth(trace.Health{})
	if got.State != string(trace.StateUnavailable) {
		t.Fatalf("state = %q, want unavailable", got.State)
	}
	if got.Reason == "" {
		t.Error("a defaulted state must still explain itself")
	}
	if got.Backend != "" || got.EventsLost != 0 {
		t.Errorf("defaulted reliability invented backend/loss data: %+v", got)
	}
}
