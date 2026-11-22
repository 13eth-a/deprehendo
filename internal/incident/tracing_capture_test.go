package incident

import (
	"errors"
	"testing"
	"time"
)

func TestStampsReliabilitySupply(t *testing.T) {
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{
		Window:   CaptureWindow{time.Second, 40 * time.Millisecond},
		Writer:   w,
		MaxBytes: 4096,
		TracingSource: func() TraceReliability {
			return TraceReliability{State: "active", Backend: "proc_connector", EventsLost: 2}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	c.Observe(sample(at.Add(-time.Second), 10))
	if _, err = c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	c.Observe(sample(at.Add(10*time.Millisecond), 10))
	time.Sleep(60 * time.Millisecond)
	waitCapture(t, c)
	got := w.incidents[len(w.incidents)-1]
	if got.Tracing == nil {
		t.Fatal("finalize did not stamp a tracing report")
	}
	if got.Tracing.State != "active" || got.Tracing.EventsLost != 2 || got.Tracing.Backend != "proc_connector" {
		t.Errorf("stamped report = %+v", got.Tracing)
	}
}

func TestStampsReliabilitySupplyFailingSource(t *testing.T) {
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{
		Window:        CaptureWindow{time.Second, 40 * time.Millisecond},
		Writer:        w,
		MaxBytes:      4096,
		TracingSource: func() TraceReliability { panic(errors.New("bad source")) },
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	c.Observe(sample(at.Add(-time.Second), 10))
	if _, err = c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	c.Observe(sample(at.Add(10*time.Millisecond), 10))
	time.Sleep(60 * time.Millisecond)
	waitCapture(t, c)
	st := c.Status()
	if st.State != Complete {
		t.Fatalf("capture failed from a bad tracing source: %+v", st)
	}
	if w.incidents[len(w.incidents)-1].Tracing != nil {
		t.Error("a failed source should leave no tracing section")
	}
}
