package incident

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
)

func terminalCapture(t *testing.T, c *Capture, id string) CaptureStatus {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, ok := c.StatusFor(id)
		if ok && (status.State == Complete || status.State == Failed) {
			return status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("capture %s did not complete: %+v", id, c.Status())
	return CaptureStatus{}
}
func TestCaptureRetainsBoundedPerIDResults(t *testing.T) {
	c, err := NewCapture(CaptureOptions{Writer: &recordingWriter{}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for range 20 {
		id, err := c.Trigger(Trigger{Type: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if got := terminalCapture(t, c, id); got.State != Complete || got.Path != "saved" {
			t.Fatal(got)
		}
	}
	for n, id := range ids {
		got, ok := c.StatusFor(id)
		if ok != (n >= 4) {
			t.Fatalf("status index %d present=%v", n, ok)
		}
		if ok && got.State != Complete {
			t.Fatal(got)
		}
	}
	if _, ok := c.StatusFor(""); ok {
		t.Fatal("empty ID matched")
	}
	waitCapture(t, c)
}
func TestCaptureRetainsPublishedPathOnFailure(t *testing.T) {
	c, err := NewCapture(CaptureOptions{Writer: &recordingWriter{err: errors.New("directory sync failed")}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Trigger(Trigger{Type: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	got := terminalCapture(t, c, id)
	if got.State != Failed || got.Path != "saved" || got.Error == "" {
		t.Fatalf("lost partial publication: %+v", got)
	}
	if err := c.Close(context.Background()); err == nil {
		t.Fatal("failed write hidden")
	}
}
func TestCaptureCanceledCloseCanBeWaitedAgain(t *testing.T) {
	w := &recordingWriter{release: make(chan struct{})}
	c, err := NewCapture(CaptureOptions{Writer: w, Window: CaptureWindow{time.Second, time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	c.Observe(sample(time.Now().Add(-time.Millisecond), 10))
	if _, err = c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = c.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close=%v", err)
	}
	if _, err = c.Trigger(Trigger{Type: "manual"}); err == nil {
		t.Fatal("closed capture accepted trigger")
	}
	close(w.release)
	waitCapture(t, c)
	if len(w.incidents) != 1 || !w.incidents[0].Truncated {
		t.Fatal("partial capture missing")
	}
	if err := Validate(w.incidents[0]); err != nil {
		t.Fatal(err)
	}
}
func TestCaptureReportsPrehistoryLossAndRejectsReplay(t *testing.T) {
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{Writer: w, Window: CaptureWindow{time.Minute, 0}, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Second)
	for n := range 20 {
		c.Observe(sample(at.Add(time.Duration(n)*time.Millisecond), 10))
	}
	oversized := sample(at.Add(30*time.Millisecond), 10)
	oversized.Processes[0].Name = strings.Repeat("x", 8192)
	c.Observe(oversized)
	// replaying a formerly dropped timestamp must not enter retained history.
	replay := sample(oversized.Timestamp, 11)
	c.Observe(replay)
	id, err := c.Trigger(Trigger{Type: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	terminalCapture(t, c, id)
	waitCapture(t, c)
	got := w.incidents[0]
	if !got.Truncated {
		t.Fatal("prehistory eviction/drop not reported")
	}
	for _, s := range got.Snapshots {
		if s.Timestamp.Equal(replay.Timestamp) {
			t.Fatal("dropped timestamp replay accepted")
		}
	}
	if err := Validate(got); err != nil {
		t.Fatal(err)
	}
}
func TestCaptureWriterMutationDoesNotChangeNextCapture(t *testing.T) {
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{Writer: w, Window: CaptureWindow{time.Minute, 0}})
	if err != nil {
		t.Fatal(err)
	}
	c.Observe(sample(time.Now().Add(-time.Millisecond), 10))
	id, _ := c.Trigger(Trigger{Type: "manual"})
	terminalCapture(t, c, id)
	w.mu.Lock()
	w.incidents[0].Snapshots[0].Processes[0].Name = "writer mutation"
	w.mu.Unlock()
	id, _ = c.Trigger(Trigger{Type: "manual"})
	terminalCapture(t, c, id)
	waitCapture(t, c)
	if w.incidents[1].Snapshots[0].Processes[0].Name == "writer mutation" {
		t.Fatal("writer aliases capture history")
	}
}
func TestCaptureRecordBudgetDropsOversizedSample(t *testing.T) {
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{Writer: w, Window: CaptureWindow{time.Minute, 0}})
	if err != nil {
		t.Fatal(err)
	}
	c.Observe(collector.Snapshot{Timestamp: time.Now().Add(-time.Millisecond), Metrics: make([]collector.CollectorTiming, MaxEvidenceRecords/2)})
	id, _ := c.Trigger(Trigger{Type: "manual"})
	terminalCapture(t, c, id)
	waitCapture(t, c)
	got := w.incidents[0]
	if !got.Truncated || len(got.Snapshots) != 0 {
		t.Fatalf("oversized records retained: %d", len(got.Snapshots))
	}
	if err := Validate(got); err != nil {
		t.Fatal(err)
	}
}
