// checklist 7.47–7.49: the queue's states, the bounded retry policy and the
// offline-first guarantee (a cloud failure never costs the local incident).
package uploadqueue

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeUploader records calls and answers with a fixed outcome.
type fakeUploader struct {
	err   error
	url   string
	calls int
}

func (f *fakeUploader) Upload(context.Context, string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.url, nil
}

// writeBundle creates a stand-in incident file with content we can compare
// after drain attempts.
func writeBundle(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "incident.runopsy")
	content := []byte("bundle-bytes-that-must-not-change")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, content
}

// testQueue opens a queue with a controllable clock.
func testQueue(t *testing.T, policy Policy) (*Queue, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	clock := now
	q, err := Open(filepath.Join(t.TempDir(), "queue.json"), policy)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	q.Now = func() time.Time { return clock }
	return q, &clock
}

func TestDelayDoublesAndIsCapped(t *testing.T) {
	p := Policy{MaxAttempts: 8, BaseDelay: time.Second, MaxDelay: 10 * time.Second}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i, expected := range want {
		if got := p.Delay(i + 1); got != expected {
			t.Errorf("Delay(%d) = %v, want %v", i+1, got, expected)
		}
	}
	// A huge attempt number cannot overflow into a negative or unbounded wait.
	if got := p.Delay(500); got != 10*time.Second {
		t.Errorf("Delay(500) = %v, want the cap", got)
	}
}

func TestOfflineFirstKeepsBundleAndDefers(t *testing.T) {
	q, clock := testQueue(t, Policy{MaxAttempts: 3, BaseDelay: time.Minute, MaxDelay: time.Hour})
	path, content := writeBundle(t)
	if _, added, err := q.Enqueue(path); err != nil || !added {
		t.Fatalf("enqueue: added=%v err=%v", added, err)
	}

	// the cloud is unreachable (the offline-first test from 7.49).
	up := &fakeUploader{err: errors.New("dial tcp 127.0.0.1:1: connect: connection refused")}
	res, err := q.Drain(context.Background(), up)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if res.Attempted != 1 || res.Retrying != 1 || res.Uploaded != 0 {
		t.Fatalf("drain result = %+v", res)
	}
	if up.calls != 1 {
		t.Errorf("uploader calls = %d, want 1", up.calls)
	}
	// the incident is still there, byte for byte: the queue only read it.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("bundle is gone after a failed upload: %v", err)
	}
	if string(after) != string(content) {
		t.Fatal("the queue modified the bundle")
	}

	entries := q.Entries()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v", entries)
	}
	e := entries[0]
	if e.State != Pending || e.Attempts != 1 {
		t.Fatalf("entry = %+v, want pending after one attempt", e)
	}
	if want := clock.Add(time.Minute); !e.NextAttempt.Equal(want) {
		t.Errorf("next attempt = %v, want %v", e.NextAttempt, want)
	}
	if !strings.Contains(e.LastError, "connection refused") {
		t.Errorf("last error = %q", e.LastError)
	}
	if s := q.Summary(); s.Pending != 1 || s.Uploaded != 0 || s.Failed != 0 {
		t.Errorf("summary = %+v", s)
	}

	// not due yet: another drain does nothing and reports no attempt.
	res, err = q.Drain(context.Background(), up)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if res.Attempted != 0 || up.calls != 1 {
		t.Fatalf("a not-yet-due entry was retried early: %+v (calls %d)", res, up.calls)
	}

	// after the backoff the same entry is due again.
	*clock = e.NextAttempt
	if res, err = q.Drain(context.Background(), up); err != nil || res.Attempted != 1 {
		t.Fatalf("due drain = %+v, err %v", res, err)
	}
}

func TestBoundedRetriesEndFailedAndStop(t *testing.T) {
	q, clock := testQueue(t, Policy{MaxAttempts: 3, BaseDelay: time.Minute, MaxDelay: time.Hour})
	path, _ := writeBundle(t)
	if _, _, err := q.Enqueue(path); err != nil {
		t.Fatal(err)
	}
	up := &fakeUploader{err: errors.New("503 service unavailable")}

	for i := 1; i <= 3; i++ {
		if _, err := q.Drain(context.Background(), up); err != nil {
			t.Fatalf("drain %d: %v", i, err)
		}
		entries := q.Entries()
		if i < 3 {
			if entries[0].State != Pending || entries[0].Attempts != i {
				t.Fatalf("after attempt %d: %+v", i, entries[0])
			}
			*clock = entries[0].NextAttempt
			continue
		}
		if entries[0].State != Failed {
			t.Fatalf("after the last attempt: %+v, want failed", entries[0])
		}
		if entries[0].Attempts != 3 {
			t.Errorf("attempts = %d, want the 3-attempt budget", entries[0].Attempts)
		}
	}

	// the terminal state is terminal: no more calls, however long we wait.
	*clock = clock.Add(100 * time.Hour)
	res, err := q.Drain(context.Background(), up)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if res.Attempted != 0 || up.calls != 3 {
		t.Fatalf("a failed entry kept retrying: %+v (calls %d)", res, up.calls)
	}

	// the manual retry gives it a fresh budget (7.48).
	if n, err := q.Retry(); err != nil || n != 1 {
		t.Fatalf("retry = %d, %v", n, err)
	}
	if e := q.Entries()[0]; e.State != Pending || e.Attempts != 0 {
		t.Fatalf("after retry: %+v", e)
	}
}

func TestSuccessIsRecordedOnce(t *testing.T) {
	q, _ := testQueue(t, DefaultPolicy())
	path, _ := writeBundle(t)
	if _, _, err := q.Enqueue(path); err != nil {
		t.Fatal(err)
	}
	up := &fakeUploader{url: "https://app.test/incidents/inc_1"}
	res, err := q.Drain(context.Background(), up)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if res.Uploaded != 1 {
		t.Fatalf("result = %+v", res)
	}
	e := q.Entries()[0]
	if e.State != Uploaded || e.URL != "https://app.test/incidents/inc_1" {
		t.Fatalf("entry = %+v", e)
	}
	if e.Attempts != 0 || !e.NextAttempt.IsZero() {
		t.Errorf("uploaded entry kept retry state: %+v", e)
	}
	// A second drain does not re-upload.
	if _, err := q.Drain(context.Background(), up); err != nil {
		t.Fatal(err)
	}
	if up.calls != 1 {
		t.Errorf("uploader calls = %d, want 1", up.calls)
	}
}

func TestEnqueueIsIdempotentAndSurvivesReopen(t *testing.T) {
	q, _ := testQueue(t, DefaultPolicy())
	path, _ := writeBundle(t)
	if _, added, err := q.Enqueue(path); err != nil || !added {
		t.Fatalf("first enqueue: %v %v", added, err)
	}
	if _, added, err := q.Enqueue(path); err != nil || added {
		t.Fatalf("second enqueue of the same path added a duplicate: %v %v", added, err)
	}
	if n := len(q.Entries()); n != 1 {
		t.Fatalf("entries = %d, want 1", n)
	}

	// A new process sees the same queue (the state is on disk).
	reopened, err := Open(q.Path(), DefaultPolicy())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	entries := reopened.Entries()
	if len(entries) != 1 || entries[0].Path != path || entries[0].State != Pending {
		t.Fatalf("reopened queue = %+v", entries)
	}
}

func TestMissingBundleFailsTerminallyWithoutUploading(t *testing.T) {
	q, _ := testQueue(t, DefaultPolicy())
	path, _ := writeBundle(t)
	if _, _, err := q.Enqueue(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	up := &fakeUploader{url: "https://app.test/incidents/inc_1"}
	res, err := q.Drain(context.Background(), up)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if up.calls != 0 {
		t.Fatalf("a missing bundle was uploaded %d times", up.calls)
	}
	if res.Failed != 1 {
		t.Fatalf("result = %+v", res)
	}
	e := q.Entries()[0]
	if e.State != Failed || !strings.Contains(e.LastError, "not readable") {
		t.Fatalf("entry = %+v", e)
	}
}

func TestQueueFileIsPrivateAndVersioned(t *testing.T) {
	q, _ := testQueue(t, DefaultPolicy())
	path, _ := writeBundle(t)
	if _, _, err := q.Enqueue(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(q.Path())
	if err != nil {
		t.Fatalf("queue file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("queue file permissions = %04o, want 0600", perm)
	}

	// an unknown version is refused, never silently reset: the file may
	// describe uploads this build does not understand.
	future := filepath.Join(t.TempDir(), "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(future, DefaultPolicy()); err == nil {
		t.Fatal("a queue from a newer version was opened")
	}
}

func TestQueueRefusesToGrowPastItsBound(t *testing.T) {
	q, _ := testQueue(t, DefaultPolicy())
	q.maxItems = 2
	for i := 0; i < 2; i++ {
		path, _ := writeBundle(t)
		if _, _, err := q.Enqueue(path); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	path, _ := writeBundle(t)
	if _, _, err := q.Enqueue(path); err == nil || !strings.Contains(err.Error(), "drain or clear") {
		t.Fatalf("full queue error = %v", err)
	}
}

func TestEnqueueRejectsUnreadablePath(t *testing.T) {
	q, _ := testQueue(t, DefaultPolicy())
	if _, _, err := q.Enqueue(filepath.Join(t.TempDir(), "absent.runopsy")); err == nil {
		t.Fatal("an absent bundle was queued")
	}
	if _, _, err := q.Enqueue(t.TempDir()); err == nil {
		t.Fatal("a directory was queued")
	}
	if n := len(q.Entries()); n != 0 {
		t.Fatalf("entries = %d, want none", n)
	}
}
