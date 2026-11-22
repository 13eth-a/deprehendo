package incident

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
)

func fixture() *Incident {
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	return &Incident{SchemaVersion: 1, ID: "inc_0123456789abcdef0123456789abcdef", CreatedAt: at.Add(time.Second), TriggeredAt: at, CaptureStart: at.Add(-time.Second), CaptureEnd: at.Add(time.Second), Window: CaptureWindow{time.Second, time.Second}, Trigger: Trigger{Type: "manual"}, Metadata: Metadata{AgentVersion: AgentVersion, Host: LocalHost()}, Snapshots: []collector.Snapshot{sample(at.Add(-time.Second), 10), sample(at, 11), sample(at.Add(time.Second), 12)}, Events: []Event{{Timestamp: at, Type: IncidentTriggered}}}
}
func sample(at time.Time, start int64) collector.Snapshot {
	return collector.Snapshot{Timestamp: at, System: &collector.SystemSnapshot{ProcessCountAvailable: true, ProcessCount: 1, DiskFilesystem: "/private/token=SECRET"}, Processes: []collector.ProcessSnapshot{{Process: platform.Process{PID: 42, PPID: 1, StartTicks: start, Name: "token=SECRET", State: "S"}}}, Metrics: []collector.CollectorTiming{{Name: "connections"}}}
}
func encoded(t testing.TB, i *Incident, compressed bool) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Encode(&b, i, compressed); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestBundleRoundTripPrivacyAndDeterminism(t *testing.T) {
	i := fixture()
	i.Snapshots[0].Errors = []collector.CollectionError{{Collector: "SECRET", Err: "Authorization=Bearer SECRET"}}
	i.Snapshots[0].Connections = []collector.ConnectionSnapshot{{LocalAddr: "SECRET", RemoteAddr: "SECRET", State: "SECRET", FD: 0}}
	i.Events = append(i.Events, Event{Timestamp: i.TriggeredAt, Type: CollectorError, Collector: "SECRET", From: "SECRET"})
	for _, compressed := range []bool{false, true} {
		raw := encoded(t, i, compressed)
		if !bytes.Equal(raw, encoded(t, i, compressed)) {
			t.Fatal("encoding not deterministic")
		}
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range zr.File {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("SECRET")) {
				t.Fatalf("secret in %s", f.Name)
			}
		}
		bundle, err := Read(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if bundle.Incident.Privacy.Policy != "conservative-v1" || len(bundle.Incident.Snapshots) != 3 {
			t.Fatalf("bad roundtrip: %+v", bundle)
		}
	}
	if i.Snapshots[0].Processes[0].Name != "token=SECRET" {
		t.Fatal("export mutated live evidence")
	}
}
func rewrite(t testing.TB, raw []byte, change func(string, []byte) (string, []byte), extra bool) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		r, _ := f.Open()
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		name, data := change(f.Name, data)
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if extra {
		w, _ := zw.Create("manifest.json")
		w.Write([]byte("{}"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestHostileAndCorruptBundles(t *testing.T) {
	base := encoded(t, fixture(), true)
	cases := map[string][]byte{"empty": {}, "truncated": base[:len(base)/2], "garbage": []byte("not zip")}
	for _, member := range []string{"manifest.json", "snapshots.json", "events.jsonl", "privacy.json", "metadata.json"} {
		member := member
		cases[member] = rewrite(t, base, func(n string, b []byte) (string, []byte) {
			if n == member {
				b = []byte("broken")
			}
			return n, b
		}, false)
	}
	cases["traversal"] = rewrite(t, base, func(n string, b []byte) (string, []byte) {
		if n == "metadata.json" {
			n = "../metadata.json"
		}
		return n, b
	}, false)
	cases["duplicate"] = rewrite(t, base, func(n string, b []byte) (string, []byte) { return n, b }, true)
	cases["unsupported"] = rewrite(t, base, func(n string, b []byte) (string, []byte) {
		if n == "manifest.json" {
			b = bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":999`), 1)
		}
		return n, b
	}, false)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(raw), int64(len(raw))); err == nil {
				t.Fatal("accepted hostile/corrupt archive")
			}
		})
	}
	if _, err := Read(bytes.NewReader(base), maxArchiveBytes+1); err == nil {
		t.Fatal("accepted oversized archive")
	}
}
func privateDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestAtomicWriterFailuresAndCollision(t *testing.T) {
	for _, step := range []string{"create", "write", "sync-file", "close", "publish", "sync-directory"} {
		t.Run(step, func(t *testing.T) {
			dir := privateDir(t)
			w := FileWriter{Directory: dir, before: func(s string) error {
				if s == step {
					return syscall.ENOSPC
				}
				return nil
			}}
			path, err := w.Write(context.Background(), fixture())
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("expected ENOSPC: %v", err)
			}
			entries, _ := os.ReadDir(dir)
			if step == "sync-directory" {
				if path == "" || len(entries) != 1 {
					t.Fatal("published result not reported")
				}
				if _, err := ReadFile(path); err != nil {
					t.Fatal(err)
				}
			} else if len(entries) != 0 {
				t.Fatalf("partial artifacts: %v", entries)
			}
		})
	}
	dir := privateDir(t)
	w := FileWriter{Directory: dir}
	path, err := w.Write(context.Background(), fixture())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err = w.Write(context.Background(), fixture()); err == nil {
		t.Fatal("overwrote collision")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing artifact corrupted")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("bundle not private")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = w.Write(ctx, fixture()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestCleanupOnlyStaleTemps(t *testing.T) {
	dir := privateDir(t)
	old := filepath.Join(dir, ".runopsy-123.tmp")
	os.WriteFile(old, []byte("partial"), 0600)
	os.Chtimes(old, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	os.WriteFile(filepath.Join(dir, "other.tmp"), nil, 0600)
	os.Symlink(old, filepath.Join(dir, ".runopsy-link.tmp"))
	count, err := CleanupStaleTemps(dir, time.Now().Add(-time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("cleanup %d %v", count, err)
	}
}

// TestDifferRecordsZombieExitStatus: the exit status is only exposed by the
// platform while the zombie still occupies its PID, so the differ stamps the
// last-seen zombie row's status on PROCESS_EXITED and leaves the ordinary
// reaped-exit case empty.
func TestDifferRecordsZombieExitStatus(t *testing.T) {
	at := time.Now().UTC()
	baseline := func(offset time.Duration, procs []collector.ProcessSnapshot) collector.Snapshot {
		return collector.Snapshot{Timestamp: at.Add(offset), System: &collector.SystemSnapshot{ProcessCountAvailable: true, ProcessCount: len(procs)}, Processes: procs}
	}
	d := &Differ{}
	exitof := func(events []Event, pid int) *Event {
		for i := range events {
			if events[i].Type == ProcessExited && events[i].PID == pid {
				return &events[i]
			}
		}
		return nil
	}
	if events := d.Observe(baseline(0, []collector.ProcessSnapshot{
		{Process: platform.Process{PID: 42, StartTicks: 7, State: "Z", ExitStatus: "signal:9"}},
		{Process: platform.Process{PID: 43, StartTicks: 8, State: "S"}},
	})); len(events) != 0 {
		t.Fatalf("first sample invented events: %v", events)
	}
	events := d.Observe(baseline(time.Second, nil))
	zombie := exitof(events, 42)
	if zombie == nil {
		t.Fatalf("no exit event for the zombie pid: %v", events)
	}
	if zombie.ExitStatus != "signal:9" {
		t.Errorf("zombie exit status = %q, want signal:9", zombie.ExitStatus)
	}
	reaped := exitof(events, 43)
	if reaped == nil {
		t.Fatalf("no exit event for the running pid: %v", events)
	}
	if reaped.ExitStatus != "" {
		t.Errorf("reaped exit status = %q, want empty (never captured)", reaped.ExitStatus)
	}
}

func TestDifferReuseUnavailableAndDebounce(t *testing.T) {
	at := time.Now().UTC()
	var d Differ
	if len(d.Observe(sample(at, 10))) != 0 {
		t.Fatal("first sample invented events")
	}
	bad := sample(at.Add(time.Second), 10)
	bad.Processes = nil
	bad.Errors = []collector.CollectionError{{Collector: "processes", Err: "denied"}}
	for _, e := range d.Observe(bad) {
		if e.Type == ProcessExited {
			t.Fatal("unavailable mistaken for death")
		}
	}
	out := d.Observe(sample(at.Add(2*time.Second), 11))
	types := map[string]bool{}
	for _, e := range out {
		types[e.Type] = true
	}
	if !types[ProcessExited] || !types[ProcessStarted] {
		t.Fatal(out)
	}
	rule := ProcessExitRule{Enabled: true}
	rule.Observe(sample(at, 10))
	empty := sample(at.Add(time.Second), 10)
	empty.Processes = nil
	if rule.Observe(empty) == nil {
		t.Fatal("missing exit trigger")
	}
	debounce := Debounce{Duration: 2 * time.Second}
	if debounce.Observe(at, true, true) || debounce.Observe(at.Add(time.Second), true, true) || !debounce.Observe(at.Add(2*time.Second), true, true) || debounce.Observe(at.Add(3*time.Second), true, true) {
		t.Fatal("bad debounce")
	}
	debounce.Observe(at.Add(4*time.Second), true, false)
	if debounce.Observe(at.Add(5*time.Second), true, true) {
		t.Fatal("unavailable did not reset debounce")
	}
}

type recordingWriter struct {
	mu        sync.Mutex
	incidents []*Incident
	release   chan struct{}
	err       error
}

func (w *recordingWriter) Write(ctx context.Context, i *Incident) (string, error) {
	if w.release != nil {
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.incidents = append(w.incidents, i)
	return "saved", w.err
}
func waitCapture(t *testing.T, c *Capture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestCaptureWraparoundDetachedPostAndDuplicateTrigger(t *testing.T) {
	w := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{Window: CaptureWindow{time.Second, 40 * time.Millisecond}, Writer: w, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	for n := 0; n < 20; n++ {
		c.Observe(sample(at.Add(time.Duration(n-20)*time.Millisecond), 10))
	}
	id, err := c.Trigger(Trigger{Type: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Trigger(Trigger{Type: "manual"}); err == nil {
		t.Fatal("double trigger accepted")
	}
	post := sample(time.Now().UTC(), 10)
	c.Observe(post)
	post.Processes[0].Name = "MUTATED"
	time.Sleep(60 * time.Millisecond)
	waitCapture(t, c)
	if c.Status().State != Complete || c.Status().ID != id {
		t.Fatal(c.Status())
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.incidents) != 1 {
		t.Fatal("wrong write count")
	}
	i := w.incidents[0]
	if err := Validate(i); err != nil {
		t.Fatal(err)
	}
	if len(i.Snapshots) == 0 || !i.Snapshots[len(i.Snapshots)-1].Timestamp.Equal(post.Timestamp) {
		t.Fatal("lost post sample")
	}
	for _, s := range i.Snapshots {
		if s.Processes[0].Name == "MUTATED" {
			t.Fatal("aliased input")
		}
	}
}
func TestCaptureWriteDoesNotBlockRecordingAndFailureAllowsRetry(t *testing.T) {
	w := &recordingWriter{release: make(chan struct{}), err: syscall.ENOSPC}
	c, _ := NewCapture(CaptureOptions{Writer: w, Window: CaptureWindow{time.Second, 0}})
	c.Observe(sample(time.Now().UTC(), 10))
	if _, err := c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for c.Status().State != Finalizing && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	c.Observe(sample(time.Now().UTC(), 10))
	if _, err := c.Trigger(Trigger{Type: "manual"}); err == nil {
		t.Fatal("trigger during finalizing accepted")
	}
	close(w.release)
	for c.Status().State == Finalizing && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Status().State != Failed {
		t.Fatal(c.Status())
	}
	if _, err := c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal("failed writer stopped recording", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Close(ctx); err == nil {
		t.Fatal("write failure hidden")
	}
}
func TestShutdownTruncatesPostWindow(t *testing.T) {
	w := &recordingWriter{}
	c, _ := NewCapture(CaptureOptions{Writer: w, Window: DefaultWindow()})
	c.Trigger(Trigger{Type: "manual"})
	waitCapture(t, c)
	if !w.incidents[0].Truncated {
		t.Fatal("shutdown not marked truncated")
	}
}
func TestValidationOrdering(t *testing.T) {
	i := fixture()
	i.Snapshots[1].Timestamp = i.Snapshots[0].Timestamp
	if err := Validate(i); err == nil {
		t.Fatal("accepted duplicate timestamp")
	}
}
func TestShortWriter(t *testing.T) {
	w := &contextWriter{ctx: context.Background(), dst: shortWriter{}, left: 1024}
	if _, err := w.Write([]byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func FuzzBundleRead(f *testing.F) {
	f.Add(encoded(f, fixture(), true))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		Read(bytes.NewReader(raw), int64(len(raw)))
	})
}
func BenchmarkBundleEncode(b *testing.B) {
	for _, compressed := range []bool{false, true} {
		name := "store"
		if compressed {
			name = "deflate"
		}
		b.Run(name, func(b *testing.B) {
			i := fixture()
			s := i.Snapshots[1]
			i.Snapshots = nil
			for n := 0; n < 120; n++ {
				s.Timestamp = i.CaptureStart.Add(time.Duration(n) * time.Millisecond)
				i.Snapshots = append(i.Snapshots, s)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var out bytes.Buffer
				if err := Encode(&out, i, compressed); err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(out.Len()), "bundle-bytes")
			}
		})
	}
}
func TestJSONMalformed(t *testing.T) {
	var i Incident
	for _, s := range []string{`{} {}`, `{"unknown":1}`, `{"id":"first","id":"second"}`, `{"created_at":"invalid"}`} {
		if err := decodeJSON([]byte(s), &i); err == nil {
			t.Fatal("accepted", s)
		}
	}
	if !strings.Contains(string(encoded(t, fixture(), false)), "manifest.json") {
		t.Fatal("not a standard archive")
	}
}
