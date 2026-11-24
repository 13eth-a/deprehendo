package trace

// performance budget (6.49–6.51) for the go half of the tracer bridge.
//
// what is measured here is real: the production encoder/decoder, the
// production Unix-socket framing and the production session reader, driven by
// a synthetic tracer process. what is NOT measured here is kernel capture
// cost. that needs the real backend on linux (live_linux_test.go) and a
// kernel, so it is reported only where it was actually observed.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

func BenchmarkReplayDecode(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReplayFile("../../testdata/trace/dropped-events.bin", nil); err != nil {
			b.Fatalf("replay: %v", err)
		}
	}
}

func BenchmarkFramingRoundTrip(b *testing.B) {
	ev := TraceEvent{
		SchemaVersion: SchemaVersion,
		Sequence:      7,
		MonotonicNs:   1234,
		WallUnixMs:    5678,
		Type:          EventEXIT,
		PID:           42,
		PPID:          1,
		PGID:          1,
		Signal:        9,
		Fact:          SignalDeliveredToExit,
		Source:        SourceProcConnector,
	}
	raw, err := encodeEvent(ev)
	if err != nil {
		b.Fatal(err)
	}
	var buf bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		w := newFramer(nil, &buf)
		if err := w.writeFrame(KindEvent, SchemaVersion, raw); err != nil {
			b.Fatal(err)
		}
		r := newFramer(bytes.NewReader(buf.Bytes()), nil)
		frame, err := r.readFrame()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := decodeEvent(frame.Raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLatencySummary(b *testing.B) {
	stats := &LatencyStats{}
	for i := 0; i < MaxLatencySamples; i++ {
		stats.Observe(int64(i) * 1000)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stats.Summary()
	}
}

// churnCount is the 1k/10k/100k switch from 6.51. the default stays small so
// an ordinary `go test ./...` stays fast; the stress sizes are opt-in.
func churnCount(tb testing.TB) int {
	tb.Helper()
	raw := os.Getenv("DEPREHENDO_TRACE_CHURN")
	if raw == "" {
		return 1000
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 500000 {
		tb.Fatalf("DEPREHENDO_TRACE_CHURN must be 1..500000, got %q", raw)
	}
	return n
}

// TestPipelineChurn pushes N events through a real unix socket, the real
// framing and the real session reader, then checks the properties 6.51 asks
// for: no event loss, no queue growth, stable memory, contiguous sequences,
// and a measured latency distribution.
func TestPipelineChurn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	n := churnCount(t)
	dir, err := os.MkdirTemp("", "deprehendo-churn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "t.sock")

	child := fakeTracerCommand(fakeModeStream, socket, n)
	if err := child.Start(); err != nil {
		t.Fatalf("start fake tracer: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})
	if err := waitForSocket(socket, 5*time.Second); err != nil {
		t.Fatalf("fake tracer never bound its socket: %v", err)
	}

	type latencySample struct {
		mono int64
		at   time.Time
	}
	var (
		mu         sync.Mutex
		through    Throughput
		latency    LatencyStats
		samples    []latencySample
		lastSeq    uint64
		contiguous = true
		restarts   int
	)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// the sink is the production contract: it must be cheap and must not
	// retain per-event state (the tracer's own history does not grow).
	session, err := Connect(SessionOptions{
		Socket:           socket,
		HandshakeTimeout: 3 * time.Second,
		Sink: func(e TraceEvent) {
			now := time.Now()
			mu.Lock()
			if e.Sequence <= lastSeq {
				restarts++
			} else if lastSeq != 0 && e.Sequence != lastSeq+1 {
				contiguous = false
			}
			if e.Sequence > lastSeq {
				lastSeq = e.Sequence
			}
			through.Observe(e, now)
			if e.MonotonicNs > 0 {
				// defer the clock-offset arithmetic to the main goroutine: the
				// session is not returned to the caller until the handshake
				// finishes, and the reader may already be running.
				samples = append(samples, latencySample{mono: e.MonotonicNs, at: now})
			}
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close(time.Second) }()

	deadline := time.Now().Add(30 * time.Second)
	for {
		mu.Lock()
		received := through.Received
		mu.Unlock()
		if received >= uint64(n) {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("received %d/%d events before timeout", received, n)
		}
		time.Sleep(2 * time.Millisecond)
	}

	mu.Lock()
	snapshot := through
	gotcontiguous, gotrestarts := contiguous, restarts
	pairs := append([]latencySample(nil), samples...)
	mu.Unlock()
	for _, pair := range pairs {
		if d, ok := session.Latency(TraceEvent{MonotonicNs: pair.mono}, pair.at); ok {
			latency.ObserveDuration(d)
		}
	}
	summary := latency.Summary()
	if summary.Count == 0 {
		t.Fatal("no latency samples were computed; the capture→receive clock path is broken")
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if snapshot.Received != uint64(n) {
		t.Fatalf("received %d events, want %d", snapshot.Received, n)
	}
	if snapshot.Lost != 0 || snapshot.PeakGap != 0 || session.Lost() != 0 {
		t.Errorf("events were lost on a healthy stream: %+v (session lost=%d)", snapshot, session.Lost())
	}
	if !gotcontiguous {
		t.Error("sequence numbers were not contiguous")
	}
	if gotrestarts > 1 {
		t.Errorf("unexpected sequence restarts: %d", gotrestarts)
	}
	// the reader must not accumulate per-event memory. the bound is generous
	// (go's GC is lazy) but a per-event retention bug blows past it quickly
	// at 10k/100k.
	if growth := int64(after.HeapAlloc) - int64(before.HeapAlloc); growth > 32<<20 {
		t.Errorf("heap grew by %d MiB across %d events; the sink path retains state", growth>>20, n)
	}

	report := PipelineReport{
		Name:     fmt.Sprintf("pipeline-churn-%d", n),
		Backend:  "fake-tracer (framing+session path only)",
		Duration: snapshot.Duration(),
		Received: snapshot.Received,
		Lost:     snapshot.Lost,
		Gaps:     snapshot.Gaps,
		PeakGap:  snapshot.PeakGap,
		Restarts: snapshot.Restarts,
		Rate:     snapshot.EventsPerSecond(),
		Latency:  summary,
		Notes:    []string{"kernel capture cost is not part of this print; see docs/tracing/benchmarks.md"},
	}
	t.Logf("%s", report)
}
