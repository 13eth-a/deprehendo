package trace

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func sampleEvent(seq uint64) TraceEvent {
	return TraceEvent{
		SchemaVersion: SchemaVersion,
		Sequence:      seq,
		MonotonicNs:   int64(seq) * 1000,
		WallUnixMs:    1767000000000 + int64(seq),
		Type:          EventEXIT,
		PID:           uint32(100 + seq),
		Source:        SourceSynthetic,
	}
}

// TestRecorderRoundTrip pins 6.46's contract: what the recorder writes is
// exactly what the production replay decoder reads, frames and sequence
// numbers intact.
func TestRecorderRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.bin")
	rec, err := NewRecorder(path, RecorderLimits{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	for i := uint64(1); i <= 3; i++ {
		rec.Record(sampleEvent(i))
	}
	stats, err := rec.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if stats.Events != 3 || stats.Truncated {
		t.Fatalf("stats = %+v", stats)
	}
	var got []TraceEvent
	replay, err := ReplayFile(path, func(e TraceEvent) { got = append(got, e) })
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Events != 3 || replay.Lost != 0 || replay.BadSamples != 0 {
		t.Fatalf("replay stats = %+v", replay)
	}
	for i, e := range got {
		if e.Sequence != uint64(i+1) || e.PID != uint32(101+i) {
			t.Fatalf("event %d = %+v", i, e)
		}
	}
	// recording a closed recorder is a no-op, never a panic: a session may
	// outlive the recorder's lifetime by a few events during shutdown.
	rec.Record(sampleEvent(4))
	if final := rec.Stats(); final.Events != 3 {
		t.Fatalf("closed recorder kept recording: %+v", final)
	}
}

// TestRecorderByteBound documents the failure mode rather than the happy
// path: a bound stops recording at a frame boundary, says why, and leaves a
// file whose complete frames still replay.
func TestRecorderByteBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded.bin")
	// one event frame is comfortably larger than this, so exactly zero
	// events fit: the recorder must report that instead of writing a
	// partial frame.
	rec, err := NewRecorder(path, RecorderLimits{MaxBytes: 8})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	rec.Record(sampleEvent(1))
	stats, err := rec.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if !stats.Truncated || stats.Events != 0 || !strings.Contains(stats.Reason, "byte bound") {
		t.Fatalf("stats = %+v", stats)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("bounded recorder wrote %d bytes", info.Size())
	}
}

func TestRecorderEventBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded-events.bin")
	rec, err := NewRecorder(path, RecorderLimits{MaxEvents: 2})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	for i := uint64(1); i <= 5; i++ {
		rec.Record(sampleEvent(i))
	}
	stats, err := rec.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if stats.Events != 2 || !stats.Truncated || !strings.Contains(stats.Reason, "event bound") {
		t.Fatalf("stats = %+v", stats)
	}
	replay, err := ReplayFile(path, nil)
	if err != nil {
		t.Fatalf("replay of a bounded recording: %v", err)
	}
	if replay.Events != 2 || replay.Lost != 0 {
		t.Fatalf("replay stats = %+v", replay)
	}
}

// TestRecorderConcurrentSink: the manager's sink is called from the session
// reader goroutine while health is read from others. recording must be
// race-free (run with -race) and must not interleave frames.
func TestRecorderConcurrentSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.bin")
	rec, err := NewRecorder(path, RecorderLimits{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	sink := rec.Sink()
	var wg sync.WaitGroup
	const writers = 4
	const each = 25
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				sink(sampleEvent(uint64(base*each + i + 1)))
			}
		}(w)
	}
	// concurrent readers of the stats must not race the writers.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = rec.Stats()
			}
		}
	}()
	wg.Wait()
	close(stop)
	stats, err := rec.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if stats.Events != writers*each {
		t.Fatalf("recorded %d events, want %d", stats.Events, writers*each)
	}
	// every frame must decode: interleaving would have corrupted the file.
	replay, err := ReplayFile(path, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Events != writers*each || replay.BadSamples != 0 {
		t.Fatalf("replay stats = %+v", replay)
	}
}

func TestRecorderRequiresPath(t *testing.T) {
	if _, err := NewRecorder("", RecorderLimits{}); err == nil {
		t.Fatal("recorder accepted an empty path")
	}
}

// TestRecorderReplacesPreviousRecording: a debug run overwrites its own
// output instead of appending to a stale file, so replay never mixes two
// sessions' sequences.
func TestRecorderReplacesPreviousRecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replace.bin")
	first, err := NewRecorder(path, RecorderLimits{})
	if err != nil {
		t.Fatal(err)
	}
	first.Record(sampleEvent(1))
	first.Record(sampleEvent(2))
	if _, err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewRecorder(path, RecorderLimits{})
	if err != nil {
		t.Fatal(err)
	}
	second.Record(sampleEvent(1))
	if _, err := second.Close(); err != nil {
		t.Fatal(err)
	}
	replay, err := ReplayFile(path, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Events != 1 {
		t.Fatalf("stale frames survived: %+v", replay)
	}
}

// TestRecordingsReplayThroughCLISurface keeps the recorded bytes and the
// debug CLI in step: the CLI's decode path is ReplayFile, so a bound or a
// truncation must be visible there rather than silently dropped.
func TestRecordingsReplayThroughCLISurface(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cli.bin")
	rec, err := NewRecorder(path, RecorderLimits{MaxEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	rec.Record(sampleEvent(1))
	rec.Record(sampleEvent(2))
	if _, err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	var lines int
	stats, err := ReplayFile(path, func(TraceEvent) { lines++ })
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if lines != 1 || stats.Events != 1 {
		t.Fatalf("lines=%d stats=%+v", lines, stats)
	}
}
