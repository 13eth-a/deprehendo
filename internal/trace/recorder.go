package trace

import (
	"fmt"
	"os"
	"sync"
)

// raw trace recording for tests and debugging (6.46).
//
// the recorder writes the very frames the socket carries, so a recording is
// replayed by the same decoder the agent uses on live data (`trace.Replay`,
// `runopsy-agent trace replay`). it is bounded on purpose: a debug recording
// on a busy CI host can otherwise grow without limit. when a bound is reached
// the recorder stops cleanly at a frame boundary and reports why; it never
// writes a partial record, and it never fails the caller. losing a debug
// recording must not cost an incident (6.40's invariant applied to the go
// side).
//
// production recordings are debug-only (contract §12): the file is not part
// of a bundle and no path from it is ever copied into one.
const (
	// DefaultMaxRecordBytes bounds one recording file (64 MiB ≈ 400k events).
	DefaultMaxRecordBytes int64 = 64 << 20
	// DefaultMaxRecordEvents bounds one recording by event count.
	DefaultMaxRecordEvents uint64 = 1 << 20
)

// RecorderLimits bound one recording. zero fields take the defaults.
type RecorderLimits struct {
	MaxBytes  int64
	MaxEvents uint64
}

// RecorderStats is the recorder's self-report. truncated is set exactly when a
// bound or an IO error stopped it early, and reason says which.
type RecorderStats struct {
	Path      string `json:"path"`
	Events    uint64 `json:"events"`
	Bytes     uint64 `json:"bytes"`
	Truncated bool   `json:"truncated,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// recorder is a sink that persists events as wire frames.
type Recorder struct {
	mu     sync.Mutex
	f      *os.File
	fr     framer
	limits RecorderLimits
	stats  RecorderStats
	closed bool
}

// NewRecorder opens path for a fresh recording (an existing file is
// truncated: a debug run replaces the previous one). the file is created
// owner-only.
func NewRecorder(path string, limits RecorderLimits) (*Recorder, error) {
	if path == "" {
		return nil, fmt.Errorf("trace: recorder requires an output path")
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = DefaultMaxRecordBytes
	}
	if limits.MaxEvents == 0 {
		limits.MaxEvents = DefaultMaxRecordEvents
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trace: open recording %s: %w", path, err)
	}
	return &Recorder{f: f, fr: newFramer(nil, f), limits: limits, stats: RecorderStats{Path: path}}, nil
}

// sink adapts the recorder to the session/manager sink signature.
func (r *Recorder) Sink() Sink {
	return func(e TraceEvent) { r.Record(e) }
}

// record appends one event frame. after truncation it is a no-op, so the sink
// stays safe to call for the rest of the session.
func (r *Recorder) Record(e TraceEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.stats.Truncated {
		return
	}
	raw, err := encodeEvent(e)
	if err != nil {
		r.stopLocked("encode: " + err.Error())
		return
	}
	size := uint64(12 + len(raw))
	if r.stats.Bytes+size > uint64(r.limits.MaxBytes) {
		r.stopLocked(fmt.Sprintf("recording reached its %d-byte bound", r.limits.MaxBytes))
		return
	}
	if r.stats.Events+1 > r.limits.MaxEvents {
		r.stopLocked(fmt.Sprintf("recording reached its %d-event bound", r.limits.MaxEvents))
		return
	}
	if err := r.fr.writeFrame(KindEvent, SchemaVersion, raw); err != nil {
		r.stopLocked("write: " + err.Error())
		return
	}
	r.stats.Events++
	r.stats.Bytes += size
}

// stopLocked records why recording ended. the file is left in place: what was
// captured is evidence, and a reader sees the same truncation from the last
// complete frame.
func (r *Recorder) stopLocked(reason string) {
	r.stats.Truncated = true
	r.stats.Reason = reason
}

// stats snapshots the recording so far.
func (r *Recorder) Stats() RecorderStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// close flushes and closes the file, returning the final statistics. closing
// twice is safe.
func (r *Recorder) Close() (RecorderStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.stats, nil
	}
	r.closed = true
	syncerr := r.f.Sync()
	closeerr := r.f.Close()
	if syncerr != nil {
		return r.stats, fmt.Errorf("trace: sync recording: %w", syncerr)
	}
	if closeerr != nil {
		return r.stats, fmt.Errorf("trace: close recording: %w", closeerr)
	}
	return r.stats, nil
}
