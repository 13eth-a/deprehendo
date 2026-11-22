package trace

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// ReplayStats summarizes one file replay (6.45).
type ReplayStats struct {
	// frames is every frame found in the file, whatever kind.
	Frames int
	// events is the number of decoded event frames.
	Events int
	// SkippedKinds counts non-event frames (handshake, acks...) present in
	// a raw debug recording.
	SkippedKinds int
	// BadSamples counts event frames whose payload failed decode. replay
	// never stops on a bad sample unless the framing itself is broken.
	BadSamples int
	// lost is the sequence-gap total across the whole file (6.26/6.27): a
	// recorded drop is replayed as a drop, never rewritten as absence.
	Lost uint64
	// LastSequence is the highest observed sequence number.
	LastSequence uint64
}

// ReplayFile decodes a framed trace recording (the same wire format as the
// socket, 6.45) and feeds each decoded event to sink. A sequence gap is
// reported in Stats.Lost; the file is authoritative evidence of what was
// recorded, so silence between sampled frames is never rewritten away.
func ReplayFile(path string, sink Sink) (ReplayStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return ReplayStats{}, fmt.Errorf("trace: open %s: %w", path, err)
	}
	defer f.Close()
	stats, err := Replay(f, sink)
	if err != nil {
		return stats, fmt.Errorf("trace: replay %s: %w", path, err)
	}
	return stats, nil
}

// replay is the io.Reader form; see ReplayFile. truncated frames beyond the
// last complete boundary return io.ErrUnexpectedEOF-style framing errors the
// same way live reads do; an EOF exactly on a frame boundary ends the file.
func Replay(r io.Reader, sink Sink) (stats ReplayStats, err error) {
	if sink == nil {
		sink = func(TraceEvent) {}
	}
	fr := newFramer(bufio.NewReader(r), io.Discard)
	for {
		var frame frame
		frame, err = fr.readFrame()
		if err == io.EOF {
			return stats, nil
		}
		if err != nil {
			return stats, err
		}
		stats.Frames++
		if frame.Kind != KindEvent {
			stats.SkippedKinds++
			continue
		}
		e, derr := decodeEvent(frame.Raw)
		if derr != nil {
			// A bad payload is a bad sample, not a broken frame: keep going
			// so one corrupt record cannot hide the rest (6.43 mirror).
			stats.BadSamples++
			continue
		}
		stats.Events++
		// sessions number events from 1, so a gap before the first one is
		// loss too (contract §8).
		if e.Sequence > stats.LastSequence+1 {
			stats.Lost += e.Sequence - stats.LastSequence - 1
		}
		if e.Sequence > stats.LastSequence {
			stats.LastSequence = e.Sequence
		}
		sink(e)
	}
}
