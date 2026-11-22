package trace

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// wire framing (6.6): every message on the unix socket is
//
//	u32 little-endian kind
//	u32 little-endian payload length
//	u32 little-endian payload schema version
//	<length> bytes payload (JSON v1)
//
// JSON was chosen instead of protobuf/binary because the event rate for the
// phase 6 scoped set (exec/exit/stop/signal on watched processes) is modest
// (docs/tracing/architecture.md §4) and JSON keeps the two-language contract
// testable without a code generator. the framing, not the encoding, is what
// guarantees message boundaries. A future binary encoding is a SchemaVersion
// change.
//
// A frame is atomic: a partial writes is completed by a single write call, or
// returns an error and the session is reset (both sides treat a mid-frame
// failure as fatal to the connection, not to the process).

type frame struct {
	Kind    MessageKind
	Version uint16
	Raw     []byte
}

type framer struct {
	r *bufio.Reader
	w io.Writer
}

func newFramer(r io.Reader, w io.Writer) framer {
	return framer{r: bufio.NewReaderSize(r, 8<<10), w: w}
}

// readFrame blocks for the next frame. it returns ErrFrameTooBig for an
// impossible length, io.EOF for a clean close, ErrShortFrame for a truncated
// payload and ErrProtocol for an unknown kind. EOF mid-header is a clean
// close; EOF mid-payload is truncated.
func (f framer) readFrame() (frame, error) {
	var header [12]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return frame{}, ErrShortFrame
		}
		return frame{}, err
	}
	kind := MessageKind(binary.LittleEndian.Uint32(header[0:4]))
	length := binary.LittleEndian.Uint32(header[4:8])
	version := binary.LittleEndian.Uint16(header[8:10])
	if length > MaxFrameSize {
		return frame{}, ErrFrameTooBig
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(f.r, raw); err != nil {
		if err == io.ErrUnexpectedEOF {
			return frame{}, ErrShortFrame
		}
		return frame{}, err
	}
	switch kind {
	case KindEvent, KindHandshake, KindControl, KindAck, KindLoss, KindHealth:
	default:
		return frame{}, fmt.Errorf("%w: kind %d", ErrProtocol, kind)
	}
	return frame{Kind: kind, Version: version, Raw: raw}, nil
}

// writeFrame emits one frame exactly; partial writes are completed by one
// call, so a caller may treat failure as a clean session teardown.
func (f framer) writeFrame(k MessageKind, version uint16, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooBig
	}
	var header [12]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(k))
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint16(header[8:10], version)
	buf := make([]byte, 0, 12+len(payload))
	buf = append(buf, header[:]...)
	buf = append(buf, payload...)
	_, err := f.w.Write(buf)
	return err
}

// --- per-kind codecs ---------------------------------------------------

func encodeEvent(e TraceEvent) ([]byte, error) { return json.Marshal(e) }

func decodeEvent(raw []byte) (TraceEvent, error) {
	var e TraceEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, fmt.Errorf("trace: decode event: %w", err)
	}
	if e.SchemaVersion != SchemaVersion {
		return e, fmt.Errorf("%w: schema %d", ErrProtocol, e.SchemaVersion)
	}
	// A zero timestamp is indistinguishable from "the sender forgot", and
	// phase 4 ordering depends on the monotonic anchor (6.28).
	if e.MonotonicNs <= 0 {
		return e, fmt.Errorf("trace: event has no monotonic timestamp")
	}
	return e, nil
}

func encodeHandshake(h Handshake) ([]byte, error) { return json.Marshal(h) }

func decodeHandshake(raw []byte) (Handshake, error) {
	var h Handshake
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, fmt.Errorf("trace: decode handshake: %w", err)
	}
	if h.ProtocolVersion < ProtocolVersionMin || h.MinVersion > ProtocolVersion {
		// range overlap, the standard rule for versioned protocols: the two
		// sides can only agree if our current version is inside the peer's
		// (min, sent] span.
		return h, fmt.Errorf("%w: peer protocol %d..%d, ours %d", ErrVersion, h.MinVersion, h.ProtocolVersion, ProtocolVersion)
	}
	return h, nil
}

func encodeControl(c Control) ([]byte, error) { return json.Marshal(c) }

func decodeControl(raw []byte) (Control, error) {
	var probe struct {
		Op ControlOp `json:"op"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Control{}, fmt.Errorf("trace: decode control op: %w", err)
	}
	switch probe.Op {
	case OpAdd, OpRemove, OpReset, OpFlush, OpPing, OpShutdown, OpAddCgroup:
	default:
		return Control{}, fmt.Errorf("%w: control op %d", ErrProtocol, probe.Op)
	}
	var c Control
	if err := json.Unmarshal(raw, &c); err != nil {
		return Control{}, fmt.Errorf("trace: decode control pids: %w", err)
	}
	c.Op = probe.Op
	// A watch set is bounded both here and in the tracer: the payload frame
	// is capped by the framer, but decode must refuse amplification it can
	// still see (hostile PID lists in otherwise-valid frames).
	if len(c.PIDs) > MaxWatchSetEntries {
		return Control{}, fmt.Errorf("trace: watch set of %d PIDs exceeds %d", len(c.PIDs), MaxWatchSetEntries)
	}
	for _, pid := range c.PIDs {
		if pid == 0 {
			return Control{}, fmt.Errorf("%w: PID 0 in watch set", ErrProtocol)
		}
	}
	return c, nil
}

func encodeAck(a ControlAck) ([]byte, error) { return json.Marshal(a) }

// the agent never sends LOSS or HEALTH frames, so only the decoders exist:
// the wire is one-directional for these kinds. decodeLoss mirrors
// framing.rs decode_loss exactly. a zero count is a frame that says
// nothing, an inverted window (last before first) corrupts §8 ordering, so
// both are protocol violations rather than ignored counters.
func decodeLoss(raw []byte) (Loss, error) {
	var l Loss
	if err := json.Unmarshal(raw, &l); err != nil {
		return l, fmt.Errorf("trace: decode loss: %w", err)
	}
	if l.CountAtLeast == 0 {
		return l, fmt.Errorf("%w: loss frame reports zero events", ErrProtocol)
	}
	if l.LastNs < l.FirstNs {
		return l, fmt.Errorf("%w: loss window is inverted", ErrProtocol)
	}
	return l, nil
}

// decodeTracerHealth mirrors framing.rs decode_health: unconstrained, because
// a health snapshot carries no claim that can contradict itself.
func decodeTracerHealth(raw []byte) (TracerHealth, error) {
	var h TracerHealth
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, fmt.Errorf("trace: decode health: %w", err)
	}
	return h, nil
}
func decodeAck(raw []byte) (ControlAck, error) {
	var a ControlAck
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, fmt.Errorf("trace: decode ack: %w", err)
	}
	// an echoed op the reader does not understand is a protocol violation.
	switch a.Op {
	case OpAdd, OpRemove, OpReset, OpFlush, OpPing, OpShutdown, OpAddCgroup:
	default:
		return a, fmt.Errorf("%w: ack op %d", ErrProtocol, a.Op)
	}
	return a, nil
}
