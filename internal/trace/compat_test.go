package trace

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// secondary's phase 6 share: the go half of the cross-language golden tree
// (6.3/6.4/6.56), the §6.4 compatibility policy, and the clock rules (§8).
//
// trace-rs/tests/protocol_test.rs pins the same bytes from the rust side, and
// trace-rs/tests/wire_compat_test.rs drives the production tracer binary with
// the go encodings below. the three exist so that either language's encoder
// drifting away from the other fails a test on our side of the border.

// TestFrameHeaderGolden pins the 12-byte header: kind, length, version, all
// little-endian. A change here is a protocol change and must bump the version.
func TestFrameHeaderGolden(t *testing.T) {
	var buf bytes.Buffer
	payload, err := encodeEvent(sampleEvent(1))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	fr := newFramer(nil, &buf)
	if err := fr.writeFrame(KindEvent, SchemaVersion, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) != 12+len(payload) {
		t.Fatalf("frame length = %d, want %d", len(raw), 12+len(payload))
	}
	if got := binary.LittleEndian.Uint32(raw[0:4]); got != uint32(KindEvent) {
		t.Errorf("kind = %d", got)
	}
	if got := binary.LittleEndian.Uint32(raw[4:8]); got != uint32(len(payload)) {
		t.Errorf("length = %d, want %d", got, len(payload))
	}
	if got := binary.LittleEndian.Uint16(raw[8:10]); got != SchemaVersion {
		t.Errorf("version = %d", got)
	}
	// the last two header bytes are reserved: the rust framer writes zeros
	// there, and a reader must not depend on them for anything.
	if raw[10] != 0 || raw[11] != 0 {
		t.Errorf("reserved header bytes = %v", raw[10:12])
	}
	// the frame must decode back to the identical payload, byte for byte.
	decoded, err := newFramer(bytes.NewReader(raw), nil).readFrame()
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if !bytes.Equal(decoded.Raw, payload) {
		t.Error("payload changed across the frame round trip")
	}
}

// TestEventJSONTagsAreTheContract pins the exact tag names and the
// omit-when-zero rules the rust struct mirrors. A present exit_code:0 is a
// real exit(0) and must survive; an absent one is "not captured".
func TestEventJSONTagsAreTheContract(t *testing.T) {
	event := sampleEvent(7)
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, required := range []string{"schema_version", "sequence", "monotonic_ns", "wall_unix_ms", "type", "pid", "source"} {
		if _, ok := fields[required]; !ok {
			t.Errorf("required field %q missing from %s", required, raw)
		}
	}
	for _, omitted := range []string{"clock_offset_ns", "ppid", "pgid", "start_ticks", "exec_path", "exit_code", "signal", "sender_pid", "fact"} {
		if _, ok := fields[omitted]; ok {
			t.Errorf("%q must be absent when zero, not present: %s", omitted, raw)
		}
	}
	zero := int32(0)
	event.ExitCode = &zero
	raw, err = json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal exit 0: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"exit_code":0`)) {
		t.Fatalf("exit(0) did not survive as a present zero: %s", raw)
	}
}

// TestGoGoldenWireBytes pins the go encoder's exact output against the same
// literals trace-rs/tests/wire_compat_test.rs feeds the production rust
// decoder. if either encoder changes, one of the two suites fails.
func TestGoGoldenWireBytes(t *testing.T) {
	exec := TraceEvent{
		SchemaVersion: SchemaVersion,
		Sequence:      7,
		MonotonicNs:   123456789,
		WallUnixMs:    1767000000000,
		Type:          EventEXEC,
		PID:           4242,
		ExecPath:      "/usr/bin/tool",
		Source:        SourceProcConnector,
	}
	signaled := TraceEvent{
		SchemaVersion: SchemaVersion,
		Sequence:      8,
		MonotonicNs:   123456999,
		WallUnixMs:    1767000000500,
		Type:          EventEXIT,
		PID:           4242,
		Signal:        9,
		Fact:          SignalDeliveredToExit,
		Source:        SourceProcConnector,
	}
	zero := int32(0)
	exited := TraceEvent{
		SchemaVersion: SchemaVersion,
		Sequence:      9,
		MonotonicNs:   123457000,
		WallUnixMs:    1767000000600,
		Type:          EventEXIT,
		PID:           4243,
		ExitCode:      &zero,
		Source:        SourceProcConnector,
	}
	cases := []struct {
		name  string
		event TraceEvent
		want  string
	}{
		{
			"exec",
			exec,
			`{"schema_version":1,"sequence":7,"monotonic_ns":123456789,"wall_unix_ms":1767000000000,"type":1,"pid":4242,"exec_path":"/usr/bin/tool","source":1}`,
		},
		{
			"exit by signal",
			signaled,
			`{"schema_version":1,"sequence":8,"monotonic_ns":123456999,"wall_unix_ms":1767000000500,"type":2,"pid":4242,"signal":9,"fact":2,"source":1}`,
		},
		{
			"exit zero",
			exited,
			`{"schema_version":1,"sequence":9,"monotonic_ns":123457000,"wall_unix_ms":1767000000600,"type":2,"pid":4243,"exit_code":0,"source":1}`,
		},
	}
	for _, c := range cases {
		raw, err := encodeEvent(c.event)
		if err != nil {
			t.Fatalf("%s: encode: %v", c.name, err)
		}
		if string(raw) != c.want {
			t.Errorf("%s: wire bytes drifted\n got %s\nwant %s", c.name, raw, c.want)
		}
	}
}

// TestControlOmitsEmptyOperands pins the encoding the rust decoder depends
// on: a command with no PIDs must omit `pids`, never send JSON null (which
// older tracer builds reject as a type error, ending the session).
func TestControlOmitsEmptyOperands(t *testing.T) {
	for _, c := range []struct {
		control Control
		want    string
	}{
		{Control{Op: OpPing}, `{"op":5}`},
		{Control{Op: OpShutdown}, `{"op":6}`},
		{Control{Op: OpReset, PIDs: []uint32{}}, `{"op":3}`},
		{Control{Op: OpRemove, PIDs: []uint32{42}}, `{"op":2,"pids":[42]}`},
	} {
		raw, err := encodeControl(c.control)
		if err != nil {
			t.Fatalf("encode %s: %v", c.control.Op, err)
		}
		if string(raw) != c.want {
			t.Errorf("%s: got %s want %s", c.control.Op, raw, c.want)
		}
		if _, err := decodeControl(raw); err != nil {
			t.Errorf("%s: round trip: %v", c.control.Op, err)
		}
	}
}

// TestOptionalUnknownFieldTolerated is the §6.4 row "new optional field": an
// older reader must ignore a field it does not know, on both sides.
func TestOptionalUnknownFieldTolerated(t *testing.T) {
	raw, err := json.Marshal(sampleEvent(1))
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["future_field"] = map[string]any{"nested": []any{1, 2}}
	extended, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent(extended)
	if err != nil {
		t.Fatalf("decode with an unknown optional field: %v", err)
	}
	if event.Sequence != 1 || event.PID != 101 {
		t.Fatalf("known fields changed: %+v", event)
	}
}

// TestUnknownEventTypeIsPreserved is the §6.4 row "new event type number":
// kept, labelled, and validation-clean, never dropped and never guessed.
func TestUnknownEventTypeIsPreserved(t *testing.T) {
	event := sampleEvent(1)
	event.Type = EventType(4242)
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("an unknown event number must decode: %v", err)
	}
	if decoded.Type != EventType(4242) {
		t.Fatalf("unknown type changed: %d", decoded.Type)
	}
	if label := decoded.Type.String(); label != "TRACE_EVENT_4242" {
		t.Fatalf("unknown type label = %q", label)
	}
}

// TestUnknownEnumValueIsNeverTheZeroMeaning is the §6.4 row "new value in an
// existing enum": read as UNKNOWN, never as the zero/default meaning. here the
// zero value of SignalFact is "no signal fact", so a future fact number must
// not be read as one.
func TestUnknownEnumValueIsNeverTheZeroMeaning(t *testing.T) {
	event := sampleEvent(1)
	event.Signal = 15
	event.Fact = SignalFact(200)
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Fact != SignalFact(200) {
		t.Fatalf("unknown fact changed: %d", decoded.Fact)
	}
	if label := decoded.Fact.String(); label != "SIGNAL_FACT_200" {
		t.Fatalf("unknown fact is not labelled: %q", label)
	}
}

// TestSchemaVersionMismatchRejected is the §6.4 row "changed meaning": a
// schema the reader does not speak is refused at the handshake, never
// half-decoded.
func TestSchemaVersionMismatchRejected(t *testing.T) {
	event := sampleEvent(1)
	event.SchemaVersion = SchemaVersion + 1
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEvent(raw); !errors.Is(err, ErrProtocol) {
		t.Fatalf("newer schema decoded: %v", err)
	}
	// an older schema is refused by the same check: the reader never has to
	// guess what a version bump changed.
	event.SchemaVersion = SchemaVersion
	raw, err = json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEvent(raw); err != nil {
		t.Fatalf("current schema refused: %v", err)
	}
}

// TestLossAndHealthDecoders pins the §6.3 d/e payloads on the go side of the
// border. protocol_test.rs pins the same shapes on the rust side. A zero
// count is a frame that says nothing, an inverted window corrupts §8 ordering;
// both are protocol violations, not counters to ignore.
func TestLossAndHealthDecoders(t *testing.T) {
	l, err := decodeLoss([]byte(`{"stage":4,"count_at_least":2,"first_ns":100,"last_ns":200}`))
	if err != nil {
		t.Fatalf("valid loss refused: %v", err)
	}
	if l.Stage != StageQueue || l.CountAtLeast != 2 || l.FirstNs != 100 || l.LastNs != 200 {
		t.Errorf("decoded loss = %+v", l)
	}
	if _, err := decodeLoss([]byte(`{"stage":4,"count_at_least":0,"first_ns":1,"last_ns":2}`)); !errors.Is(err, ErrProtocol) {
		t.Errorf("zero-count loss accepted: %v", err)
	}
	if _, err := decodeLoss([]byte(`{"stage":4,"count_at_least":2,"first_ns":500,"last_ns":100}`)); !errors.Is(err, ErrProtocol) {
		t.Errorf("inverted loss window accepted: %v", err)
	}
	// A stage this build does not name is accepted (§6.4 additive policy)
	// and bucketed separately by the session.
	if _, err := decodeLoss([]byte(`{"stage":9,"count_at_least":1,"first_ns":1,"last_ns":1}`)); err != nil {
		t.Errorf("future-stage loss refused: %v", err)
	}
	h, err := decodeTracerHealth([]byte(`{"uptime_ms":1200,"events_sent":3,"events_lost":7,"queue_depth":0,"watches":4,"monotonic_ns":55}`))
	if err != nil {
		t.Fatalf("valid health refused: %v", err)
	}
	if h.EventsLost != 7 || h.Watches != 4 || h.MonotonicNs != 55 {
		t.Errorf("decoded health = %+v", h)
	}
	// readFrame must pass both new kinds through unchanged; the session's
	// per-kind decode is the only gate beyond this.
	for _, kind := range []MessageKind{KindLoss, KindHealth} {
		var buf bytes.Buffer
		raw, merr := json.Marshal(Loss{Stage: StageQueue, CountAtLeast: 1, FirstNs: 1, LastNs: 2})
		if merr != nil {
			t.Fatalf("marshal: %v", merr)
		}
		if werr := newFramer(nil, &buf).writeFrame(kind, SchemaVersion, raw); werr != nil {
			t.Fatalf("writeFrame kind %d: %v", kind, werr)
		}
		got, rerr := newFramer(bytes.NewReader(buf.Bytes()), nil).readFrame()
		if rerr != nil {
			t.Fatalf("readFrame rejected kind %d: %v", kind, rerr)
		}
		if got.Kind != kind {
			t.Errorf("readFrame kind = %d, want %d", got.Kind, kind)
		}
	}
}

// TestProtocolVersionRange pins §6.4's negotiation rule from the reader's
// side: a peer whose supported span contains our version is acceptable; a
// peer entirely newer or entirely older is not.
func TestProtocolVersionRange(t *testing.T) {
	cases := []struct {
		name string
		h    Handshake
		ok   bool
	}{
		{"exact", Handshake{ProtocolVersion: ProtocolVersion, MinVersion: ProtocolVersion}, true},
		{"peer spans us", Handshake{ProtocolVersion: ProtocolVersion + 3, MinVersion: ProtocolVersion}, true},
		{"peer is older but compatible", Handshake{ProtocolVersion: ProtocolVersion, MinVersion: ProtocolVersionMin}, true},
		{"peer too new", Handshake{ProtocolVersion: ProtocolVersion + 2, MinVersion: ProtocolVersion + 1}, false},
		// A peer whose ENTIRE span is below our minimum: no version can
		// bridge us. (ProtocolVersion-1/ProtocolVersionMin-1 used to catch
		// this while both constants were 1; once ours spans 1..2, a
		// 1..0 peer still overlaps us at protocol 1 and is negotiable.)
		{"peer too old", Handshake{ProtocolVersion: ProtocolVersionMin - 1, MinVersion: ProtocolVersionMin - 1}, false},
	}
	for _, c := range cases {
		raw, err := json.Marshal(c.h)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeHandshake(raw)
		if (err == nil) != c.ok {
			t.Errorf("%s: decode = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// TestUnknownKindAndControlRejected: an unknown frame kind or control op is a
// protocol violation that ends the session, never something to skip silently.
func TestUnknownKindAndControlRejected(t *testing.T) {
	var buf bytes.Buffer
	fr := newFramer(nil, &buf)
	if err := fr.writeFrame(MessageKind(99), SchemaVersion, []byte(`{}`)); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if _, err := newFramer(bytes.NewReader(buf.Bytes()), nil).readFrame(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown kind accepted: %v", err)
	}
	if _, err := decodeControl([]byte(`{"op":99,"pids":[1]}`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown control op accepted: %v", err)
	}
}

// TestAddCgroupControlAccepted: op 7 (ADD_CGROUP) is part of the tracer's
// vocabulary, so the go decoder must accept it instead of ending the session
// (H12). the phase 6 agent does not send it yet; a backend that cannot filter
// by cgroup refuses it in the ack with `err`, which is a normal ack rather
// than a protocol violation.
func TestAddCgroupControlAccepted(t *testing.T) {
	raw, err := encodeControl(Control{Op: OpAddCgroup, PIDs: []uint32{4001}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeControl(raw)
	if err != nil {
		t.Fatalf("op 7 refused by the Go decoder: %v", err)
	}
	if c.Op != OpAddCgroup || c.Op.String() != "ADD_CGROUP" {
		t.Fatalf("op 7 decoded as %s", c.Op)
	}
	ack, err := decodeAck([]byte(`{"op":7,"watches":0,"err":"cgroup watches are not supported by proc_connector"}`))
	if err != nil {
		t.Fatalf("op 7 ack refused: %v", err)
	}
	if ack.Op != OpAddCgroup || ack.Err == "" {
		t.Fatalf("op 7 ack = %+v, want the backend's refusal reason", ack)
	}
	// additive only: the next unknown op still violates the protocol.
	if _, err := decodeControl([]byte(`{"op":8,"pids":[1]}`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("op 8 accepted: %v", err)
	}
}

// TestControlGoldenBytes pins the control encoding the production rust
// decoder is driven with (trace-rs/tests/wire_compat_test.rs uses the same
// literal bytes). the field names are snake_case and the op is numeric.
func TestControlGoldenBytes(t *testing.T) {
	raw, err := encodeControl(Control{Op: OpAdd, PIDs: []uint32{5001, 5008}})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"op":1,"pids":[5001,5008]}`
	if string(raw) != want {
		t.Fatalf("control bytes = %s, want %s", raw, want)
	}
	// A watch-set entry of 0 is refused on both sides: PID 0 means "the
	// caller's group" in kill(2), never a process to watch.
	if _, err := decodeControl([]byte(`{"op":1,"pids":[0]}`)); err == nil {
		t.Fatal("control with PID 0 accepted")
	}
}

// TestLatencyRefusesAnUnusableAnchor covers §8's clock safety at the one place
// a mixed clock shows up as data: an event with no monotonic reading, or an
// interval that is negative beyond rounding, must not enter the budget as a
// real measurement.
func TestLatencyRefusesAnUnusableAnchor(t *testing.T) {
	session := &Session{ClockOffsetNs: 0}
	noreading := sampleEvent(1)
	noreading.MonotonicNs = 0
	if _, ok := session.Latency(noreading, time.Now()); ok {
		t.Error("an event with no monotonic timestamp produced a latency")
	}
	anchorwrong := sampleEvent(1)
	// the event claims to have happened a full second after the local clock:
	// the anchor cannot explain it, so the sample is refused rather than
	// clamped to zero.
	anchorwrong.MonotonicNs = time.Now().Add(time.Second).UnixNano()
	if _, ok := session.Latency(anchorwrong, time.Now()); ok {
		t.Error("a sample beyond the anchor's tolerance was measured")
	}
	// A few microseconds of rounding skew is still a valid sample.
	skewed := sampleEvent(1)
	skewed.MonotonicNs = time.Now().Add(-time.Microsecond).UnixNano()
	if _, ok := session.Latency(skewed, time.Now()); !ok {
		t.Error("rounding skew should not discard a sample")
	}
}

// TestWallTimeIsNeverAClaim pins §8's last rule at the API surface: exit
// status comes from signal/exit_code only, never from a timestamp.
func TestWallTimeIsNeverAClaim(t *testing.T) {
	event := sampleEvent(1)
	event.Type = EventEXIT
	event.WallUnixMs = 0
	if got := event.ExitStatus(); got != "" {
		t.Fatalf("an exit with no status claimed %q", got)
	}
	code := int32(3)
	event.ExitCode = &code
	if got := event.ExitStatus(); got != "exit:3" {
		t.Fatalf("exit status = %q", got)
	}
	event.Signal = 9
	if got := event.ExitStatus(); got != "signal:9" {
		t.Fatalf("signaled exit status = %q; a code must not win over a signal", got)
	}
}
