package trace

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// native go fuzz targets for the framed wire protocol (6.42). each target
// checks the same invariants as the rust fuzz tests in
// trace-rs/src/framing.rs (fuzz_tests), so a divergence between the two
// decoders shows up as one side failing a seed the other accepts.
//
// run one target for a while:
//
//	go test -run '^$' -fuzz '^FuzzReadFrame$' -fuzztime 60s ./internal/trace/
//
// every seed below is also a normal unit test under `go test`, so the
// corpus runs on every CI pass without -fuzz.

// seedFixtures adds every Rust-encoded fixture as a seed. these are real
// frames produced by runopsy-trace genfixtures, so the fuzzer starts from
// the cross-language contract instead of from nothing (6.44).
func seedFixtures(f *testing.F) {
	paths, _ := filepath.Glob("../../testdata/trace/*.bin")
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			f.Fatalf("seed %s: %v", p, err)
		}
		f.Add(raw)
	}
}

func frameBytes(kind uint32, version uint16, payload []byte) []byte {
	var b bytes.Buffer
	var header [12]byte
	putU32(header[0:4], kind)
	putU32(header[4:8], uint32(len(payload)))
	header[8] = byte(version)
	header[9] = byte(version >> 8)
	b.Write(header[:])
	b.Write(payload)
	return b.Bytes()
}

func putU32(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

// checkAcceptedFrame asserts what readFrame promises when it returns nil.
func checkAcceptedFrame(t *testing.T, fr frame) {
	t.Helper()
	switch fr.Kind {
	case KindEvent, KindHandshake, KindControl, KindAck, KindLoss, KindHealth:
	default:
		t.Fatalf("readFrame accepted kind %d", fr.Kind)
	}
	if len(fr.Raw) > MaxFrameSize {
		t.Fatalf("readFrame accepted %d bytes, limit %d", len(fr.Raw), MaxFrameSize)
	}
}

// checkAcceptedPayload runs every decoder the frame kind could feed and
// asserts the invariants each decoder promises on success.
func checkAcceptedPayload(t *testing.T, fr frame) {
	t.Helper()
	switch fr.Kind {
	case KindEvent:
		if e, err := decodeEvent(fr.Raw); err == nil {
			if e.SchemaVersion != SchemaVersion || e.MonotonicNs <= 0 {
				t.Fatalf("decodeEvent accepted %+v", e)
			}
			// accepted events must survive a re-encode unchanged.
			raw, err := encodeEvent(e)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			back, err := decodeEvent(raw)
			if err != nil || !reflect.DeepEqual(back, e) {
				t.Fatalf("round trip changed event: %v\n%+v\n%+v", err, e, back)
			}
		}
	case KindHandshake:
		if h, err := decodeHandshake(fr.Raw); err == nil {
			if h.ProtocolVersion < ProtocolVersionMin || h.MinVersion > ProtocolVersion {
				t.Fatalf("decodeHandshake accepted out-of-range %+v", h)
			}
		}
	case KindControl:
		if c, err := decodeControl(fr.Raw); err == nil {
			if len(c.PIDs) > MaxWatchSetEntries {
				t.Fatalf("decodeControl accepted %d PIDs", len(c.PIDs))
			}
			for _, pid := range c.PIDs {
				if pid == 0 {
					t.Fatal("decodeControl accepted PID 0")
				}
			}
			if c.Op < OpAdd || c.Op > OpShutdown {
				t.Fatalf("decodeControl accepted op %d", c.Op)
			}
		}
	case KindAck:
		if a, err := decodeAck(fr.Raw); err == nil {
			if a.Op < OpAdd || a.Op > OpShutdown {
				t.Fatalf("decodeAck accepted op %d", a.Op)
			}
		}
	case KindLoss:
		if l, err := decodeLoss(fr.Raw); err == nil {
			if l.CountAtLeast == 0 || l.LastNs < l.FirstNs {
				t.Fatalf("decodeLoss accepted %+v", l)
			}
		}
	case KindHealth:
		_, _ = decodeTracerHealth(fr.Raw)
	}
}

func FuzzReadFrame(f *testing.F) {
	seedFixtures(f)
	f.Add(frameBytes(uint32(KindEvent), 1, []byte(`{"schema_version":1}`)))
	f.Add(frameBytes(0, 1, []byte(`{}`))) // kind 0: must be refused
	f.Add(frameBytes(uint32(KindAck), 1, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		fr := newFramer(bytes.NewReader(data), io.Discard)
		// A bounded loop: a fuzz input can hold many frames, none may hang.
		for i := 0; i < 64; i++ {
			got, err := fr.readFrame()
			if err != nil {
				return
			}
			checkAcceptedFrame(t, got)
			checkAcceptedPayload(t, got)
		}
	})
}

func FuzzDecodeEvent(f *testing.F) {
	seedFixtures(f)
	f.Add([]byte(`{"schema_version":1,"monotonic_ns":5,"type":1,"pid":3}`))
	f.Add([]byte(`{"schema_version":2,"monotonic_ns":5}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		fr := frame{Kind: KindEvent, Raw: raw}
		checkAcceptedPayload(t, fr)
	})
}

func FuzzDecodeControl(f *testing.F) {
	f.Add([]byte(`{"op":1,"pids":[5,6]}`))
	f.Add([]byte(`{"op":0}`))
	f.Add([]byte(`{"op":3,"pids":[0]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkAcceptedPayload(t, frame{Kind: KindControl, Raw: raw})
	})
}

func FuzzDecodeHandshake(f *testing.F) {
	f.Add([]byte(`{"protocol_version":1,"min_version":1}`))
	f.Add([]byte(`{"protocol_version":0,"min_version":9}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkAcceptedPayload(t, frame{Kind: KindHandshake, Raw: raw})
	})
}

func FuzzDecodeAck(f *testing.F) {
	f.Add([]byte(`{"op":5,"watches":0}`))
	f.Add([]byte(`{"op":9}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkAcceptedPayload(t, frame{Kind: KindAck, Raw: raw})
	})
}

// TestFramingRefusesKindZeroAndOversize pins the two framing rules the
// rust side was found to disagree on (kind 0) and enforces before any
// allocation (oversize).
func TestFramingRefusesKindZeroAndOversize(t *testing.T) {
	fr := newFramer(bytes.NewReader(frameBytes(0, 1, []byte(`{}`))), io.Discard)
	if _, err := fr.readFrame(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("kind 0 accepted: %v", err)
	}
	var big [12]byte
	putU32(big[0:4], uint32(KindEvent))
	putU32(big[4:8], 0xFFFFFFFF)
	fr = newFramer(bytes.NewReader(big[:]), io.Discard)
	if _, err := fr.readFrame(); !errors.Is(err, ErrFrameTooBig) {
		t.Fatalf("oversize accepted: %v", err)
	}
}
