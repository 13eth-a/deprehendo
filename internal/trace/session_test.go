package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeTracer is a minimal in-test server speaking the framing protocol with
// its own loop, so the tests exercise the real go framer and session code.
type fakeTracer struct {
	ln        net.Listener
	conns     []net.Conn
	caps      Capabilities
	pingCount int
}

func startFakeTracer(t *testing.T, caps Capabilities) *fakeTracer {
	t.Helper()
	// macOS sun_path is 104 bytes; the default t.TempDir is too deep.
	dir, err := os.MkdirTemp("", "runopsy-trace-test")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := dir + "/t.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ft := &fakeTracer{ln: ln, caps: caps}
	go ft.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		for _, c := range ft.conns {
			_ = c.Close()
		}
	})
	return ft
}

func (ft *fakeTracer) acceptLoop() {
	for {
		c, err := ft.ln.Accept()
		if err != nil {
			return
		}
		ft.conns = append(ft.conns, c)
		go ft.serve(c)
	}
}

func (ft *fakeTracer) serve(c net.Conn) {
	f := newFramer(c, c)
	frame, err := f.readFrame()
	if err != nil {
		return
	}
	// the agent's handshake is answered with ours; caps from the fixture.
	if frame.Kind != KindHandshake {
		return
	}
	hs, err := decodeHandshake(frame.Raw)
	if err != nil {
		return
	}
	_ = hs
	reply, _ := encodeHandshake(Handshake{
		ProtocolVersion: ProtocolVersion,
		MinVersion:      ProtocolVersionMin,
		TracerVersion:   "test-tracer 1.0",
		Capabilities:    ft.caps,
		SchemaVersion:   SchemaVersion,
		MonotonicNs:     time.Now().UnixNano(),
		WallUnixMs:      time.Now().UnixMilli(),
	})
	if err := f.writeFrame(KindHandshake, SchemaVersion, reply); err != nil {
		return
	}
	seq := uint64(0)
	for {
		frame, err := f.readFrame()
		if err != nil {
			return
		}
		var ackErr string
		c2, err := decodeControl(frame.Raw)
		if err != nil {
			return
		}
		watches := uint32(3)
		switch c2.Op {
		case OpPing:
			ft.pingCount++
		case OpShutdown:
			watches = 0
		}
		ack, _ := encodeAck(ControlAck{Op: c2.Op, Watches: watches, Err: ackErr})
		if err := f.writeFrame(KindAck, SchemaVersion, ack); err != nil {
			return
		}
		if c2.Op == OpShutdown {
			return
		}
		_ = seq
	}
}

// pushEvent writes an event frame to a test-managed connection.
func pushEvent(t *testing.T, c net.Conn, e TraceEvent) {
	t.Helper()
	raw, err := encodeEvent(e)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	f := newFramer(bytes.NewReader(nil), c)
	if err := f.writeFrame(KindEvent, SchemaVersion, raw); err != nil {
		t.Fatalf("push: %v", err)
	}
}

// pushLoss / pushHealth write the §6.3 d/e frames from the tracer side of a
// test connection. they marshal exactly the wire shapes schema.rs encodes;
// the interesting validation lives in the decoders under test.
func pushLoss(t *testing.T, c net.Conn, l Loss) {
	t.Helper()
	raw, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal loss: %v", err)
	}
	f := newFramer(bytes.NewReader(nil), c)
	if err := f.writeFrame(KindLoss, SchemaVersion, raw); err != nil {
		t.Fatalf("push loss: %v", err)
	}
}

func pushHealth(t *testing.T, c net.Conn, h TracerHealth) {
	t.Helper()
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal health: %v", err)
	}
	f := newFramer(bytes.NewReader(nil), c)
	if err := f.writeFrame(KindHealth, SchemaVersion, raw); err != nil {
		t.Fatalf("push health: %v", err)
	}
}

// TestSessionLossAndHealthFrames: the §6.3 d/e frames must be decoded and
// accounted for WITHOUT ending the session. before this support existed the
// first LOSS frame from the production tracer was a protocol error that
// killed the reader loop (the loss/health mismatch).
func TestSessionLossAndHealthFrames(t *testing.T) {
	ft := startFakeTracer(t, Capabilities{})
	collect := newEventCollector()
	s, err := Connect(SessionOptions{Socket: ft.ln.Addr().String(), Sink: collect.add})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = s.conn.Close() }()
	conn := ft.conns[len(ft.conns)-1]

	pushLoss(t, conn, Loss{Stage: StageQueue, CountAtLeast: 3, FirstNs: 100, LastNs: 200})
	pushLoss(t, conn, Loss{Stage: StageQueue, CountAtLeast: 1, FirstNs: 300, LastNs: 400})
	pushLoss(t, conn, Loss{Stage: StageKernel, CountAtLeast: 2, FirstNs: 5, LastNs: 9})
	// A stage this build does not name (schema may add stages, §6.4): its
	// count must still surface, never vanish silently.
	pushLoss(t, conn, Loss{Stage: LossStage(9), CountAtLeast: 4, FirstNs: 500, LastNs: 600})
	pushHealth(t, conn, TracerHealth{UptimeMs: 1500, EventsSent: 12, EventsLost: 6, QueueDepth: 7, Watches: 3, MonotonicNs: 1005000})
	pushEvent(t, conn, TraceEvent{SchemaVersion: SchemaVersion, Sequence: 1, MonotonicNs: 1, Type: EventEXEC, PID: 1})
	s.waitSinkDeadline()
	deadline := time.Now().Add(2 * time.Second)
	for collect.len() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := collect.len(); got != 1 {
		t.Fatalf("got %d events after LOSS/HEALTH frames, want 1 — did the session die against kind 5/6?", got)
	}
	if got := s.LostUpstream(); got != 10 {
		t.Errorf("LostUpstream() = %d, want 10 (frame deltas accumulate: 3+1+2+4)", got)
	}
	stages := s.LostUpstreamByStage()
	if stages[StageQueue-1] != 4 || stages[StageKernel-1] != 2 {
		t.Errorf("per stage = %v, want queue=4 kernel=2", stages)
	}
	if stages[len(stages)-1] != 4 {
		t.Errorf("unknown-stage count = %d, want 4", stages[len(stages)-1])
	}
	if s.Lost() != 0 {
		t.Errorf("sequence-gap loss = %d, want 0 (the counters are distinct)", s.Lost())
	}
	th, at, ok := s.LastTracerHealth()
	if !ok {
		t.Fatal("LastTracerHealth reported no frame")
	}
	if th.EventsSent != 12 || th.EventsLost != 6 || th.QueueDepth != 7 || th.Watches != 3 {
		t.Errorf("last health = %+v, want the pushed snapshot", th)
	}
	if time.Since(at) > 2*time.Second {
		t.Errorf("health arrival timestamp stale: %v", at)
	}
	if s.LastFrameAt().IsZero() {
		t.Errorf("LastFrameAt is zero after frames arrived")
	}
	// the stream is still fully usable: the control path round trips.
	if err := s.Control(Control{Op: OpPing}, time.Second); err != nil {
		t.Fatalf("ping after LOSS/HEALTH frames: %v", err)
	}
}

func TestSessionHandshakeAndControl(t *testing.T) {
	ft := startFakeTracer(t, Capabilities{ProcessExec: true, ProcessExit: true, Backend: "proc_connector"})
	s, err := Connect(SessionOptions{Socket: ft.ln.Addr().String(), Sink: func(TraceEvent) {}})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if s.Version != ProtocolVersion {
		t.Errorf("Version = %d, want %d", s.Version, ProtocolVersion)
	}
	if !s.Caps.ProcessExec {
		t.Errorf("caps lost: %+v", s.Caps)
	}
	if err := s.Control(Control{Op: OpAdd, PIDs: []uint32{4242}}, time.Second); err != nil {
		t.Fatalf("control: %v", err)
	}
	if ft.pingCount != 0 {
		t.Errorf("unexpected ping count %d", ft.pingCount)
	}
	if err := s.Control(Control{Op: OpPing}, time.Second); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if ft.pingCount != 1 {
		t.Errorf("ping count %d, want 1", ft.pingCount)
	}
	if err := s.Close(time.Second); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestSessionSequenceGapsAreCounted(t *testing.T) {
	ft := startFakeTracer(t, Capabilities{})
	collect := newEventCollector()
	s, err := Connect(SessionOptions{
		Socket: ft.ln.Addr().String(),
		Sink:   collect.add,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = s.conn.Close() }()

	conn := ft.conns[len(ft.conns)-1]
	events := []uint64{1, 2, 3, 7, 8, 12}
	for _, seq := range events {
		pushEvent(t, conn, TraceEvent{SchemaVersion: SchemaVersion, Sequence: seq, MonotonicNs: 1, Type: EventEXEC, PID: 1})
		s.waitSinkDeadline()
	}
	deadline := time.Now().Add(2 * time.Second)
	for collect.len() < len(events) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := collect.all(); len(got) != len(events) {
		t.Fatalf("got %d events, want %d", len(got), len(events))
	}
	if want := uint64(6); s.Lost() != want { // gaps 4,5,6,9,10,11 = 6 missing
		t.Errorf("Lost() = %d, want %d", s.Lost(), want)
	}
}

func TestSessionTracerCrashLeavesAgentAlive(t *testing.T) {
	ft := startFakeTracer(t, Capabilities{})
	s, err := Connect(SessionOptions{Socket: ft.ln.Addr().String(), Sink: func(TraceEvent) {}})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// kill the tracer side abruptly.
	for _, c := range ft.conns {
		_ = c.Close()
	}
	<-s.Done()
	if s.Err() == nil {
		t.Errorf("expected terminal error after tracer close")
	}
	// controls against a dead session must not hang or panic.
	if err := s.Control(Control{Op: OpPing}, 100*time.Millisecond); err == nil {
		t.Errorf("control on dead session succeeded")
	}
}

// TestErrOnLiveSessionDoesNotWedgeShutdown is the regression for the churn
// run's finding: err() consumed the publish-once, so a status reader polling
// a healthy session left done() open and close() blocked forever.
func TestErrOnLiveSessionDoesNotWedgeShutdown(t *testing.T) {
	ft := startFakeTracer(t, Capabilities{})
	s, err := Connect(SessionOptions{Socket: ft.ln.Addr().String(), Sink: func(TraceEvent) {}})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("a live session reported a terminal error: %v", err)
	}
	closed := make(chan struct{})
	go func() {
		_ = s.Close(2 * time.Second)
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked after Err() was read on a live session")
	}
	select {
	case <-s.Done():
	default:
		t.Error("Done did not close after Close returned")
	}
}

func TestSessionRejectsMalformedFrames(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"huge-length", headerBytes(KindEvent, 0xFFFFFFF0, SchemaVersion)},
		{"unknown-kind", headerBytes(MessageKind(199), 0, SchemaVersion)},
		{"zero-schema", headerBytes(KindEvent, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ft := startFakeTracer(t, Capabilities{})
			s, err := Connect(SessionOptions{Socket: ft.ln.Addr().String(), Sink: func(TraceEvent) {}})
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			conn := ft.conns[len(ft.conns)-1]
			if _, err := conn.Write(tc.raw); err != nil {
				t.Fatalf("write: %v", err)
			}
			<-s.Done()
			if s.Err() == nil {
				t.Errorf("session survived malformed frame %q; it must tear down", tc.name)
			}
		})
	}
}

func headerBytes(kind MessageKind, length uint32, version uint16) []byte {
	return []byte{
		byte(kind), 0, 0, 0,
		byte(length), byte(length >> 8), byte(length >> 16), byte(length >> 24),
		byte(version), byte(version >> 8), 0, 0,
	}
}

func TestDecodeEventRejectsBadInput(t *testing.T) {
	if _, err := decodeEvent(nil); err == nil {
		t.Errorf("nil event accepted")
	}
	if _, err := decodeEvent([]byte(`{"schema_version":999}`)); err == nil {
		t.Errorf("bad schema accepted")
	}
	if _, err := decodeEvent([]byte(`{`)); err == nil {
		t.Errorf("truncated JSON accepted")
	}
	e, err := decodeEvent([]byte(fmt.Sprintf(`{"schema_version":%d,"sequence":3,"monotonic_ns":10,"type":1,"pid":42}`, SchemaVersion)))
	if err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	if e.Type != EventEXEC || e.PID != 42 {
		t.Errorf("parsed %+v", e)
	}
}

func TestDecodeControlOversized(t *testing.T) {
	all := []uint32{}
	for i := 0; i < 10; i++ {
		all = append(all, 1)
	}
	var sb strings.Builder
	sb.WriteString(`{"op":1,"pids":[`)
	for i := 0; i < 200000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("1")
	}
	sb.WriteString("]}")
	if _, err := decodeControl([]byte(sb.String())); err == nil {
		t.Errorf("giant pid list accepted; the framer caps payloads, but decode must refuse this too")
	}
	_ = all
	// PID 0 is a protocol violation because the kernel never allocates it.
	if _, err := decodeControl([]byte(`{"op":1,"pids":[0]}`)); err == nil {
		t.Errorf("pid 0 accepted")
	}
	// unknown op.
	if _, err := decodeControl([]byte(`{"op":99}`)); err == nil {
		t.Errorf("unknown op accepted")
	}
}

func TestDecodeHandshakeRange(t *testing.T) {
	// the agent speaks 1..2 (protocol 2 adds LOSS/HEALTH; min 1 keeps older
	// tracers connectable). A peer whose span contains ours negotiates;
	// a peer entirely above ours does not.
	ok := []byte(`{"protocol_version":3,"min_version":1,"schema_version":1,"tracer_version":"x"}`)
	if _, err := decodeHandshake(ok); err != nil {
		t.Errorf("peer span containing ours rejected: %v", err)
	}
	broken := []byte(`{"protocol_version":3,"min_version":4,"schema_version":1}`)
	if _, err := decodeHandshake(broken); err == nil {
		t.Errorf("non-overlapping version accepted")
	}
}

func TestFrameSizeLimit(t *testing.T) {
	var buf bytes.Buffer
	f := newFramer(bytes.NewReader(nil), &buf)
	// 1 MiB payload plus 1 byte must be refused by the writer.
	huge := bytes.Repeat([]byte{0x41}, MaxFrameSize+1)
	if err := f.writeFrame(KindEvent, SchemaVersion, huge); err == nil {
		t.Errorf("oversized frame written")
	}
}

type fakeCloser struct{}

func TestEventExitStatusRendering(t *testing.T) {
	code := int32(143)
	e := TraceEvent{Type: EventEXIT, ExitCode: &code}
	if got := e.ExitStatus(); got != "exit:143" {
		t.Errorf("ExitStatus() = %q", got)
	}
	// A signaled exit names its signal, in the incident Event.ExitStatus
	// vocabulary; it must not render as a normal exit code.
	e2 := TraceEvent{Type: EventEXIT, Signal: 9}
	if got := e2.ExitStatus(); got != "signal:9" {
		t.Errorf("ExitStatus() = %q, want signal:9", got)
	}
	e3 := TraceEvent{Type: EventEXIT}
	if got := e3.ExitStatus(); got != "" {
		t.Errorf("unknown exit must render empty, got %q", got)
	}
}

func TestEventTypeStrings(t *testing.T) {
	if EventEXEC.String() != "PROCESS_EXEC" || EventEXIT.String() != "PROCESS_EXIT" || EventSTOP.String() != "PROCESS_STOPPED" {
		t.Errorf("unexpected type strings")
	}
	if EventType(77).String() != "TRACE_EVENT_77" {
		t.Errorf("unknown types must stay stable, got %s", EventType(77))
	}
}

// principal phase 6 review: a session's first event is sequence 1, so events lost
// before the first delivered one are a gap like any other.
func TestNoteSequenceCountsLossBeforeTheFirstEvent(t *testing.T) {
	s := &Session{}
	s.noteSequence(TraceEvent{Sequence: 3})
	s.noteSequence(TraceEvent{Sequence: 4})
	if s.Lost() != 2 {
		t.Fatalf("Lost() = %d, want 2 (sequences 1 and 2 never arrived)", s.Lost())
	}
	clean := &Session{}
	clean.noteSequence(TraceEvent{Sequence: 1})
	if clean.Lost() != 0 {
		t.Fatalf("a stream starting at 1 reported %d lost", clean.Lost())
	}
}
