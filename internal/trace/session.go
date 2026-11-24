// package trace implements the go half of the phase 6 tracer contract:
// framing, handshake, controls and clock-offset bookkeeping towards the
// deprehendo-trace rust component. the rust side mirrors schema.go and
// framing.go exactly (docs/tracing/protocol.md).
package trace

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// CommandTimeout bounds one control round trip.
const CommandTimeout = 5 * time.Second

// ErrIdentityMismatch is returned when the tracer's §6.3 b environment cannot
// coexist with the agent's: another boot, another PID namespace or another
// event clock. each is permanent for the machine. the supervisor must
// degrade cleanly instead of retrying, and the error text says what
// mismatched.
var ErrIdentityMismatch = errors.New("trace: tracer identity mismatch")

// session is the go side of one tracer connection (6.5/6.7/6.24). the tracer
// (rust) is the server end of the unix socket and emits events; the go agent
// connects, handshakes, then drives the watch set with controls that are
// acknowledged synchronously.
//
// guarantees (session_test.go):
//   - a tracer crash or close ends the reader loop and leaves the go process
//     alive;
//   - any protocol error tears the session down, never panics;
//   - watch-set updates are acknowledged with the new watch count, so
//     callers know the filter is live;
//   - a slow sink cannot stall the socket: the reader loop never blocks on
//     the sink, the kernel socket buffer provides real backpressure and any
//     resulting loss is visible in sequence gaps (6.25/6.26).
type Session struct {
	Version uint32
	Caps    Capabilities
	// SelectionReason is the tracer's account of its backend choice (6.53).
	SelectionReason string
	// ClockOffsetNs is the coarse agent-monotonic minus tracer-monotonic
	// offset sampled at handshake (6.28). ordering across the process border
	// is anchored on monotonic time within one boot; wall timestamps are
	// never compared across the bridge.
	ClockOffsetNs int64
	// identity is the agent's own §6.3 b environment recorded at handshake,
	// alongside caps which carries the tracer's side: a later report can
	// always say whose boot and namespace the session served.
	Identity LocalIdentity

	conn    net.Conn
	f       framer
	mu      sync.Mutex // serializes writes and guards loss/health/frame bookkeeping
	lastSeq uint64
	lost    uint64 // events inferred lost from sequence gaps (6.26/6.27)

	// §6.3 d/e bookkeeping. lostStages accumulates the per-stage deltas the
	// LOSS frames carry (each frame reports what moved since the previous
	// one); unknownStageLost catches stages this build does not name yet, so
	// an out-of-range stage never makes loss vanish silently. lastFrameAt
	// is the arrival time of the newest frame of any kind, the liveness
	// fact the supervisor's silence watchdog reads (HealthSilenceInterval).
	lostStages       [4]uint64
	unknownStageLost uint64
	lastHealth       TracerHealth
	lastHealthAt     time.Time
	lastFrameAt      time.Time
	sink             Sink
	controlWait      chan ControlAck // set immediately before write; never two controls at once (single-driver rule)

	// errOnce publishes the terminal error and closes closedCh exactly once;
	// errMu guards the value so a status reader can call err() on a live
	// session without consuming the publish-once (which used to leave
	// closedCh open forever and hang close()).
	errOnce  sync.Once
	errMu    sync.Mutex
	err      error
	closedCh chan struct{}
}

// sink receives decoded events. it must return quickly and perform no
// unbounded work: see the type doc for the backpressure stance.
type Sink func(TraceEvent)

// SessionOptions bounds one session bring-up.
type SessionOptions struct {
	// socket path of the tracer listener.
	Socket string
	Sink   Sink
	// HandshakeTimeout bounds the initial exchange (default 5 s).
	HandshakeTimeout time.Duration
}

// connect performs the handshake and starts the reader loop. the returned
// session is usable even with zero capabilities: the caller degrades
// deliberately (6.20).
func Connect(o SessionOptions) (*Session, error) {
	if o.Sink == nil {
		o.Sink = func(TraceEvent) {}
	}
	timeout := o.HandshakeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.Dial("unix", o.Socket)
	if err != nil {
		return nil, fmt.Errorf("trace: dial %s: %w", o.Socket, err)
	}
	s := &Session{
		conn:        conn,
		f:           newFramer(conn, conn),
		sink:        o.Sink,
		controlWait: make(chan ControlAck, 1),
		closedCh:    make(chan struct{}),
		Identity:    localIdentityFn(),
	}
	if err := s.handshake(timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go s.readLoop()
	return s, nil
}

// handshake sends the agent's info, then reads the tracer's. version
// negotiation is range-overlap based: connect only if our protocol version
// is inside [theirs.MinVersion, theirs.ProtocolVersion].
func (s *Session) handshake(timeout time.Duration) error {
	_ = s.conn.SetDeadline(time.Now().Add(timeout))
	mine := Handshake{
		ProtocolVersion: ProtocolVersion,
		MinVersion:      ProtocolVersionMin,
		TracerVersion:   "go-agent-1",
		SchemaVersion:   SchemaVersion,
		MonotonicNs:     time.Now().UnixNano(),
		WallUnixMs:      time.Now().UnixMilli(),
		// §6.3 b: the agent's own identity goes on the wire so the tracer
		// can run the same checks in its direction.
		BootID:            s.Identity.BootID,
		PIDNamespaceInode: s.Identity.PIDNamespaceInode,
		EventClock:        EventClockMonotonic,
	}
	payload, err := encodeHandshake(mine)
	if err != nil {
		return err
	}
	if err := s.f.writeFrame(KindHandshake, SchemaVersion, payload); err != nil {
		return fmt.Errorf("trace: send handshake: %w", err)
	}
	frame, err := s.f.readFrame()
	if err != nil {
		return fmt.Errorf("trace: handshake: %w", err)
	}
	if frame.Kind != KindHandshake {
		return fmt.Errorf("trace: expected handshake frame, got kind %d", frame.Kind)
	}
	theirs, err := decodeHandshake(frame.Raw)
	if err != nil {
		return err
	}
	if theirs.SchemaVersion != SchemaVersion {
		return fmt.Errorf("trace: tracer schema %d, agent schema %d", theirs.SchemaVersion, SchemaVersion)
	}
	if err := s.checkIdentity(theirs); err != nil {
		return err
	}
	if conflict := theirs.Capabilities.Conflict(); conflict != "" {
		return fmt.Errorf("%w: capability states contradict the boolean claims: %s", ErrProtocol, conflict)
	}
	s.Version = theirs.ProtocolVersion
	s.Caps = theirs.Capabilities
	s.SelectionReason = theirs.SelectionReason
	// the handshake frames themselves are the first liveness signal; the
	// silence watchdog reads lastFrameAt from here on (§6.3 e).
	s.mu.Lock()
	s.lastFrameAt = time.Now()
	s.mu.Unlock()
	// 6.28: both sides pair (monotonic, wall) at handshake. the agent keeps
	// the difference as bookkeeping; ordering decisions must never compare
	// the two wall clocks.
	s.ClockOffsetNs = mine.MonotonicNs - theirs.MonotonicNs
	_ = s.conn.SetDeadline(time.Time{})
	return nil
}

// checkIdentity enforces §6.3 b on the tracer's side of the handshake.
// any fact either side does not know is skipped ("unknown", never
// fabricated): a mismatch is only decidable when both sides know.
func (s *Session) checkIdentity(theirs Handshake) error {
	if theirs.EventClock != "" && theirs.EventClock != EventClockMonotonic {
		return fmt.Errorf("%w: tracer stamps events on clock %q, the agent's clock is %q", ErrIdentityMismatch, theirs.EventClock, EventClockMonotonic)
	}
	if s.Identity.BootID != "" && theirs.BootID != "" && s.Identity.BootID != theirs.BootID {
		return fmt.Errorf("%w: tracer boot_id differs from the agent's boot (%q vs %q): the socket names a tracer from a previous boot", ErrIdentityMismatch, theirs.BootID, s.Identity.BootID)
	}
	if s.Identity.PIDNamespaceInode != 0 && theirs.PIDNamespaceInode != 0 && s.Identity.PIDNamespaceInode != theirs.PIDNamespaceInode {
		return fmt.Errorf("%w: tracer reports PID-namespace inode %d but the agent's is %d: its PIDs are not the agent's PIDs", ErrIdentityMismatch, theirs.PIDNamespaceInode, s.Identity.PIDNamespaceInode)
	}
	return nil
}

// readLoop decodes frames sequentially: events go to the sink, acks go to
// the pending control (there can be at most one pending control at a time
// under the single-driver rule). any error terminates the loop once.
func (s *Session) readLoop() {
	err := func() error {
		for {
			frame, err := s.f.readFrame()
			if err != nil {
				return err
			}
			s.mu.Lock()
			s.lastFrameAt = time.Now()
			s.mu.Unlock()
			switch frame.Kind {
			case KindEvent:
				e, err := decodeEvent(frame.Raw)
				if err != nil {
					return err
				}
				s.noteSequence(e)
				s.sink(e)
			case KindLoss:
				// §6.3 d: upstream loss the sending side observed. unlike a
				// sequence gap (lost), this says WHICH mechanism dropped events,
				// and frames arrive promptly enough that the coverage rules can
				// locate the window (§7.1).
				l, err := decodeLoss(frame.Raw)
				if err != nil {
					return err
				}
				s.noteUpstreamLoss(l)
			case KindHealth:
				// §6.3 e: the once-a-second heartbeat. its primary job is to
				// exist; the counters are carried for status surfaces.
				h, err := decodeTracerHealth(frame.Raw)
				if err != nil {
					return err
				}
				s.noteTracerHealth(h)
			case KindAck:
				ack, err := decodeAck(frame.Raw)
				if err != nil {
					return err
				}
				select {
				case s.controlWait <- ack:
				default:
					return fmt.Errorf("%w: unexpected ack %s", ErrProtocol, ack.Op)
				}
			default:
				return fmt.Errorf("trace: unexpected frame kind %d", frame.Kind)
			}
		}
	}()
	_ = s.conn.Close()
	s.errOnce.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		close(s.closedCh)
	})
}

// noteSequence tracks per-session sequence monotonicity. A gap means events
// were lost upstream (never "the missing events did not happen", 6.27); it is
// counted for the reliability metadata (6.48). the first event of a session is
// sequence 1, so a gap before it counts too (principal phase 6 review: losses before
// the first delivered event used to be invisible).
func (s *Session) noteSequence(e TraceEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Sequence > s.lastSeq+1 {
		s.lost += e.Sequence - s.lastSeq - 1
	}
	if e.Sequence > s.lastSeq {
		s.lastSeq = e.Sequence
	}
}

// lost reports how many events were inferred lost from sequence gaps.
func (s *Session) Lost() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lost
}

// noteUpstreamLoss accumulates one LOSS frame (§6.3 d). A frame carries the
// delta since its stage's previous frame, so counts add; a stage this build
// does not name is kept in its own bucket. upstream loss must never be
// underreported because a future wire added a stage.
func (s *Session) noteUpstreamLoss(l Loss) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Stage >= StageKernel && int(l.Stage) <= len(s.lostStages) {
		s.lostStages[l.Stage-1] += l.CountAtLeast
		return
	}
	s.unknownStageLost += l.CountAtLeast
}

// noteTracerHealth records the newest HEALTH snapshot (§6.3 e).
func (s *Session) noteTracerHealth(h TracerHealth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHealth = h
	s.lastHealthAt = time.Now()
}

// LostUpstream is the total loss the tracer itself reported (LOSS frames).
// it is distinct from (and in addition to) lost(): gaps are inferred on
// the receiving side, LOSS frames name the sending side's stage.
func (s *Session) LostUpstream() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total uint64
	for _, c := range s.lostStages {
		total += c
	}
	return total + s.unknownStageLost
}

// LostUpstreamByStage breaks LostUpstream() down by named stage, index
// stage-1, plus one trailing entry for stages this build does not name.
func (s *Session) LostUpstreamByStage() [5]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [5]uint64
	copy(out[:], s.lostStages[:])
	out[4] = s.unknownStageLost
	return out
}

// LastTracerHealth reports the newest HEALTH frame and when it arrived,
// with ok=false before the first one. (§6.3 e)
func (s *Session) LastTracerHealth() (TracerHealth, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastHealthAt.IsZero() {
		return TracerHealth{}, time.Time{}, false
	}
	return s.lastHealth, s.lastHealthAt, true
}

// LastFrameAt is when the newest frame of any kind arrived; the supervisor
// reads it to enforce HealthSilenceInterval. zero only before the handshake
// completes, which no live session can observe.
func (s *Session) LastFrameAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFrameAt
}

// control sends a control op and waits for the tracer's ack. the single-
// driver rule: callers must not invoke control concurrently (the recorder
// drive path is single-goroutine; violations fail loudly here rather than
// corrupting ack routing). A non-empty ack.Err is an error.
func (s *Session) Control(c Control, timeout time.Duration) error {
	_, err := s.ControlAck(c, timeout)
	return err
}

// ControlAck is control returning the tracer's acknowledgement, for callers
// that need its contents (the watch tracker reads the stale PIDs of an ADD).
func (s *Session) ControlAck(c Control, timeout time.Duration) (ControlAck, error) {
	payload, err := encodeControl(c)
	if err != nil {
		return ControlAck{}, err
	}
	select {
	case <-s.closedCh:
		return ControlAck{}, fmt.Errorf("trace: session closed: %w", s.Err())
	default:
	}
	select {
	case <-s.controlWait:
		return ControlAck{}, fmt.Errorf("%w: stale ack in flight", ErrProtocol)
	default:
	}
	s.mu.Lock()
	err = s.f.writeFrame(KindControl, SchemaVersion, payload)
	s.mu.Unlock()
	if err != nil {
		return ControlAck{}, fmt.Errorf("trace: send %s: %w", c.Op, err)
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case ack := <-s.controlWait:
		if ack.Err != "" {
			return ack, fmt.Errorf("trace: %s rejected: %s", c.Op, ack.Err)
		}
		return ack, nil
	case <-t.C:
		return ControlAck{}, fmt.Errorf("trace: %s ack timed out", c.Op)
	case <-s.closedCh:
		return ControlAck{}, fmt.Errorf("trace: session closed: %w", s.Err())
	}
}

// close shuts the session down gracefully, attempting SHUTDOWN first so the
// tracer exits cleanly (6.7). an already-dead tracer is not an error.
func (s *Session) Close(timeout time.Duration) error {
	closeerr := s.Control(Control{Op: OpShutdown}, timeout)
	_ = s.conn.Close()
	<-s.closedCh
	if closeerr != nil && s.Err() == nil {
		return closeerr
	}
	return nil
}

// err returns the terminal reader-loop error, or nil while still running.
// it is safe to call at any time: reading the error must not affect the
// session's own shutdown bookkeeping.
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// done closes when the reader loop terminates for any reason.
func (s *Session) Done() <-chan struct{} { return s.closedCh }
