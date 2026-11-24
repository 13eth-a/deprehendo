// package trace contains the phase 6 wire contract between the go agent and
// the deprehendo-trace rust component. everything in this package is language
// neutral: the rust side implements the identical module in
// trace-rs/src/schema.rs, and the two must be changed together (see
// docs/tracing/protocol.md for the compatibility policy).
package trace

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// SchemaVersion is the version of the trace wire schema. A minor bump
// (additive field with default) keeps compatibility; a major bump breaks it.
const SchemaVersion uint16 = 1

// ProtocolVersion is the handshake protocol version. negotiation is a range
// overlap on both sides (§6.4): a session runs at the smaller of the two
// newest versions, and a peer the session negotiated BELOW 2 must never see
// the protocol-2 frames, so version and wire changes move together.
//
// 2 adds the LOSS (kind 5) and HEALTH (kind 6) frames (§6.3 d/e).
const ProtocolVersion uint32 = 2

// ProtocolVersionMin is the oldest protocol version the go side speaks.
const ProtocolVersionMin uint32 = 1

// MaxFrameSize bounds one framed message. A larger declared length is a
// protocol error, not a memory allocation.
const MaxFrameSize = 1 << 20 // 1 MiB

// MaxWatchSetEntries bounds one control's PID list. A hostile or buggy peer
// cannot make the tracer allocate proportional to a frame, only to this.
const MaxWatchSetEntries = 4096

// TraceSchemaDir is the location of the schema module shared by both
// languages (single source of truth; the rust module mirrors this file).
const TraceSchemaDir = "trace-rs"

// EventType is a stable, numbered trace event type. numbers are the wire
// contract: never renumber, never reuse. unknown numbers on future schema
// minors are recorded, not dropped.
type EventType uint16

const (
	// EventHANDSHAKE is only negotiated out of band (see handshake); it is
	// given number 0 so it can never collide with a real stream event.
	EventHANDSHAKE EventType = 0
	EventEXEC      EventType = 1 // process exec (new program image)
	EventEXIT      EventType = 2 // process exit
	EventSIGNAL    EventType = 3 // signal sent (sender known) or delivered
	EventSTOP      EventType = 4 // SIGSTOP-style stop observed
	EventCONT      EventType = 5 // SIGCONT-style resume observed
	EventOOM       EventType = 6 // OOM kill (capability-gated)
)

// string implements the product vocabulary used in analysis output.
func (t EventType) String() string {
	switch t {
	case EventEXEC:
		return "PROCESS_EXEC"
	case EventEXIT:
		return "PROCESS_EXIT"
	case EventSIGNAL:
		return "SIGNAL_SENT"
	case EventSTOP:
		return "PROCESS_STOPPED"
	case EventCONT:
		return "PROCESS_RESUMED"
	case EventOOM:
		return "OOM_KILL"
	case EventHANDSHAKE:
		return "HANDSHAKE"
	default:
		return fmt.Sprintf("TRACE_EVENT_%d", uint16(t))
	}
}

// signal semantics (6.14): the kernel does not let userspace observe signal
// delivery as a generic event, so deprehendo records strictly weaker facts and
// lets the causal engine treat them accordingly.
type SignalFact uint8

const (
	// SignalSent records an observed signal send where the sender PID is
	// known. it never asserts delivery.
	SignalSent SignalFact = 1
	// SignalDeliveredToExit records that the process exited by a signal
	// (the exit record names it). it implies that the signal arrived, but
	// never which sender delivered it.
	SignalDeliveredToExit SignalFact = 2
	// SignalObservedStop records a stop of the target without sender or
	// delivery claims beyond the stop itself.
	SignalObservedStop SignalFact = 3
)

func (f SignalFact) String() string {
	switch f {
	case SignalSent:
		return "SIGNAL_SENT"
	case SignalDeliveredToExit:
		return "EXITED_BY_SIGNAL"
	case SignalObservedStop:
		return "SIGNAL_STOP"
	default:
		return fmt.Sprintf("SIGNAL_FACT_%d", uint8(f))
	}
}

// source records where a trace event came from, for provenance tagging
// (6.29/6.47): the go side must never merge trace data into an incident
// without it.
type Source uint8

const (
	// SourceProcConnector is the linux proc connector (netlink CN_IDX_PROC).
	SourceProcConnector Source = 1
	// SourceSynthetic is used by replay fixtures and tests only, and is
	// never written by a real tracer.
	SourceSynthetic Source = 2
	// SourceEBPF is the primary phase 6 backend: tracepoints + ring buffer
	// (contract §2.1). its sent/stop/oom events carry facts the proc
	// connector cannot produce; provenance differs, facts do not.
	SourceEBPF Source = 3
)

func (s Source) String() string {
	switch s {
	case SourceProcConnector:
		return "proc_connector"
	case SourceSynthetic:
		return "synthetic"
	case SourceEBPF:
		return "ebpf"
	default:
		return fmt.Sprintf("source_%d", uint8(s))
	}
}

// TraceEvent is one high-resolution lifecycle observation. it is the
// platform-neutral record; the transport frames it and the encoder stamps
// sequence and ClockOffset.
type TraceEvent struct {
	// SchemaVersion is stamped by the sender, checked by the receiver.
	SchemaVersion uint16 `json:"schema_version"`
	// sequence is a monotonically increasing per-session counter. A gap
	// means loss: never interpret a gap as "the missing events did not
	// happen" (6.27).
	Sequence uint64 `json:"sequence"`
	// MonotonicNs is CLOCK_MONOTONIC at capture, the ordering anchor.
	MonotonicNs int64 `json:"monotonic_ns"`
	// WallUnixMs is wall time at capture, for human disclosure; it is a
	// secondary, spoofable clock and must never be the causal ordering key
	// (6.28).
	WallUnixMs int64 `json:"wall_unix_ms"`
	// ClockOffsetNs is stamped at handshake: monotonic(agent) minus
	// monotonic(tracer). the agent folds it into MonotonicNs locally; it is
	// not authoritative per event.
	ClockOffsetNs int64     `json:"clock_offset_ns,omitempty"`
	Type          EventType `json:"type"`
	PID           uint32    `json:"pid"`
	PPID          uint32    `json:"ppid,omitempty"`        // 0 = unknown
	PGID          uint32    `json:"pgid,omitempty"`        // 0 = unknown
	StartTicks    int64     `json:"start_ticks,omitempty"` // kernel identity key, not PID
	ExecPath      string    `json:"exec_path,omitempty"`   // EXEC only; argv is deliberately absent (privacacy, 6.54)
	// ExitCode is nil when the exit status was not captured (the ordinary
	// short-lived/reaped case). A present 0 is a real exit(0), which is
	// evidence and must survive; a signaled exit carries signal instead.
	ExitCode  *int32     `json:"exit_code,omitempty"`
	Signal    uint8      `json:"signal,omitempty"`     // SIGNAL/EXIT source signal number (0 = none)
	SenderPID uint32     `json:"sender_pid,omitempty"` // SIGNAL only; 0 = unknown sender
	Fact      SignalFact `json:"fact,omitempty"`
	Source    Source     `json:"source"`
}

// ExitStatus renders the exit result in the same vocabulary as the incident
// Event.ExitStatus field ("exit:<code>" or "signal:<number>"). A signaled
// exit carries signal, never a code.
func (e TraceEvent) ExitStatus() string {
	if e.Type != EventEXIT {
		return ""
	}
	if e.Signal != 0 {
		return "signal:" + strconv.Itoa(int(e.Signal))
	}
	if e.ExitCode == nil {
		return ""
	}
	return "exit:" + strconv.Itoa(int(*e.ExitCode))
}

// handshake is the first frame on a connection in each direction. each side
// states its protocol version and capabilities; go then acts as the driver
// (6.7) by sending the initial watch set. every protocol struct carries
// explicit snake_case tags: the wire names are part of the contract and must
// not depend on either language's field-naming conventions.
type Handshake struct {
	ProtocolVersion uint32       `json:"protocol_version"`
	MinVersion      uint32       `json:"min_version"`
	TracerVersion   string       `json:"tracer_version"`
	Capabilities    Capabilities `json:"capabilities"`
	// MonotonicNs/WallUnixMs are the clock pair sampled at write time by
	// the sender, for the receiver's offset estimate (6.28).
	MonotonicNs   int64  `json:"monotonic_ns"`
	WallUnixMs    int64  `json:"wall_unix_ms"`
	SchemaVersion uint16 `json:"schema_version"`
	// SelectionReason says how the tracer chose its backend and, when it
	// refused the mechanism, why (6.53). carried to the health report.
	SelectionReason string `json:"selection_reason,omitempty"`
	// §6.3 b identity/environment. `boot_id` and the PID-namespace inode
	// are omitted when the OS does not expose them, and an unknown fact
	// never mismatches: a value is only checked when both sides know
	// ("unknown", never fabricated). `event_clock` names the clock all
	// event timestamps are stamped in; ordering across the process border
	// is only valid when both sides stamp the same one (§8).
	BootID            string `json:"boot_id,omitempty"`
	PIDNamespaceInode uint64 `json:"pid_namespace_inode,omitempty"`
	EventClock        string `json:"event_clock,omitempty"`
}

// capabilities states what this tracer build/kernel can actually observe
// (6.8). go must not assume a feature exists without checking it here.
type Capabilities struct {
	ProcessExec  bool   `json:"process_exec"`
	ProcessExit  bool   `json:"process_exit"`
	Signals      bool   `json:"signals"`
	StopResume   bool   `json:"stop_resume"`
	OOMKill      bool   `json:"oom_kill"`
	Backend      string `json:"backend"` // e.g. "proc_connector"; "" = none compiled in
	Kernel       string `json:"kernel"`  // uts_release, informational
	Privileged   bool   `json:"privileged"`
	Unprivileged bool   `json:"unprivileged"`
	Unsupported  bool   `json:"unsupported"` // kernel lacks the mechanism entirely
	// §6.3 b: one {state, reason} pair per capability. the boolean says what
	// the backend can observe, the state what actually happened at attach
	// time, so a missing capability carries its why with it instead of a
	// silent false. the pairs follow the rust field names exactly.
	ExecState        string `json:"exec_state,omitempty"`
	ExecReason       string `json:"exec_reason,omitempty"`
	ExitState        string `json:"exit_state,omitempty"`
	ExitReason       string `json:"exit_reason,omitempty"`
	SignalsState     string `json:"signals_state,omitempty"`
	SignalsReason    string `json:"signals_reason,omitempty"`
	StopResumeState  string `json:"stop_resume_state,omitempty"`
	StopResumeReason string `json:"stop_resume_reason,omitempty"`
	OomState         string `json:"oom_state,omitempty"`
	OomReason        string `json:"oom_reason,omitempty"`
}

// capability attach states (§6.3 b), mirroring trace-rs/src/schema.rs:
// never renumber, never rename.
const (
	// CapStateAttached: the mechanism attached to the kernel successfully.
	CapStateAttached = "attached"
	// CapStateUnavailable: the kernel refused or the attach failed; the
	// reason names it.
	CapStateUnavailable = "unavailable"
	// CapStateNotCollected: this backend does not collect the event class.
	CapStateNotCollected = "not_collected_by_backend"
)

// EventClockMonotonic is the only clock both implementations stamp event
// timestamps in (CLOCK_MONOTONIC, §8). any other value is refused at the
// handshake, because cross-process ordering is meaningless otherwise.
const EventClockMonotonic = "monotonic"

// CapabilityConflict reports the name of the first capability whose boolean
// and attach state contradict each other (§6.3 b coherence), or "" when the
// handshake is coherent. A state this build does not know is ignored for
// coherence (additive policy §6.4); only the checked contradictions fail.
func (c Capabilities) Conflict() string {
	pairs := []struct {
		name, state string
		observable  bool
	}{
		{"process_exec", c.ExecState, c.ProcessExec},
		{"process_exit", c.ExitState, c.ProcessExit},
		{"signals", c.SignalsState, c.Signals},
		{"stop_resume", c.StopResumeState, c.StopResume},
		{"oom_kill", c.OomState, c.OOMKill},
	}
	for _, p := range pairs {
		switch p.state {
		case CapStateAttached:
			if !p.observable {
				return p.name + ": state attached, but the capability is false"
			}
		case CapStateUnavailable, CapStateNotCollected:
			if p.observable {
				return p.name + ": claimed observable, but attach state is " + p.state
			}
		}
	}
	return ""
}

// control is the command vocabulary from go to rust (6.23/6.24). each
// mutating command is acknowledged with ControlAck.
type Control struct {
	Op ControlOp `json:"op"`
	// PIDs is the watch-set operand: ADD/REMOVE change the set by those
	// PIDs; RESET replaces it atomically. there is deliberately no
	// recursive "watch my subtree" here: the agent resolves the tree from
	// its own snapshots so the kernel-side rule stays a plain PID set.
	// omitempty matters on the wire: the rust decoder reads a missing pids as
	// an empty list, but a JSON null is a different type and older tracers
	// reject it. commands without operands (PING/SHUTDOWN/FLUSH, and RESET
	// with an empty set) must therefore omit the field entirely.
	PIDs []uint32 `json:"pids,omitempty"`
	// StartTicks, when set, is the identity of each PID (StartTicks[i] for
	// PIDs[i]; 0 = unknown, no claim). the tracer applies an ADD only for
	// PIDs whose live identity still matches and lists the rest in the ack's
	// stale (§6.3 f): a PID reused while the tracer restarted is refused
	// instead of adopted. omitted when no identity is known, which keeps the
	// frame identical to a PID-only agent's.
	StartTicks []int64 `json:"start_ticks,omitempty"`
}

type ControlOp uint8

const (
	OpAdd      ControlOp = 1
	OpRemove   ControlOp = 2
	OpReset    ControlOp = 3
	OpFlush    ControlOp = 4
	OpPing     ControlOp = 5
	OpShutdown ControlOp = 6
	// OpAddCgroup watches a cgroup instead of a PID set (§5 item 4). the
	// tracer defines it (OP_ADD_CGROUP in trace-rs/src/schema.rs); a backend
	// that cannot filter by cgroup answers the ack with `err` rather than
	// ignoring the op. the agent does not send it until cgroup watches land,
	// but the decoder must agree with the tracer's vocabulary now (H12).
	OpAddCgroup ControlOp = 7
)

func (op ControlOp) String() string {
	switch op {
	case OpAdd:
		return "ADD_PROCESS"
	case OpRemove:
		return "REMOVE_PROCESS"
	case OpReset:
		return "RESET_WATCH_SET"
	case OpFlush:
		return "FLUSH"
	case OpPing:
		return "PING"
	case OpShutdown:
		return "SHUTDOWN"
	case OpAddCgroup:
		return "ADD_CGROUP"
	default:
		return fmt.Sprintf("CONTROL_%d", uint8(op))
	}
}

// ControlAck confirms one control with the flag state the tracer now holds.
type ControlAck struct {
	Op      ControlOp `json:"op"`
	Watches uint32    `json:"watches"`
	Err     string    `json:"err"` // empty on success
	// stale lists the PIDs of an ADD refused because their identity no
	// longer matched (§6.3 f STALE_IDENTITY); the rest of the ADD applied.
	Stale []uint32 `json:"stale,omitempty"`
}

// MessageKind is the framing types on the socket, per 6.24.
type MessageKind uint8

// LossStage names where events went missing between the kernel and the
// socket (§6.3 d, §7.1). numbers mirror schema.rs STAGE_*: never renumber.
type LossStage uint8

const (
	// StageKernel is the collection mechanism itself (connector ENOBUFS,
	// eBPF ring-buffer reserve failure).
	StageKernel LossStage = 1
	// StageResubscribe is the window while a lost mechanism was re-attached.
	StageResubscribe LossStage = 2
	// StageWatchFull is watch-set overflow, the inheritance refusals.
	StageWatchFull LossStage = 3
	// StageQueue is the tracer's bounded queue count of dropped events.
	StageQueue LossStage = 4
)

func (s LossStage) String() string {
	switch s {
	case StageKernel:
		return "kernel"
	case StageResubscribe:
		return "resubscribe"
	case StageWatchFull:
		return "watch_full"
	case StageQueue:
		return "queue"
	default:
		return "unknown_stage"
	}
}

// loss is the LOSS frame payload (kind 5, §6.3 d). A stage counter move is
// reported at once: gaps alone say THAT events were lost, the window says
// WHEN. CountAtLeast is a lower bound (the kernel reports overrun as "at
// least one") and each frame carries the delta since the previous LOSS
// frame for its stage, so a receiver accumulates instead of replacing.
type Loss struct {
	Stage        LossStage `json:"stage"`
	CountAtLeast uint64    `json:"count_at_least"`
	// FirstNs..LastNs is the window on CLOCK_MONOTONIC, the same clock as
	// event timestamps (§8).
	FirstNs int64 `json:"first_ns"`
	LastNs  int64 `json:"last_ns"`
}

// TracerHealth is the HEALTH frame payload (kind 6, §6.3 e): liveness plus
// live counters, once a second. go is only ever the receiver, so the type
// mirrors the rust side read-only.
type TracerHealth struct {
	UptimeMs   uint64 `json:"uptime_ms"`
	EventsSent uint64 `json:"events_sent"`
	EventsLost uint64 `json:"events_lost"`
	QueueDepth uint32 `json:"queue_depth"`
	Watches    uint32 `json:"watches"`
	// MonotonicNs anchors the health snapshot on the same clock the loss
	// windows and events use (§8).
	MonotonicNs int64 `json:"monotonic_ns"`
}

// HealthSilenceInterval is the receiver-side corollary of the once-a-second
// HEALTH heartbeat (§6.3 e): a session that negotiated protocol 2 must see a
// frame at least this often; longer silence is a hung tracer, which the
// supervisor tears down (6.39). sessions at protocol 1 promise no frames, so
// silence is not observable there and must never be a fault.
const HealthSilenceInterval = 5 * time.Second

const (
	KindEvent     MessageKind = 1
	KindHandshake MessageKind = 2
	KindControl   MessageKind = 3
	KindAck       MessageKind = 4
	// protocol 2 additions (§6.3 d/e). LossStage/TracerHealth below are
	// their payloads; both are tracer→agent only.
	KindLoss   MessageKind = 5
	KindHealth MessageKind = 6
)

// error vocabulary shared by both languages.
var (
	ErrProtocol    = errors.New("trace: protocol violation")
	ErrFrameTooBig = fmt.Errorf("trace: frame exceeds %d bytes", MaxFrameSize)
	ErrShortFrame  = errors.New("trace: truncated frame")
	ErrVersion     = errors.New("trace: protocol version mismatch")
)
