//! The wire contract between deprehendo-trace (Rust) and the Go agent.
//!
//! This module mirrors `internal/trace/schema.go` exactly. The two files MUST
//! be changed together: field names, tag casing, event-type numbers and
//! version constants are part of the protocol (docs/tracing/protocol.md).
//!
//! Design points carried over from the Go side:
//! - JSON with explicit snake_case names, framed by u32 kind/length headers
//!   (framing.rs). The encoding is deliberately boring; correctness comes
//!   from framing, bounds and version negotiation.
//! - Sequence numbers are per-session and monotonic. A receiver-observed gap
//!   means loss, never "the missing events did not happen" (issue 6.27).
//! - Wall time is disclosure, never the causal ordering key (6.28).
//! - PID != identity: start_ticks carries the kernel's identity key.

use serde::{Deserialize, Serialize};

/// Version of the trace event schema (additive fields keep compatibility).
pub const SCHEMA_VERSION: u16 = 1;
/// Handshake protocol version; matching range is checked on both sides.
///
/// Protocol 2 adds the LOSS (kind 5) and HEALTH (kind 6) frames, the
/// handshake boot/namespace/clock fields and per-capability states
/// (contract §6.3 b–e). A 1..1 peer negotiates to 1: the newer side must
/// then never emit the new kinds (compatibility policy, §6.4).
pub const PROTOCOL_VERSION: u32 = 2;
/// Oldest protocol version this tracer speaks.
pub const PROTOCOL_VERSION_MIN: u32 = 1;

/// Sentinel for an unsigned identity/env fact that an OS could not
/// determine. "Unknown", never a fabricated value.
pub const UNKNOWN_U64: u64 = 0;
/// Effectively negotiated protocol version for a session: the overlap of
/// both peers' ranges. Today a single integer per side, so `min`; the
/// caller has already verified the spans intersect.
pub fn negotiated_protocol(their_protocol_version: u32, _their_min: u32) -> u32 {
    PROTOCOL_VERSION.min(their_protocol_version)
}

/// One framed message must never exceed this; larger is a protocol error.
pub const MAX_FRAME_SIZE: u32 = 1 << 20; // 1 MiB
/// Watch-set bound shared with the Go decoder.
pub const MAX_WATCH_SET_ENTRIES: usize = 4096;

/// Stable event-type numbers. Never renumber, never reuse. (HANDSHAKE sits
/// at 0 so it can never collide with a real stream event.)
pub const TYPE_HANDSHAKE: u16 = 0;
pub const TYPE_EXEC: u16 = 1;
pub const TYPE_EXIT: u16 = 2;
pub const TYPE_SIGNAL: u16 = 3;
pub const TYPE_STOP: u16 = 4;
pub const TYPE_CONT: u16 = 5;
pub const TYPE_OOM: u16 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventType(pub u16);

impl EventType {
    /// Product vocabulary, matching the Go `String()` methods.
    pub fn name(self) -> &'static str {
        match self.0 {
            TYPE_EXEC => "PROCESS_EXEC",
            TYPE_EXIT => "PROCESS_EXIT",
            TYPE_SIGNAL => "SIGNAL_SENT",
            TYPE_STOP => "PROCESS_STOPPED",
            TYPE_CONT => "PROCESS_RESUMED",
            TYPE_OOM => "OOM_KILL",
            TYPE_HANDSHAKE => "HANDSHAKE",
            _ => "TRACE_EVENT_UNKNOWN",
        }
    }
}

/// What the kernel mechanism actually established about a signal (6.14).
/// The numbers match `SignalFact` in Go.
#[allow(dead_code)] // wire contract: numbers are shared with internal/trace/schema.go
pub const FACT_SIGNAL_SENT: u8 = 1;
pub const FACT_EXITED_BY_SIGNAL: u8 = 2;
#[allow(dead_code)]
pub const FACT_OBSERVED_STOP: u8 = 3;

/// Provenance: which backend produced the event (6.29). Matches `Source`.
/// Never renumber: SOURCE_EBPF (3) is the primary backend's provenance, an
/// additive extension the Go decoder reads as a known source.
pub const SOURCE_PROC_CONNECTOR: u8 = 1;
#[allow(dead_code)]
pub const SOURCE_SYNTHETIC: u8 = 2;
pub const SOURCE_EBPF: u8 = 3;

/// One high-resolution lifecycle observation. Field names are the contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEvent {
    #[serde(rename = "schema_version")]
    pub schema_version: u16,
    #[serde(rename = "sequence")]
    pub sequence: u64,
    /// CLOCK_MONOTONIC at capture, nanoseconds; the ordering anchor.
    #[serde(rename = "monotonic_ns")]
    pub monotonic_ns: i64,
    /// Wall clock at capture, epoch milliseconds: disclosure only.
    #[serde(rename = "wall_unix_ms")]
    pub wall_unix_ms: i64,
    #[serde(
        rename = "clock_offset_ns",
        skip_serializing_if = "is_zero_i64",
        default
    )]
    pub clock_offset_ns: i64,
    #[serde(rename = "type")]
    pub event_type: EventType,
    #[serde(rename = "pid")]
    pub pid: u32,
    #[serde(rename = "ppid", skip_serializing_if = "is_zero_u32", default)]
    pub ppid: u32,
    #[serde(rename = "pgid", skip_serializing_if = "is_zero_u32", default)]
    pub pgid: u32,
    /// Process start time in clock ticks: the kernel identity key (6.11).
    #[serde(rename = "start_ticks", skip_serializing_if = "is_zero_i64", default)]
    pub start_ticks: i64,
    /// Executable path for EXEC events. argv/env are deliberately absent:
    /// they are private by default (privacy review, 6.54).
    #[serde(
        rename = "exec_path",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub exec_path: String,
    /// Real exit status when the kernel exposed one. `None` == unknown:
    /// encoding omits the field, and a decoded 0 is a real exit(0).
    #[serde(rename = "exit_code", skip_serializing_if = "Option::is_none", default)]
    pub exit_code: Option<i32>,
    /// Source signal number for SIGNAL / signaled EXIT (0 = none).
    #[serde(rename = "signal", skip_serializing_if = "is_zero_u8", default)]
    pub signal: u8,
    #[serde(rename = "sender_pid", skip_serializing_if = "is_zero_u32", default)]
    pub sender_pid: u32,
    #[serde(rename = "fact", skip_serializing_if = "is_zero_u8", default)]
    pub fact: u8,
    #[serde(rename = "source")]
    pub source: u8,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Handshake payload, first frame in each direction. Field names mirror
/// `Handshake` in Go. Protocol 2 adds the §6.3 b identity/environment
/// fields; a 1.x peer that does not know them simply ignores the new
/// optional fields (compatibility policy §6.4, additive with defaults).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Handshake {
    #[serde(rename = "protocol_version")]
    pub protocol_version: u32,
    #[serde(rename = "min_version")]
    pub min_version: u32,
    #[serde(rename = "tracer_version")]
    pub tracer_version: String,
    #[serde(rename = "capabilities")]
    pub capabilities: Capabilities,
    #[serde(rename = "monotonic_ns")]
    pub monotonic_ns: i64,
    #[serde(rename = "wall_unix_ms")]
    pub wall_unix_ms: i64,
    #[serde(rename = "schema_version")]
    pub schema_version: u16,
    /// Boot identity (/proc/sys/kernel/random/boot_id). A session refuse
    /// when both sides know it and it differs: a socket file surviving a
    /// reboot names a tracer that is not this kernel's (§6.3 b, §11.1).
    #[serde(rename = "boot_id", skip_serializing_if = "String::is_empty", default)]
    pub boot_id: String,
    /// Inode of /proc/self/ns/pid. A tracer outside our PID namespace
    /// reports PIDs that are meaningless to the agent (§2, initial-ns rule).
    #[serde(
        rename = "pid_namespace_inode",
        skip_serializing_if = "is_zero_u64",
        default
    )]
    pub pid_namespace_inode: u64,
    /// The clock all event timestamps are expressed in. Ordering across the
    /// two processes is only valid when both sides stamp the same clock.
    #[serde(
        rename = "event_clock",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub event_clock: String,
    /// Set only when the primary backend was refused and a lower one was
    /// selected (contract §2.1: each step's failure reason is visible, and
    /// the agent can state it). Empty means the primary was chosen.
    #[serde(
        rename = "selection_reason",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub selection_reason: String,
}

pub const EVENT_CLOCK_MONOTONIC: &str = "monotonic";

/// What this build/kernel can really observe (6.8). The agent must consult
/// this before assuming any feature exists.
///
/// §6.3 b adds one `{state, reason}` pair per capability: the boolean says
/// what the backend can observe, the state says what actually happened at
/// attach time ("attached", "unavailable: ..."), so a missing capability
/// carries its why with it instead of a silent false.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Capabilities {
    #[serde(rename = "process_exec")]
    pub process_exec: bool,
    #[serde(rename = "process_exit")]
    pub process_exit: bool,
    #[serde(rename = "signals")]
    pub signals: bool,
    #[serde(rename = "stop_resume")]
    pub stop_resume: bool,
    #[serde(rename = "oom_kill")]
    pub oom_kill: bool,
    #[serde(rename = "backend")]
    pub backend: String,
    #[serde(rename = "kernel")]
    pub kernel: String,
    #[serde(rename = "privileged")]
    pub privileged: bool,
    #[serde(rename = "unprivileged")]
    pub unprivileged: bool,
    #[serde(rename = "unsupported")]
    pub unsupported: bool,
    #[serde(
        rename = "exec_state",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub exec_state: String,
    #[serde(
        rename = "exec_reason",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub exec_reason: String,
    #[serde(
        rename = "exit_state",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub exit_state: String,
    #[serde(
        rename = "exit_reason",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub exit_reason: String,
    #[serde(
        rename = "signals_state",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub signals_state: String,
    #[serde(
        rename = "signals_reason",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub signals_reason: String,
    #[serde(
        rename = "stop_resume_state",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub stop_resume_state: String,
    #[serde(
        rename = "stop_resume_reason",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub stop_resume_reason: String,
    #[serde(
        rename = "oom_state",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub oom_state: String,
    #[serde(
        rename = "oom_reason",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub oom_reason: String,
}

/// Per-capability states. "attached" is earned at attach time, never
/// assumed from a kernel-version guess (§2.1).
pub const CAP_STATE_ATTACHED: &str = "attached";
pub const CAP_STATE_UNAVAILABLE: &str = "unavailable";
pub const CAP_STATE_NOT_COLLECTED: &str = "not_collected_by_backend";
/// Loss stages (§6.3 d, §7.1): where events went missing between the
/// kernel and the socket. Numbers are shared with the Go side.
pub const STAGE_KERNEL: u8 = 1;
pub const STAGE_RESUBSCRIBE: u8 = 2;
pub const STAGE_WATCH_FULL: u8 = 3;
pub const STAGE_QUEUE: u8 = 4;

pub fn stage_name(stage: u8) -> &'static str {
    match stage {
        STAGE_KERNEL => "kernel",
        STAGE_RESUBSCRIBE => "resubscribe",
        STAGE_WATCH_FULL => "watch_full",
        STAGE_QUEUE => "queue",
        _ => "unknown_stage",
    }
}

/// LOSS frame payload (kind 5, §6.3 d): events were lost upstream and a
/// sequence gap alone cannot say when. `count_at_least` is a lower bound:
/// the kernel reports "at least one" for overrun; it never says exactly.
pub const KIND_LOSS: u8 = 5;
pub const KIND_HEALTH: u8 = 6;

/// HEALTH frame payload (kind 6, §6.3 e): liveness plus live counters, once
/// a second. The agent treats 5 s of frame silence as a hung (§ e) tracer.
pub const HEALTH_INTERVAL_MS: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Loss {
    /// STAGE_*
    #[serde(rename = "stage")]
    pub stage: u8,
    #[serde(rename = "count_at_least")]
    pub count_at_least: u64,
    #[serde(rename = "first_ns")]
    pub first_ns: i64,
    #[serde(rename = "last_ns")]
    pub last_ns: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Health {
    #[serde(rename = "uptime_ms")]
    pub uptime_ms: u64,
    #[serde(rename = "events_sent")]
    pub events_sent: u64,
    #[serde(rename = "events_lost")]
    pub events_lost: u64,
    /// Events waiting in the tracer's internal queue right now.
    #[serde(rename = "queue_depth")]
    pub queue_depth: u32,
    #[serde(rename = "watches")]
    pub watches: u32,
    /// Tracer CLOCK_MONOTONIC at emit: anchors the loss windows on the
    /// same clock as events (§8).
    #[serde(rename = "monotonic_ns")]
    pub monotonic_ns: i64,
}
pub const OP_ADD: u8 = 1;
pub const OP_REMOVE: u8 = 2;
pub const OP_RESET: u8 = 3;
pub const OP_FLUSH: u8 = 4;
pub const OP_PING: u8 = 5;
pub const OP_SHUTDOWN: u8 = 6;
/// Watch a cgroup id rather than PIDs (§5 item 4). Checked like every op;
/// a backend that cannot filter by cgroup answers the ack with `err`.
pub const OP_ADD_CGROUP: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlOp(pub u8);

impl ControlOp {
    /// Matching `ControlOp.String()` in Go; unknown ops still label.
    #[allow(dead_code)]
    pub fn name(self) -> String {
        match self.0 {
            OP_ADD => "ADD_PROCESS".to_string(),
            OP_REMOVE => "REMOVE_PROCESS".to_string(),
            OP_RESET => "RESET_WATCH_SET".to_string(),
            OP_FLUSH => "FLUSH".to_string(),
            OP_PING => "PING".to_string(),
            OP_SHUTDOWN => "SHUTDOWN".to_string(),
            OP_ADD_CGROUP => "ADD_CGROUP".to_string(),
            n => format!("CONTROL_{}", n),
        }
    }
}

/// `pids` accepts three encodings on the wire, all meaning "these PIDs":
/// the list itself (current Go), absent (omitempty, current Go for commands
/// without operands), and JSON null (an older Go encoder with a nil slice).
/// Rejecting null would silently break PING/SHUTDOWN against such an agent,
/// so it is normalized here instead. Serialization always writes a list or
/// nothing at all.
fn null_as_empty_pids<'de, D>(deserializer: D) -> Result<Vec<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pids = Option::<Vec<u32>>::deserialize(deserializer)?;
    Ok(pids.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Control {
    #[serde(rename = "op")]
    pub op: ControlOp,
    #[serde(
        rename = "pids",
        skip_serializing_if = "Vec::is_empty",
        default,
        deserialize_with = "null_as_empty_pids"
    )]
    pub pids: Vec<u32>,
    /// Kernel identity per PID (§6.3 f, §4): `start_ticks[i]` is the
    /// start time of `pids[i]`. An ADD whose start_ticks does not match
    /// the live process is refused (STALE_IDENTITY) so a recycled PID can
    /// never adopt a dead process's watch. Empty when unset: an older
    /// agent that keyes only by PID is still accepted (additive field).
    #[serde(
        rename = "start_ticks",
        skip_serializing_if = "Vec::is_empty",
        default,
        deserialize_with = "null_as_empty_ticks"
    )]
    pub start_ticks: Vec<i64>,
}

fn null_as_empty_ticks<'de, D>(deserializer: D) -> Result<Vec<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ticks = Option::<Vec<i64>>::deserialize(deserializer)?;
    Ok(ticks.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlAck {
    #[serde(rename = "op")]
    pub op: ControlOp,
    #[serde(rename = "watches")]
    pub watches: u32,
    #[serde(rename = "err")]
    pub err: String,
    /// PIDs of an ADD that were refused because their identity no longer
    /// matches the agent's claim (§6.3 f STALE_IDENTITY): the process died,
    /// or its PID was reused. The rest of the ADD was applied. Additive and
    /// omitted when empty, so older agents read the ack unchanged.
    #[serde(rename = "stale", skip_serializing_if = "Vec::is_empty", default)]
    pub stale: Vec<u32>,
}

/// Framing message kinds (matching `MessageKind` in Go). Plain constants:
/// the framing layer keeps the discriminant space tiny and validated.
pub const KIND_EVENT: u8 = 1;
pub const KIND_HANDSHAKE: u8 = 2;
pub const KIND_CONTROL: u8 = 3;
pub const KIND_ACK: u8 = 4;
