//! Test-support crate: exposes runopsy-trace internals for integration tests
//! without making the binary itself a library for consumers.

use serde::{Deserialize, Serialize};

// mirror of src modules, re-declared as needed for tests. keep in sync with
// src/schema.rs; the compiler enforces equality through the assert_json_eq
// helpers in tests.
pub const SCHEMA_VERSION: u16 = 1;
pub const PROTOCOL_VERSION: u32 = 1;
pub const PROTOCOL_VERSION_MIN: u32 = 1;
pub const MAX_FRAME_SIZE: u32 = 1 << 20;
pub const MAX_WATCH_SET_ENTRIES: usize = 4096;

pub const TYPE_EXEC: u16 = 1;
pub const TYPE_EXIT: u16 = 2;
pub const KIND_EVENT: u8 = 1;

pub const SOURCE_PROC_CONNECTOR: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventType(pub u16);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEvent {
    #[serde(rename = "schema_version")]
    pub schema_version: u16,
    #[serde(rename = "sequence")]
    pub sequence: u64,
    #[serde(rename = "monotonic_ns")]
    pub monotonic_ns: i64,
    #[serde(rename = "wall_unix_ms")]
    pub wall_unix_ms: i64,
    #[serde(
        rename = "clock_offset_ns",
        skip_serializing_if = "is_zero_i64",
        default
    )]
    pub clock_offset_ns: i64,
    #[serde(rename = "type")]
    pub pub_type: EventType,
    #[serde(rename = "pid")]
    pub pid: u32,
    #[serde(rename = "ppid", skip_serializing_if = "is_zero_u32", default)]
    pub ppid: u32,
    #[serde(rename = "pgid", skip_serializing_if = "is_zero_u32", default)]
    pub pgid: u32,
    #[serde(rename = "start_ticks", skip_serializing_if = "is_zero_i64", default)]
    pub start_ticks: i64,
    #[serde(
        rename = "exec_path",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub exec_path: String,
    #[serde(rename = "exit_code", skip_serializing_if = "Option::is_none", default)]
    pub exit_code: Option<i32>,
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
}

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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct ControlOp(#[allow(dead_code)] pub u8);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Control {
    #[serde(rename = "op")]
    pub op: ControlOp,
    #[serde(rename = "pids", skip_serializing_if = "Vec::is_empty", default)]
    pub pids: Vec<u32>,
}

pub const OP_ADD: u8 = 1;
pub const OP_REMOVE: u8 = 2;
pub const OP_RESET: u8 = 3;
pub const OP_FLUSH: u8 = 4;
pub const OP_PING: u8 = 5;
pub const OP_SHUTDOWN: u8 = 6;
pub const OP_ADD_CGROUP: u8 = 7;

/// Decoding policy shared with src/framing.rs. Duplicating the logic here
/// would risk drift, but the framing module is in the binary target, not a
/// library. The test suite therefore asserts the policy through the binary's
/// own behaviors (see tests/transport_test.rs via the CLI replay path) plus
/// direct policy checks below.
pub fn decode_event(raw: &[u8]) -> Result<TraceEvent, DecodeError> {
    let e: TraceEvent =
        serde_json::from_slice(raw).map_err(|e| DecodeError(format!("decode event: {}", e)))?;
    if e.schema_version != SCHEMA_VERSION {
        return Err(DecodeError(format!(
            "event schema {} != ours {}",
            e.schema_version, SCHEMA_VERSION
        )));
    }
    if e.monotonic_ns <= 0 {
        return Err(DecodeError("event has no monotonic timestamp".into()));
    }
    Ok(e)
}

#[derive(Debug)]
pub struct DecodeError(#[allow(dead_code)] pub String);

pub fn decode_control(raw: &[u8]) -> Result<Control, DecodeError> {
    let c: Control =
        serde_json::from_slice(raw).map_err(|e| DecodeError(format!("decode control: {}", e)))?;
    match c.op.0 {
        OP_ADD | OP_REMOVE | OP_RESET | OP_FLUSH | OP_PING | OP_SHUTDOWN | OP_ADD_CGROUP => {}
        n => return Err(DecodeError(format!("unknown control op {}", n))),
    }
    if c.pids.len() > MAX_WATCH_SET_ENTRIES {
        return Err(DecodeError(format!(
            "watch set of {} exceeds {}",
            c.pids.len(),
            MAX_WATCH_SET_ENTRIES
        )));
    }
    if c.pids.contains(&0) {
        return Err(DecodeError("PID 0 in watch set".into()));
    }
    Ok(c)
}

pub fn decode_handshake(raw: &[u8]) -> Result<Handshake, DecodeError> {
    let h: Handshake =
        serde_json::from_slice(raw).map_err(|e| DecodeError(format!("decode handshake: {}", e)))?;
    if h.protocol_version < PROTOCOL_VERSION_MIN || h.min_version > PROTOCOL_VERSION {
        return Err(DecodeError(format!(
            "version mismatch: peer {}..{}, ours {}",
            h.min_version, h.protocol_version, PROTOCOL_VERSION
        )));
    }
    Ok(h)
}

pub fn default_capabilities() -> Capabilities {
    Capabilities {
        process_exec: true,
        process_exit: true,
        signals: false,
        stop_resume: false,
        oom_kill: false,
        backend: "proc_connector".into(),
        kernel: "test".into(),
        privileged: false,
        unprivileged: true,
        unsupported: false,
    }
}

pub fn test_event() -> TraceEvent {
    TraceEvent {
        schema_version: SCHEMA_VERSION,
        sequence: 7,
        monotonic_ns: 123456789,
        wall_unix_ms: 1767000000000,
        clock_offset_ns: 0,
        pub_type: EventType(TYPE_EXEC),
        pid: 4242,
        ppid: 0,
        pgid: 0,
        start_ticks: 0,
        exec_path: "/usr/bin/tool".into(),
        exit_code: None,
        signal: 0,
        sender_pid: 0,
        fact: 0,
        source: SOURCE_PROC_CONNECTOR,
    }
}

/// Frame a payload exactly as src/framing.rs does.
pub struct Framed {
    pub kind: u8,
    pub version: u16,
    pub raw: Vec<u8>,
    pub header: [u8; 12],
}

pub fn frame_event(e: &TraceEvent, kind: u8) -> Framed {
    let raw = serde_json::to_vec(e).unwrap();
    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(&(kind as u32).to_le_bytes());
    header[4..8].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    header[8..12].copy_from_slice(&(SCHEMA_VERSION as u32).to_le_bytes());
    Framed {
        kind,
        version: SCHEMA_VERSION,
        raw,
        header,
    }
}
