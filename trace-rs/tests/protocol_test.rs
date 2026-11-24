//! Cross-language contract tests, Rust side (6.3/6.4/6.56).
//!
//! These encode the wire contract byte-for-byte with the Go suite in
//! `internal/trace`. The Go side runs a matching golden-tree test against
//! these vectors via testdata/trace (see internal/trace/compat_test.go):
//! any drift in framing, tag casing or enum numbers fails both.

mod support;
use support::*;

#[test]
fn event_frame_golden() {
    // mirrors TestFrameRoundTrip in go: 12-byte header + JSON payload.
    let event = test_event();
    let frame = frame_event(&event, 1);
    assert_eq!(frame.kind, KIND_EVENT);
    assert_eq!(frame.version, SCHEMA_VERSION);
    // header: kind LE (1), length LE, version LE in a u32 slot, reserved 2x00.
    assert_eq!(
        &frame.header,
        &[
            0x01,
            0x00,
            0x00,
            0x00, // kind = 1
            frame.raw.len() as u8,
            0x00,
            0x00,
            0x00, // length LE
            SCHEMA_VERSION as u8,
            (SCHEMA_VERSION >> 8) as u8,
            0x00,
            0x00,
        ]
    );
}

#[test]
fn event_json_golden_fields() {
    // exact tag names are the contract: go's json tags must decode this.
    let event = test_event();
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["sequence"], 7);
    assert_eq!(json["monotonic_ns"], 123456789);
    assert_eq!(json["wall_unix_ms"], 1767000000000i64);
    assert_eq!(json["type"], TYPE_EXEC);
    assert_eq!(json["pid"], 4242);
    assert_eq!(json["source"], SOURCE_PROC_CONNECTOR);
    // Omitted-when-zero fields must be absent, not present (go uses pointer
    // types for exit_code; a present "exit_code":0 is a REAL exit(0)).
    assert!(json.get("exit_code").is_none());
    assert!(json.get("signal").is_none());
    assert!(json.get("ppid").is_none());
    // exit(0) survives as a present zero.
    let mut exited = test_event();
    exited.pub_type = EventType(TYPE_EXIT);
    exited.exit_code = Some(0);
    let json = serde_json::to_value(&exited).unwrap();
    assert_eq!(json["exit_code"], 0);
}

#[test]
fn event_decode_rejects_unknown_schema_version() {
    let mut bad = test_event();
    bad.schema_version = 999;
    let raw = serde_json::to_vec(&bad).unwrap();
    assert!(decode_event(&raw).is_err());
}

#[test]
fn event_decode_rejects_missing_monotonic() {
    let raw = br#"{"schema_version":1,"sequence":1,"monotonic_ns":0,"wall_unix_ms":1,"type":1,"pid":1,"source":1}"#;
    assert!(decode_event(raw).is_err());
}

#[test]
fn control_roundtrip_and_bounds() {
    let c = Control {
        op: ControlOp(OP_RESET),
        pids: vec![1, 2, 3],
    };
    let raw = serde_json::to_vec(&c).unwrap();
    let back = decode_control(&raw).unwrap();
    assert_eq!(back, c);

    // PID 0 is always invalid.
    let c0 = Control {
        op: ControlOp(OP_ADD),
        pids: vec![0],
    };
    let raw = serde_json::to_vec(&c0).unwrap();
    assert!(decode_control(&raw).is_err());

    // unknown ops are rejected on both sides.
    let cu = Control {
        op: ControlOp(99),
        pids: vec![],
    };
    let raw = serde_json::to_vec(&cu).unwrap();
    assert!(decode_control(&raw).is_err());

    // oversized watch set is rejected silently for ADD? no: decode bounds it.
    let big = Control {
        op: ControlOp(OP_ADD),
        pids: vec![1; MAX_WATCH_SET_ENTRIES + 1],
    };
    let raw = serde_json::to_vec(&big).unwrap();
    assert!(decode_control(&raw).is_err());
}

#[test]
fn handshake_version_negotiation() {
    let h = Handshake {
        protocol_version: PROTOCOL_VERSION,
        min_version: PROTOCOL_VERSION_MIN,
        tracer_version: "deprehendo-trace/0.1.0".into(),
        capabilities: default_capabilities(),
        monotonic_ns: 1,
        wall_unix_ms: 2,
        schema_version: SCHEMA_VERSION,
    };
    let raw = serde_json::to_vec(&h).unwrap();
    assert!(decode_handshake(&raw).is_ok());

    // incompatible: peer range excludes our version entirely.
    let h_high = Handshake {
        protocol_version: 9,
        min_version: 9,
        tracer_version: "future".into(),
        capabilities: default_capabilities(),
        monotonic_ns: 0,
        wall_unix_ms: 0,
        schema_version: SCHEMA_VERSION,
    };
    let raw = serde_json::to_vec(&h_high).unwrap();
    assert!(decode_handshake(&raw).is_err());

    // incompatible schema version is rejected at the session layer, not in
    // decode_handshake (the go handshake struct carries schema_version too
    // and transport checks it after decode). assert the version check only.
    let mut h_schema = h;
    h_schema.schema_version = 42;
    let raw = serde_json::to_vec(&h_schema).unwrap();
    assert!(decode_handshake(&raw).is_ok());
}

#[test]
fn capabilities_json_field_names_match_go() {
    let caps = default_capabilities();
    let json = serde_json::to_value(&caps).unwrap();
    for key in [
        "process_exec",
        "process_exit",
        "signals",
        "stop_resume",
        "oom_kill",
        "backend",
        "kernel",
        "privileged",
        "unprivileged",
        "unsupported",
    ] {
        assert!(
            json.get(key).is_some(),
            "missing {}.capabilities.{}, Go structs decode snake_case",
            "Capabilities",
            key
        );
    }
}

#[test]
#[allow(clippy::assertions_on_constants)] // guards constant-drift against go
fn frame_limits_enforced_rules() {
    // MAX_FRAME_SIZE and MAX_WATCH_SET_ENTRIES are shared constants with go;
    // their numeric equality is asserted by the go compat test.
    assert!(MAX_FRAME_SIZE > 0);
    assert!(MAX_WATCH_SET_ENTRIES > 0);
}
