//! Frame protocol shared with `internal/trace/framing.go`; change both files
//! together. Layout per frame:
//!
//! ```text
//! u32 LE message kind
//! u32 LE payload length
//! u16 LE payload schema version, u16 reserved (0)
//! <length> bytes JSON payload
//! ```
//!
//! A declared length above MAX_FRAME_SIZE is a protocol error, never an
//! allocation. Semantics per frame: a read_timeout(WouldBlock) with zero
//! bytes consumed is a clean `Timeout` (poll state and retry); EOF at a
//! frame boundary is `Ok(None)`; EOF or timeout after bytes were consumed,
//! an oversized length or an unknown kind are all fatal session errors, so
//! no partial state is ever treated as silence.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::schema::*;

#[derive(Debug)]
pub struct ProtocolError(pub String);

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trace protocol error: {}", self.0)
    }
}

impl std::error::Error for ProtocolError {}

pub type Result<T> = std::result::Result<T, ProtocolError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ProtocolError(msg.into()))
}

#[derive(Debug)]
pub struct Frame {
    pub kind: u8,
    #[allow(dead_code)] // carried for future version-aware routing
    pub version: u16,
    pub raw: Vec<u8>,
}

/// Typed read outcome: a complete frame, a clean close exactly on a frame
/// boundary, or a timeout with nothing consumed (poll-and-retry mode).
#[derive(Debug)]
pub enum ReadOutcome {
    Frame(Frame),
    Closed,
    Timeout,
}

pub struct Framer<R: Read, W: Write> {
    reader: R,
    writer: W,
}

enum HeaderRead {
    /// A full 12-byte header is in place.
    Done,
    /// Peer hung up exactly on a frame boundary.
    Eof,
    /// Timeout with nothing consumed (poll mode); state is intact.
    Timeout,
    /// Peer hung up, or a timeout hit, after partial bytes: irrecoverable
    /// framing state; the session must end.
    Fatal(String),
}

impl<R: Read, W: Write> Framer<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Framer { reader, writer }
    }

    /// Read one complete frame.
    /// Frame/Closed/Timeout as documented on `ReadOutcome`; Err(...) for
    /// oversized lengths, unknown kinds, and anything truncated or timed
    /// out mid-frame (irrecoverable framing state in every case).
    pub fn read_frame(&mut self) -> Result<ReadOutcome> {
        let mut header = [0u8; 12];
        match self.read_header(&mut header)? {
            HeaderRead::Done => {}
            HeaderRead::Eof => return Ok(ReadOutcome::Closed),
            HeaderRead::Timeout => return Ok(ReadOutcome::Timeout),
            HeaderRead::Fatal(e) => return err(e),
        }
        let kind = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let version = u16::from_le_bytes([header[8], header[9]]);
        // kinds 1..=6 (EVENT, HANDSHAKE, CONTROL, ACK, LOSS, HEALTH) match
        // internal/trace/framing.go. kind 0 was accepted here before the 6.43
        // fuzz tests found the divergence.
        if !(1..=6).contains(&kind) {
            return err(format!("unknown message kind {}", kind));
        }
        if length > MAX_FRAME_SIZE {
            return err(format!(
                "frame length {} exceeds {}",
                length, MAX_FRAME_SIZE
            ));
        }
        let mut raw = vec![0u8; length as usize];
        if let Err(e) = self.reader.read_exact(&mut raw) {
            return err(format!("truncated frame payload: {}", e));
        }
        Ok(ReadOutcome::Frame(Frame {
            kind: kind as u8,
            version,
            raw,
        }))
    }

    fn read_header(&mut self, header: &mut [u8]) -> Result<HeaderRead> {
        let mut filled = 0usize;
        while filled < header.len() {
            match self.reader.read(&mut header[filled..]) {
                Ok(0) => {
                    if filled == 0 {
                        return Ok(HeaderRead::Eof);
                    }
                    return Ok(HeaderRead::Fatal("peer closed mid-frame".into()));
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if filled == 0 {
                        return Ok(HeaderRead::Timeout);
                    }
                    return Ok(HeaderRead::Fatal("timeout mid-frame".into()));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(ProtocolError(format!("read: {}", e))),
            }
        }
        Ok(HeaderRead::Done)
    }

    /// Write one frame atomically; a partial write is completed by this
    /// call, so a caller may treat any error as a clean session teardown.
    pub fn write_frame(&mut self, kind: u8, version: u16, payload: &[u8]) -> Result<()> {
        if payload.len() as u64 > MAX_FRAME_SIZE as u64 {
            return err("payload exceeds frame limit");
        }
        let mut buf = Vec::with_capacity(12 + payload.len());
        buf.extend_from_slice(&(kind as u32).to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(version as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        self.writer
            .write_all(&buf)
            .map_err(|e| ProtocolError(format!("write frame: {}", e)))
    }

    pub fn write_json<T: Serialize>(&mut self, kind: u8, version: u16, value: &T) -> Result<()> {
        let payload =
            serde_json::to_vec(value).map_err(|e| ProtocolError(format!("encode: {}", e)))?;
        self.write_frame(kind, version, &payload)
    }

    /// Read exactly one frame of the expected kind and decode its payload.
    pub fn read_json<T: DeserializeOwned>(&mut self, want_kind: u8) -> Result<T> {
        let frame = match self.read_frame()? {
            ReadOutcome::Frame(frame) => frame,
            ReadOutcome::Closed => return err("peer closed before frame"),
            ReadOutcome::Timeout => return err("timeout before frame"),
        };
        if frame.kind != want_kind {
            return err(format!("expected kind {}, got {}", want_kind, frame.kind));
        }
        serde_json::from_slice(&frame.raw).map_err(|e| ProtocolError(format!("decode: {}", e)))
    }
}

// ---- payload codecs (exact mirrors of internal/trace/framing.go) ---------

/// Read exactly one frame of the expected kind and decode its payload
/// (free-function form used by transport.rs).
pub fn read_json<T: DeserializeOwned>(
    fr: &mut Framer<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>,
    want_kind: u8,
) -> Result<T> {
    fr.read_json(want_kind)
}

pub fn write_json<T: Serialize>(
    fr: &mut Framer<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>,
    kind: u8,
    version: u16,
    value: &T,
) -> Result<()> {
    fr.write_json(kind, version, value)
}

pub fn encode_event(e: &TraceEvent) -> Result<Vec<u8>> {
    serde_json::to_vec(e).map_err(|e| ProtocolError(format!("encode event: {}", e)))
}

#[allow(dead_code)] // symmetric codec used by tests and the go contract
pub fn encode_handshake(h: &Handshake) -> Result<Vec<u8>> {
    serde_json::to_vec(h).map_err(|e| ProtocolError(format!("encode handshake: {}", e)))
}

#[allow(dead_code)]
pub fn encode_control(c: &Control) -> Result<Vec<u8>> {
    serde_json::to_vec(c).map_err(|e| ProtocolError(format!("encode control: {}", e)))
}

pub fn encode_ack(a: &ControlAck) -> Result<Vec<u8>> {
    serde_json::to_vec(a).map_err(|e| ProtocolError(format!("encode ack: {}", e)))
}

pub fn decode_event(raw: &[u8]) -> Result<TraceEvent> {
    let e: TraceEvent =
        serde_json::from_slice(raw).map_err(|e| ProtocolError(format!("decode event: {}", e)))?;
    if e.schema_version != SCHEMA_VERSION {
        return err(format!(
            "event schema {} != ours {}",
            e.schema_version, SCHEMA_VERSION
        ));
    }
    if e.monotonic_ns <= 0 {
        return err("event has no monotonic timestamp");
    }
    Ok(e)
}

#[allow(dead_code)]
pub fn decode_handshake(raw: &[u8]) -> Result<Handshake> {
    let h: Handshake = serde_json::from_slice(raw)
        .map_err(|e| ProtocolError(format!("decode handshake: {}", e)))?;
    // Range-overlap negotiation, identical to the go side.
    if h.protocol_version < PROTOCOL_VERSION_MIN || h.min_version > PROTOCOL_VERSION {
        return err(format!(
            "version mismatch: peer {}..{}, ours {}",
            h.min_version, h.protocol_version, PROTOCOL_VERSION
        ));
    }
    Ok(h)
}

pub fn decode_control(raw: &[u8]) -> Result<Control> {
    let c: Control =
        serde_json::from_slice(raw).map_err(|e| ProtocolError(format!("decode control: {}", e)))?;
    match c.op.0 {
        OP_ADD | OP_REMOVE | OP_RESET | OP_FLUSH | OP_PING | OP_SHUTDOWN | OP_ADD_CGROUP => {}
        n => return err(format!("unknown control op {}", n)),
    }
    if c.pids.len() > MAX_WATCH_SET_ENTRIES {
        return err(format!(
            "watch set of {} exceeds {}",
            c.pids.len(),
            MAX_WATCH_SET_ENTRIES
        ));
    }
    if c.pids.contains(&0) {
        return err("PID 0 in watch set");
    }
    // identity operand (§6.3 f): either empty (older agent, PID keying) or
    // exactly one entry per PID. A negative start time is not a kernel
    // fact; a mismatched length is a corrupt operand, not an interpretation.
    if !c.start_ticks.is_empty() && c.start_ticks.len() != c.pids.len() {
        return err(format!(
            "start_ticks has {} entries for {} pids",
            c.start_ticks.len(),
            c.pids.len()
        ));
    }
    if c.start_ticks.iter().any(|t| *t < 0) {
        return err("negative start_ticks in watch set");
    }
    Ok(c)
}

#[allow(dead_code)]
pub fn decode_ack(raw: &[u8]) -> Result<ControlAck> {
    let a: ControlAck =
        serde_json::from_slice(raw).map_err(|e| ProtocolError(format!("decode ack: {}", e)))?;
    // same op set as the controls this side accepts (6.43 finding).
    match a.op.0 {
        OP_ADD..=OP_ADD_CGROUP => Ok(a),
        n => err(format!("unknown ack op {}", n)),
    }
}

pub fn encode_loss(l: &Loss) -> Result<Vec<u8>> {
    serde_json::to_vec(l).map_err(|e| ProtocolError(format!("encode loss: {}", e)))
}

pub fn decode_loss(raw: &[u8]) -> Result<Loss> {
    let l: Loss =
        serde_json::from_slice(raw).map_err(|e| ProtocolError(format!("decode loss: {}", e)))?;
    if l.count_at_least == 0 {
        return err("loss frame reports zero events");
    }
    if l.last_ns < l.first_ns {
        return err("loss window is inverted");
    }
    Ok(l)
}

pub fn encode_health(h: &Health) -> Result<Vec<u8>> {
    serde_json::to_vec(h).map_err(|e| ProtocolError(format!("encode health: {}", e)))
}

pub fn decode_health(raw: &[u8]) -> Result<Health> {
    serde_json::from_slice(raw).map_err(|e| ProtocolError(format!("decode health: {}", e)))
}

// -- conveniences over write targets ---------------------------------------

/// Write a run of (kind, version, payload) frames through one writer using
/// the production framing path, then flush. Used by the CLI to emit framed
/// fixture files without reimplementing the header (single source of truth).
pub fn write_frames<W: std::io::Write>(
    writer: &mut W,
    frames: &[(u8, u16, Vec<u8>)],
) -> Result<()> {
    let mut fr = Framer::new(std::io::empty(), &mut *writer);
    for (kind, version, payload) in frames {
        fr.write_frame(*kind, *version, payload)?;
    }
    writer
        .flush()
        .map_err(|e| ProtocolError(format!("flush: {}", e)))
}

#[cfg(test)]
mod fuzz_tests {
    //! Deterministic fuzz and property tests for the production decoders
    //! (6.42/6.43). They call the same functions the transport calls. Each
    //! test seeds its own xorshift stream, so any failure reproduces from the
    //! seed in the test.

    use super::*;
    use std::io::{sink, Cursor};

    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed | 1)
        }
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let n = self.below(max + 1);
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    fn event(rng: &mut Rng) -> TraceEvent {
        let kinds = [
            TYPE_EXEC,
            TYPE_EXIT,
            TYPE_SIGNAL,
            TYPE_STOP,
            TYPE_CONT,
            TYPE_OOM,
        ];
        let t = kinds[rng.below(kinds.len())];
        TraceEvent {
            schema_version: SCHEMA_VERSION,
            sequence: rng.next() % 1_000_000 + 1,
            monotonic_ns: (rng.next() % 1_000_000_000_000 + 1) as i64,
            wall_unix_ms: (rng.next() % 2_000_000_000_000) as i64,
            clock_offset_ns: 0,
            event_type: EventType(t),
            pid: (rng.next() % 4_000_000 + 1) as u32,
            ppid: (rng.next() % 4_000_000) as u32,
            pgid: (rng.next() % 4_000_000) as u32,
            start_ticks: (rng.next() % 1_000_000_000) as i64,
            exec_path: if t == TYPE_EXEC {
                "/usr/bin/true".into()
            } else {
                String::new()
            },
            exit_code: if t == TYPE_EXIT && rng.below(2) == 0 {
                Some(rng.below(256) as i32 - 128)
            } else {
                None
            },
            signal: if t == TYPE_SIGNAL { 15 } else { 0 },
            sender_pid: 0,
            fact: 0,
            source: SOURCE_PROC_CONNECTOR,
        }
    }

    fn one_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frames(&mut out, &[(kind, 1, payload.to_vec())]).unwrap();
        out
    }

    /// Asserts what each decoder promises on success. A panic or a violated
    /// invariant fails the test.
    fn check_accepted(frame: &Frame) {
        assert!((1..=6).contains(&frame.kind), "kind {} escaped", frame.kind);
        assert!(frame.raw.len() <= MAX_FRAME_SIZE as usize);
        match frame.kind {
            KIND_EVENT => {
                if let Ok(e) = decode_event(&frame.raw) {
                    assert_eq!(e.schema_version, SCHEMA_VERSION);
                    assert!(e.monotonic_ns > 0);
                }
            }
            KIND_HANDSHAKE => {
                if let Ok(h) = decode_handshake(&frame.raw) {
                    assert!(h.protocol_version >= PROTOCOL_VERSION_MIN);
                    assert!(h.min_version <= PROTOCOL_VERSION);
                }
            }
            KIND_CONTROL => {
                if let Ok(c) = decode_control(&frame.raw) {
                    assert!(c.pids.len() <= MAX_WATCH_SET_ENTRIES);
                    assert!(!c.pids.contains(&0));
                    assert!((OP_ADD..=OP_ADD_CGROUP).contains(&c.op.0));
                }
            }
            KIND_ACK => {
                if let Ok(a) = decode_ack(&frame.raw) {
                    assert!((OP_ADD..=OP_ADD_CGROUP).contains(&a.op.0));
                }
            }
            KIND_LOSS => {
                if let Ok(l) = decode_loss(&frame.raw) {
                    assert!(l.count_at_least > 0);
                    assert!(l.last_ns >= l.first_ns);
                }
            }
            KIND_HEALTH => {
                let _ = decode_health(&frame.raw);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn random_byte_streams_never_panic_and_accepted_frames_hold_invariants() {
        let mut rng = Rng::new(0x5EED_0001);
        for _ in 0..20_000 {
            let bytes = rng.bytes(160);
            let mut fr = Framer::new(Cursor::new(bytes), sink());
            for _ in 0..64 {
                match fr.read_frame() {
                    Ok(ReadOutcome::Frame(f)) => check_accepted(&f),
                    Ok(_) | Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn mutated_valid_frames_hold_invariants() {
        let mut rng = Rng::new(0x5EED_0002);
        for i in 0..8_000 {
            let (kind, payload) = match i % 4 {
                0 => (KIND_EVENT, encode_event(&event(&mut rng)).unwrap()),
                1 => (
                    KIND_HANDSHAKE,
                    serde_json::to_vec(&Handshake {
                        protocol_version: PROTOCOL_VERSION,
                        min_version: PROTOCOL_VERSION_MIN,
                        tracer_version: "fuzz".into(),
                        capabilities: Capabilities::default(),
                        monotonic_ns: 1,
                        wall_unix_ms: 1,
                        schema_version: SCHEMA_VERSION,
                        boot_id: "fuzz-boot".into(),
                        pid_namespace_inode: 1,
                        event_clock: "monotonic".into(),
                        selection_reason: String::new(),
                    })
                    .unwrap(),
                ),
                2 => (
                    KIND_CONTROL,
                    serde_json::to_vec(&Control {
                        op: ControlOp(OP_ADD),
                        pids: vec![(rng.next() % 90_000 + 1) as u32, 7],
                        start_ticks: Vec::new(),
                    })
                    .unwrap(),
                ),
                _ => (
                    KIND_ACK,
                    serde_json::to_vec(&ControlAck {
                        op: ControlOp(OP_PING),
                        watches: 0,
                        err: String::new(),
                        stale: Vec::new(),
                    })
                    .unwrap(),
                ),
            };
            let mut bytes = one_frame(kind, &payload);
            match rng.below(3) {
                0 => {
                    // flip one to four bytes anywhere, header included.
                    for _ in 0..1 + rng.below(4) {
                        let at = rng.below(bytes.len());
                        bytes[at] ^= (rng.next() as u8) | 1;
                    }
                }
                1 => {
                    // truncate: a cut frame must never come back as a Frame.
                    let cut = rng.below(bytes.len());
                    bytes.truncate(cut);
                    let out = Framer::new(Cursor::new(bytes), sink()).read_frame();
                    assert!(
                        !matches!(out, Ok(ReadOutcome::Frame(_))),
                        "truncated frame was accepted"
                    );
                    continue;
                }
                _ => {
                    // append garbage: only the leading frame may decode.
                    bytes.extend(rng.bytes(64));
                }
            }
            let mut fr = Framer::new(Cursor::new(bytes), sink());
            for _ in 0..8 {
                match fr.read_frame() {
                    Ok(ReadOutcome::Frame(f)) => check_accepted(&f),
                    Ok(_) | Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn every_truncation_point_is_a_clean_close_or_an_error() {
        let mut rng = Rng::new(0x5EED_0003);
        for _ in 0..64 {
            let payload = encode_event(&event(&mut rng)).unwrap();
            let full = one_frame(KIND_EVENT, &payload);
            for cut in 0..full.len() {
                let out = Framer::new(Cursor::new(full[..cut].to_vec()), sink()).read_frame();
                if cut == 0 {
                    assert!(matches!(out, Ok(ReadOutcome::Closed)), "cut 0: {:?}", out);
                } else {
                    assert!(
                        out.is_err(),
                        "cut {} of {} was not an error",
                        cut,
                        full.len()
                    );
                }
            }
        }
    }

    #[test]
    fn oversized_and_unknown_frames_are_refused_before_allocation() {
        let header = |kind: u32, len: u32| {
            let mut h = Vec::new();
            h.extend_from_slice(&kind.to_le_bytes());
            h.extend_from_slice(&len.to_le_bytes());
            h.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes()[..2]);
            h.extend_from_slice(&[0, 0]);
            h
        };
        // A length of u32::MAX with no payload fails on the length check.
        for len in [MAX_FRAME_SIZE + 1, u32::MAX] {
            let out = Framer::new(Cursor::new(header(1, len)), sink()).read_frame();
            assert!(
                matches!(out, Err(ref e) if e.0.contains("exceeds")),
                "len {}: {:?}",
                len,
                out
            );
        }
        // kind 0 and kind 7 are unknown; 5 and 6 (LOSS, HEALTH) are known.
        for kind in [0u32, 7, 0xFFFF_FFFF] {
            let out = Framer::new(Cursor::new(header(kind, 0)), sink()).read_frame();
            assert!(
                matches!(out, Err(ref e) if e.0.contains("unknown message kind")),
                "kind {}: {:?}",
                kind,
                out
            );
        }
    }

    #[test]
    fn valid_events_round_trip_exactly() {
        let mut rng = Rng::new(0x5EED_0004);
        for _ in 0..2_000 {
            let e = event(&mut rng);
            let raw = encode_event(&e).unwrap();
            assert_eq!(decode_event(&raw).unwrap(), e);
        }
    }

    #[test]
    fn control_bounds_are_enforced() {
        let ctl = |op: u8, pids: Vec<u32>| {
            serde_json::to_vec(&Control {
                op: ControlOp(op),
                pids,
                start_ticks: Vec::new(),
            })
            .unwrap()
        };
        assert!(decode_control(&ctl(OP_ADD, vec![5])).is_ok());
        assert!(
            decode_control(&ctl(OP_RESET, vec![0])).is_err(),
            "PID 0 must be refused"
        );
        for op in [0u8, 8, 255] {
            assert!(
                decode_control(&ctl(op, vec![])).is_err(),
                "op {} accepted",
                op
            );
        }
        let full: Vec<u32> = (1..=MAX_WATCH_SET_ENTRIES as u32).collect();
        assert!(decode_control(&ctl(OP_RESET, full.clone())).is_ok());
        let mut over = full;
        over.push(1);
        assert!(decode_control(&ctl(OP_RESET, over)).is_err());
    }

    #[test]
    fn unknown_ack_ops_are_refused_like_go_does() {
        for op in [0u8, 8, 200] {
            let raw = serde_json::to_vec(&ControlAck {
                op: ControlOp(op),
                watches: 0,
                err: String::new(),
                stale: Vec::new(),
            })
            .unwrap();
            assert!(decode_ack(&raw).is_err(), "ack op {} accepted", op);
        }
    }

    #[test]
    fn loss_frames_with_bad_windows_are_refused() {
        let zero = serde_json::to_vec(&Loss {
            stage: 1,
            count_at_least: 0,
            first_ns: 1,
            last_ns: 2,
        })
        .unwrap();
        assert!(decode_loss(&zero).is_err(), "zero-count loss accepted");
        let inverted = serde_json::to_vec(&Loss {
            stage: 1,
            count_at_least: 1,
            first_ns: 9,
            last_ns: 2,
        })
        .unwrap();
        assert!(
            decode_loss(&inverted).is_err(),
            "inverted loss window accepted"
        );
    }
}
