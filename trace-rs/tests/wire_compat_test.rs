//! Cross-language wire tests, Rust side (6.3/6.4/6.56).
//!
//! Unlike `protocol_test.rs` (which checks the *schema mirror* in
//! `tests/support.rs`), these tests drive the **production** decoder and
//! server: `deprehendo-trace replay` and `deprehendo-trace --socket`. The bytes fed
//! in are exactly what the Go encoder in `internal/trace` produces, and the
//! matching Go test (`internal/trace/compat_test.go`, TestGoGoldenWireBytes)
//! asserts the Go encoder emits those same literals. Neither language can
//! drift without the other's suite failing.
//!
//! The server tests run on any Unix: on non-Linux the proc-connector backend
//! reports `unsupported` and produces no events, but the handshake, control,
//! ack and framing paths under test are the same code CI exercises on Linux.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const KIND_EVENT: u8 = 1;
const KIND_HANDSHAKE: u8 = 2;
const KIND_CONTROL: u8 = 3;
const KIND_ACK: u8 = 4;

/// Go's production encoder output for a PROCESS_EXEC (field order is Go
/// struct order; absent optional fields are omitted, never zero-filled).
const GO_EXEC_JSON: &str = concat!(
    r#"{"schema_version":1,"sequence":7,"monotonic_ns":123456789,"#,
    r#""wall_unix_ms":1767000000000,"type":1,"pid":4242,"#,
    r#""exec_path":"/usr/bin/tool","source":1}"#
);

/// A signaled exit: the signal number is present, `exit_code` is absent.
const GO_EXIT_SIGNAL_JSON: &str = concat!(
    r#"{"schema_version":1,"sequence":8,"monotonic_ns":123456999,"#,
    r#""wall_unix_ms":1767000000500,"type":2,"pid":4242,"signal":9,"#,
    r#""fact":2,"source":1}"#
);

/// A real exit(0): a present zero is evidence and must not be dropped.
const GO_EXIT_ZERO_JSON: &str = concat!(
    r#"{"schema_version":1,"sequence":9,"monotonic_ns":123457000,"#,
    r#""wall_unix_ms":1767000000600,"type":2,"pid":4243,"exit_code":0,"#,
    r#""source":1}"#
);

/// Frame a payload exactly as documented in docs/tracing/protocol.md:
/// kind u32 LE, length u32 LE, schema version u16 LE, two reserved zero bytes.
fn frame(kind: u8, payload: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(&(kind as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&[0u8, 0u8]);
    out.extend_from_slice(payload.as_bytes());
    out
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_deprehendo-trace")
}

fn go_socket_handshake() -> String {
    concat!(
        r#"{"protocol_version":1,"min_version":1,"tracer_version":"go-agent-1","#,
        r#""capabilities":{"process_exec":true,"process_exit":true,"signals":true,"#,
        r#""stop_resume":true,"oom_kill":false,"backend":"proc_connector","#,
        r#""kernel":"6.8.0","privileged":false,"unprivileged":true,"unsupported":false},"#,
        r#""monotonic_ns":1767000000000,"wall_unix_ms":1767000000000,"#,
        r#""schema_version":1}"#
    )
    .to_string()
}

/// `deprehendo-trace replay` must accept the Go encoder's bytes and print the
/// same values back: this is the Rust-production half of "Rust encode → Go
/// decode" and "Go encode → Rust decode" (6.56).
#[test]
fn production_replay_decodes_go_encoded_frames() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("go-golden.bin");
    let mut bytes = Vec::new();
    bytes.extend(frame(KIND_EVENT, GO_EXEC_JSON));
    bytes.extend(frame(KIND_EVENT, GO_EXIT_SIGNAL_JSON));
    bytes.extend(frame(KIND_EVENT, GO_EXIT_ZERO_JSON));
    std::fs::write(&path, &bytes).unwrap();

    let out = Command::new(bin())
        .arg("replay")
        .arg(&path)
        .output()
        .expect("run tracer replay");
    assert!(
        out.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for want in [
        "seq=7 PROCESS_EXEC pid=4242 mono=123456789",
        "seq=8 PROCESS_EXIT pid=4242 mono=123456999",
        "seq=9 PROCESS_EXIT pid=4243 mono=123457000",
    ] {
        assert!(stdout.contains(want), "missing {want:?} in {stdout}");
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("bad sample") && stderr.contains("bad_samples=0"),
        "a clean file reported bad samples: {stderr}"
    );
}

/// A bad *sample* is recoverable and must not hide the rest of the file: the
/// same policy as the Go decoder in `internal/trace/replay.go` (6.43/6.56).
/// The corrupt record is counted and reported, never silently dropped.
#[test]
fn production_replay_counts_a_bad_sample_and_keeps_going() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-schema.bin");
    let bad = GO_EXEC_JSON.replace(r#""schema_version":1"#, r#""schema_version":2"#);
    let mut bytes = frame(KIND_EVENT, &bad);
    bytes.extend(frame(KIND_EVENT, GO_EXIT_ZERO_JSON));
    std::fs::write(&path, &bytes).unwrap();

    let out = Command::new(bin())
        .arg("replay")
        .arg(&path)
        .output()
        .expect("run tracer replay");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a bad sample ended the replay: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("seq=9 PROCESS_EXIT pid=4243"),
        "the sample after the corrupt one was hidden: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("bad sample") && stderr.contains("bad_samples=1"),
        "the corrupt sample was not reported: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "decoder panicked: {stderr}");
}

/// A truncated frame is *not* recoverable: the boundaries are gone, so replay
/// stops with an error instead of inventing a resynchronization point.
#[test]
fn production_replay_rejects_a_broken_frame() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncated.bin");
    let mut bytes = frame(KIND_EVENT, GO_EXEC_JSON);
    bytes.truncate(bytes.len() - 5);
    std::fs::write(&path, &bytes).unwrap();

    let out = Command::new(bin())
        .arg("replay")
        .arg(&path)
        .output()
        .expect("run tracer replay");
    assert!(!out.status.success(), "a truncated frame was accepted");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "decoder panicked on a truncated frame: {stderr}"
    );
}

/// The production server must accept Go's handshake, ack every control with
/// Go's field names, and shut down cleanly when asked. This exercises
/// schema.rs + framing.rs + transport.rs end to end instead of a mirror.
#[test]
fn production_server_speaks_go_control_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = spawn_server(&dir.path().join("trace.sock"));
    let mut stream = connect(&server.socket);
    let mut reader = FrameReader::default();

    stream
        .write_all(&frame(KIND_HANDSHAKE, &go_socket_handshake()))
        .unwrap();
    stream.flush().unwrap();
    let hello = reader.read(&mut stream).expect("handshake reply");
    assert_eq!(
        hello.kind, KIND_HANDSHAKE,
        "first reply must be the handshake"
    );
    let hello: serde_json::Value = serde_json::from_slice(&hello.payload).unwrap();
    // the tracer advertises its own span (max 2, min 1); the session with
    // a 1..1 agent runs at the overlap, protocol 1 (§6.3 negotiation).
    assert_eq!(hello["protocol_version"], 2);
    assert_eq!(hello["min_version"], 1);
    assert_eq!(hello["schema_version"], 1);
    assert!(
        hello["tracer_version"]
            .as_str()
            .unwrap_or_default()
            .starts_with("deprehendo-trace/"),
        "tracer_version: {hello:?}"
    );
    assert!(
        hello["capabilities"]["process_exec"].is_boolean(),
        "capabilities missing from the handshake: {hello:?}"
    );

    // ADD with go's exact encoding (the golden literal from TestControlGoldenBytes).
    stream
        .write_all(&frame(KIND_CONTROL, r#"{"op":1,"pids":[5001,5008]}"#))
        .unwrap();
    let ack: serde_json::Value =
        serde_json::from_slice(&read_ack(&mut reader, &mut stream)).unwrap();
    assert_eq!(ack["op"], 1);
    assert_eq!(ack["watches"], 2, "ack: {ack:?}");
    assert_eq!(ack["err"], "");

    // RESET with an empty watch set: go omits `pids` entirely once the field
    // is omitempty, and the tracer must read that as "no PIDs".
    stream
        .write_all(&frame(KIND_CONTROL, r#"{"op":3}"#))
        .unwrap();
    let ack: serde_json::Value =
        serde_json::from_slice(&read_ack(&mut reader, &mut stream)).unwrap();
    assert_eq!(ack["op"], 3);
    assert_eq!(ack["watches"], 0, "ack: {ack:?}");

    // an older go agent encodes an empty operand list as JSON null. the
    // tracer must tolerate it rather than dropping the session: null and
    // absent both mean "no PIDs".
    stream
        .write_all(&frame(KIND_CONTROL, r#"{"op":5,"pids":null}"#))
        .unwrap();
    let ack: serde_json::Value =
        serde_json::from_slice(&read_ack(&mut reader, &mut stream)).unwrap();
    assert_eq!(ack["op"], 5, "PING rejected: {ack:?}");
    assert_eq!(ack["err"], "");

    // SHUTDOWN is acked and then ends the process (6.7 graceful shutdown).
    stream
        .write_all(&frame(KIND_CONTROL, r#"{"op":6}"#))
        .unwrap();
    let ack: serde_json::Value =
        serde_json::from_slice(&read_ack(&mut reader, &mut stream)).unwrap();
    assert_eq!(ack["op"], 6);
    drop(stream);
    assert!(
        server.wait_for_exit(Duration::from_secs(10)),
        "tracer did not exit after SHUTDOWN"
    );
    assert!(
        server.child.try_wait().unwrap().is_some(),
        "tracer still running"
    );
    assert!(!server.socket.exists(), "socket file left behind");
}

/// A malformed or hostile session must end that session only: the tracer has
/// to keep serving, and its exit status must stay clean (6.40).
#[test]
fn production_server_survives_a_malformed_session() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = spawn_server(&dir.path().join("trace.sock"));
    let socket = server.socket.clone();

    // 1: a frame whose declared length runs past the end of the file, then
    // the client disappears mid-frame.
    {
        let mut stream = connect(&socket);
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&(KIND_EVENT as u32).to_le_bytes());
        truncated.extend_from_slice(&4096u32.to_le_bytes());
        truncated.extend_from_slice(&1u16.to_le_bytes());
        truncated.extend_from_slice(&[0u8, 0u8]);
        truncated.extend_from_slice(b"{\"schema_version\":1");
        stream.write_all(&truncated).unwrap();
        let _ = stream.flush();
    }

    // 2: an unknown frame kind.
    {
        let mut stream = connect(&socket);
        stream.write_all(&frame(99, "{}")).unwrap();
        let _ = stream.flush();
    }

    // 3: a handshake the tracer's version rule must refuse.
    {
        let mut stream = connect(&socket);
        let future = go_socket_handshake().replace(
            r#""protocol_version":1,"min_version":1"#,
            r#""protocol_version":9,"min_version":9"#,
        );
        stream.write_all(&frame(KIND_HANDSHAKE, &future)).unwrap();
        let _ = stream.flush();
    }

    // the server must still be alive and still serve a good session.
    let mut stream = connect(&socket);
    let mut reader = FrameReader::default();
    stream
        .write_all(&frame(KIND_HANDSHAKE, &go_socket_handshake()))
        .unwrap();
    let hello = reader
        .read(&mut stream)
        .expect("server stopped serving after bad sessions");
    assert_eq!(hello.kind, KIND_HANDSHAKE);
    stream
        .write_all(&frame(KIND_CONTROL, r#"{"op":6}"#))
        .unwrap();
    let _ = read_ack(&mut reader, &mut stream);
    assert!(
        server.wait_for_exit(Duration::from_secs(10)),
        "tracer did not exit after SHUTDOWN"
    );
    let status = server.child.wait().unwrap();
    assert!(
        status.success(),
        "tracer exit status was {status} after malformed sessions"
    );
}

// --- harness ------------------------------------------------------------

struct Server {
    child: Child,
    socket: PathBuf,
}

impl Server {
    fn wait_for_exit(&mut self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        false
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the production server and wait for its socket to be listening.
///
/// On success the child is carried into `Server`, whose `Drop` reaps it; the
/// early-return and panic paths below reap it themselves before leaving.
#[allow(clippy::zombie_processes)]
fn spawn_server(socket: &Path) -> Server {
    let mut child = Command::new(bin())
        .arg("--socket")
        .arg(socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn deprehendo-trace server");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if socket.exists() {
            return Server {
                child,
                socket: socket.to_path_buf(),
            };
        }
        if child.try_wait().unwrap().is_some() {
            let mut err = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut err);
            }
            let _ = child.wait();
            panic!("tracer exited before binding its socket: {err}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("tracer never bound {}", socket.display());
}

fn connect(socket: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(socket) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                return s;
            }
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("connect {}: {e}", socket.display()),
        }
    }
}

/// Minimal framed-message reader: the Go agent's read side, reduced to what
/// these tests assert.
#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
}

struct RawFrame {
    kind: u8,
    payload: Vec<u8>,
}

impl FrameReader {
    fn fill(&mut self, stream: &mut UnixStream) -> std::io::Result<()> {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed",
            ));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    fn read(&mut self, stream: &mut UnixStream) -> std::io::Result<RawFrame> {
        loop {
            if self.buf.len() >= 12 {
                let kind = u32::from_le_bytes(self.buf[0..4].try_into().unwrap()) as u8;
                let len = u32::from_le_bytes(self.buf[4..8].try_into().unwrap()) as usize;
                assert!(len <= 1 << 20, "tracer declared an oversized frame: {len}");
                if self.buf.len() >= 12 + len {
                    let payload = self.buf[12..12 + len].to_vec();
                    self.buf.drain(..12 + len);
                    return Ok(RawFrame { kind, payload });
                }
            }
            self.fill(stream)?;
        }
    }
}

fn read_ack(reader: &mut FrameReader, stream: &mut UnixStream) -> Vec<u8> {
    let frame = reader.read(stream).expect("ack frame");
    assert_eq!(
        frame.kind, KIND_ACK,
        "expected an ACK, got kind {}",
        frame.kind
    );
    frame.payload
}
