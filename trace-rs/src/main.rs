// deprehendo-trace: linux high-resolution lifecycle tracer (phase 6).
//
// binary entry point. command modes:
//   deprehendo-trace --socket PATH [--unix-socket PATH]  serve the go agent over a unix socket (standalone)
//   deprehendo-trace --supervised --socket PATH          one session, dies with the agent (§6.3 a)
//   deprehendo-trace debug                               command-line live feed (acceptance POC)
//   deprehendo-trace replay FILE                         replay a captured event stream (6.45)
//   deprehendo-trace capabilities                        print the probed capability set (6.58)
//   deprehendo-trace status                              short health line
//   deprehendo-trace genfixtures DIR                     write the wire fixtures (6.44)
//
// the library (src/lib.rs) exposes every module for the integration tests
// and the go cross-language suite; this binary is a thin shell over it
// (finding O17).
//
// Linux-only by design (docs/tracing/architecture.md): the proc-connector
// backend does not exist on other platforms and the crate refuses to claim
// support there.
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use deprehendo_trace::framing::{
    decode_event, encode_event, write_frames, Framer, ProtocolError, ReadOutcome, Result,
};
use deprehendo_trace::schema::*;
use deprehendo_trace::transport::Tracer;
use deprehendo_trace::watch::WatchSet;
use deprehendo_trace::LossCounters;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--version") | Some("version") => {
            println!("deprehendo-trace {}", env!("CARGO_PKG_VERSION"));
        }
        Some("capabilities") => {
            // the attach IS the probe (contract §2.1): a capability is
            // true only when its programs actually attached, and the
            // selection's fallback reason is printed with the states.
            run_caps_command();
        }
        Some("status") => {
            let sel = deprehendo_trace::backend::select_backend();
            if !sel.selection_reason.is_empty() {
                eprintln!("selection: {}", sel.selection_reason);
            }
            println!(
                "backend={} kernel={} ok={}",
                sel.caps.backend,
                sel.caps.kernel,
                (!sel.caps.unsupported)
            );
        }
        Some("debug") => {
            if let Err(e) = debug_mode() {
                eprintln!("deprehendo-trace: debug: {}", e);
                std::process::exit(1);
            }
        }
        Some("replay") => {
            if let Err(e) = replay_mode(args.get(2)) {
                eprintln!("deprehendo-trace: replay: {}", e);
                std::process::exit(1);
            }
        }
        Some("genfixtures") => {
            if let Err(e) = genfixtures(args.get(2)) {
                eprintln!("deprehendo-trace: genfixtures: {}", e);
                std::process::exit(1);
            }
        }
        Some("--supervised") | Some("--socket") | Some("--unix-socket") => {
            let mode = if args.first().map(|a| a.as_str()) == Some("--supervised")
                || args.iter().any(|a| a.as_str() == "--supervised")
            {
                // --supervised accompanies --socket: the agent owns our
                // lifetime (§6.3 a).
                true
            } else {
                false
            };
            let path = args
                .iter()
                .position(|a| a.as_str() == "--socket")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from);
            let path = match path {
                Some(p) => p,
                None => {
                    eprintln!("deprehendo-trace: --socket requires a path");
                    std::process::exit(2);
                }
            };
            let tracer = Tracer::new(path.to_string_lossy().into_owned());
            let result = if mode {
                tracer.serve_supervised()
            } else {
                tracer.serve()
            };
            if let Err(e) = result {
                eprintln!("deprehendo-trace: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: deprehendo-trace [--socket PATH | --supervised --socket PATH | debug | replay FILE | capabilities | status | genfixtures DIR | --version]");
            std::process::exit(2);
        }
    }
}

/// `deprehendo-trace capabilities`: a real attach attempt, then detach.
/// Reports per-capability `{state, reason}` honestly, plus the selection
/// reason when the primary backend was refused (contract §2.1).
fn run_caps_command() {
    let sel = deprehendo_trace::backend::select_backend();
    if !sel.selection_reason.is_empty() {
        eprintln!("selection: {}", sel.selection_reason);
    }
    let c = &sel.caps;
    println!("backend             {}", c.backend);
    println!("kernel              {}", c.kernel);
    println!(
        "process exec        {:<4} [{}]",
        yesno(c.process_exec),
        state_line(&c.exec_state, &c.exec_reason)
    );
    println!(
        "process exit        {:<4} [{}]",
        yesno(c.process_exit),
        state_line(&c.exit_state, &c.exit_reason)
    );
    println!(
        "signals             {:<4} [{}]",
        yesno(c.signals),
        state_line(&c.signals_state, &c.signals_reason)
    );
    println!(
        "stop/resume         {:<4} [{}]",
        yesno(c.stop_resume),
        state_line(&c.stop_resume_state, &c.stop_resume_reason)
    );
    println!(
        "oom kill            {:<4} [{}]",
        yesno(c.oom_kill),
        state_line(&c.oom_state, &c.oom_reason)
    );
    println!("unprivileged        {}", yesno(c.unprivileged));
    println!("kernel refused      {}", yesno(c.unsupported));
}

/// A short state line for one capability: "attached" / "unavailable: …".
fn state_line(state: &str, reason: &str) -> String {
    if !state.is_empty() {
        state.to_string()
    } else if !reason.is_empty() && reason != "no" {
        reason.to_string()
    } else {
        "not_collected_by_backend".to_string()
    }
}

fn yesno(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

/// `deprehendo-trace debug`: stream matched exec/exit events to stdout so the
/// tracer can be validated end to end without the Go agent (6.19 POC).
/// Ctrl-C ends the session cleanly: the exit-event stream is flushed to
/// EOF and the process leaves with a normal status.
fn debug_mode() -> Result<()> {
    // name the real refusal (6.53), not a generic one: the operator needs
    // to know whether the kernel or the privilege level said no.
    let (caps, refusal) = deprehendo_trace::backend::probe_with_reason();
    if caps.unsupported {
        let why = refusal.unwrap_or_else(|| "the tracer gave no reason".into());
        return Err(ProtocolError(format!(
            "no tracing mechanism available: {why}"
        )));
    }
    let watch = WatchSet::new();
    let args: Vec<String> = std::env::args().collect();
    for pid in args.iter().skip(2).filter_map(|s| s.parse::<u32>().ok()) {
        watch.apply(OP_ADD, &[pid], MAX_WATCH_SET_ENTRIES).ok();
    }
    let loss = LossCounters::new();
    let stop = Arc::new(AtomicBool::new(false));
    // SIGINT/SIGTERM set SIGNALLED; the loop below polls it. (principal review:
    // the handler used to set a flag nothing read, so Ctrl-C did nothing.)
    signal_setup();
    eprintln!("deprehendo-trace: streaming exec/exit events (Ctrl-C to stop)");
    let (tx, rx) = std::sync::mpsc::sync_channel::<TraceEvent>(1024);
    // selection here too: debug streams from whichever backend attached
    // (eBPF primary, proc connector fallback), and says which.
    let mut chosen = deprehendo_trace::backend::select_backend();
    eprintln!("deprehendo-trace: backend {}", chosen.caps.backend);
    if !chosen.selection_reason.is_empty() {
        eprintln!("deprehendo-trace: {}", chosen.selection_reason);
    }
    let collector = {
        let watch = Arc::clone(&watch);
        let loss = Arc::clone(&loss);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || chosen.backend.run(watch, tx, loss, stop))
    };
    let stdout = std::io::stdout();
    loop {
        if stop.load(Ordering::SeqCst) || SIGNALLED.load(Ordering::SeqCst) {
            stop.store(true, Ordering::SeqCst);
            break;
        }
        match rx.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(ev) => {
                let mut line = format!(
                    "{} pid={} seq={} mono={}",
                    ev.event_type.name(),
                    ev.pid,
                    ev.sequence,
                    ev.monotonic_ns
                );
                if !ev.exec_path.is_empty() {
                    line.push_str(&format!(" path={}", ev.exec_path));
                }
                if let Some(code) = ev.exit_code {
                    line.push_str(&format!(" exit={}", code));
                }
                if ev.signal != 0 {
                    line.push_str(&format!(" signal={} fact={}", ev.signal, ev.fact));
                }
                if ev.event_type.0 == TYPE_SIGNAL {
                    // addressing (§3.3): pid for one process, pgid for a
                    // group, both 0 for kill(-1) or an unresolved target.
                    line.push_str(&format!(" sender={} pgid={}", ev.sender_pid, ev.pgid));
                }
                let mut out = stdout.lock();
                writeln!(out, "{}", line).ok();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // the collector sits in a blocking recv until the next process event on
    // the host; it sees `stop` then. waiting for it here could hang an idle
    // host, and leaving main ends the process anyway.
    drop(collector);
    let dropped = loss.total();
    if dropped > 0 {
        eprintln!("deprehendo-trace: {} events dropped", dropped);
    }
    Ok(())
}

// -- signal wiring ---------------------------------------------------------

/// Set from the signal handler; the debug loop polls it.
static SIGNALLED: AtomicBool = AtomicBool::new(false);

/// Route SIGINT/SIGTERM to SIGNALLED (Linux). Elsewhere the default action
/// (terminate) stays in place.
#[cfg(target_os = "linux")]
fn signal_setup() {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SAFETY: `sig_handler` is an `extern "C" fn(i32)`, the type signal(2)
    // expects, and it only performs an atomic store, which is
    // async-signal-safe.
    unsafe {
        signal(SIGINT, sig_handler as *const () as usize);
        signal(SIGTERM, sig_handler as *const () as usize);
    }
}

#[cfg(target_os = "linux")]
extern "C" fn sig_handler(_sig: i32) {
    SIGNALLED.store(true, Ordering::SeqCst);
}

#[cfg(not(target_os = "linux"))]
fn signal_setup() {}

/// `deprehendo-trace replay FILE`: read the same framed format the Go agent
/// writes for raw trace capture (6.45) and dump events as text.
///
/// Bad-sample policy is the Go decoder's (`internal/trace/replay.go`), on
/// purpose: a frame that cannot be decoded is one bad record, so it is
/// counted and skipped so it cannot hide the rest of the recording, while a
/// broken *frame* (truncated, oversized, unknown kind) means the stream
/// boundaries are lost and replay stops with an error. Same file in, same
/// verdict out, in either language (6.56).
fn replay_mode(path: Option<&String>) -> Result<()> {
    let path = path.ok_or_else(|| ProtocolError("replay requires a file path".into()))?;
    let f =
        std::fs::File::open(path).map_err(|e| ProtocolError(format!("open {}: {}", path, e)))?;
    let mut fr = Framer::new(std::io::BufReader::new(f), std::io::sink());
    let mut events = 0u64;
    let mut bad_samples = 0u64;
    loop {
        match fr.read_frame() {
            Ok(ReadOutcome::Frame(frame)) => {
                if frame.kind != KIND_EVENT {
                    continue;
                }
                match decode_event(&frame.raw) {
                    Ok(ev) => {
                        events += 1;
                        println!(
                            "seq={} {} pid={} mono={}",
                            ev.sequence,
                            ev.event_type.name(),
                            ev.pid,
                            ev.monotonic_ns
                        );
                    }
                    Err(e) => {
                        // visible, counted, never silent: a corrupt record is
                        // evidence about the recording, not an absence.
                        bad_samples += 1;
                        eprintln!("bad sample: {}", e);
                    }
                }
            }
            Ok(ReadOutcome::Closed) => break,
            Ok(ReadOutcome::Timeout) => {
                // A zero read-timeout on a file would spin forever. files are
                // blocking: a file on disk never reads as a timeout.
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    eprintln!("replay: events={} bad_samples={}", events, bad_samples);
    Ok(())
}

/// `deprehendo-trace genfixtures DIR` (6.44/6.56): write the long-term fixture
/// set with the *production* encoder, so the Go suite decodes exactly what
/// the Rust tracer emits, a real cross-language check, not a mirror of
/// mirrored structs. Files (matching testdata/trace):
///
/// ```text
/// process-exec.bin       one framed PROCESS_EXEC
/// process-exit.bin       framed PROCESS_EXIT, died by signal 9
/// signal.bin             framed SIGNAL_SENT (sender known)
/// process-stop.bin       framed PROCESS_STOPPED
/// oom.bin                framed OOM_KILL (capability-gated; fixture only)/// dropped-events.bin    sequence 1..3 then 5: a visible gap
/// unknown-version.bin    mis-versioned payload: a bad sample, not silent
/// ```
fn genfixtures(dir: Option<&String>) -> Result<()> {
    let dir = dir.ok_or_else(|| ProtocolError("genfixtures requires a directory".into()))?;
    std::fs::create_dir_all(dir).map_err(|e| ProtocolError(format!("create {}: {}", dir, e)))?;

    let evts: Vec<(String, TraceEvent)> = {
        let mut v = Vec::with_capacity(5);
        #[allow(clippy::vec_init_then_push)] // fixtures read as a literal list
        {
            v.push((
                "process-exec.bin".to_string(),
                TraceEvent {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    monotonic_ns: 1_000_000_000,
                    wall_unix_ms: 1_767_000_000_000,
                    clock_offset_ns: 0,
                    event_type: EventType(TYPE_EXEC),
                    pid: 8241,
                    ppid: 5001,
                    pgid: 5001,
                    start_ticks: 0,
                    exec_path: "/usr/local/bin/Runner.Worker".to_string(),
                    exit_code: None,
                    signal: 0,
                    sender_pid: 0,
                    fact: 0,
                    source: SOURCE_PROC_CONNECTOR,
                },
            ));

            // A signaled death: fact names what the kernel established (6.14).
            v.push((
                "process-exit.bin".to_string(),
                TraceEvent {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    monotonic_ns: 1_234_000_000,
                    wall_unix_ms: 1_767_000_001_000,
                    clock_offset_ns: 0,
                    event_type: EventType(TYPE_EXIT),
                    pid: 8241,
                    ppid: 0,
                    pgid: 0,
                    start_ticks: 0,
                    exec_path: String::new(),
                    exit_code: None,
                    signal: 9,
                    sender_pid: 0,
                    fact: FACT_EXITED_BY_SIGNAL,
                    source: SOURCE_PROC_CONNECTOR,
                },
            ));

            v.push((
                "signal.bin".to_string(),
                TraceEvent {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    monotonic_ns: 1_230_000_000,
                    wall_unix_ms: 1_767_000_001_000,
                    clock_offset_ns: 0,
                    event_type: EventType(TYPE_SIGNAL),
                    pid: 8241,
                    ppid: 0,
                    pgid: 5001,
                    start_ticks: 0,
                    exec_path: String::new(),
                    exit_code: None,
                    signal: 15,
                    sender_pid: 8211,
                    fact: FACT_SIGNAL_SENT,
                    source: SOURCE_PROC_CONNECTOR,
                },
            ));

            v.push((
                "process-stop.bin".to_string(),
                TraceEvent {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    monotonic_ns: 1_800_000_000,
                    wall_unix_ms: 1_767_000_002_000,
                    clock_offset_ns: 0,
                    event_type: EventType(TYPE_STOP),
                    pid: 8241,
                    ppid: 0,
                    pgid: 0,
                    start_ticks: 0,
                    exec_path: String::new(),
                    exit_code: None,
                    signal: 19, // SIGSTOP; observed stop only, no sender claim (6.13)
                    sender_pid: 0,
                    fact: FACT_OBSERVED_STOP,
                    source: SOURCE_PROC_CONNECTOR,
                },
            ));

            v.push((
                "oom.bin".to_string(),
                TraceEvent {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    monotonic_ns: 2_000_000_000,
                    wall_unix_ms: 1_767_000_003_000,
                    clock_offset_ns: 0,
                    event_type: EventType(TYPE_OOM),
                    pid: 9900,
                    ppid: 0,
                    pgid: 0,
                    start_ticks: 0,
                    exec_path: String::new(),
                    exit_code: Some(137),
                    signal: 0,
                    sender_pid: 0,
                    fact: 0,
                    source: SOURCE_PROC_CONNECTOR,
                },
            ));

            v
        }
    };
    for (name, ev) in evts {
        let raw = encode_event(&ev)?;
        write_fixture_file(
            &format!("{}/{}", dir, name),
            KIND_EVENT,
            SCHEMA_VERSION,
            &raw,
        )?;
    }

    // dropped-events.bin: sequences 1..3 then 5, a visible gap the go and
    // rust analysts agree came from upstream loss, never absence (6.26).
    let mut frames: Vec<(u8, u16, Vec<u8>)> = Vec::new();
    for seq in [1u64, 2, 3, 5] {
        let ev = TraceEvent {
            schema_version: SCHEMA_VERSION,
            sequence: seq,
            monotonic_ns: (seq as i64) * 1_000_000,
            wall_unix_ms: 1_767_000_000_000 + (seq as i64) * 1_000,
            clock_offset_ns: 0,
            event_type: EventType(TYPE_EXEC),
            pid: 1000 + seq as u32,
            ppid: 0,
            pgid: 0,
            start_ticks: 0,
            exec_path: "/bin/tool".to_string(),
            exit_code: None,
            signal: 0,
            sender_pid: 0,
            fact: 0,
            source: SOURCE_SYNTHETIC,
        };
        frames.push((KIND_EVENT, SCHEMA_VERSION, encode_event(&ev)?));
    }
    let mut f = std::fs::File::create(format!("{}/dropped-events.bin", dir))
        .map_err(|e| ProtocolError(format!("create: {}", e)))?;
    write_frames(&mut f, &frames)?;

    // unknown-version.bin: schema 999 payload in a well-formed frame: the
    // receiver must reject the sample loudly, never silently (6.57).
    let bad = br#"{"schema_version":999,"sequence":1,"monotonic_ns":1,"wall_unix_ms":1,"type":1,"pid":1,"source":1}"#.to_vec();
    let mut f = std::fs::File::create(format!("{}/unknown-version.bin", dir))
        .map_err(|e| ProtocolError(format!("create: {}", e)))?;
    write_frames(&mut f, &[(KIND_EVENT, 999, bad)])?;

    Ok(())
}

/// One fixture file, exactly one frame, through the production framing path.
fn write_fixture_file(path: &str, kind: u8, version: u16, raw: &[u8]) -> Result<()> {
    let mut f = std::fs::File::create(path)
        .map_err(|e| ProtocolError(format!("create {}: {}", path, e)))?;
    write_frames(&mut f, &[(kind, version, raw.to_vec())])
        .map_err(|e| ProtocolError(format!("write {}: {}", path, e)))
}
