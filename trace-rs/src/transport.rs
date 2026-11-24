//! Unix socket server (6.5/6.7/6.24; §6.3 a–f). One live agent connection at
//! a time; a new one replaces a stale one after the previous session ends.
//!
//! Session guarantees:
//!   - every event carries a strictly increasing per-session sequence
//!     number, stamped at the source thread (backend::publish);
//!   - every control is acked, with `err` set when the watch set refused
//!     or the identity operand failed (STALE_IDENTITY, §6.3 f);
//!   - SHUTDOWN stops the whole tracer process cleanly;
//!   - an agent disconnect does not kill the tracer: the backend keeps
//!     running only for the session; the process returns to accept-loop
//!     and serves the next agent connection (6.39). In supervised mode
//!     (`--supervised`) the process serves exactly one session and exits
//!     on EOF, and dies with the agent via PR_SET_PDEATHSIG (§6.3 a);
//!   - a LOSS frame (§6.3 d) goes out as soon as a stage counter moves,
//!     so the agent knows *where* events went missing, not just *that*;
//!   - a HEALTH frame (§6.3 e) goes out once a second: counters, queue
//!     depth, watches, uptime. The agent treats 5 s of frame silence as a
//!     hung tracer;
//!   - LOSS/HEALTH are protocol-2 frames: a session that negotiated to
//!     protocol 1 never receives them (compatibility policy §6.4).

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::backend::LossCounters;
use crate::framing::{
    decode_control, encode_ack, encode_event, encode_health, encode_loss, read_json, write_json,
    Framer, ProtocolError, ReadOutcome,
};
use crate::proc_connector::{monotonic_ns, wall_millis};
use crate::schema::*;
use crate::watch::WatchSet;

pub const TRACER_VERSION: &str = concat!("deprehendo-trace/", env!("CARGO_PKG_VERSION"));

/// Bounded event queue between kernel thread and socket thread. Producers
/// never block: a full queue is an explicit, sequence-visible loss (6.25).
pub const QUEUE_DEPTH: usize = 4096;

/// A short read timeout on the agent socket keeps the event pump responsive
/// without a dedicated reactor.
const SOCKET_POLL: Duration = Duration::from_millis(50);

/// The pump reads controls at least every N drained events (§6.3 c): under
/// an event backlog acks must not starve, or the agent's command timeout
/// fires and it kills a healthy tracer.
const MAX_EVENTS_PER_CONTROL_POLL: usize = 256;

/// How long a watch control waits for an in-kernel backend to mirror the set
/// before its ack reports failure (6.23). The eBPF pump syncs within one
/// poll cycle; this bound only catches a pump that is not running, and a
/// timeout is an error ack, never a silent "applied".
const WATCH_SYNC_TIMEOUT: Duration = Duration::from_millis(2000);

pub struct Tracer {
    pub socket_path: String,
    /// Process-wide shutdown caused by an agent SHUTDOWN control.
    stop_requested: Arc<AtomicBool>,
    watch: Arc<WatchSet>,
    loss: Arc<LossCounters>,
}

// NOTE: loss is per-session (reset at every handshake); `session()` keeps
// its own counters as a local Arc. the struct field is unused legacy and
// stays for the standalone status surface only.

impl Tracer {
    pub fn new(socket_path: String) -> Self {
        Tracer {
            socket_path,
            stop_requested: Arc::new(AtomicBool::new(false)),
            watch: WatchSet::new(),
            loss: LossCounters::new(),
        }
    }

    #[allow(dead_code)] // used by agent status endpoints in later integration
    pub fn watches(&self) -> u32 {
        self.watch.watches()
    }

    #[allow(dead_code)]
    pub fn lost(&self) -> u64 {
        // Session-local counters make a Tracer-level total meaningless;
        // keep the method for the status surface only.
        self.loss.total()
    }

    pub fn stop_requested(&self) -> bool {
        self.stop_requested.load(Ordering::Relaxed)
    }

    /// Standalone mode: serve agent sessions until `stop_requested`. The
    /// socket file lives exactly as long as this call.
    pub fn serve(&self) -> Result<(), ProtocolError> {
        let listener = self.bind()?;
        while !self.stop_requested() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_read_timeout(Some(SOCKET_POLL));
                    if let Err(e) = self.session(stream) {
                        eprintln!("deprehendo-trace: session ended: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("deprehendo-trace: accept: {}", e);
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    /// Supervised mode (§6.3 a): the agent owns our lifetime. Die with the
    /// parent (PR_SET_PDEATHSIG SIGKILL, checked against the fork→prctl
    /// race), serve exactly one session, exit on EOF. A refused pdeathsig
    /// is fatal here: the whole point of the mode is a tracer that cannot
    /// outlive the agent.
    pub fn serve_supervised(&self) -> Result<(), ProtocolError> {
        if !crate::nix::set_pdeathsig(crate::nix::SIGKILL_NUM) {
            return Err(ProtocolError(
                "PR_SET_PDEATHSIG refused: refusing supervised mode".into(),
            ));
        }
        // close the fork→prctl race: armed after the parent died means
        // reparented, and the signal will never come.
        if crate::nix::parent_pid() == 1 {
            return Err(ProtocolError(
                "parent already gone at startup; supervised tracer exits".into(),
            ));
        }
        let listener = self.bind()?;
        // exactly one session; extra connections while it runs are closed
        // unceremoniously. there is no second session in this mode.
        let (stream, _) = match listener.accept() {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_file(&self.socket_path);
                return Err(ProtocolError(format!("accept: {}", e)));
            }
        };
        let _ = stream.set_read_timeout(Some(SOCKET_POLL));
        let result = self.session(stream);
        let _ = std::fs::remove_file(&self.socket_path);
        result
    }

    fn bind(&self) -> std::result::Result<UnixListener, ProtocolError> {
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| ProtocolError(format!("bind {}: {}", self.socket_path, e)))?;
        let _ = std::fs::set_permissions(
            &self.socket_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
        Ok(listener)
    }

    fn session(&self, stream: UnixStream) -> Result<(), ProtocolError> {
        let peer = stream
            .try_clone()
            .map_err(|e| ProtocolError(format!("clone: {}", e)))?;
        let mut fr = Framer::new(peer, stream);

        // 6.7: the agent says hello first; negotiation is the same range
        // rule mirrored on both sides.
        let theirs: Handshake = read_json(&mut fr, KIND_HANDSHAKE)?;
        if theirs.schema_version != SCHEMA_VERSION {
            return Err(ProtocolError(format!(
                "agent schema {} != ours {}",
                theirs.schema_version, SCHEMA_VERSION
            )));
        }
        // Range-overlap negotiation (mirrors decode_handshake): the session
        // exists only when the two declared spans intersect. an agent still
        // at 1..1 meets us at protocol 1 and never sees protocol-2 frames.
        if theirs.protocol_version < PROTOCOL_VERSION_MIN || theirs.min_version > PROTOCOL_VERSION {
            return Err(ProtocolError(format!(
                "agent protocol {}..{} does not overlap ours {}..{}",
                theirs.min_version, theirs.protocol_version, PROTOCOL_VERSION_MIN, PROTOCOL_VERSION
            )));
        }
        // effective protocol for this session: the overlap of both ranges,
        // which after the intersection test is simpler: min of the two tops.
        // below 2, LOSS/HEALTH frames are never emitted (§6.4).
        let negotiated = negotiated_protocol(theirs.protocol_version, theirs.min_version);
        // Per-session sequence resets at every handshake: a new agent
        // session starts a fresh stream, recorded as a restart by the agent.
        let loss = LossCounters::new();
        // so does the watch set. PIDs from an earlier session may belong to
        // other processes by now (6.23); the new agent pushes its own.
        let _ = self.watch.apply(OP_RESET, &[], MAX_WATCH_SET_ENTRIES);
        // backend selection (§2.1) happens per session, before the
        // handshake: the attach's per-capability states ARE the advertised
        // capabilities, and a fallback carries its reason on the wire.
        let selection = crate::backend::select_backend();
        let unsupported = selection.caps.unsupported;
        let reply = Handshake {
            protocol_version: PROTOCOL_VERSION,
            min_version: PROTOCOL_VERSION_MIN,
            tracer_version: TRACER_VERSION.to_string(),
            capabilities: selection.caps,
            monotonic_ns: monotonic_ns(),
            wall_unix_ms: wall_millis(),
            schema_version: SCHEMA_VERSION,
            // §6.3 b: boot identity, PID namespace and the ordering clock,
            // so the agent can refuse a tracer from another boot or a
            // different PID namespace instead of mistranslating every PID.
            boot_id: crate::proc_connector::boot_id(),
            pid_namespace_inode: crate::proc_connector::pid_namespace_inode(),
            event_clock: EVENT_CLOCK_MONOTONIC.to_string(),
            selection_reason: selection.selection_reason,
        };
        write_json(&mut fr, KIND_HANDSHAKE, SCHEMA_VERSION, &reply)?;

        let (tx, rx) = sync_channel::<TraceEvent>(QUEUE_DEPTH);
        let started = Instant::now();
        let worker_stop = Arc::new(AtomicBool::new(false));
        // the kernel refused the collector (6.53): answer the handshake
        // honestly and serve controls only. no collector means no pipeline
        // to die, so the sender stays with this session; otherwise pump
        // would read the absent collector as a dead pipeline.
        let mut idle_tx = None;
        // only a backend that filters in the kernel makes the ack wait for
        // the map write; the transport must know before the backend moves
        // into its thread.
        let kernel_watch_sync = !unsupported && selection.backend.watch_sync_is_kernel_visible();
        let worker = if unsupported {
            idle_tx = Some(tx);
            None
        } else {
            let watch = Arc::clone(&self.watch);
            let loss = Arc::clone(&loss);
            let stop = Arc::clone(&worker_stop);
            let mut backend = selection.backend;
            Some(thread::spawn(move || {
                backend.run(watch, tx, loss, stop);
            }))
        };

        let result = self.pump(&mut fr, &rx, negotiated, started, &loss, kernel_watch_sync);
        worker_stop.store(true, Ordering::Relaxed);
        if let Some(worker) = worker {
            let _ = worker.join();
        }
        drop(idle_tx);
        result
    }

    fn pump(
        &self,
        fr: &mut Framer<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>,
        rx: &Receiver<TraceEvent>,
        negotiated: u32,
        started: Instant,
        loss: &LossCounters,
        kernel_watch_sync: bool,
    ) -> Result<(), ProtocolError> {
        let mut drained_without_control = 0usize;
        let mut seen_loss: [u64; 4] = [0; 4];
        let mut last_health = Instant::now();
        let mut events_sent: u64 = 0;
        loop {
            // SHUTDOWN is process-wide: once stored, end this session and
            // the accept loop, even if the client keeps the socket open.
            if self.stop_requested() {
                return Ok(());
            }
            // events first, always in sequence order. A control poll is
            // forced every MAX_EVENTS_PER_CONTROL_POLL drained events even
            // while the queue stays non-empty (§6.3 c).
            if drained_without_control >= MAX_EVENTS_PER_CONTROL_POLL {
                drained_without_control = 0;
                self.drain_control(fr, negotiated, kernel_watch_sync)?;
            }
            match rx.try_recv() {
                Ok(ev) => {
                    let raw = encode_event(&ev)?;
                    fr.write_frame(KIND_EVENT, SCHEMA_VERSION, &raw)?;
                    events_sent += 1;
                    drained_without_control += 1;
                    continue;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    // never pretend events simply stopped (6.27): say the
                    // pipeline died and let the agent decide.
                    return Err(ProtocolError("backend pipeline closed".into()));
                }
            }
            if negotiated >= 2 {
                // §6.3 d: a stage counter move is a LOSS frame at once; the
                // window is bounded by this observation interval.
                for (i, (stage, _)) in loss.all_names().iter().enumerate() {
                    let seen = seen_loss[i];
                    let now = loss.get(*stage);
                    if now > seen {
                        let _ = encode_loss(&Loss {
                            stage: *stage,
                            count_at_least: now - seen,
                            first_ns: monotonic_ns(),
                            last_ns: monotonic_ns(),
                        })
                        .and_then(|raw| fr.write_frame(KIND_LOSS, SCHEMA_VERSION, &raw));
                        seen_loss[i] = now;
                    }
                }
                // §6.3 e: liveness once a second. Worst-poll skew below is
                // bounded by SOCKET_POLL; the agent's threshold is 5 s.
                if last_health.elapsed().as_millis() as u64 >= HEALTH_INTERVAL_MS {
                    last_health = Instant::now();
                    let health = Health {
                        uptime_ms: started.elapsed().as_millis() as u64,
                        events_sent,
                        events_lost: loss.total(),
                        queue_depth: queue_depth(rx),
                        watches: self.watch.watches(),
                        monotonic_ns: monotonic_ns(),
                    };
                    let raw = encode_health(&health)?;
                    fr.write_frame(KIND_HEALTH, SCHEMA_VERSION, &raw)?;
                }
            }
            // one socket read; a timeout means nothing arrived in this poll
            // window and framing state is intact, so loop straight back
            // into the event flush.
            match fr.read_frame() {
                Ok(ReadOutcome::Timeout) => {}
                Ok(ReadOutcome::Closed) => return Ok(()), // agent hung up
                Ok(ReadOutcome::Frame(frame)) => match frame.kind {
                    KIND_CONTROL => {
                        drained_without_control = 0;
                        self.handle_control_frame(fr, negotiated, &frame.raw, kernel_watch_sync)?;
                    }
                    KIND_EVENT | KIND_HANDSHAKE | KIND_ACK | KIND_LOSS | KIND_HEALTH => {
                        return Err(ProtocolError(format!(
                            "unexpected frame kind {} from agent",
                            frame.kind
                        )));
                    }
                    n => return Err(ProtocolError(format!("unknown kind {}", n))),
                },
                Err(e) => return Err(e),
            }
        }
    }

    /// Read and answer one control without waiting for events: the §6.3 c
    /// starvation bound. A Timeout (nothing pending) is success.
    fn drain_control(
        &self,
        fr: &mut Framer<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>,
        negotiated: u32,
        kernel_watch_sync: bool,
    ) -> Result<(), ProtocolError> {
        match fr.read_frame() {
            Ok(ReadOutcome::Timeout) => Ok(()),
            Ok(ReadOutcome::Closed) => Ok(()),
            Ok(ReadOutcome::Frame(frame)) if frame.kind == KIND_CONTROL => {
                self.handle_control_frame(fr, negotiated, &frame.raw, kernel_watch_sync)
            }
            Ok(ReadOutcome::Frame(frame)) => Err(ProtocolError(format!(
                "unexpected frame kind {} from agent",
                frame.kind
            ))),
            Err(e) => Err(e),
        }
    }

    fn handle_control_frame(
        &self,
        fr: &mut Framer<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>,
        negotiated: u32,
        raw: &[u8],
        kernel_watch_sync: bool,
    ) -> Result<(), ProtocolError> {
        let control = decode_control(raw)?;
        let op = control.op;
        let (err, stale) = match self.apply_control(&control, kernel_watch_sync) {
            Ok(stale) => (String::new(), stale),
            Err(e) => (e, Vec::new()),
        };
        let ack = ControlAck {
            op,
            watches: self.watch.watches(),
            err,
            stale,
        };
        let ack_raw = encode_ack(&ack)?;
        fr.write_frame(KIND_ACK, SCHEMA_VERSION, &ack_raw)?;
        let _ = negotiated;
        if op.0 == OP_SHUTDOWN {
            self.stop_requested.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Apply one control. Ok carries the PIDs an ADD refused as stale; the
    /// rest of that ADD was applied.
    fn apply_control(
        &self,
        control: &Control,
        kernel_watch_sync: bool,
    ) -> std::result::Result<Vec<u32>, String> {
        match control.op.0 {
            OP_ADD => {
                let (accepted, stale) =
                    split_identities(control, crate::proc_connector::live_start_ticks)?;
                self.watch
                    .apply(control.op.0, &accepted, MAX_WATCH_SET_ENTRIES)?;
                self.await_kernel_watch(kernel_watch_sync)?;
                Ok(stale)
            }
            OP_REMOVE | OP_RESET => {
                self.watch
                    .apply(control.op.0, &control.pids, MAX_WATCH_SET_ENTRIES)?;
                self.await_kernel_watch(kernel_watch_sync)?;
                Ok(Vec::new())
            }
            OP_ADD_CGROUP => Err(format!(
                "cgroup watches unsupported by backend {}",
                "proc_connector"
            )),
            OP_FLUSH | OP_PING => Ok(Vec::new()),
            n => Err(format!("unsupported op {}", n)),
        }
    }

    /// 6.23: the ack for a watch control is written only once the backend's
    /// kernel-side filter holds the set this control applied. Backends whose
    /// filter is in user space return immediately.
    fn await_kernel_watch(&self, required: bool) -> std::result::Result<(), String> {
        if !required {
            return Ok(());
        }
        let version = self.watch.version();
        if self.watch.wait_synced(version, WATCH_SYNC_TIMEOUT) {
            Ok(())
        } else {
            Err(
                "watch set not applied in the kernel: the backend did not confirm the filter"
                    .to_string(),
            )
        }
    }
}

/// §6.3 f / §4: split an identity-keyed ADD into the PIDs whose claimed
/// start time still matches the live process and the stale ones (dead, or
/// the PID now belongs to another process), so a recycled PID never adopts a
/// dead process's watch.
///
/// Stale PIDs are refused one by one, not by failing the whole control: an
/// agent re-pushing its set after a restart routinely names a process that
/// exited in the gap, and refusing the batch made the agent treat the push as
/// a failed attempt and restart again with the same set.
pub(crate) fn split_identities(
    control: &Control,
    live: impl Fn(u32) -> Option<i64>,
) -> std::result::Result<(Vec<u32>, Vec<u32>), String> {
    if control.start_ticks.is_empty() {
        // an older agent keys by PID only: no claim to check.
        return Ok((control.pids.clone(), Vec::new()));
    }
    if control.start_ticks.len() != control.pids.len() {
        return Err(format!(
            "start_ticks has {} entries for {} pids",
            control.start_ticks.len(),
            control.pids.len()
        ));
    }
    let mut accepted = Vec::with_capacity(control.pids.len());
    let mut stale = Vec::new();
    for (pid, claimed) in control.pids.iter().zip(control.start_ticks.iter()) {
        if *claimed <= 0 || live(*pid) == Some(*claimed) {
            // unknown identity from the agent carries no claim to refuse.
            accepted.push(*pid);
        } else {
            stale.push(*pid);
        }
    }
    Ok((accepted, stale))
}

fn queue_depth(rx: &Receiver<TraceEvent>) -> u32 {
    // the bounded channel exposes no depth; the honest estimate is a poll
    // loop with a bounded budget, or zero on a drained queue.
    let mut n = 0u32;
    while n < 65536 {
        match rx.try_recv() {
            Ok(_) => n += 1,
            Err(_) => break,
        }
    }
    n
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn add(pids: Vec<u32>, ticks: Vec<i64>) -> Control {
        Control {
            op: ControlOp(OP_ADD),
            pids,
            start_ticks: ticks,
        }
    }

    // live identities: pid 10 started at 100, pid 20 at 200; pid 30 is dead.
    fn live(pid: u32) -> Option<i64> {
        match pid {
            10 => Some(100),
            20 => Some(200),
            _ => None,
        }
    }

    #[test]
    fn stale_pids_are_refused_one_by_one() {
        // 20 was reused (the agent watched an older process), 30 is dead.
        let c = add(vec![10, 20, 30], vec![100, 150, 300]);
        let (accepted, stale) = split_identities(&c, live).unwrap();
        assert_eq!(accepted, vec![10]);
        assert_eq!(stale, vec![20, 30]);
    }

    #[test]
    fn unknown_claims_and_pid_only_agents_are_accepted() {
        let c = add(vec![10, 30], vec![0, -1]);
        assert_eq!(split_identities(&c, live).unwrap(), (vec![10, 30], vec![]));
        let old = add(vec![10, 30], vec![]);
        assert_eq!(
            split_identities(&old, live).unwrap(),
            (vec![10, 30], vec![])
        );
    }

    #[test]
    fn mismatched_operand_lengths_are_a_protocol_error() {
        assert!(split_identities(&add(vec![10, 20], vec![100]), live).is_err());
    }
}
