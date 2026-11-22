//! eBPF backend: the Phase 6 primary collection mechanism (contract §2,
//! engineering queue item 4). Everything here is cfg(target_os = "linux") at the
//! module root. the crate keeps building on macOS with the backend
//! refusing before any of this compiles in (§2.2).
//!
//! Layers:
//!   - `runopsy.bpf.c`: the kernel programs, tracepoints and one raw
//!     tracepoint for exec/exit/fork/sent/stop-resume/oom, a ring buffer,
//!     and an identity-aware watch map;
//!   - `libbpf.rs`: the FFI this module drives;
//!   - here: attach with per-capability honesty (§2.1: a capability is
//!     true only when its programs actually attached), the ring pump that
//!     parses samples byte-wise into `TraceEvent`s, and the watch-set
//!     control that mirrors the agent's set into the kernel map.
//!
//! Invariants carried over from the proc connector (never diverge):
//!   - loss is stage-labelled and counted, never silent (6.25–6.27);
//!   - events are published through `backend::publish` (sequence stamped
//!     before the bounded enqueue, so a queue drop is a visible gap);
//!   - a recycled PID never adopts a watch: the kernel map is keyed
//!     `(tgid, start_ticks)` and mismatches delete (§6.3 f).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use crate::backend::{publish, should_stop, BoundedSender, LossCounters, TraceBackend};
use crate::schema::*;
use crate::watch::WatchSet;

use crate::libbpf::{self, Link, Object, PollRing};

// ---- record layout (mirrors `struct rec` in runopsy.bpf.c) -----------------
//
// u64 ts; u32 kind, pid, ppid, pgid, other_pid, sig, fact, flags;
// (natural pad 4) s64 status, start_ticks, other_start_ticks, send_result;
// char path[512].
// the parser reads with from_le_bytes and bounds checks only, never a
// transmuted struct (§11.2).

const REC_HEADER_SIZE: usize = 72;
const PATH_MAX: usize = 512;

const OFF_KIND: usize = 8;
const OFF_PID: usize = 12;
const OFF_PPID: usize = 16;
const OFF_PAGEID: usize = 20;
const OFF_OTHER_PID: usize = 24;
const OFF_SIG: usize = 28;
const OFF_FACT: usize = 32;
const OFF_FLAGS: usize = 36;
const OFF_STATUS: usize = 40;
const OFF_START_TICKS: usize = 48;
const OFF_OTHER_TICKS: usize = 56;
const OFF_SEND_RESULT: usize = 64;
const OFF_PATH: usize = REC_HEADER_SIZE;

// record kinds; numbers are shared with runopsy.bpf.c.
const REC_EXEC: u32 = 1;
const REC_EXIT: u32 = 2;
const REC_FORK: u32 = 3;
const REC_SENT: u32 = 4;
const REC_STOP: u32 = 5;
const REC_RESUME: u32 = 6;
const REC_OOM: u32 = 7;

const FLAG_STATUS_PRESENT: u32 = 1;

const REC_SIZE_FLOOR: usize = OFF_SEND_RESULT + 8;

/// Poll timeout in ms: the stop-check and watch-sync cadence (§6.3: the
/// pump never blocks indefinitely).
const POLL_TIMEOUT_MS: i32 = 100;

// ---- attach ----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Unavailable {
    pub reason: String,
}

/// Backend selection (contract §2.1): eBPF attach → proc connector →
/// unavailable. When the primary refused, the reason rides into the
/// handshake's `selection_reason` and the per-capability states.
pub fn select() -> crate::backend::Selected {
    libbpf::set_print(true);
    match attach() {
        Ok((backend, caps)) => crate::backend::Selected {
            backend: Box::new(backend),
            caps,
            selection_reason: String::new(),
        },
        Err(Unavailable { reason }) => {
            let (mut caps, refusal) = crate::backend::probe_with_reason();
            if let Some(refusal) = refusal {
                // the kernel refused the connector too (6.53): nothing
                // attaches. the session still answers the handshake honestly
                // and the agent degrades once to polling with the reason.
                caps.exec_state = CAP_STATE_UNAVAILABLE.into();
                caps.exec_reason = refusal.clone();
                caps.exit_state = CAP_STATE_UNAVAILABLE.into();
                caps.exit_reason = refusal.clone();
                return crate::backend::Selected {
                    backend: Box::new(crate::proc_connector::ProcConnectorBackend),
                    caps,
                    selection_reason: format!(
                        "eBPF attach failed; proc connector refused: {reason}; {refusal}"
                    ),
                };
            }
            // the proc connector observes exactly exec/exit; every other
            // capability stays honestly false with its reason (§6.3 b).
            caps.exec_state = CAP_STATE_ATTACHED.into();
            caps.exit_state = CAP_STATE_ATTACHED.into();
            caps.signals_state = CAP_STATE_NOT_COLLECTED.into();
            caps.signals_reason = "sent/delivered signals need the eBPF backend".into();
            caps.stop_resume_state = CAP_STATE_NOT_COLLECTED.into();
            caps.stop_resume_reason = "job-control stop/resume needs the eBPF backend".into();
            caps.oom_state = CAP_STATE_NOT_COLLECTED.into();
            caps.oom_reason = "OOM victim needs the eBPF backend".into();
            crate::backend::Selected {
                backend: Box::new(crate::proc_connector::ProcConnectorBackend),
                caps,
                selection_reason: format!("eBPF attach failed; proc connector selected: {reason}"),
            }
        }
    }
}

/// Attach every attachable program. Base capabilities (exec, exit) failing
/// aborts the whole attach. that is what the proc fallback is for
/// (§2.1). Partial capabilities degrade with per-cap reasons, not lies.
pub fn attach() -> Result<(EbpfBackend, Capabilities), Unavailable> {
    if cfg!(not(target_os = "linux")) {
        return Err(Unavailable {
            reason: "eBPF backend exists on Linux only".into(),
        });
    }
    prerun_checks()?;
    let obj_path = object_path().map_err(|reason| Unavailable { reason })?;
    let mut obj = Object::open_and_load(&obj_path).map_err(|e| Unavailable {
        reason: format!("BPF object failed to load ({}): {}", obj_path.display(), e),
    })?;

    let rb_fd = obj.map_fd("rb").ok_or_else(|| Unavailable {
        reason: "BPF object lacks the rb map (build mismatch?)".into(),
    })?;
    let watched_fd = obj.map_fd("watched").ok_or_else(|| Unavailable {
        reason: "BPF object lacks the watched map (build mismatch?)".into(),
    })?;
    let loss_fd = obj.map_fd("loss_kernel").ok_or_else(|| Unavailable {
        reason: "BPF object lacks the loss_kernel map (build mismatch?)".into(),
    })?;

    let mut caps = AttachCaps::default();
    let mut links: Vec<Link> = Vec::new();

    // exec: base capability.
    match obj.attach_tracepoint("tp_exec", "sched", "sched_process_exec") {
        Ok(l) => {
            caps.exec_ok = true;
            links.push(l);
        }
        Err(e) => {
            return Err(Unavailable {
                reason: format!("attach sched_process_exec failed: {e}"),
            })
        }
    }
    // exit: base capability.
    match obj.attach_tracepoint("tp_exit", "sched", "sched_process_exit") {
        Ok(l) => {
            caps.exit_ok = true;
            links.push(l);
        }
        Err(e) => {
            return Err(Unavailable {
                reason: format!("attach sched_process_exit failed: {e}"),
            })
        }
    }
    // fork: inheritance inside the tracer (§5); failure degrades toward
    // agent-driven watch sync, a reason recorded on the exec capability.
    match obj.attach_raw_tracepoint("raw_fork", "sched_process_fork") {
        Ok(l) => links.push(l),
        Err(e) => caps.exec_reason = format!("fork inheritance unavailable: {e}"),
    }

    // SENT: all six syscall enter/exit pairs. one missing part means the
    // capability stays false: partial signal evidence is not signal truth.
    let mut sentinel_missing: Option<String> = None;
    for (sym, cat, name) in SENT_PROGRAMS {
        match obj.attach_tracepoint(sym, cat, name) {
            Ok(l) => links.push(l),
            Err(e) => {
                sentinel_missing = Some(format!("{name}: {e}"));
                break;
            }
        }
    }
    match sentinel_missing {
        None => caps.signals_ok = true,
        Some(m) => caps.signals_reason = format!("send syscall tract incomplete: {m}"),
    }

    // generate: stop/resume confirmations (§3.5) and the SENT rule-1
    // marking (§3.3 rule 1). one program serves both.
    match obj.attach_tracepoint("tp_signal_generate", "signal", "signal_generate") {
        Ok(l) => {
            caps.stop_resume_ok = true;
            links.push(l);
        }
        Err(e) => caps.stop_resume_reason = format!("attach signal_generate failed: {e}"),
    }

    // OOM (§3.6).
    match obj.attach_tracepoint("tp_oom", "oom", "mark_victim") {
        Ok(l) => {
            caps.oom_ok = true;
            links.push(l);
        }
        Err(e) => caps.oom_reason = format!("attach oom:mark_victim failed: {e}"),
    }

    if !caps.exec_ok || !caps.exit_ok {
        // drop links first: drop order on the vector is reverse, so the
        // attached programs outlive the object. Forbidden. detach them
        // explicitly.
        return Err(Unavailable {
            reason: format!(
                "base processes not attachable; refusing partial backend (exec_ok={}, exit_ok={})",
                caps.exec_ok, caps.exit_ok
            ),
        });
    }

    let backend = EbpfBackend {
        state: Some(Attached {
            ring: None,
            links,
            obj,
            rb_fd,
            watched_fd,
            loss_fd,
        }),
    };
    Ok((backend, caps.into()))
}

/// The SENT syscall pairs, all parts mandatory for `signals`.
const SENT_PROGRAMS: &[(&str, &str, &str)] = &[
    ("tp_enter_kill", "syscalls", "sys_enter_kill"),
    ("tp_exit_kill", "syscalls", "sys_exit_kill"),
    ("tp_enter_tkill", "syscalls", "sys_enter_tkill"),
    ("tp_exit_tkill", "syscalls", "sys_exit_tkill"),
    ("tp_enter_tgkill", "syscalls", "sys_enter_tgkill"),
    ("tp_exit_tgkill", "syscalls", "sys_exit_tgkill"),
    (
        "tp_enter_rt_sigqueueinfo",
        "syscalls",
        "sys_enter_rt_sigqueueinfo",
    ),
    (
        "tp_exit_rt_sigqueueinfo",
        "syscalls",
        "sys_exit_rt_sigqueueinfo",
    ),
    (
        "tp_enter_rt_tgsigqueueinfo",
        "syscalls",
        "sys_enter_rt_tgsigqueueinfo",
    ),
    (
        "tp_exit_rt_tgsigqueueinfo",
        "syscalls",
        "sys_exit_rt_tgsigqueueinfo",
    ),
    (
        "tp_enter_pidfd_send_signal",
        "syscalls",
        "sys_enter_pidfd_send_signal",
    ),
    (
        "tp_exit_pidfd_send_signal",
        "syscalls",
        "sys_exit_pidfd_send_signal",
    ),
];

/// Typed attach-state the per-capability report fills. Honest per
/// capability: only actual attach success sets the bool.
#[derive(Default)]
struct AttachCaps {
    exec_ok: bool,
    exec_reason: String,
    exit_ok: bool,
    exit_reason: String,
    signals_ok: bool,
    signals_reason: String,
    stop_resume_ok: bool,
    stop_resume_reason: String,
    oom_ok: bool,
    oom_reason: String,
}

impl From<AttachCaps> for Capabilities {
    fn from(c: AttachCaps) -> Capabilities {
        Capabilities {
            backend: "ebpf".into(),
            kernel: crate::backend::kernel_version(),
            process_exec: c.exec_ok,
            process_exit: c.exit_ok,
            signals: c.signals_ok,
            stop_resume: c.stop_resume_ok,
            oom_kill: c.oom_ok,
            privileged: true, // attach passed the privilege checks it needed
            unprivileged: false,
            unsupported: false,
            exec_state: cap_state(c.exec_ok, &c.exec_reason),
            exec_reason: c.exec_reason,
            exit_state: cap_state(c.exit_ok, &c.exit_reason),
            exit_reason: c.exit_reason,
            signals_state: cap_state(c.signals_ok, &c.signals_reason),
            signals_reason: c.signals_reason,
            stop_resume_state: cap_state(c.stop_resume_ok, &c.stop_resume_reason),
            stop_resume_reason: c.stop_resume_reason,
            oom_state: cap_state(c.oom_ok, &c.oom_reason),
            oom_reason: c.oom_reason,
        }
    }
}

fn cap_state(ok: bool, reason: &str) -> String {
    if ok {
        CAP_STATE_ATTACHED.into()
    } else if reason.is_empty() {
        CAP_STATE_UNAVAILABLE.into()
    } else {
        format!("{CAP_STATE_UNAVAILABLE}: {reason}")
    }
}

/// Object path: build-time-embedded default, with a runtime override for
/// tests pointing at an object built elsewhere.
fn object_path() -> Result<std::path::PathBuf, String> {
    if let Ok(p) = std::env::var("RUNOPSY_TRACE_BPF_OBJECT") {
        if !p.is_empty() {
            return Ok(std::path::PathBuf::from(p));
        }
    }
    let p = option_env!("RUNOPSY_BPF_O").unwrap_or("");
    if p.is_empty() {
        return Err(
            "this binary was built without the BPF object (clang + bpftool missing at \
             build time); rebuild with the recorded toolchain"
                .into(),
        );
    }
    Ok(std::path::PathBuf::from(p))
}

/// Environment checks in contract order (§2.4): kernel floor, privilege
/// shape (CAP_BPF+CAP_PERFMON, or CAP_SYS_ADMIN), lockdown, each with its
/// honest reason. The attach itself still proves the truth: a refused
/// load carries libbpf's reason verbatim.
fn prerun_checks() -> Result<(), Unavailable> {
    #[cfg(target_os = "linux")]
    {
        let kernel = crate::backend::kernel_version();
        if !kernel_at_least(&kernel, (5, 15)) {
            return Err(Unavailable {
                reason: format!("kernel {kernel}: eBPF backend needs 5.15+"),
            });
        }
        if !has_bpf_privileges() {
            return Err(Unavailable {
                reason: "this process holds no CAP_BPF/CAP_PERFMON (or CAP_SYS_ADMIN); \
                         grant them to the tracer binary, never to the agent (§2.4)"
                    .into(),
            });
        }
        if std::fs::read_to_string("/sys/kernel/security/lockdown")
            .map(|s| s.contains("[confidentiality]"))
            .unwrap_or(false)
        {
            return Err(Unavailable {
                reason: "kernel lockdown is in confidentiality mode".into(),
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn kernel_at_least(release: &str, floor: (u8, u8)) -> bool {
    let text = release.split(['-', ' ']).next().unwrap_or("");
    let mut it = text.split('.');
    let a: u8 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let b: u8 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (a, b) >= floor
}

#[cfg(target_os = "linux")]
fn has_bpf_privileges() -> bool {
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    const CAP_PERFMON: u64 = 1 << 38;
    const CAP_BPF: u64 = 1 << 39;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let bits = u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
            return ((bits & CAP_BPF) != 0 && (bits & CAP_PERFMON) != 0)
                || (bits & CAP_SYS_ADMIN) != 0;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn has_bpf_privileges() -> bool {
    false
}

// ---- the attached state ----------------------------------------------------

/// Everything the pump touches after a successful attach. Drop order is
/// declaration order: ring, links (detach), object (free).
pub struct Attached {
    /// Created in `run()`; the sample callback is used only from the
    /// single poll owner thread, so `None` here means "no pump yet".
    pub ring: Option<PollRing>,
    pub links: Vec<Link>,
    pub obj: Object,
    pub rb_fd: i32,
    pub watched_fd: i32,
    /// fd of the kernel-side loss counter (array map, key 0).
    pub loss_fd: i32,
}

pub struct EbpfBackend {
    /// One session per attach (the agent restarts spawn a new process and
    /// a new attach; kernel-side maps die with the old process).
    state: Option<Attached>,
}

impl EbpfBackend {
    /// Attach, read the honest per-capability states, detach. The CLI's
    /// `capabilities` surface and the tests use this; leaves nothing
    /// attached.
    pub fn probe_caps() -> Result<Capabilities, Unavailable> {
        let (backend, caps) = attach()?;
        drop(backend);
        Ok(caps)
    }
}

impl TraceBackend for EbpfBackend {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    /// The filter lives in the `watched` map, so a watch ack must wait for
    /// the pump to write it (6.23).
    fn watch_sync_is_kernel_visible(&self) -> bool {
        true
    }

    /// The pump. Never blocks indefinitely (poll timeout ≤ 100 ms), never
    /// panics; loss stays stage-labelled. On exit, everything detaches.
    fn run(
        &mut self,
        watch: Arc<WatchSet>,
        out: BoundedSender,
        loss: Arc<LossCounters>,
        stop: Arc<AtomicBool>,
    ) {
        let mut attached = match self.state.take() {
            Some(a) => a,
            None => {
                eprintln!("runopsy-trace: eBPF backend already ran (one session per attach)");
                return;
            }
        };

        let pump = Arc::new(Mutex::new(Pump {
            out,
            seq: 0, // publish() pre-increments: the first event is sequence 1
            watch: Arc::clone(&watch),
            watched_fd: attached.watched_fd,
            applied: HashMap::new(),
        }));

        let ring = match PollRing::new(attached.rb_fd, {
            let pump = Arc::clone(&pump);
            let loss = Arc::clone(&loss);
            move |sample: &[u8]| {
                // the callback runs under libbpf's `extern "C"` frame: a
                // panic there would abort the tracer. contain it to this
                // sample and count it as kernel-stage loss instead.
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut pump = pump_lock(&pump);
                    sample_dispatch(sample, &mut pump, &loss);
                }));
                if ok.is_err() {
                    loss.bump(STAGE_KERNEL, 1);
                }
            }
        }) {
            Ok(r) => r,
            Err(e) => {
                // ring refused: collection is degraded, which is health
                // visible, never a dead process (§6.40). the counters show
                // a quiet pump; the resubscribe stage records the gap.
                eprintln!("runopsy-trace: eBPF ring buffer unavailable: {e}");
                loss.bump(STAGE_RESUBSCRIBE, 1);
                return;
            }
        };

        // observe the current version once: the pump syncs on every bump
        // after this point. A first SYNC happens immediately, so events
        // between attach and the agent's first RESET are not mis-watched.
        let mut last_version = watch.version();
        {
            let mut pump = pump_lock(&pump);
            sync_watch_map(&watch, attached.watched_fd, &mut pump.applied, &loss);
        }
        watch.mark_synced(last_version);

        let mut ring_loss_seen: u64 = read_kernel_loss(attached.loss_fd, LOSS_RING).unwrap_or(0);
        let mut watch_loss_seen: u64 =
            read_kernel_loss(attached.loss_fd, LOSS_WATCH_FULL).unwrap_or(0);
        loop {
            if should_stop(&stop) {
                break;
            }
            match ring.poll(POLL_TIMEOUT_MS) {
                Ok(_) => {}
                Err(e) => eprintln!("runopsy-trace: ring poll: {e}"),
            }
            // Kernel-side loss: ring-buffer reserve failures (KERNEL) and
            // fork inheritance refused by a full watch map (WATCH_FULL). A
            // delta is "at least one", same overrun semantics as ENOBUFS
            // (§7.1).
            if let Ok(now) = read_kernel_loss(attached.loss_fd, LOSS_RING) {
                if let Some(delta) = counter_delta(&mut ring_loss_seen, now) {
                    loss.bump(STAGE_KERNEL, delta);
                }
            }
            if let Ok(now) = read_kernel_loss(attached.loss_fd, LOSS_WATCH_FULL) {
                if let Some(delta) = counter_delta(&mut watch_loss_seen, now) {
                    loss.bump(STAGE_WATCH_FULL, delta);
                }
            }
            // Watch-set changes: diff the mirror on each version bump. the
            // agent's whole control set applies within ~one poll cycle.
            let v = watch.version();
            if v != last_version {
                last_version = v;
                let mut pump = pump_lock(&pump);
                sync_watch_map(&watch, attached.watched_fd, &mut pump.applied, &loss);
                // only after the map write: the transport acks watch controls
                // off this mark, and an early ack would claim a filter that
                // does not exist yet (6.23).
                drop(pump);
                watch.mark_synced(v);
            }
        }

        // teardown: ring and links drop with `attached` whenever the
        // caller drops the backend (i.e. at session end).
        attached.ring = Some(ring);
        attached.links.clear();
        drop(attached);
    }
}

// ---- the pump --------------------------------------------------------------

/// Per-session sink: publish() stamps the sequence *before* the bounded
/// enqueue, so a queue-saturated drop stays a visible sequence gap
/// (6.25–6.27). All mutation happens behind the one Pump mutex, from the
/// single poll-owner thread.
pub(crate) struct Pump {
    pub out: BoundedSender,
    pub seq: u64,
    pub watch: Arc<WatchSet>,
    pub watched_fd: i32,
    /// User-space mirror of what this pump last wrote to the kernel watch
    /// map, so resyncs are diffs. Lives inside the same mutex as the seq:
    /// one lock protects both.
    pub applied: HashMap<u32, u64>,
}

/// Lock a poisoned pump mutex too: panics in the sample path must not eat
/// the session's sink state.
#[inline]
fn pump_lock(pump: &Mutex<Pump>) -> std::sync::MutexGuard<'_, Pump> {
    match pump.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The sample dispatch: byte-parse, build the TraceEvent, publish. Any
/// length or parse error is a KERNEL-stage loss event, never a panic.
pub(crate) fn sample_dispatch(sample: &[u8], pump: &mut Pump, loss: &LossCounters) {
    if sample.len() < REC_SIZE_FLOOR {
        loss.bump(STAGE_KERNEL, 1);
        return;
    }
    let mut e = TraceEvent {
        schema_version: SCHEMA_VERSION,
        sequence: 0,
        monotonic_ns: read_s64(sample, 0),
        wall_unix_ms: crate::proc_connector::wall_millis(),
        clock_offset_ns: 0,
        event_type: EventType(0),
        pid: read_u32(sample, OFF_PID),
        ppid: read_u32(sample, OFF_PPID),
        pgid: read_u32(sample, OFF_PAGEID),
        start_ticks: read_s64(sample, OFF_START_TICKS),
        exec_path: String::new(),
        exit_code: None,
        signal: 0,
        sender_pid: 0,
        fact: 0,
        source: SOURCE_EBPF,
    };
    let kind = read_u32(sample, OFF_KIND);
    let other_pid = read_u32(sample, OFF_OTHER_PID);
    let sig = read_u32(sample, OFF_SIG);
    let fact = read_u32(sample, OFF_FACT);
    let flags = read_u32(sample, OFF_FLAGS);
    let status = read_s64(sample, OFF_STATUS);

    match kind {
        REC_EXEC => {
            e.event_type = EventType(TYPE_EXEC);
            e.exec_path = read_path(sample);
            publish(&mut pump.seq, loss, &pump.out, e);
        }
        REC_EXIT => {
            e.event_type = EventType(TYPE_EXIT);
            // §3.2: the termination signal comes only from the exit status
            // (what the parent's wait would see). the kernel sent it only
            // when it could decode(status present); anything else is
            // unknown, never fabricated.
            if flags & FLAG_STATUS_PRESENT != 0 {
                let (signal, code) = decode_wait_status(status);
                if signal != 0 {
                    e.signal = signal as u8;
                    e.fact = FACT_EXITED_BY_SIGNAL;
                } else {
                    e.exit_code = Some(code);
                }
            }
            let subject = e.pid;
            publish(&mut pump.seq, loss, &pump.out, e);
            // the subject is over: forget it in user space and the mirror,
            // so a reused PID never inherits the dead watch (§6.3 f).
            pump.watch.forget(subject);
            pump.applied.remove(&subject);
        }
        REC_SENT => {
            e.event_type = EventType(TYPE_SIGNAL);
            e.signal = (sig & 0xff) as u8;
            e.fact = fact as u8;
            // sender identity from the syscall context; the resolved
            // target is in `pid` (or pgid for group-addressed sends).
            e.sender_pid = other_pid;
            publish(&mut pump.seq, loss, &pump.out, e);
        }
        REC_STOP => {
            e.event_type = EventType(TYPE_STOP);
            e.fact = fact as u8;
            publish(&mut pump.seq, loss, &pump.out, e);
        }
        REC_RESUME => {
            e.event_type = EventType(TYPE_CONT);
            publish(&mut pump.seq, loss, &pump.out, e);
        }
        REC_OOM => {
            e.event_type = EventType(TYPE_OOM);
            e.exec_path = {
                let bytes = &sample[OFF_PATH..];
                let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..end.min(15)]).into_owned()
            };
            publish(&mut pump.seq, loss, &pump.out, e);
        }
        REC_FORK => {
            // inheritance (§5 item 1): the kernel map already received the
            // child; mirror the user-space WatchSet so the agent-visible
            // watch count and the kernel map agree, and the pump can
            // reconcile a reset later. overflow is WATCH_FULL loss.
            if other_pid != 0 && other_pid != e.pid {
                let child_ticks = read_s64(sample, OFF_OTHER_TICKS);
                if pump.watch.inherit(other_pid, MAX_WATCH_SET_ENTRIES) {
                    pump.applied.insert(other_pid, child_ticks.max(0) as u64);
                    write_watch(pump.watched_fd, other_pid, child_ticks);
                } else {
                    loss.bump(STAGE_WATCH_FULL, 1);
                }
            }
        }
        unknown => {
            // unknown record kind: forward-compat protection (§6.4):
            // counted and skipped, never fatal, never silent.
            loss.bump(STAGE_KERNEL, 1);
            eprintln!("runopsy-trace: unknown kernel record kind {unknown} skipped");
        }
    }
}

fn read_path(sample: &[u8]) -> String {
    let bytes = &sample[OFF_PATH..sample.len().min(OFF_PATH + PATH_MAX)];
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A wait-record status word (`wait(2)` encoding) to the (signal, exit
/// code) pair: low 7 bits nonzero and not 0x7f (stopped) mean killed-by-
/// signal; otherwise the high byte is the code (the 0x80 core/SI_KERNEL
/// bit, per §3.1, decodes as "killed by SIGKILL with core").
pub(crate) fn decode_wait_status(status: i64) -> (u32, i32) {
    let sig = status & 0x7f;
    if sig != 0 && sig != WAIT_STOPPED {
        (sig as u32, 0)
    } else {
        (0, ((status >> 8) & 0xff) as i32)
    }
}

const WAIT_STOPPED: i64 = 0x7f;

/// Write one identity to the kernel watch map. Failures are WATCH_FULL
/// loss, never fatal.
fn write_watch(fd: i32, pid: u32, ticks: i64) {
    let key = pid.to_le_bytes();
    let value = (ticks.max(0) as u64).to_le_bytes();
    if let Err(e) = libbpf::map_update(fd, &key, &value, 0) {
        eprintln!("runopsy-trace: watch update: {e}");
    }
}

/// Sync the kernel watch map to the current agent set: deletions first,
/// then upserts, so a transient overlap never watches a PID the agent
/// withdrew (§6.3 f). Losses here are WATCH_FULL, visible as gaps.
fn sync_watch_map(
    watch: &Arc<WatchSet>,
    watched_fd: i32,
    applied: &mut HashMap<u32, u64>,
    loss: &LossCounters,
) {
    let current: HashSet<u32> = watch.snapshot(MAX_WATCH_SET_ENTRIES).into_iter().collect();
    for pid in applied.keys().copied().collect::<Vec<u32>>() {
        if !current.contains(&pid) {
            let key = pid.to_le_bytes();
            if libbpf::map_delete(watched_fd, &key).is_err() {
                // deleting an already-dead identity is fine; a real failure
                // surfaces via a resync attempt on the next version bump.
            }
            applied.remove(&pid);
        }
    }
    let mut overflow: u64 = 0;
    for pid in current {
        let ticks = crate::proc_connector::live_start_ticks(pid).filter(|t| *t > 0);
        let exists = ticks.is_some() || std::path::Path::new(&format!("/proc/{pid}")).exists();
        match watch_entry(ticks, exists, applied.get(&pid).copied(), applied.len()) {
            WatchEntry::Keep => {}
            WatchEntry::Write(value) => {
                write_watch(watched_fd, pid, value as i64);
                applied.insert(pid, value);
            }
            WatchEntry::Gone => {
                // the process no longer exists. watching its PID would let
                // the next process to reuse it adopt this watch (§6.3 f),
                // and nothing is lost by not watching a dead process: its
                // exit was either reported or happened before the watch.
                if applied.remove(&pid).is_some() {
                    let _ = libbpf::map_delete(watched_fd, &pid.to_le_bytes());
                }
            }
            WatchEntry::Full => overflow += 1,
        }
    }
    if overflow > 0 {
        loss.bump(STAGE_WATCH_FULL, overflow);
    }
}

/// What the kernel watch map should hold for one PID of the agent's set.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WatchEntry {
    /// The map already holds the right value.
    Keep,
    /// Write this start_ticks value (0 = any identity).
    Write(u64),
    /// The process is gone: hold nothing for this PID.
    Gone,
    /// The map is full: the PID is unobserved, which is WATCH_FULL loss.
    Full,
}

/// Decide one PID's kernel watch entry. `ticks` is the live identity when
/// it could be read; `exists` says whether `/proc/<pid>` exists at all.
///
/// Only a process that exists but whose identity cannot be read gets an
/// "any identity" entry. That is degraded matching, not lost events, so it
/// is not counted as loss. A dead PID gets no entry: before this rule it got
/// an "any identity" entry on every resync and a WATCH_FULL loss each time,
/// which both invited PID-reuse adoption and reported loss that never
/// happened.
pub(crate) fn watch_entry(
    ticks: Option<i64>,
    exists: bool,
    applied: Option<u64>,
    applied_len: usize,
) -> WatchEntry {
    let want = match (ticks, exists) {
        (Some(t), _) if t > 0 => t as u64,
        (_, true) => 0,
        (_, false) => return WatchEntry::Gone,
    };
    if applied == Some(want) {
        return WatchEntry::Keep;
    }
    if applied.is_none() && applied_len >= MAX_WATCH_SET_ENTRIES {
        return WatchEntry::Full;
    }
    WatchEntry::Write(want)
}

/// Kernel-side loss counter indices (mirror `LOSS_*` in runopsy.bpf.c).
const LOSS_RING: u32 = 0;
const LOSS_WATCH_FULL: u32 = 1;

fn read_kernel_loss(loss_fd: i32, index: u32) -> Result<u64, ()> {
    let mut buf = [0u8; 8];
    if !libbpf::map_lookup(loss_fd, &index.to_le_bytes(), &mut buf) {
        return Err(());
    }
    Ok(u64::from_le_bytes(buf))
}

/// The increase of a monotonic kernel counter since the last read, if any.
pub(crate) fn counter_delta(seen: &mut u64, now: u64) -> Option<u64> {
    if now > *seen {
        let delta = now - *seen;
        *seen = now;
        Some(delta)
    } else {
        None
    }
}

#[inline]
fn read_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn read_s64(b: &[u8], off: usize) -> i64 {
    if off + 8 > b.len() {
        return 0;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    i64::from_le_bytes(v)
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn a_live_identity_is_written_once_then_kept() {
        assert_eq!(
            watch_entry(Some(500), true, None, 0),
            WatchEntry::Write(500)
        );
        assert_eq!(watch_entry(Some(500), true, Some(500), 1), WatchEntry::Keep);
        // PID reuse between syncs: a new identity replaces the old one.
        assert_eq!(
            watch_entry(Some(900), true, Some(500), 1),
            WatchEntry::Write(900)
        );
    }

    #[test]
    fn a_dead_pid_gets_no_entry_and_no_loss() {
        // before the fix this wrote an "any identity" entry and counted a
        // WATCH_FULL loss on every resync.
        assert_eq!(watch_entry(None, false, None, 0), WatchEntry::Gone);
        assert_eq!(watch_entry(None, false, Some(500), 1), WatchEntry::Gone);
    }

    #[test]
    fn an_unreadable_live_process_is_watched_by_pid_only_once() {
        assert_eq!(watch_entry(None, true, None, 0), WatchEntry::Write(0));
        assert_eq!(watch_entry(None, true, Some(0), 1), WatchEntry::Keep);
    }

    #[test]
    fn a_full_map_is_loss_only_for_a_new_pid() {
        let full = MAX_WATCH_SET_ENTRIES;
        assert_eq!(watch_entry(Some(7), true, None, full), WatchEntry::Full);
        // an existing entry can still be refreshed when the map is full.
        assert_eq!(
            watch_entry(Some(8), true, Some(7), full),
            WatchEntry::Write(8)
        );
    }

    #[test]
    fn kernel_counter_deltas_are_reported_once() {
        let mut seen = 0;
        assert_eq!(counter_delta(&mut seen, 0), None);
        assert_eq!(counter_delta(&mut seen, 3), Some(3));
        assert_eq!(counter_delta(&mut seen, 3), None);
        assert_eq!(counter_delta(&mut seen, 10), Some(7));
    }
}
