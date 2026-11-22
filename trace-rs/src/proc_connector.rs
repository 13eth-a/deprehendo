//! Linux proc-connector backend: AF_NETLINK CN_IDX_PROC over CN_VAL_PROC.
//!
//! Scope honesty (6.14): cn_proc exposes exec, fork, exit, core dump, uid,
//! gid, sid, ptrace and comm events. It does NOT expose sent/delivered
//! signals or stop/resume; this backend therefore reports only what the
//! kernel gives it and the handshake advertises `signals: false` (see
//! backend::probe). The exit event's wait status, when its low seven bits
//! are nonzero, yields FACT_EXITED_BY_SIGNAL: a fact about the target
//! process, never a claim about a sender.
//!
//! Wire facts this decoder depends on were verified against a live 6.18
//! kernel (principal Phase 6 review, `docs/tracing/contract.md` §4.1) and are
//! pinned by the real-kernel vectors in the tests below:
//!   - `PROC_EVENT_EXIT` is 0x8000_0000 (a bit flag), not a small ordinal;
//!   - the exit payload is `process_pid, process_tgid, exit_code (wait
//!     status), exit_signal (SIGCHLD bookkeeping, -1 for threads),
//!     parent_pid, parent_tgid`;
//!   - an exit is reported for every *thread*; only `pid == tgid` is a
//!     process exit;
//!   - the event header carries the kernel's own CLOCK_MONOTONIC stamp,
//!     taken when the event happened, not when we read it.
//!
//! Privilege: unprivileged listeners are accepted on recent kernels
//! (verified on 6.18 with uid 65534 and no CAP_NET_ADMIN); older kernels
//! need CAP_NET_ADMIN. A subscribe failure degrades the session (reported at
//! startup); it never panics.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::backend::{publish, should_stop, BoundedSender, LossCounters, TraceBackend};
use crate::schema::*;
use crate::watch::WatchSet;

// Netlink/connector constants (linux/connector.h, linux/cn_proc.h).
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

// proc_event `what` values (linux/cn_proc.h `enum what`): bit flags.
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

/// recv() errno for a netlink receive-buffer overrun: the kernel dropped
/// multicast messages for this socket. The socket stays usable.
const ENOBUFS: i32 = 105;

/// Requested netlink receive buffer: about 20k queued proc events.
const RECEIVE_BUFFER_BYTES: i32 = 16 << 20;

/// USER_HZ: the unit of /proc/<pid>/stat `starttime`. Fixed at 100 on every
/// Linux architecture Runopsy targets (the kernel exports USER_HZ, not HZ).
const TICKS_PER_SEC: i64 = 100;
const NS_PER_TICK: i64 = 1_000_000_000 / TICKS_PER_SEC;

const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_BOOTTIME: i32 = 7;

#[derive(Default)]
pub struct ProcConnectorBackend;

/// Owns one fd; closes exactly once on drop. Transfer by std::mem::forget.
struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        crate::nix::close(self.0);
    }
}

/// Process identity as Phase 1 keys it (6.11): PID alone is never identity.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Identity {
    start_ticks: i64,
    ppid: u32,
    pgid: u32,
}

/// Per-subscription decoder state. Kept separate from the socket loop so the
/// decoding rules are testable against recorded kernel bytes.
pub(crate) struct Decoder {
    seq: u64,
    /// Identities of watched processes, read while they were alive (at fork
    /// or exec). Bounded by the watch set: only watched tgids are cached.
    ids: HashMap<u32, Identity>,
    /// /proc root; tests point it at a missing directory.
    proc_root: PathBuf,
}

impl Decoder {
    pub(crate) fn new(proc_root: impl Into<PathBuf>) -> Self {
        Decoder {
            // publish() pre-increments: the first event of a session is
            // sequence 1, so a loss before it is still a visible gap.
            seq: 0,
            ids: HashMap::new(),
            proc_root: proc_root.into(),
        }
    }

    /// Record that `n` (at least one) events may have been lost, by skipping
    /// sequence numbers and counting the stage: the agent sees a gap even
    /// though no frame says so, and the LOSS frame names where it happened
    /// (6.25–6.27). Used when the kernel or the subscription lost events the
    /// tracer never saw, so nothing on the wire could otherwise show it.
    fn mark_gap(&mut self, loss: &LossCounters, stage: u8, n: u64) {
        self.seq += n;
        loss.bump(stage, n);
    }
}

impl TraceBackend for ProcConnectorBackend {
    fn name(&self) -> &'static str {
        "proc_connector"
    }

    fn run(
        &mut self,
        watch: Arc<WatchSet>,
        out: BoundedSender,
        loss: Arc<LossCounters>,
        stop: Arc<AtomicBool>,
    ) {
        // state machine: subscribe -> collect -> on socket death close,
        // back off, resubscribe. A failed subscribe degrades collection
        // (reported at startup) but never panics or kills the process
        // (6.40): an fd of none simply retries on the next loop.
        let mut fd: Option<RawFd> = match subscribe() {
            Ok(fd) => Some(fd),
            Err(e) => {
                eprintln!("runopsy-trace: proc connector subscribe failed: {}", e);
                None
            }
        };
        let mut dec = Decoder::new("/proc");
        let mut buf = vec![0u8; 64 * 1024];
        let mut backoff = std::time::Duration::from_millis(250);
        while !should_stop(&stop) {
            let raw = match fd {
                Some(raw) => raw,
                None => {
                    std::thread::sleep(backoff);
                    fd = match subscribe() {
                        Ok(raw) => {
                            backoff = std::time::Duration::from_millis(250);
                            Some(raw)
                        }
                        Err(e) => {
                            eprintln!("runopsy-trace: resubscribe failed: {}", e);
                            backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
                            None
                        }
                    };
                    continue;
                }
            };
            match crate::nix::recv(raw, &mut buf) {
                Ok(n) => dec.datagram(&buf[..n], watch.as_ref(), &loss, &out),
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                    // the kernel overran our receive buffer and dropped
                    // events. the socket is still subscribed; the loss must
                    // be visible, not silent (6.25).
                    dec.mark_gap(&loss, STAGE_KERNEL, 1);
                }
                Err(e) => {
                    // the kernel invalidates connector sockets when the
                    // listened group vanishes; close, back off with limited
                    // escalation, resubscribe (6.39). whatever happens until
                    // the new subscription is live is unobserved: a gap.
                    eprintln!("runopsy-trace: connector reset ({}); resubscribing", e);
                    crate::nix::close(raw);
                    fd = None;
                    dec.mark_gap(&loss, STAGE_RESUBSCRIBE, 1);
                }
            }
        }
        if let Some(raw) = fd {
            crate::nix::close(raw);
        }
    }
}

pub(crate) fn subscribe() -> std::result::Result<RawFd, String> {
    let raw = crate::nix::socket_connector().map_err(|e| format!("socket: {}", e))?;
    let guard = FdGuard(raw);
    crate::nix::bind_groups(raw, CN_IDX_PROC).map_err(|e| format!("bind: {}", e))?;
    // the default receive buffer (~208 KiB) overflows under a few hundred
    // processes started at once (principal review: a 200-process burst lost about
    // 20% of its exits). ask for more; the kernel caps the request, and a
    // refusal only leaves the default, never fails the subscription.
    crate::nix::grow_receive_buffer(raw, RECEIVE_BUFFER_BYTES);
    send_listen(raw).map_err(|e| format!("listen: {}", e))?;
    std::mem::forget(guard); // ownership moves to the caller (run)
    Ok(raw)
}

fn send_listen(raw: i32) -> std::result::Result<(), String> {
    // 6.7-with-a-kernel-twist: nlmsghdr(16) + cn_msg(20) + enum op(4).
    let total = (16 + 20 + 4) as u32;
    let mut msg = Vec::with_capacity(total as usize);
    msg.extend_from_slice(&total.to_le_bytes()); // nlmsg_len
    msg.extend_from_slice(&3u16.to_le_bytes()); // nlmsg_type = NLMSG_DONE
    msg.extend_from_slice(&0u16.to_le_bytes()); // nlmsg_flags
    msg.extend_from_slice(&1u32.to_le_bytes()); // nlmsg_seq
    msg.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_pid = kernel
                                                // cn_msg
    msg.extend_from_slice(&CN_IDX_PROC.to_le_bytes());
    msg.extend_from_slice(&CN_VAL_PROC.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes()); // seq
    msg.extend_from_slice(&0u32.to_le_bytes()); // ack
    msg.extend_from_slice(&4u16.to_le_bytes()); // len
    msg.extend_from_slice(&0u16.to_le_bytes()); // flags
    msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_le_bytes());
    crate::nix::send(raw, &msg)
        .map(|_| ())
        .map_err(|e| format!("send: {}", e))
}

impl Decoder {
    /// Decode every netlink message in one received datagram.
    pub(crate) fn datagram(
        &mut self,
        data: &[u8],
        watch: &WatchSet,
        loss: &LossCounters,
        out: &BoundedSender,
    ) {
        let mut offset = 0usize;
        while offset + 16 <= data.len() {
            let len = read_u32(data, offset) as usize;
            if len < 16 || offset + len > data.len() {
                // malformed kernel datagram: skip it, never fatal; the
                // stream continues.
                break;
            }
            self.body(&data[offset + 16..offset + len], watch, loss, out);
            // netlink messages are NLMSG_ALIGN(4)-aligned.
            offset += (len + 3) & !3;
        }
    }

    fn body(&mut self, body: &[u8], watch: &WatchSet, loss: &LossCounters, out: &BoundedSender) {
        // cn_msg: idx, val, seq, ack (u32 each), len, flags (u16 each).
        if body.len() < 20 {
            return;
        }
        if read_u32(body, 0) != CN_IDX_PROC || read_u32(body, 4) != CN_VAL_PROC {
            return;
        }
        // proc_event header: what (u32), cpu (u32), timestamp_ns (u64).
        let ev = &body[20..];
        if ev.len() < 16 {
            return;
        }
        let what = read_u32(ev, 0);
        let kernel_ns = read_u64(ev, 8) as i64;
        let data = &ev[16..];

        match what {
            PROC_EVENT_FORK if data.len() >= 16 => {
                // fork { parent_pid, parent_tgid, child_pid, child_tgid }
                let parent_tgid = read_s32(data, 4).max(0) as u32;
                let child_pid = read_s32(data, 8).max(0) as u32;
                let child_tgid = read_s32(data, 12).max(0) as u32;
                if child_pid != child_tgid || !watch.contains(parent_tgid) {
                    return; // a new thread, or an unwatched parent
                }
                // descendants of a watched process are watched from birth,
                // here, before the child can run: an agent round trip would
                // miss every short-lived child, which is the reason this
                // tracer exists (6.9/6.22, contract §6).
                if !watch.inherit(child_tgid, MAX_WATCH_SET_ENTRIES) {
                    // watch set full: this subtree is now unobserved,
                    // visible to the agent as a WATCH_FULL loss (§7.1).
                    self.mark_gap(loss, STAGE_WATCH_FULL, 1);
                    return;
                }
                if let Some(id) = self.identity_at(child_tgid, kernel_ns) {
                    self.ids.insert(child_tgid, id);
                }
            }
            PROC_EVENT_EXEC if data.len() >= 8 => {
                // exec { process_pid, process_tgid }
                let tgid = read_s32(data, 4).max(0) as u32;
                if !watch.contains(tgid) {
                    return;
                }
                let mut e = self.event(TYPE_EXEC, tgid, kernel_ns);
                if let Some(id) = self.identity_at(tgid, kernel_ns) {
                    self.ids.insert(tgid, id);
                    apply_identity(&mut e, id);
                    e.exec_path = self.exec_path(tgid);
                }
                publish(&mut self.seq, loss, out, e);
            }
            PROC_EVENT_EXIT if data.len() >= 16 => {
                // exit { process_pid, process_tgid, exit_code (wait status),
                //        exit_signal, parent_pid, parent_tgid }
                let pid = read_s32(data, 0).max(0) as u32;
                let tgid = read_s32(data, 4).max(0) as u32;
                let wait_status = read_u32(data, 8);
                if pid != tgid || !watch.contains(tgid) {
                    // A thread exit is not a process exit: the runner .NET
                    // processes retire threads all the time.
                    return;
                }
                let mut e = self.event(TYPE_EXIT, tgid, kernel_ns);
                // the exiting task is still readable (zombie until reaped);
                // prefer that, then the identity cached while it lived.
                let id = self.identity_at(tgid, kernel_ns).or_else(|| {
                    self.ids
                        .get(&tgid)
                        .copied()
                        .filter(|id| started_by(id.start_ticks, kernel_ns))
                });
                if let Some(id) = id {
                    apply_identity(&mut e, id);
                }
                let term_sig = wait_status & 0x7f;
                if term_sig != 0 {
                    // died by signal (WIFSIGNALED). A fact about the target
                    // only: no sender claim (6.14).
                    e.fact = FACT_EXITED_BY_SIGNAL;
                    e.signal = term_sig as u8;
                } else {
                    e.exit_code = Some(((wait_status >> 8) & 0xff) as i32);
                }
                publish(&mut self.seq, loss, out, e);
                // the process is gone; a later process reusing this PID is
                // not watched by inheritance from a dead one (6.23).
                watch.forget(tgid);
                self.ids.remove(&tgid);
            }
            // uid/gid/sid/ptrace/comm/coredump: not phase 6 scope.
            _ => {}
        }
    }

    fn event(&self, kind: u16, tgid: u32, kernel_ns: i64) -> TraceEvent {
        TraceEvent {
            schema_version: SCHEMA_VERSION,
            sequence: 0,
            monotonic_ns: kernel_ns,
            wall_unix_ms: wall_millis_at(kernel_ns),
            clock_offset_ns: 0,
            event_type: EventType(kind),
            pid: tgid,
            ppid: 0,
            pgid: 0,
            start_ticks: 0,
            exec_path: String::new(),
            exit_code: None,
            signal: 0,
            sender_pid: 0,
            fact: 0,
            source: SOURCE_PROC_CONNECTOR,
        }
    }

    /// Identity of `tgid` as /proc shows it now, accepted only if that
    /// process had started by the event time. A PID reused after the event
    /// fails the check and yields `None`: unknown identity, never a wrong
    /// one (6.11).
    fn identity_at(&self, tgid: u32, kernel_ns: i64) -> Option<Identity> {
        let id = read_stat(&self.proc_root, tgid)?;
        if started_by(id.start_ticks, kernel_ns) {
            Some(id)
        } else {
            None
        }
    }

    fn exec_path(&self, tgid: u32) -> String {
        // needs the same uid or CAP_SYS_PTRACE; empty means unknown.
        std::fs::read_link(self.proc_root.join(tgid.to_string()).join("exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

fn apply_identity(e: &mut TraceEvent, id: Identity) {
    e.start_ticks = id.start_ticks;
    e.ppid = id.ppid;
    e.pgid = id.pgid;
}

/// Whether a process that started at `start_ticks` (boot-relative USER_HZ
/// ticks) existed at the monotonic instant `kernel_ns`. The two clocks share
/// an origin except for time spent suspended, so the event instant is moved
/// onto CLOCK_BOOTTIME first. One tick of slack covers tick truncation.
fn started_by(start_ticks: i64, kernel_ns: i64) -> bool {
    if start_ticks <= 0 {
        return false;
    }
    let (mono_now, boot_now) = (clock_ns(CLOCK_MONOTONIC), clock_ns(CLOCK_BOOTTIME));
    if mono_now == 0 || boot_now == 0 {
        return true; // no clocks to compare: cannot refute
    }
    let event_boot_ns = boot_now - (mono_now - kernel_ns);
    start_ticks.saturating_mul(NS_PER_TICK) <= event_boot_ns + NS_PER_TICK
}

/// Parse `<root>/<tgid>/stat`: fields 4 (ppid), 5 (pgrp) and 22 (starttime).
/// The command name (field 2) may contain spaces and ')', so fields are
/// counted from the last ')'.
fn read_stat(root: &Path, tgid: u32) -> Option<Identity> {
    let raw = std::fs::read_to_string(root.join(tgid.to_string()).join("stat")).ok()?;
    parse_stat(&raw)
}

fn parse_stat(raw: &str) -> Option<Identity> {
    let rest = &raw[raw.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // f[0] is field 3 (state), so field N is f[N - 3].
    Some(Identity {
        ppid: f.get(1)?.parse().ok()?,
        pgid: f.get(2)?.parse().ok()?,
        start_ticks: f.get(19)?.parse().ok()?,
    })
}

fn read_s32(b: &[u8], at: usize) -> i32 {
    if at + 4 > b.len() {
        return 0;
    }
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    if at + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn read_u64(b: &[u8], at: usize) -> u64 {
    if at + 8 > b.len() {
        return 0;
    }
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}

/// Read a kernel clock in nanoseconds; 0 if unavailable.
fn clock_ns(clock_id: i32) -> i64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = Timespec::default();
        // the single FFI call for time: ts is the caller-owned,
        // zero-initialized out-buffer; clock_gettime writes exactly its size
        // under the platform ABI (64-bit time_t on every target runopsy
        // builds for; see the compile-time check below).
        extern "C" {
            fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
        }
        if unsafe { clock_gettime(clock_id, &mut ts as *mut Timespec) } != 0 {
            return 0;
        }
        ts.sec * 1_000_000_000 + ts.nsec
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = clock_id;
        0
    }
}

/// Live start time of `pid` in USER_HZ ticks, as /proc reports it right
/// now (§6.3 f): the identity check behind STALE_IDENTITY. `None` when the
/// process is not readable (dead, or a system without /proc): the caller
/// then refuses the identity-keyed add, because "cannot verify" is not
/// "verified".
pub fn live_start_ticks(pid: u32) -> Option<i64> {
    read_stat(Path::new("/proc"), pid).map(|id| id.start_ticks)
}

/// /proc/sys/kernel/random/boot_id: the boot identity crossed at the
/// handshake (§6.3 b). Empty when the OS does not expose it, which the
/// agent treats as unknown rather than as a mismatch.
pub fn boot_id() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        String::new()
    }
}

/// Inode of our PID namespace (/proc/self/ns/pid, format `pid:[4026531836]`).
/// A tracer outside the agent's namespace reports PIDs that are meaningless
/// to the agent (§2, initial-namespace rule); the agent refuses the session.
pub fn pid_namespace_inode() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(link) = std::fs::read_link("/proc/self/ns/pid") {
            let text = link.to_string_lossy();
            if let (Some(open), Some(close)) = (text.find('['), text.find(']')) {
                if open < close {
                    if let Ok(n) = text[open + 1..close].parse::<u64>() {
                        return n;
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

pub fn monotonic_ns() -> i64 {
    #[cfg(target_os = "linux")]
    {
        clock_ns(CLOCK_MONOTONIC)
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }
}

pub fn wall_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Wall time of a past monotonic instant, for display only (6.28: never an
/// ordering key).
fn wall_millis_at(kernel_ns: i64) -> i64 {
    let mono_now = monotonic_ns();
    if mono_now == 0 || kernel_ns <= 0 || kernel_ns > mono_now {
        return wall_millis();
    }
    wall_millis() - (mono_now - kernel_ns) / 1_000_000
}

#[allow(dead_code)] // used only on linux targets via clock_gettime
#[repr(C)]
#[derive(Default)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

// timespec mirrors the 64-bit `struct timespec`; a 32-bit time_t target
// would let clock_gettime write past it (6.41).
#[cfg(target_os = "linux")]
const _: () = assert!(
    std::mem::size_of::<usize>() == 8,
    "runopsy-trace needs a 64-bit target"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::sync_channel;

    // netlink datagrams recorded from a live 6.18 kernel (principal review,
    // 2026-11-02): `sh -c 'sleep 0.05; kill -TERM $$'` (pid 4841) and a
    // python process that starts one thread (4844) and exits 7 (pid 4842),
    // both children of pid 4840.
    const FORK_4841: &str = "4c000000030000003e0100000000000001000000010000003e01000000000000280000000100000000000000f1cf68f419010000e8120000e8120000e9120000e91200000000000000000000";
    const EXEC_4841: &str = "4c00000003000000540100000000000001000000010000005401000000000000280000000200000001000000394c72f419010000e9120000e912000000000000000000000000000000000000";
    const EXIT_4841_SIGTERM: &str = "4c00000003000000420100000000000001000000010000004201000000000000280000000000008000000000d69aa0f719010000e9120000e91200000f00000011000000e8120000e8120000";
    const THREAD_EXIT_4844: &str = "4c00000003000000580100000000000001000000010000005801000000000000280000000000008001000000835182f819010000ec120000ea12000000000000ffffffff0000000000000000";
    const EXIT_4842_CODE7: &str = "4c00000003000000430100000000000001000000010000004301000000000000280000000000008000000000213ebbfb19010000ea120000ea1200000007000011000000e8120000e8120000";
    const EXIT_4841_KERNEL_NS: i64 = 1211040307926;

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn run(vectors: &[&str], watched: &[u32]) -> (Vec<TraceEvent>, Arc<WatchSet>, u64) {
        let watch = WatchSet::new();
        watch.apply(OP_ADD, watched, MAX_WATCH_SET_ENTRIES).unwrap();
        let loss = LossCounters::default();
        let (tx, rx) = sync_channel(64);
        // A /proc root with nothing in it: identities are unknown, which is
        // what a reader sees when the recorded processes are long gone.
        let mut dec = Decoder::new("/nonexistent-proc");
        for v in vectors {
            dec.datagram(&bytes(v), &watch, &loss, &tx);
        }
        drop(tx);
        (rx.iter().collect(), watch, loss.total())
    }

    #[test]
    fn real_kernel_exit_by_sigterm_is_decoded() {
        let (evs, _, _) = run(&[EXIT_4841_SIGTERM], &[4841]);
        assert_eq!(
            evs.len(),
            1,
            "the exit of a watched process must be forwarded"
        );
        let e = &evs[0];
        assert_eq!(e.event_type, EventType(TYPE_EXIT));
        assert_eq!(e.pid, 4841);
        assert_eq!((e.signal, e.fact), (15, FACT_EXITED_BY_SIGNAL));
        assert_eq!(e.exit_code, None);
        // the kernel's own stamp, not the read time.
        assert_eq!(e.monotonic_ns, EXIT_4841_KERNEL_NS);
    }

    #[test]
    fn real_kernel_exit_code_is_decoded() {
        let (evs, _, _) = run(&[EXIT_4842_CODE7], &[4842]);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].exit_code, Some(7));
        assert_eq!(evs[0].signal, 0);
    }

    #[test]
    fn thread_exit_is_not_a_process_exit() {
        let (evs, watch, _) = run(&[THREAD_EXIT_4844], &[4842]);
        assert!(
            evs.is_empty(),
            "thread 4844 of 4842 exiting produced {:?}",
            evs
        );
        assert!(
            watch.contains(4842),
            "a thread exit must not unwatch its process"
        );
    }

    #[test]
    fn children_of_a_watched_process_are_watched_from_fork() {
        // only the parent (4840) is watched; the agent never heard of 4841.
        let (evs, watch, _) = run(&[FORK_4841, EXEC_4841, EXIT_4841_SIGTERM], &[4840]);
        let kinds: Vec<u16> = evs.iter().map(|e| e.event_type.0).collect();
        assert_eq!(kinds, vec![TYPE_EXEC, TYPE_EXIT]);
        assert!(evs.iter().all(|e| e.pid == 4841));
        assert!(
            !watch.contains(4841),
            "an exited process must leave the watch set, or a reused PID inherits it"
        );
        assert!(watch.contains(4840));
    }

    #[test]
    fn unwatched_processes_are_filtered() {
        let (evs, _, _) = run(&[FORK_4841, EXEC_4841, EXIT_4841_SIGTERM], &[1]);
        assert!(evs.is_empty());
    }

    #[test]
    fn a_full_watch_set_is_a_visible_gap() {
        let watch = WatchSet::new();
        let fill: Vec<u32> = (100_000..100_000 + MAX_WATCH_SET_ENTRIES as u32 - 1).collect();
        watch.apply(OP_ADD, &fill, MAX_WATCH_SET_ENTRIES).unwrap();
        watch.apply(OP_ADD, &[4840], MAX_WATCH_SET_ENTRIES).unwrap();
        let loss = LossCounters::default();
        let (tx, rx) = sync_channel(64);
        let mut dec = Decoder::new("/nonexistent-proc");
        dec.datagram(&bytes(FORK_4841), &watch, &loss, &tx);
        dec.datagram(&bytes(EXEC_4841), &watch, &loss, &tx);
        drop(tx);
        assert_eq!(rx.iter().count(), 0, "an uninherited child is not watched");
        assert_eq!(
            loss.get(STAGE_WATCH_FULL),
            1,
            "the unobserved subtree must be recorded as WATCH_FULL loss"
        );
        assert_eq!(
            dec.seq, 1,
            "the loss must open a sequence gap the agent can see"
        );
    }

    #[test]
    fn stat_parsing_survives_hostile_comm() {
        let raw = "4841 (a) b (c) R 4840 4841 4841 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 1234567 2453504 300";
        assert_eq!(
            parse_stat(raw),
            Some(Identity {
                start_ticks: 1234567,
                ppid: 4840,
                pgid: 4841
            })
        );
        assert_eq!(parse_stat("garbage"), None);
        assert_eq!(parse_stat("1 (x) S 0"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pid_reuse_after_the_event_yields_unknown_identity() {
        let mono = monotonic_ns();
        let boot_ticks_now = clock_ns(CLOCK_BOOTTIME) / NS_PER_TICK;
        // started five seconds ago: existed now.
        assert!(started_by(boot_ticks_now - 500, mono));
        // started now: did not exist one second ago (a reused PID).
        assert!(!started_by(boot_ticks_now, mono - 1_000_000_000));
        assert!(
            !started_by(0, mono),
            "an unknown start time is never accepted"
        );
    }

    /// Live check against this kernel's proc connector, skipped when the
    /// connector cannot be subscribed (non-Linux, an old kernel without
    /// CAP_NET_ADMIN, a non-initial network namespace). The test process
    /// itself is watched, so the harness's own thread exits must not show up
    /// as an exit of this process.
    #[test]
    #[cfg(target_os = "linux")]
    fn live_short_lived_grandchild_is_captured() {
        let fd = match subscribe() {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("skipping: proc connector unavailable: {}", e);
                return;
            }
        };
        crate::nix::close(fd);
        let me = std::process::id();
        let watch = WatchSet::new();
        watch.apply(OP_ADD, &[me], MAX_WATCH_SET_ENTRIES).unwrap();
        let loss = LossCounters::new();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel(4096);
        let worker = {
            let (watch, loss, stop) = (Arc::clone(&watch), Arc::clone(&loss), Arc::clone(&stop));
            std::thread::spawn(move || ProcConnectorBackend.run(watch, tx, loss, stop))
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        let status = std::process::Command::new("sh")
            .args(["-c", "/bin/true; kill -TERM $$"])
            .status()
            .unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(15)
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        stop.store(true, Ordering::SeqCst);
        // the worker is blocked in recv until one more event arrives.
        let _ = std::process::Command::new("true").status();
        worker.join().unwrap();
        let evs: Vec<TraceEvent> = rx.try_iter().collect();
        assert!(
            !evs.iter()
                .any(|e| e.pid == me && e.event_type == EventType(TYPE_EXIT)),
            "a thread exit of the test process was reported as its exit"
        );
        let sh_exit = evs
            .iter()
            .find(|e| e.event_type == EventType(TYPE_EXIT) && e.signal == 15)
            .unwrap_or_else(|| panic!("no SIGTERM exit for the sh child in {:?}", evs));
        assert_ne!(
            sh_exit.start_ticks, 0,
            "the exit carries the process identity"
        );
        assert_eq!(sh_exit.ppid, me);
        let grandchild_exec = evs.iter().any(|e| {
            e.event_type == EventType(TYPE_EXEC)
                // the exec path is the resolved binary, not the argv[0]:
                // e.g. an usr-merged image may link /bin/true -> gnutrue,
                // so only the name suffix is constant across hosts. the
                // ppid anchor is what ties this event to the sh child.
                && e.exec_path.ends_with("true")
                && e.ppid == sh_exit.pid
        });
        assert!(
            grandchild_exec,
            "the short-lived grandchild /bin/true was missed: {:?}",
            evs
        );
        assert!(evs.iter().any(|e| e.event_type == EventType(TYPE_EXIT)
            && e.ppid == sh_exit.pid
            && e.exit_code == Some(0)));
    }
}
