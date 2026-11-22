//! Backend trait (6.17/6.18): the kernel collection mechanism is deliberately
//! separate from transport. One backend ships in Phase 6 (proc connector,
//! unprivileged, honest scope); an eBPF backend later would slot in here
//! without touching transport or agent code.
//!
//! Contract for `run`:
//!   - stamp `trace.sequence` from the counter BEFORE enqueueing, so any
//!     upload drop shows up later as a receiver-visible sequence gap
//!     (6.25/6.26: never silent loss);
//!   - a full channel is a drop: increment `loss` and continue. Never
//!     block the kernel reader indefinitely; never panic;
//!   - return when `stop` flips. Nothing is assumed about the caller.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use crate::schema::*;
use crate::schema::{stage_name, STAGE_KERNEL, STAGE_QUEUE, STAGE_RESUBSCRIBE, STAGE_WATCH_FULL};
use crate::watch::WatchSet;

/// Per-stage loss counters (§6.3 d / §7.1): a gap alone says *that* events
/// were lost, never *where* between the kernel and the socket. Each counter
/// is monotonic within a session; the transport emits a LOSS frame whenever
/// one of them advances.
#[derive(Debug, Default)]
pub struct LossCounters {
    kernel: AtomicU64,
    resubscribe: AtomicU64,
    watch_full: AtomicU64,
    queue: AtomicU64,
}

impl LossCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn bump(&self, stage: u8, n: u64) {
        match stage {
            STAGE_KERNEL => &self.kernel,
            STAGE_RESUBSCRIBE => &self.resubscribe,
            STAGE_WATCH_FULL => &self.watch_full,
            _ => &self.queue,
        }
        .fetch_add(n, Ordering::SeqCst);
    }

    pub fn get(&self, stage: u8) -> u64 {
        match stage {
            STAGE_KERNEL => &self.kernel,
            STAGE_RESUBSCRIBE => &self.resubscribe,
            STAGE_WATCH_FULL => &self.watch_full,
            _ => &self.queue,
        }
        .load(Ordering::SeqCst)
    }

    /// Sum across all stages, for the total in the old single-counter API.
    pub fn total(&self) -> u64 {
        self.kernel.load(Ordering::SeqCst)
            + self.resubscribe.load(Ordering::SeqCst)
            + self.watch_full.load(Ordering::SeqCst)
            + self.queue.load(Ordering::SeqCst)
    }

    pub fn all_names(&self) -> [(u8, &'static str); 4] {
        [
            (STAGE_KERNEL, stage_name(STAGE_KERNEL)),
            (STAGE_RESUBSCRIBE, stage_name(STAGE_RESUBSCRIBE)),
            (STAGE_WATCH_FULL, stage_name(STAGE_WATCH_FULL)),
            (STAGE_QUEUE, stage_name(STAGE_QUEUE)),
        ]
    }
}

/// Backend selection (contract §2.1): eBPF attach → proc connector →
/// unavailable. Each step's failure reason is carried in
/// `selection_reason`; the chosen backend runs the session.
///
/// `Debug` is hand-written: the boxed backend is a dyn trait object that
/// has nothing to say, so the report covers the fields an operator needs.
impl std::fmt::Debug for Selected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selected")
            .field("caps", &self.caps)
            .field("selection_reason", &self.selection_reason)
            .finish()
    }
}
pub struct Selected {
    pub backend: Box<dyn TraceBackend + Send>,
    pub caps: Capabilities,
    /// Empty when the primary (eBPF) was selected.
    pub selection_reason: String,
}

/// Select and attach the backend for one session or one probe. On Linux
/// the eBPF backend's attach IS the availability probe: a capability is
/// true only when its programs actually attached (§2.1).
#[cfg(target_os = "linux")]
pub fn select_backend() -> Selected {
    crate::ebpf_backend::select()
}

#[cfg(not(target_os = "linux"))]
pub fn select_backend() -> Selected {
    // nothing attaches on this OS; the proc connector refuses too, so the
    // capabilities stay honest per probe() (unsupported = true).
    Selected {
        backend: Box::new(crate::proc_connector::ProcConnectorBackend),
        caps: probe(),
        selection_reason: String::new(),
    }
}

/// Capabilities detected by actually probing this build. Claims are honest:
/// cn_proc cannot expose sent/delivered signals or stop/resume, so those
/// stay false (6.14) until a backend that can observe them exists.
pub fn probe() -> Capabilities {
    probe_with_reason().0
}

/// Probe this build AND this kernel. On Linux a real connector subscription
/// is opened and closed, so a kernel that refuses the listener (for example
/// a network namespace other than the initial one, where the connector
/// answers ECONNREFUSED) reports no process capability instead of claiming
/// one (6.8, 6.53). The reason is returned for the selection report.
#[cfg(target_os = "linux")]
pub fn probe_with_reason() -> (Capabilities, Option<String>) {
    match crate::proc_connector::subscribe() {
        Ok(raw) => {
            crate::nix::close(raw);
            (
                Capabilities {
                    backend: "proc_connector".to_string(),
                    kernel: kernel_version(),
                    unprivileged: true,
                    process_exec: true,
                    process_exit: true,
                    ..Capabilities::default()
                },
                None,
            )
        }
        Err(reason) => (
            Capabilities {
                backend: "proc_connector".to_string(),
                kernel: kernel_version(),
                unsupported: true,
                ..Capabilities::default()
            },
            Some(classify_refusal(&reason)),
        ),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_with_reason() -> (Capabilities, Option<String>) {
    (
        Capabilities {
            backend: "proc_connector".to_string(),
            kernel: kernel_version(),
            unsupported: true,
            ..Capabilities::default()
        },
        Some("proc connector is Linux-only".to_string()),
    )
}

/// Names a refusal for operators (6.52/6.53): a permission refusal is told
/// apart from a kernel that does not offer the connector at all.
pub fn classify_refusal(err: &str) -> String {
    if err.contains("Operation not permitted") || err.contains("Permission denied") {
        format!("insufficient permission: {}", err)
    } else {
        format!("kernel does not offer the connector: {}", err)
    }
}

pub fn kernel_version() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            return release.trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Generic collection backend. Kept as a trait so an eBPF backend (6.19's
/// successor) can be added with zero transport changes.
pub trait TraceBackend {
    #[allow(dead_code)] // future eBPF backend registry (6.17); run() is the live path
    fn name(&self) -> &'static str;

    /// Subscribe, collect and forward matched events until `stop` flips.
    fn run(
        &mut self,
        watch: Arc<WatchSet>,
        out: BoundedSender,
        loss: Arc<LossCounters>,
        stop: Arc<AtomicBool>,
    );

    /// True when filtering happens in the kernel against a map the transport
    /// cannot see. A watch control then waits for the backend to mirror the
    /// set before it is acked (6.23); otherwise processes that exec in the
    /// gap are filtered as unwatched with no loss counted. The proc
    /// connector filters in user space (applied by `WatchSet::apply` before
    /// the ack), so its answer stays false.
    fn watch_sync_is_kernel_visible(&self) -> bool {
        false
    }
}

pub type BoundedSender = SyncSender<TraceEvent>;

/// Publishes one event to the session pipeline with source-side sequence
/// stamping and bounded backpressure (6.25). Shared by current + future
/// backends so drop semantics cannot accidentally diverge.
pub fn publish(seq: &mut u64, loss: &LossCounters, out: &BoundedSender, mut ev: TraceEvent) {
    *seq += 1;
    ev.sequence = *seq;
    match out.try_send(ev) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            // the event already had its sequence number stamped: the agent
            // will see a gap and count it. that is exactly the honest
            // outcome (6.27): loss is never silence.
            loss.bump(STAGE_QUEUE, 1);
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            // session teardown mid-flight: nothing to forward.
            loss.bump(STAGE_QUEUE, 1);
        }
    }
}

/// Uniform stop check for backend loops.
pub fn should_stop(stop: &AtomicBool) -> bool {
    stop.load(Ordering::Relaxed)
}

#[cfg(test)]
mod refusal_tests {
    use super::classify_refusal;

    #[test]
    fn permission_refusals_are_named_as_permission() {
        let r = classify_refusal("listen: send: Operation not permitted (os error 1)");
        assert!(r.starts_with("insufficient permission:"), "{}", r);
        let r = classify_refusal("bind: Permission denied (os error 13)");
        assert!(r.starts_with("insufficient permission:"), "{}", r);
    }

    #[test]
    fn other_refusals_name_the_kernel_not_offering_the_connector() {
        // observed on a network namespace other than the initial one (6.53).
        let r = classify_refusal("listen: send: Connection refused (os error 111)");
        assert!(
            r.starts_with("kernel does not offer the connector:"),
            "{}",
            r
        );
    }
}
