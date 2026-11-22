//! Watch-set (6.22/6.23): the tracer forwards only events whose subject PID
//! is in this set. The agent resolves trees/cgroups itself and pushes plain
//! PID lists via controls; the kernel-side rule stays a simple set so updates
//! stay atomic: two Mutex-protected snapshots swapped under one lock rather
//! than applied incrementally.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Default)]
pub struct WatchSet {
    inner: Mutex<HashSet<u32>>,
    /// Bumped on every mutation (§5): the eBPF pump's sync trigger. It is
    /// the version the pump diffs against, not a statement about order.
    version: AtomicU64,
    /// Highest version an in-kernel backend has confirmed it mirrored into
    /// the kernel-side filter. The transport waits for this before acking a
    /// watch control (6.23): an ack must never name a filter the kernel is
    /// not applying yet, or processes that run in the gap are filtered as
    /// unwatched with no loss counted anywhere.
    synced: AtomicU64,
    /// Wakes a wait on `synced` when it advances (pump thread -> transport).
    sync_ready: Mutex<()>,
    sync_cv: Condvar,
}

use crate::schema::{OP_ADD, OP_REMOVE, OP_RESET};

impl WatchSet {
    pub fn new() -> Arc<Self> {
        Arc::new(WatchSet::default())
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.inner.lock().map(|w| w.contains(&pid)).unwrap_or(false)
    }

    /// Monotonic mutation counter: changes on apply/forget/inherit. A
    /// pump that saw version v already mirrored every set present at v.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Record that the kernel-side filter now reflects `version`. Only
    /// in-kernel backends call this. Monotonic because a pump may sync a
    /// newer version before an older sync returns.
    pub fn mark_synced(&self, version: u64) {
        self.synced.fetch_max(version, Ordering::SeqCst);
        let _guard = self.sync_ready.lock();
        self.sync_cv.notify_all();
    }

    /// Wait until the kernel-side filter reflects at least `version`. False
    /// on timeout: the caller must answer the control with an error rather
    /// than acknowledge a watch the kernel is not applying.
    pub fn wait_synced(&self, version: u64, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = match self.sync_ready.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            if self.synced.load(Ordering::SeqCst) >= version {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            guard = match self.sync_cv.wait_timeout(guard, deadline - now) {
                Ok((g, _)) => g,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// The current set, bounded and sorted. Used by the eBPF pump to
    /// reconcile its kernel map against the agent's whole set.
    #[cfg(target_os = "linux")]
    pub fn snapshot(&self, max_entries: usize) -> Vec<u32> {
        match self.inner.lock() {
            Ok(w) => {
                let mut v: Vec<u32> = w.iter().copied().collect();
                v.sort_unstable();
                v.truncate(max_entries);
                v
            }
            Err(_) => Vec::new(),
        }
    }

    /// Watch a child of a watched process from its fork (contract §6). Done
    /// in the tracer because an agent round trip would arrive after a
    /// short-lived child has already exited. Returns false when the set is
    /// full: the caller must record the unobserved subtree as loss.
    pub fn inherit(&self, child: u32, max_entries: usize) -> bool {
        match self.inner.lock() {
            Ok(mut w) => {
                if w.contains(&child) {
                    return true;
                }
                if w.len() >= max_entries {
                    return false;
                }
                w.insert(child);
                self.version.fetch_add(1, Ordering::SeqCst);
                true
            }
            Err(_) => false,
        }
    }

    /// Stop watching a PID whose process has exited, so a later process that
    /// reuses the number is not mistaken for it (6.23).
    pub fn forget(&self, pid: u32) {
        if let Ok(mut w) = self.inner.lock() {
            if w.remove(&pid) {
                self.version.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    pub fn watches(&self) -> u32 {
        self.inner.lock().map(|w| w.len() as u32).unwrap_or(0)
    }

    /// Apply one mutation atomically, bounding size. Returns the new count
    /// or an error message for the ack.
    pub fn apply(
        &self,
        op: u8,
        pids: &[u32],
        max_entries: usize,
    ) -> std::result::Result<u32, String> {
        let result = self.apply_inner(op, pids, max_entries);
        if result.is_ok() {
            self.version.fetch_add(1, Ordering::SeqCst);
        }
        result
    }

    fn apply_inner(
        &self,
        op: u8,
        pids: &[u32],
        max_entries: usize,
    ) -> std::result::Result<u32, String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "watch set poisoned".to_string())?;
        match op {
            OP_ADD => {
                for p in pids {
                    guard.insert(*p);
                }
            }
            OP_REMOVE => {
                for p in pids {
                    guard.remove(p);
                }
            }
            OP_RESET => {
                if pids.len() > max_entries {
                    return Err(format!(
                        "watch set of {} exceeds {}",
                        pids.len(),
                        max_entries
                    ));
                }
                guard.clear();
                guard.extend(pids.iter().copied());
            }
            other => return Err(format!("unsupported op {}", other)),
        }
        if guard.len() > max_entries {
            return Err(format!(
                "watch set of {} exceeds {}",
                guard.len(),
                max_entries
            ));
        }
        Ok(guard.len() as u32)
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;
    use std::time::Duration;

    // 6.23: the ack must not be sent before the kernel-side filter holds the
    // set, or a process that execs in between is filtered as unwatched and
    // nothing counts it as loss.
    #[test]
    fn a_set_is_not_synced_until_the_backend_confirms_it() {
        let w = WatchSet::new();
        w.apply(OP_RESET, &[10, 20], 8).unwrap();
        let v = w.version();
        assert!(
            !w.wait_synced(v, Duration::from_millis(5)),
            "sync claimed before the backend mirrored the set"
        );
        w.mark_synced(v);
        assert!(w.wait_synced(v, Duration::from_millis(5)));
    }

    #[test]
    fn an_older_sync_does_not_cover_a_newer_set() {
        let w = WatchSet::new();
        w.apply(OP_RESET, &[10], 8).unwrap();
        let first = w.version();
        w.apply(OP_ADD, &[20], 8).unwrap();
        let second = w.version();
        w.mark_synced(first);
        assert!(
            !w.wait_synced(second, Duration::from_millis(5)),
            "a later watch add was covered by an earlier sync"
        );
        w.mark_synced(second);
        assert!(w.wait_synced(second, Duration::from_millis(5)));
    }

    #[test]
    fn sync_marks_are_monotonic() {
        let w = WatchSet::new();
        w.mark_synced(7);
        w.mark_synced(3);
        assert!(w.wait_synced(7, Duration::from_millis(5)));
    }
}
