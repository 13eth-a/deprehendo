package incident

import (
	"strings"
	"time"

	"deprehendo/internal/collector"
)

// SnapshotRule evaluates one completed, ordered sample and returns a factual
// trigger when its condition is observed. rules never diagnose: they report
// that a threshold was crossed or a watched process entered a stopped state.
// rules are owned by one sampling goroutine and are not safe for concurrent
// observe calls. ProcessExitRule satisfies the same interface.
type SnapshotRule interface {
	Observe(collector.Snapshot) *Trigger
}

// ThresholdRule crosses when a percentage stays above (or, for free space,
// below) value for a continuous Duration. zero or invalid values disable it.
type ThresholdRule struct {
	Value    float64
	Duration time.Duration
}

func (t ThresholdRule) valid() bool {
	return t.Value >= 0 && t.Value <= 100 && t.Duration >= 0
}

// ResourceRules adds automatic triggers for host memory pressure and low disk
// free space. both read only the system section sampled by the phase 1 host
// collector; an unavailable sensor resets the debounce and never fires.
type ResourceRules struct {
	Memory   *ThresholdRule
	DiskFree *ThresholdRule

	memoryDebounce Debounce
	diskDebounce   Debounce
}

// observe returns at most one trigger per sample. memory is evaluated first.
func (r *ResourceRules) Observe(s collector.Snapshot) *Trigger {
	if s.Timestamp.IsZero() {
		return nil
	}
	var result *Trigger
	var system *collector.SystemSnapshot
	if s.System != nil {
		system = s.System
	}
	if r.Memory != nil && r.Memory.Value > 0 && r.Memory.valid() {
		r.memoryDebounce.Duration = r.Memory.Duration
		available := system != nil && system.MemoryStatsAvailable && system.MemoryTotal > 0 && system.MemoryUsed <= system.MemoryTotal
		usedpercent := 0.0
		if available {
			usedpercent = float64(system.MemoryUsed) * 100 / float64(system.MemoryTotal)
		}
		if r.memoryDebounce.Observe(s.Timestamp, usedpercent >= r.Memory.Value, available) {
			result = &Trigger{Type: "memory_threshold"}
		}
	}
	if r.DiskFree != nil && r.DiskFree.Value > 0 && r.DiskFree.valid() {
		r.diskDebounce.Duration = r.DiskFree.Duration
		available := system != nil && system.DiskStatsAvailable && system.DiskTotal > 0 && system.DiskFree <= system.DiskTotal
		freepercent := 0.0
		if available {
			freepercent = float64(system.DiskFree) * 100 / float64(system.DiskTotal)
		}
		if r.diskDebounce.Observe(s.Timestamp, freepercent <= r.DiskFree.Value, available) {
			if result == nil {
				result = &Trigger{Type: "disk_threshold"}
			}
		}
	}
	return result
}

// StoppedProcessRule triggers once when a watched process is first observed in
// a stopped state. it fires once per continuous episode per process identity
// and resets when that process runs again or the process section is
// unavailable, so a stopped worker does not generate an incident every sample.
// the caller must feed the watched selection, not an arbitrary host table.
type StoppedProcessRule struct {
	Enabled bool
	stopped map[identity]bool
	last    time.Time
}

// WatchedProcessExitRule emits once when any previously-observed watched
// process identity disappears from a successful process-table observation.
// it cannot distinguish an intentional shutdown from an unexpected one; this
// explicit opt-in is the documented MVP policy.
type WatchedProcessExitRule struct {
	Enabled bool
	seen    map[identity]bool
	last    time.Time
}

func stoppedState(state string) bool {
	return strings.HasPrefix(state, "T") || strings.HasPrefix(state, "t")
}

func (r *WatchedProcessExitRule) Observe(s collector.Snapshot) *Trigger {
	if !r.Enabled || s.Timestamp.IsZero() || (!r.last.IsZero() && !s.Timestamp.After(r.last)) {
		return nil
	}
	r.last = s.Timestamp
	if !processOK(s) {
		// A failed process sample breaks continuity, so do not report exits based
		// on the next successful sample after an unknown interval.
		r.seen = nil
		return nil
	}
	next := make(map[identity]bool, len(s.Processes))
	for _, p := range s.Processes {
		next[identity{p.PID, p.StartTicks}] = true
	}
	var missing *identity
	for old := range r.seen {
		if !next[old] && (missing == nil || identityLess(old, *missing)) {
			key := old
			missing = &key
		}
	}
	if missing != nil {
		r.seen = next
		return &Trigger{Type: "process_exit", PID: missing.pid, StartTicks: missing.start}
	}

	r.seen = next
	return nil
}

func (r *StoppedProcessRule) Observe(s collector.Snapshot) *Trigger {
	if !r.Enabled || s.Timestamp.IsZero() || (!r.last.IsZero() && !s.Timestamp.After(r.last)) {
		return nil
	}
	r.last = s.Timestamp
	if !processOK(s) {
		r.stopped = nil
		return nil
	}
	next := make(map[identity]bool, len(r.stopped)+1)
	var trigger *Trigger
	for _, p := range s.Processes {
		key := identity{p.PID, p.StartTicks}
		if !stoppedState(p.State) {
			continue
		}
		next[key] = true
		if !r.stopped[key] && (trigger == nil || identityLess(key, identity{trigger.PID, trigger.StartTicks})) {
			trigger = &Trigger{Type: "process_stopped", PID: p.PID, StartTicks: p.StartTicks}
		}
	}
	r.stopped = next
	return trigger
}

func identityLess(a, b identity) bool { return a.pid < b.pid || (a.pid == b.pid && a.start < b.start) }
