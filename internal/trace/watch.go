package trace

import (
	"fmt"
	"sync"
	"time"
)

// WatchTracker (6.22/6.23) holds the *desired* watch set on the go side and
// applies it to whichever session is live. the tracer's kernel-side rule is a
// plain PID set; the agent resolves trees and cgroups itself and pushes
// leaves here.
//
// semantics (contract §6.3, audit O22):
//   - the desired set is authoritative: every drive applies it in full,
//     starting from RESET, so a stale move by an older tracer process can
//     never survive a reconnect;
//   - entries dedup, bounded at MaxWatchPerSession (the tracer's own set is
//     bounded identically): overflow drops the newest candidates and is
//     counted, never applied silently;
//   - only one goroutine may call drive at a time (the single-driver rule
//     inherited from Session.Control). the manager's supervision loop is
//     that driver; Set/Add/Remove only mutate the desired set and poke the
//     driver through watchCh, which is safe from any goroutine.
type WatchTracker struct {
	limit int

	mu      sync.Mutex
	calls   int // Set/Add/Remove calls, test observability
	changes int // mutations that changed the set; drive consumes this
	// desired maps each PID to the identity the agent observed for it
	// (start_ticks; 0 = unknown). pushed with the PID so the tracer can
	// refuse a PID that now belongs to another process (§6.3 f).
	desired map[uint32]int64
	order   []uint32 // deterministic application order
	dropped int      // candidates refused because the set is full
	stale   int      // PIDs the tracer refused as STALE_IDENTITY
}

// watched is one watch-set entry: a PID and the identity the agent observed
// for it (StartTicks 0 when unknown).
type Watched struct {
	PID        uint32
	StartTicks int64
}

// MaxWatchPerSession must match the tracer's watch cap: an over-limit set is
// refused with an error ack, so the go side clamps first and counts what it
// refused instead of sending a control that cannot succeed.
const MaxWatchPerSession = 4096

func NewWatchTracker() *WatchTracker {
	return &WatchTracker{limit: MaxWatchPerSession, desired: make(map[uint32]int64)}
}

// set replaces the desired watch set with pids (dedup, bounded), identities
// unknown.
func (t *WatchTracker) Set(pids []uint32) {
	ws := make([]Watched, len(pids))
	for i, pid := range pids {
		ws[i] = Watched{PID: pid}
	}
	t.SetWatched(ws)
}

// SetWatched replaces the desired watch set with identity-keyed entries
// (dedup, bounded). this is what the agent uses: it knows each process's
// start time from its snapshot, and pushing it is what lets a re-push after
// a tracer restart refuse a PID that was reused in the gap.
func (t *WatchTracker) SetWatched(ws []Watched) {
	t.mu.Lock()
	t.calls++
	t.desired = make(map[uint32]int64, len(ws))
	t.order = t.order[:0]
	t.changes++
	for _, w := range ws {
		t.insertLocked(w.PID, w.StartTicks)
	}
	t.mu.Unlock()
}

// add inserts pids into the desired set, identities unknown.
func (t *WatchTracker) Add(pids []uint32) {
	t.mu.Lock()
	t.calls++
	for _, pid := range pids {
		t.insertLocked(pid, 0)
	}
	t.mu.Unlock()
}

// remove deletes pids from the desired set.
func (t *WatchTracker) Remove(pids []uint32) {
	t.mu.Lock()
	t.calls++
	if t.desired != nil {
		for _, pid := range pids {
			if _, ok := t.desired[pid]; ok {
				delete(t.desired, pid)
				t.dropOrdered(pid)
				t.changes++
			}
		}
	}
	t.mu.Unlock()
}

// setClamp accounts PID 0 (never watchable: it is "any process") and the
// bounded-set overflow with a count, not silence.
func (t *WatchTracker) insertLocked(pid uint32, ticks int64) {
	if pid == 0 || t.desired == nil {
		return
	}
	if have, ok := t.desired[pid]; ok {
		if ticks != 0 && have != ticks {
			// same PID, new identity: the PID was reused between snapshots.
			t.desired[pid] = ticks
			t.changes++
		}
		return
	}
	if len(t.desired) >= t.limit {
		t.dropped++
		return
	}
	t.desired[pid] = ticks
	t.order = append(t.order, pid)
	t.changes++
}

func (t *WatchTracker) dropOrdered(pid uint32) {
	for i, have := range t.order {
		if have == pid {
			t.order = append(t.order[:i], t.order[i+1:]...)
			return
		}
	}
}

// drive applies the desired set to sess: RESET, then ADDs in chunks small
// enough for one control frame, each acknowledged before the next. returns
// an error when the session cannot carry the set (ack timeout, tracer
// refusal); the caller treats that as a failed attempt, not a degraded watch,
// so a bundle never claims coverage the tracer did not confirm.
//
// PIDs the tracer refuses as stale (their identity no longer matches: the
// process died or its PID was reused, typically while the tracer restarted)
// are dropped from the desired set and counted, not treated as a failed
// push: the next snapshot re-adds the PID under its current identity if
// that process belongs to the watched tree.
func (t *WatchTracker) Drive(sess *Session, timeout time.Duration) error {
	t.mu.Lock()
	desired := make([]Watched, len(t.order))
	for i, pid := range t.order {
		desired[i] = Watched{PID: pid, StartTicks: t.desired[pid]}
	}
	t.changes = 0
	t.mu.Unlock()

	if err := sess.Control(Control{Op: OpReset}, timeout); err != nil {
		return fmt.Errorf("reset watch set: %w", err)
	}
	for len(desired) > 0 {
		n := len(desired)
		if n > MaxWatchSetEntries {
			n = MaxWatchSetEntries
		}
		chunk := desired[:n]
		desired = desired[n:]
		c := Control{Op: OpAdd, PIDs: make([]uint32, n)}
		known := false
		ticks := make([]int64, n)
		for i, w := range chunk {
			c.PIDs[i] = w.PID
			ticks[i] = w.StartTicks
			known = known || w.StartTicks != 0
		}
		if known {
			c.StartTicks = ticks
		}
		ack, err := sess.ControlAck(c, timeout)
		if err != nil {
			return fmt.Errorf("add %d watched PIDs: %w", n, err)
		}
		if len(ack.Stale) > 0 {
			t.dropStale(chunk, ack.Stale)
		}
	}
	return nil
}

// dropStale removes the PIDs the tracer refused, but only while the desired
// set still holds the identity that was pushed: a newer snapshot may already
// have replaced it with the PID's current process.
func (t *WatchTracker) dropStale(pushed []Watched, stale []uint32) {
	sent := make(map[uint32]int64, len(pushed))
	for _, w := range pushed {
		sent[w.PID] = w.StartTicks
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, pid := range stale {
		t.stale++
		ticks, ok := sent[pid]
		if have, present := t.desired[pid]; ok && present && have == ticks {
			delete(t.desired, pid)
			t.dropOrdered(pid)
		}
	}
}

// stale reports how many pushed PIDs the tracer refused as STALE_IDENTITY.
func (t *WatchTracker) Stale() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stale
}

// view snapshots the desired set in application order.
func (t *WatchTracker) View() []uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]uint32, len(t.order))
	copy(out, t.order)
	return out
}

// status reports observer counters for health: mutated-entries pending push
// plus refused candidates.
func (t *WatchTracker) Status() (pendingChanges, dropped int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.changes, t.dropped
}
