package trace

// failure isolation (6.40): the rust enhancement may degrade; the go recorder
// must continue. every failure below happens in a real child process, exactly
// as it would in production, and every assertion is about the supervisor
// living through it, never about the tracer succeeding.

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func isolationManager(t *testing.T, mode string, tune func(*ManagerConfig)) *Manager {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix process semantics")
	}
	cfg := ManagerConfig{
		BaseBackoff:        10 * time.Millisecond,
		MaxBackoff:         40 * time.Millisecond,
		StartTimeout:       3 * time.Second, // test-binary startup, not just the bind
		CommandTimeout:     300 * time.Millisecond,
		MaxConsecutiveFail: 60, // reconnect churn is expected; give-up is tested separately
		linuxAllowed:       func() bool { return true },
		spawnCmd: func(socket string) *exec.Cmd {
			return fakeTracerCommand(mode, socket, 0)
		},
	}
	if tune != nil {
		tune(&cfg)
	}
	return NewManager(cfg)
}

type runningManager struct {
	manager *Manager
	done    chan struct{}
	cancel  context.CancelFunc
}

func startManagerRun(t *testing.T, m *Manager) *runningManager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &runningManager{manager: m, done: make(chan struct{}), cancel: cancel}
	go func() { _ = m.Run(ctx); close(run.done) }()
	t.Cleanup(func() {
		m.Stop()
		cancel()
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
			t.Errorf("supervisor did not return after Stop (tracer leaked)")
		}
	})
	return run
}

func (r *runningManager) alive() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func waitForState(t *testing.T, m *Manager, within time.Duration, what string, cond func(Health) bool) Health {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		h := m.Health()
		if cond(h) {
			return h
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out waiting for %s; last health: %+v", what, h)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestIsolationCorruptFrameKillsOnlyTheSession: a non-frame on a live
// connection ends that session, the supervisor counts the failure and tries
// again, and the recorder keeps running.
func TestIsolationCorruptFrameKillsOnlyTheSession(t *testing.T) {
	m := isolationManager(t, fakeModeGarbage, nil)
	run := startManagerRun(t, m)
	h := waitForState(t, m, 6*time.Second, "a failed session", func(h Health) bool {
		return h.Attempts >= 1 && h.Reason != ""
	})
	if !strings.Contains(h.Reason, "session") && !strings.Contains(h.Reason, "protocol") {
		t.Errorf("failure reason %q does not name the corrupt session", h.Reason)
	}
	if !run.alive() {
		t.Fatal("supervisor returned; the recorder would have stopped")
	}
}

func TestIsolationTracerPanic(t *testing.T) {
	m := isolationManager(t, fakeModePanic, nil)
	run := startManagerRun(t, m)
	waitForState(t, m, 8*time.Second, "a tracer crash", func(h Health) bool {
		return h.Attempts >= 1 && h.Reason != ""
	})
	if !run.alive() {
		t.Fatal("supervisor returned after a tracer panic")
	}
}

func TestIsolationMidFrameCrash(t *testing.T) {
	m := isolationManager(t, fakeModeCrashMidFrame, nil)
	run := startManagerRun(t, m)
	waitForState(t, m, 8*time.Second, "a truncated-frame failure", func(h Health) bool {
		return h.Attempts >= 1
	})
	if !run.alive() {
		t.Fatal("supervisor returned after a mid-frame crash")
	}
}

// TestActiveSessionWithEmptyWatchSet pins the 6.23 connect gate: a fresh
// tracer owns an empty watch set by construction, so a session with an empty
// desired set becomes active without a control round trip. the regression
// guard behind this is exact: a fake that never acks controls used to wedge
// every attempt, which is the wrong shape for "nothing to apply".
func TestActiveSessionWithEmptyWatchSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix process semantics")
	}
	m := isolationManager(t, fakeModeKill9, nil)
	run := startManagerRun(t, m)
	h := waitForState(t, m, 15*time.Second, "an active session with nothing to drive", func(h Health) bool {
		return h.State == StateActive && h.PID > 0
	})
	if h.Watches != 0 {
		t.Errorf("watched entries = %d, want 0", h.Watches)
	}
	killed := h.PID
	if err := syscall.Kill(h.PID, syscall.SIGKILL); err != nil {
		t.Fatalf("kill tracer %d: %v", h.PID, err)
	}
	waitForState(t, m, 15*time.Second, "a replacement tracer after SIGKILL", func(h Health) bool {
		return h.State == StateActive && h.PID > 0 && h.PID != killed
	})
	m.Stop()
	<-run.done
}

// TestWatchSetRefusalIsVisibleAndKeepsSupervision: once a desired set is
// named, a tracer that cannot carry it must not report active coverage: the
// attempts keep failing with a named reason and the supervisor stays alive.
func TestWatchSetRefusalIsVisibleAndKeepsSupervision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix process semantics")
	}
	m := isolationManager(t, fakeModeKill9, nil)
	m.Watches().Set([]uint32{5001, 5008})
	run := startManagerRun(t, m)
	h := waitForState(t, m, 8*time.Second, "a named watch-set refusal", func(h Health) bool {
		return strings.Contains(h.Reason, "watch set")
	})
	if h.State == StateActive {
		t.Fatalf("a session without its watch set reported StateActive")
	}
	if !run.alive() {
		t.Fatal("supervisor returned after watch-set refusals")
	}
}

// TestIsolationKill9: SIGKILL the tracer mid-session. the agent must notice
// the dead child, restart it with backoff, and stay alive.
func TestIsolationKill9(t *testing.T) {
	m := isolationManager(t, fakeModeKill9, nil)
	run := startManagerRun(t, m)
	h := waitForState(t, m, 15*time.Second, "an active session", func(h Health) bool {
		return h.State == StateActive && h.PID > 0
	})
	if err := syscall.Kill(h.PID, syscall.SIGKILL); err != nil {
		t.Fatalf("kill tracer %d: %v", h.PID, err)
	}
	killed := h.PID
	waitForState(t, m, 15*time.Second, "a replacement tracer after SIGKILL", func(h Health) bool {
		return h.State == StateActive && h.PID > 0 && h.PID != killed
	})
	if !run.alive() {
		t.Fatal("supervisor returned after the tracer was killed")
	}
}

// TestIsolationHungHandshake: the tracer accepts but never speaks. the
// handshake deadline must fire; the recorder must not block on it.
func TestIsolationHungHandshake(t *testing.T) {
	m := isolationManager(t, fakeModeHangHandshake, func(c *ManagerConfig) {
		c.StartTimeout = 150 * time.Millisecond
	})
	run := startManagerRun(t, m)
	h := waitForState(t, m, 8*time.Second, "handshake timeouts", func(h Health) bool {
		return h.Attempts >= 2
	})
	if h.State == StateActive {
		t.Errorf("a silent tracer was reported active: %+v", h)
	}
	if !run.alive() {
		t.Fatal("supervisor returned after a hung handshake")
	}
}

// TestIsolationMissingSocketGivesUp: a tracer that never binds is a broken
// deployment. after bounded retries the supervisor gives up permanently and
// run returns nil. polling continues, tracing is simply unavailable.
func TestIsolationMissingSocketGivesUp(t *testing.T) {
	m := isolationManager(t, fakeModeNoSocket, func(c *ManagerConfig) {
		c.StartTimeout = 100 * time.Millisecond
		c.MaxConsecutiveFail = 2
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after giving up")
	}
	h := m.Health()
	if h.State != StateUnavailable || !h.GaveUp {
		t.Fatalf("expected unavailable+gaveUp, got %+v", h)
	}
	if h.Attempts != 2 {
		t.Errorf("attempts = %d, want exactly 2", h.Attempts)
	}
	if h.Reason == "" {
		t.Error("give-up carries no reason; degraded mode must be explainable")
	}
}

// TestIsolationIncompatibleVersion: a schema/protocol mismatch is rejected at
// the handshake (6.57), never patched over, and gives up after the bound.
func TestIsolationIncompatibleVersion(t *testing.T) {
	m := isolationManager(t, fakeModeVersionMismatch, func(c *ManagerConfig) {
		c.MaxConsecutiveFail = 2
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after an incompatible handshake")
	}
	h := m.Health()
	if h.State != StateUnavailable || !h.GaveUp {
		t.Fatalf("expected unavailable+gaveUp, got %+v", h)
	}
	if !strings.Contains(h.Reason, "schema") && !strings.Contains(h.Reason, "protocol") {
		t.Errorf("reason %q does not mention the version mismatch", h.Reason)
	}
}

// TestIsolationRecoveryAfterFailure: a healthy tracer that arrives after a
// failure streak is picked up, and its events reach the sink. the supervisor
// must not have poisoned itself during the bad phase.
func TestIsolationRecoveryAfterFailure(t *testing.T) {
	var attempts atomic.Int64
	m := isolationManager(t, fakeModeStream, func(c *ManagerConfig) {
		c.MaxConsecutiveFail = 60
		c.Events = func(TraceEvent) {}
		c.spawnCmd = func(socket string) *exec.Cmd {
			n := attempts.Add(1)
			mode := fakeModeStream
			events := 2
			if n < 2 {
				// first attempt never binds, so the supervisor fails, backs
				// off and respawns.
				mode, events = fakeModeNoSocket, 0
			}
			return fakeTracerCommand(mode, socket, events)
		}
	})
	run := startManagerRun(t, m)
	waitForState(t, m, 10*time.Second, "recovery to active", func(h Health) bool {
		return h.State == StateActive
	})
	if !run.alive() {
		t.Fatal("supervisor returned during recovery")
	}
}

// TestIsolationSilentTracerIsRestarted: §6.3 e's flip side. A tracer that
// answers the handshake and then wedges (sending no frames of any kind)
// used to hang the supervisor forever, because the steady state sends no
// controls for the command timeout to fire on. HealthSilenceInterval must end
// such a session, and supervision must then rebuild (the invariant 6.40:
// wedged tracer, live recorder).
func TestIsolationSilentTracerIsRestarted(t *testing.T) {
	m := isolationManager(t, fakeModeSilent, nil)
	run := startManagerRun(t, m)
	// two observations, because the facts are transient in opposite
	// directions. ConsecutiveFailures>0 only exists during the backoff
	// between teardown and reconnect (a successful connect resets it to 0),
	// while the reconnect itself is what proves supervision came back. asking
	// for both in one snapshot meant the test had to catch a ~10ms window in
	// the second 5s silence cycle, which timed out under -race and load.
	teardown := waitForState(t, m, 15*time.Second, "the silence watchdog tearing down a hung session", func(h Health) bool {
		return h.ConsecutiveFailures > 0 && strings.Contains(h.Reason, "silent")
	})
	if !strings.Contains(teardown.Reason, "silent") {
		t.Errorf("health reason lost the silence diagnosis: %+v", teardown)
	}
	waitForState(t, m, 15*time.Second, "supervision rebuilding after the silence teardown", func(h Health) bool {
		// A new handshake sets StartedAt afresh and clears the streak; the
		// stale failure reason is expected to survive as health's record of
		// the last failure, so it is not part of this condition.
		return h.State == StateActive && h.ConsecutiveFailures == 0 && h.StartedAt.After(teardown.StartedAt)
	})
	if !run.alive() {
		t.Fatal("supervisor returned instead of surviving the hang")
	}
}

// TestManagerSurfacesLossAndHealth: what the tracer reports with its own
// frames (§6.3 d/e) must reach the manager's status surface, not be decoded
// into a void. the reliability metadata (6.48) is built from it.
func TestManagerSurfacesLossAndHealth(t *testing.T) {
	m := isolationManager(t, fakeModeLossHealth, nil)
	startManagerRun(t, m)
	var h Health
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		h = m.Health()
		if h.LostUpstream >= 7 && h.Tracer != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if h.Tracer == nil {
		t.Fatalf("health never surfaced the tracer snapshot: %+v", h)
	}
	if h.Tracer.EventsSent != 3 || h.Tracer.EventsLost != 7 || h.Tracer.Watches != 0 {
		t.Errorf("tracer snapshot = %+v, want the §6.3 e send state", h.Tracer)
	}
	if h.LostUpstream != 7 {
		t.Errorf("LostUpstream = %d, want 7", h.LostUpstream)
	}
	if h.LostStages == nil || h.LostStages["queue"] != 7 {
		t.Errorf("LostStages = %v, want queue:7", h.LostStages)
	}
	if h.LastFrameAt.IsZero() {
		t.Errorf("LastFrameAt unset though frames arrived")
	}
}

// §11.1, "a restart while a watched PID has been reused": the agent pushes
// each PID with the identity it observed, and the tracer refuses PIDs whose
// identity no longer matches. the refused PIDs are dropped and counted; the
// rest of the set applies and the session is not treated as failed (before,
// one stale PID failed the whole push, so every restart repeated it).
func TestReusedWatchedPIDIsRefusedNotAdopted(t *testing.T) {
	m := isolationManager(t, fakeModeStale, nil)
	m.Watches().SetWatched([]Watched{
		{PID: 5001, StartTicks: 100},
		{PID: 5002, StartTicks: fakeStaleTicks}, // reused while the tracer was away
		{PID: 5003, StartTicks: 300},
	})
	startManagerRun(t, m)
	h := waitForState(t, m, 5*time.Second, "stale PID dropped", func(h Health) bool {
		return h.State == StateActive && h.WatchesStale == 1
	})
	if got := m.Watches().View(); len(got) != 2 || got[0] != 5001 || got[1] != 5003 {
		t.Fatalf("desired set after the stale refusal = %v, want [5001 5003]", got)
	}
	if h.Restarts != 0 || h.ConsecutiveFailures != 0 {
		t.Fatalf("a stale PID must not fail the push: %+v", h)
	}
}

// §11.1, "100k events queued at a crash": the tracer writes 100,000 events
// and dies mid-frame. every complete event already queued is delivered in
// order with no invented loss, the torn frame ends only that session, the
// supervisor restarts, and the agent holds none of it in memory (the sink
// is synchronous: there is no Go-side queue to grow).
func TestHundredThousandQueuedEventsSurviveACrash(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 100k events")
	}
	const n = 100000
	var mu sync.Mutex
	var first, next uint64 = 0, 1
	firstdone := false
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	m := isolationManager(t, fakeModeFloodCrash, func(c *ManagerConfig) {
		c.spawnCmd = func(socket string) *exec.Cmd { return fakeTracerCommand(fakeModeFloodCrash, socket, n) }
		c.Events = func(e TraceEvent) {
			mu.Lock()
			defer mu.Unlock()
			if firstdone {
				return
			}
			if e.Sequence != next {
				// the next session restarts the sequence at 1.
				firstdone = true
				return
			}
			first++
			next++
		}
	})
	startManagerRun(t, m)
	waitForState(t, m, 60*time.Second, "restart after the torn frame", func(h Health) bool {
		return h.Restarts >= 1
	})
	mu.Lock()
	got := first
	mu.Unlock()
	if got != n {
		t.Fatalf("delivered %d of %d queued events in order before the crash", got, n)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 32<<20 {
		t.Fatalf("heap grew %d bytes across 100k events: something queues them", grew)
	}
}
