// manager (6.7/6.39/6.40): supervises the runopsy-trace child process.
//
// invariants, in priority order:
//   - a tracer failure (missing binary, crash, protocol error) never takes
//     the agent down: it degrades to polling-only and reports why;
//   - restarts use capped exponential backoff and stop after
//     MaxConsecutiveFailures consecutive failures (no hot loops);
//   - the tracer child is always reaped: every spawned process is either
//     shut down cleanly (SHUTDOWN control + wait) or killed after a grace
//     period, and waited on, so no tracer zombie accumulates;
//   - decoded events are forwarded to the configured sink unchanged; loss
//     visibility stays with session (sequence gaps), not here.
package trace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// manager states. StateUnavailable always carries a reason in Health.LastError.
type ManagerState string

const (
	// StateUnavailable: tracing could not start or gave up after repeated
	// failures. the agent continues in polling-only mode.
	StateUnavailable ManagerState = "unavailable"
	// StateStarting: child spawned, handshake not confirmed yet.
	StateStarting ManagerState = "starting"
	// StateActive: handshake ok, events streaming.
	StateActive ManagerState = "active"
	// StateRestarting: previous session died; backing off before the next
	// spawn attempt.
	StateRestarting ManagerState = "restarting"
	// StateStopped: stopped deliberately (close or context cancellation).
	StateStopped ManagerState = "stopped"
)

// supervision defaults.
const (
	DefaultStartTimeout       = 5 * time.Second
	DefaultCommandTimeout     = 2 * time.Second
	DefaultBaseBackoff        = 250 * time.Millisecond
	DefaultMaxBackoff         = 5 * time.Second
	DefaultMaxConsecutiveFail = 5
	shutdownGrace             = 3 * time.Second
	silenceWatchPoll          = 250 * time.Millisecond
	// childExitDrain bounds how long a dead tracer's already-written events
	// are read before the session is closed.
	childExitDrain = 2 * time.Second
)

// health is the tracer component's self-report for status surfaces (6.38).
type Health struct {
	State               ManagerState  `json:"state"`
	Reason              string        `json:"reason,omitempty"`
	Attempts            int           `json:"spawn_attempts"`
	PID                 int           `json:"pid,omitempty"` // current/last tracer child
	Restarts            int           `json:"restarts"`
	ConsecutiveFailures int           `json:"-"` // internal; surfaced via GaveUp
	GaveUp              bool          `json:"gave_up"`
	StartedAt           time.Time     `json:"started_at,omitempty"` // last successful handshake
	Uptime              time.Duration `json:"uptime,omitempty"`
	Caps                Capabilities  `json:"capabilities,omitempty"`
	Lost                uint64        `json:"events_lost"`
	LastEventAt         time.Time     `json:"last_event_at,omitempty"`
	// recording is the debug-recording report (6.46). RecorderEvents is
	// cumulative over the whole run, not per session.
	RecordFile      string `json:"record_file,omitempty"`
	RecordedEvents  uint64 `json:"recorded_events,omitempty"`
	RecordTruncated bool   `json:"record_truncated,omitempty"`
	RecordReason    string `json:"record_reason,omitempty"`
	// watches is the size of the applied desired set (6.23) and
	// WatchesDropped the candidates refused after the set hit its bound.
	Watches        int `json:"watches"`
	WatchesDropped int `json:"watches_dropped,omitempty"`
	// WatchesStale counts pushed PIDs the tracer refused because their
	// identity no longer matched (§6.3 f): the process died or its PID was
	// reused, typically across a tracer restart.
	WatchesStale int `json:"watches_stale,omitempty"`
	// upstream loss the tracer itself reported with LOSS frames (§6.3 d),
	// broken down by stage, distinct from lost above, which is inferred on
	// the receiving side from sequence gaps. TracerHealth is the newest
	// HEALTH snapshot (§6.3 e) and LastFrameAt the arrival time of the
	// newest frame of any kind: the liveness facts that silence supervision
	// uses (a session silent beyond HealthSilenceInterval is torn down and
	// restarted).
	LostUpstream uint64            `json:"lost_upstream,omitempty"`
	LostStages   map[string]uint64 `json:"lost_stages,omitempty"`
	Tracer       *TracerHealth     `json:"tracer_health,omitempty"`
	LastFrameAt  time.Time         `json:"last_frame_at,omitempty"`

	lastHandshake time.Time
}

// manager spawns and supervises runopsy-trace. run blocks until the context
// is cancelled, the tracer is given up on, or stop is called; it returns nil
// in every degradation case (errors are reported through Health/LastError,
// never by aborting the recording agent).
type Manager struct {
	cfg         ManagerConfig
	mu          sync.Mutex
	health      Health
	session     *Session
	recorder    *Recorder
	child       *exec.Cmd
	childWait   chan error
	stopOnce    sync.Once
	stopCh      chan struct{}
	stateChange func(ManagerState) // test seam

	// Watch-set plumbing (6.23): the tracker holds the desired set; watchCh
	// wakes the single driver (the supervision loop) to apply it to the live
	// session. buffered so a poke never blocks its caller.
	tracker *WatchTracker
	watchCh chan struct{}
}

// watches exposes the desired watch-set tracker (6.23). the agent keeps it
// current as snapshots arrive; the supervision loop then drives it into every
// live session before one counts as active. the tracker is never nil.
func (m *Manager) Watches() *WatchTracker { return m.tracker }

// ManagerConfig bounds supervision; zero fields take the defaults below.
type ManagerConfig struct {
	// binary is the runopsy-trace executable. empty resolves a sibling of
	// the current executable, then PATH.
	Binary string
	// SocketPath for the unix listener. empty creates a private temp dir
	// with a short socket name.
	SocketPath string
	// events receives decoded events; must be quick and non-reentrant.
	Events Sink
	// StartTimeout bounds waiting for the child's socket + handshake.
	StartTimeout time.Duration
	// CommandTimeout bounds each control round trip (wall and close).
	CommandTimeout time.Duration
	// BaseBackoff / MaxBackoff bound restart delays.
	BaseBackoff, MaxBackoff time.Duration
	// MaxConsecutiveFail consecutive spawn/connect failures give up
	// permanently for this manager instance (StateUnavailable, GaveUp).
	MaxConsecutiveFail int
	// mode is the agent's requested collection mode (6.21). empty means
	// auto. an explicit ebpf/proc mode refuses a session served by the other
	// backend, because the proc connector cannot report signals, stop/resume
	// or OOM (contract §2.1).
	Mode Mode
	// DebugOutput records the raw event stream to this file for replay
	// (6.46). Debug-only; empty disables recording.
	DebugOutput string
	// RecordLimits bound the debug recording; zero takes the defaults.
	RecordLimits RecorderLimits
	// spawnCmd is a test seam producing the child process command. it must
	// start a process that creates the unix socket at the configured path
	// (or serve one there) and live until killed.
	spawnCmd func(socket string) *exec.Cmd
	// linuxAllowed is a test seam over the platform gate; production uses
	// the fixed linux check below.
	linuxAllowed func() bool
}

// NewManager applies defaults. it never fails: an unstartable manager is a
// valid, permanently-unavailable manager (6.20 degradation).
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Events == nil {
		cfg.Events = func(TraceEvent) {}
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = DefaultStartTimeout
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = DefaultCommandTimeout
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.MaxConsecutiveFail <= 0 {
		cfg.MaxConsecutiveFail = DefaultMaxConsecutiveFail
	}
	if cfg.linuxAllowed == nil {
		cfg.linuxAllowed = func() bool { return runtime.GOOS == "linux" }
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeAuto
	}
	return &Manager{cfg: cfg, stopCh: make(chan struct{}), tracker: NewWatchTracker(), watchCh: make(chan struct{}, 1)}
}

// ResolveBinary prefers an explicit path, then a sibling of the running
// agent binary, then PATH. the reason describes why nothing resolved.
func ResolveBinary(override string) (string, string) {
	if override != "" {
		// A configured path that is not an executable file is "tracer not
		// installed" (6.7/6.52): polling-only at once, not a restart loop
		// that burns the backoff schedule on a file that will not appear.
		// A bare name is looked up on PATH as that exact name; it is never
		// replaced by a different binary.
		path := override
		if !strings.ContainsRune(override, os.PathSeparator) {
			if p, err := exec.LookPath(override); err == nil {
				path = p
			}
		}
		if st, err := os.Stat(path); err != nil || st.IsDir() || st.Mode()&0111 == 0 {
			return "", fmt.Sprintf("runopsy-trace binary not found at %s", override)
		}
		return path, ""
	}
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), "runopsy-trace")
		if st, err := os.Stat(sibling); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return sibling, ""
		}
	}
	if p, err := exec.LookPath("runopsy-trace"); err == nil {
		return p, ""
	}
	return "", "runopsy-trace binary not found (build trace-rs/ and install it on PATH)"
}

func socketPath(preferred string) (string, func(), error) {
	if preferred != "" {
		return preferred, func() {}, nil
	}
	// short path: macOS sun_path is 104 bytes and t.TempDir chains are deep.
	dir, err := os.MkdirTemp("", "runopsy-trace")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "t.sock"), func() { _ = os.RemoveAll(dir) }, nil
}

// run supervises until ctx is done or supervision permanently ends. tracing
// is Linux-only (6.20): every other platform degrades immediately.
func (m *Manager) Run(ctx context.Context) error {
	if !m.cfg.Mode.Enabled() {
		// 6.21: an explicit disabled mode is a decision, not a failure. it
		// reports why tracing is off so a later reader of the bundle can
		// tell "not observed" from "not observed because tracing was off".
		m.setState(StateStopped, "tracing disabled by configuration (--tracing disabled); polling only")
		return nil
	}
	if !m.cfg.linuxAllowed() {
		m.setState(StateUnavailable, "tracing is Linux-only; continuing in polling mode")
		return nil
	}
	if err := m.startRecording(); err != nil {
		// A debug recording that cannot be opened must not cost the trace
		// itself: the session proceeds, and the reason is visible in Health.
		m.setState(m.currentState(), fmt.Sprintf("debug recording unavailable: %v", err))
	}
	defer m.closeRecording()
	bin, why := "", ""
	if m.cfg.spawnCmd == nil {
		bin, why = ResolveBinary(m.cfg.Binary)
		if why != "" {
			m.setState(StateUnavailable, why)
			return nil
		}
	}
	sock, cleanup, err := socketPath(m.cfg.SocketPath)
	if err != nil {
		m.setState(StateUnavailable, fmt.Sprintf("socket path: %v", err))
		return nil
	}
	defer cleanup()

	backoff := m.cfg.BaseBackoff
	for {
		if m.isStopped() || ctx.Err() != nil {
			break
		}
		_ = m.watchDrained()
		m.setState(StateStarting, "")
		spawn := m.cfg.spawnCmd
		if spawn == nil {
			spawn = func(socket string) *exec.Cmd {
				return exec.Command(bin, "--socket", socket)
			}
		}
		child := spawn(sock)
		// one wait owner per spawn attempt: the reaper channel below. no
		// code path may call child.Wait directly after this point.
		childwait := make(chan error, 1)
		// exitCh is a broadcast form of the same fact: connectWithRetry must be
		// able to notice an early exit without consuming the single wait result
		// that the supervision loop owns.
		childexit := make(chan struct{})
		m.mu.Lock()
		m.child = child
		m.childWait = childwait
		m.mu.Unlock()
		if err := child.Start(); err != nil {
			close(childwait)
			if m.noteFailure(fmt.Sprintf("spawn %s: %v", bin, err), &backoff) {
				break
			}
			continue
		}
		go func() {
			childwait <- child.Wait()
			close(childexit)
		}()
		// published for health reports and for /proc-based measurement of the
		// tracer child (6.38/6.49). cleared when the child is reaped.
		m.mu.Lock()
		m.health.PID = child.Process.Pid
		m.mu.Unlock()
		sess, err := m.connectWithRetry(ctx, sock, childexit)
		if err != nil {
			m.killChild()
			// §6.3 b: an identity mismatch (another boot, another PID
			// namespace, another clock) is a property of the machine, not a
			// transient failure. resubscribing cannot change boot_id, so
			// like an unsupported kernel this degrades once instead of
			// looping. GaveUp keeps the run epilogue from overwriting the
			// state with StateStopped.
			if errors.Is(err, ErrIdentityMismatch) {
				m.mu.Lock()
				m.health.GaveUp = true
				m.mu.Unlock()
				m.setState(StateUnavailable, unavailableReason(err.Error()))
				break
			}
			if m.noteFailure(fmt.Sprintf("connect: %v", err), &backoff) {
				break
			}
			continue
		}
		// A kernel the tracer cannot serve at all is terminal, not a restart
		// loop: the binary is fine and resubscribing will not change the
		// kernel. this is 6.53's degrade-cleanly path.
		if sess.Caps.Unsupported {
			m.mu.Lock()
			m.health.Caps = sess.Caps
			// GaveUp keeps the epilogue from overwriting this state with
			// StateStopped when run returns.
			m.health.GaveUp = true
			m.mu.Unlock()
			_ = sess.Close(m.cfg.CommandTimeout)
			m.killChild()
			m.setState(StateUnavailable, unavailableReason(sess.SelectionReason))
			break
		}
		// 6.21 mode discipline: a session served by a backend the operator
		// did not ask for is refused rather than silently accepted, so the
		// bundle never claims evidence a different backend cannot produce.
		if reason := m.cfg.Mode.UnavailableReason(sess.Caps); reason != "" {
			m.mu.Lock()
			m.health.Caps = sess.Caps
			m.mu.Unlock()
			_ = sess.Close(m.cfg.CommandTimeout)
			m.killChild()
			if m.noteFailure(reason, &backoff) {
				break
			}
			continue
		}
		// 6.23: a session must carry its desired watch set before it counts
		// as active. a session without its watch set must never report
		// coverage it does not have. A fresh session needs the drive only
		// when the desired set is non-empty: a newly spawned tracer owns an
		// empty set by construction, and a set that shrinks to empty later
		// is still cleared through the watchCh drive below. every applied
		// set is driven from RESET, so a stale watch from an older tracer
		// process cannot survive a reconnect and a restart cannot strand it.
		if len(m.tracker.View()) > 0 {
			if err := m.tracker.Drive(sess, m.cfg.CommandTimeout); err != nil {
				_ = sess.Close(m.cfg.CommandTimeout)
				m.killChild()
				if m.noteFailure(fmt.Sprintf("watch set: %v", err), &backoff) {
					break
				}
				continue
			}
		} else {
			m.refreshWatchHealth()
		}
		// connected: backoff and the failure streak reset.
		backoff = m.cfg.BaseBackoff
		m.mu.Lock()
		m.session = sess
		m.health.Caps = sess.Caps
		m.health.lastHandshake = time.Now()
		m.health.StartedAt = m.health.lastHandshake
		m.health.ConsecutiveFailures = 0
		m.health.GaveUp = false
		m.mu.Unlock()
		m.setState(StateActive, "")
		m.refreshWatchHealth()

		// block until the session dies, the child exits early, or shutdown.
		reason := m.awaitSession(sess, child)

		m.mu.Lock()
		m.session = nil
		m.mu.Unlock()
		_ = sess.Close(m.cfg.CommandTimeout)
		m.killChild()
		if m.isStopped() || ctx.Err() != nil {
			break
		}
		// only unexpected session deaths restart (6.39). A tracer that
		// refuses us or exits cleanly without complaint also counts as a
		// failure streak member: repeated clean refusals are still a broken
		// deployment.
		if m.noteFailure(reason, &backoff) {
			break
		}
		m.setState(StateRestarting, "")
	}
	m.mu.Lock()
	gaveUp := m.health.GaveUp
	m.mu.Unlock()
	if !gaveUp {
		m.setState(StateStopped, "")
	}
	return nil
}

// awaitSession waits for one of: session teardown (returns its reason),
// early child exit, a watch-set poke, or our stop signal. the child normally
// outlives the session; an early exit is surfaced as its own reason. watch
// updates from the agent are applied here, on the live session, by the same
// single driver that owns every other control (6.23).
func (m *Manager) awaitSession(sess *Session, child *exec.Cmd) string {
	m.mu.Lock()
	childwait := m.childWait
	m.mu.Unlock()
	if childwait == nil {
		return ""
	}
	for {
		select {
		case <-sess.Done():
			if err := sess.Err(); err != nil {
				return fmt.Sprintf("session ended: %v", err)
			}
			return "session closed by tracer"
		case <-time.After(silenceWatchPoll):
			// §6.3 e: a protocol-2 tracer sends HEALTH at least once a second,
			// so a live session always shows a frame eventually: events,
			// acks, LOSS or HEALTH. HealthSilenceInterval without one is a
			// hung tracer: the session must be torn down so supervision
			// rebuilds, instead of blocking forever (the agent sends no
			// controls in the steady state, which is exactly when a wedged
			// sensor used to go undetected). A protocol-1 tracer promises no
			// frames, so silence is not a fault there.
			if sess.Version >= 2 && time.Since(sess.LastFrameAt()) > HealthSilenceInterval {
				return fmt.Sprintf("session silent for %s: no loss/health frames, hung tracer", HealthSilenceInterval)
			}
		case err := <-childwait:
			// the child ended the session by exiting; remember it is consumed.
			m.mu.Lock()
			m.child = nil
			m.mu.Unlock()
			// events the tracer wrote before it died are still in the socket
			// (contract §11.1, "100k events queued at a crash"). let the read
			// loop drain them to end of stream before the caller closes the
			// connection; bounded, in case another process holds the socket.
			select {
			case <-sess.Done():
			case <-time.After(childExitDrain):
			case <-m.stopCh:
			}
			if err == nil {
				return "tracer exited (code 0)"
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return fmt.Sprintf("tracer exited: %v", ee)
			}
			return fmt.Sprintf("tracer wait: %v", err)
		case <-m.watchCh:
			if err := m.tracker.Drive(sess, m.cfg.CommandTimeout); err != nil {
				// the live session cannot carry the watch set: end it and
				// let the supervision loop rebuild, so health never shows a
				// watch the tracer did not acknowledge.
				return fmt.Sprintf("watch set: %v", err)
			}
			m.refreshWatchHealth()
		case <-m.stopCh:
			return ""
		}
	}
}

// refreshWatchHealth mirrors the tracker into health after a successful
// application.
func (m *Manager) refreshWatchHealth() {
	_, dropped := m.tracker.Status()
	m.mu.Lock()
	m.health.Watches = len(m.tracker.View())
	m.health.WatchesDropped = dropped
	m.mu.Unlock()
}

// noteFailure records one supervision failure and evaluates give-up. returns
// true when supervision must stop. sleeps the (escalated) backoff otherwise.
func (m *Manager) noteFailure(reason string, backoff *time.Duration) bool {
	m.mu.Lock()
	h := &m.health
	h.Attempts++
	h.ConsecutiveFailures++
	h.Restarts = maxInt(h.Restarts, h.Attempts-1)
	h.Reason = reason
	gaveUp := h.ConsecutiveFailures >= m.cfg.MaxConsecutiveFail
	if gaveUp {
		h.GaveUp = true
	}
	wait := *backoff
	next := *backoff * 2
	if next > m.cfg.MaxBackoff {
		next = m.cfg.MaxBackoff
	}
	*backoff = next
	if wait > m.cfg.MaxBackoff {
		wait = m.cfg.MaxBackoff
	}
	m.mu.Unlock()
	if gaveUp {
		m.setState(StateUnavailable, reason+"; giving up tracing until restart")
		return true
	}
	m.setState(StateRestarting, reason)
	select {
	case <-time.After(wait):
	case <-m.stopCh:
	}
	return false
}

// connectWithRetry waits up to StartTimeout for a freshly spawned child to
// bind its socket. the spawn→bind window is not a failure: a real tracer needs
// milliseconds to start, and dialing exactly once used to kill the child
// before it could ever listen (observed as a permanent "no such file" loop).
// only dial failures are retried; a handshake/protocol rejection is terminal
// for the attempt and is reported as such.
func (m *Manager) connectWithRetry(ctx context.Context, socket string, childExit <-chan struct{}) (*Session, error) {
	deadline := time.Now().Add(m.cfg.StartTimeout)
	var lastErr error
	for {
		timeout := m.cfg.StartTimeout
		if remaining := time.Until(deadline); remaining < timeout && remaining > 0 {
			timeout = remaining
		}
		if timeout <= 0 {
			timeout = time.Second
		}
		sess, err := Connect(SessionOptions{Socket: socket, Sink: m.sink, HandshakeTimeout: timeout})
		if err == nil {
			return sess, nil
		}
		lastErr = err
		if !dialFailure(err) {
			return nil, err
		}
		if !time.Now().Before(deadline) || m.isStopped() || ctx.Err() != nil {
			return nil, lastErr
		}
		select {
		case <-childExit:
			// the child died without ever listening (bad binary, immediate
			// crash, refused privileges). waiting out the rest of StartTimeout
			// would only delay the honest restart.
			return nil, lastErr
		case <-m.stopCh:
			return nil, lastErr
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// dialFailure reports whether err is the child not listening yet, as opposed
// to a protocol-level rejection that retrying cannot fix.
func dialFailure(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

func (m *Manager) sink(e TraceEvent) {
	m.mu.Lock()
	m.health.LastEventAt = time.Now()
	recorder := m.recorder
	m.mu.Unlock()
	if recorder != nil {
		recorder.Record(e)
	}
	m.cfg.Events(e)
}

// startRecording opens the debug recording (6.46) before any event can
// arrive, so a recording is either complete from the first frame or reports
// why it is not.
func (m *Manager) startRecording() error {
	if m.cfg.DebugOutput == "" {
		return nil
	}
	recorder, err := NewRecorder(m.cfg.DebugOutput, m.cfg.RecordLimits)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.recorder = recorder
	m.health.RecordFile = m.cfg.DebugOutput
	m.mu.Unlock()
	return nil
}

// closeRecording closes the debug recording and folds its report into Health.
func (m *Manager) closeRecording() {
	m.mu.Lock()
	recorder := m.recorder
	m.recorder = nil
	m.mu.Unlock()
	if recorder == nil {
		return
	}
	stats, err := recorder.Close()
	m.mu.Lock()
	m.health.RecordedEvents = stats.Events
	m.health.RecordTruncated = stats.Truncated
	m.health.RecordReason = stats.Reason
	m.mu.Unlock()
	if err != nil {
		m.mu.Lock()
		m.health.RecordTruncated = true
		m.health.RecordReason = err.Error()
		m.mu.Unlock()
	}
}

// currentState reads the supervision state without publishing a transition;
// used to keep a degradation reason attached to the state it happened in.
func (m *Manager) currentState() ManagerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health.State
}

func (m *Manager) setState(s ManagerState, reason string) {
	m.mu.Lock()
	m.health.State = s
	if reason != "" {
		m.health.Reason = reason
	}
	if s == StateActive && !m.health.lastHandshake.IsZero() {
		m.health.Uptime = time.Since(m.health.lastHandshake)
	}
	m.mu.Unlock()
	if m.stateChange != nil {
		m.stateChange(s)
	}
}

func (m *Manager) isStopped() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// SetWatches replaces the desired watch set (6.23). safe to call from any
// goroutine; the supervision loop applies it to the live session, or to the
// next one after a reconnect. the application point is drive, never here.
func (m *Manager) SetWatches(pids []uint32) {
	m.tracker.Set(pids)
	m.pokeWatches()
}

// AddWatches / RemoveWatches adjust the desired set; agents call these per
// snapshot as the watched tree grows and shrinks.
func (m *Manager) AddWatches(pids []uint32) {
	m.tracker.Add(pids)
	m.pokeWatches()
}

func (m *Manager) RemoveWatches(pids []uint32) {
	m.tracker.Remove(pids)
	m.pokeWatches()
}

func (m *Manager) pokeWatches() {
	select {
	case m.watchCh <- struct{}{}:
	default:
	}
}

// watchDrained consumes one pending watch poke without blocking; the
// supervision loop polls it when a session is not yet live.
func (m *Manager) watchDrained() bool {
	select {
	case <-m.watchCh:
		return true
	default:
		return false
	}
}

// health snapshots the supervision state (6.38).
func (m *Manager) Health() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.health
	if h.State == StateActive && !h.lastHandshake.IsZero() {
		h.Uptime = time.Since(h.lastHandshake)
	}
	if s := m.session; s != nil {
		h.Lost = s.Lost()
		h.LostUpstream = s.LostUpstream()
		h.LastFrameAt = s.LastFrameAt()
		if th, _, ok := s.LastTracerHealth(); ok {
			thc := th
			h.Tracer = &thc
		}
		stages := map[string]uint64{}
		bystage := s.LostUpstreamByStage()
		for i, c := range bystage {
			name := LossStage(i + 1).String()
			if i == len(bystage)-1 {
				name = "unknown_stage"
			}
			if c > 0 {
				stages[name] = c
			}
		}
		if len(stages) > 0 {
			h.LostStages = stages
		}
	}
	h.Watches = len(m.tracker.View())
	_, h.WatchesDropped = m.tracker.Status()
	h.WatchesStale = m.tracker.Stale()
	return h
}

// stop shuts the tracer down cleanly: SHUTDOWN control, socket close, child
// kill after a grace period, and a wait so nothing is left running (6.7).
// safe to call before, during, or after Run.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
	m.mu.Lock()
	sess := m.session
	m.mu.Unlock()
	if sess != nil {
		_ = sess.Close(m.cfg.CommandTimeout)
	}
	// the supervision loop (or, if it already returned, the cleanup it ran)
	// owns child reaping; killing the child here would race its Wait.
}

// killChild force-ends the current child during supervision; used when a
// session fails to come up so a stale socket owner cannot linger. the wait
// owner is the childWait channel from the spawn attempt, never a direct
// child.Wait call.
func (m *Manager) killChild() {
	m.mu.Lock()
	child := m.child
	childwait := m.childWait
	m.mu.Unlock()
	if child != nil && child.Process != nil {
		_ = child.Process.Kill()
	}
	if childwait != nil {
		select {
		case <-childwait:
		case <-time.After(shutdownGrace):
		}
	}
	m.mu.Lock()
	m.child = nil
	m.childWait = nil
	m.health.PID = 0
	m.mu.Unlock()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// unavailableReason is the one wording every refusal path uses. it always
// says the agent keeps polling, so a status reader never infers that
// tracing failing means the agent stopped.
func unavailableReason(reason string) string {
	if reason == "" {
		reason = "the tracer gave no reason"
	}
	return "tracing unavailable: " + reason + "; continuing in polling mode"
}
