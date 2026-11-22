package simulator

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"runopsy/internal/platform"
)

const (
	defaultZombieGrace = 2 * time.Second
	// the unwaited corpse must outlive every plausible sampling cadence, so
	// the default window dwarfs the recorder's interval while staying short
	// for interactive runs.
	defaultZombieWindow  = 8 * time.Second
	zombieSpawnBudget    = 2 * time.Second
	zombieObserveBudget  = 3 * time.Second
	zombieTeardownBudget = 3 * time.Second
)

// ZombieWorker kills its only helper child and deliberately does not wait for
// it. the kernel parks the dead child as a zombie until its parent (this
// runner) reaps it, and the platform capture reports a terminal wait status
// ("signal:9" on linux) exactly during that window. the scenario exists so the
// exit-status chain can be rehearsed end to end: a sampler that catches the
// zombie records PROCESS_EXITED with exit_state signal:9 instead of UNKNOWN.
//
// nothing leaks: the runner reaps the leaf at the end of the window (and
// reaps it even when the run is cancelled mid-window or the kill failed) so
// teardown leaves no zombie behind. the corpse occupies the process table
// only while the window is open.
type ZombieWorker struct {
	// grace is the leaf's run time before the SIGKILL.
	Grace time.Duration
	// window is how long the unwaited corpse stays unreaped.
	Window time.Duration
}

func init() { Register(&ZombieWorker{}) }

func (z *ZombieWorker) Name() string { return "zombie" }

func (z *ZombieWorker) Description() string {
	return "kill a helper child, leave the corpse unwaited while a capture can record its terminal status, then reap it"
}

func (z *ZombieWorker) RegisterFlags(fs *flag.FlagSet) {
	fs.DurationVar(&z.Grace, "grace", defaultZombieGrace, "leaf run time before the SIGKILL")
	fs.DurationVar(&z.Window, "window", defaultZombieWindow, "how long the unreaped corpse stays observable")
}

func (z *ZombieWorker) Run(ctx context.Context, cfg Config) error {
	grace := z.Grace
	if grace <= 0 {
		grace = defaultZombieGrace
	}
	window := z.Window
	if window <= 0 {
		window = defaultZombieWindow
	}
	cycle := zombieSpawnBudget + grace + window + zombieObserveBudget + time.Second
	deadline := cycle
	if cfg.Duration > 0 && cfg.Duration < deadline {
		deadline = cfg.Duration
	}
	runctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	start := time.Now()
	cfg.Emit("started", map[string]any{"runner_pid": os.Getpid(), "grace_ms": grace.Milliseconds(), "window_ms": window.Milliseconds()})
	cfg.Say(fmt.Sprintf("Runner PID: %d; grace=%s window=%s", os.Getpid(), grace, window))

	bin, err := SimBinary()
	if err != nil {
		return fmt.Errorf("locate sim binary: %w", err)
	}
	// the leaf parks through the whole cycle as its own safety net (it dies
	// again at hold if the runner itself is SIGKILLed and cannot reap). the
	// runner is the leaf's parent, so only the runner can reap it, and
	// during the window, nothing does.
	leafhold := grace + window + zombieObserveBudget + zombieTeardownBudget + 2*time.Second
	leaf, err := spawn(bin, HelperArgs("task", leafhold), "leaf", false)
	if err != nil {
		return err
	}
	leafpid := leaf.PID()
	cfg.Emit("leaf_spawned", map[string]any{"leaf_pid": leafpid})
	cfg.Say(fmt.Sprintf("Leaf PID: %d", leafpid))

	// exactly one reaper: done yields the wait result once and waitDone
	// remembers it, so cleanup never blocks on an already-consumed result.
	done := make(chan waitRes, 1)
	reapstarted := false
	reapleaf := func() {
		if reapstarted {
			return
		}
		reapstarted = true
		go func() {
			code, kind, err := reap(leaf.Cmd)
			done <- waitRes{code: code, kind: kind, err: err}
		}()
	}
	var got *waitRes
	waitdone := func() (waitRes, bool) {
		if got != nil {
			return *got, true
		}
		res, ok := doneOrTimeout(done, zombieTeardownBudget)
		if ok {
			got = &res
		}
		return res, ok
	}

	cleanup := func(reason string) error {
		if !reapstarted {
			// whatever state the leaf is in, teardown must not leave a corpse:
			// kill first (harmless if it already died), then wait. the wait is
			// what reaps the zombie and frees the PID if the window is open.
			_ = platform.SignalProcess(leafpid, syscall.SIGKILL)
			reapleaf()
		}
		if _, ok := waitdone(); !ok {
			return fmt.Errorf("leaf %d was not reaped during teardown", leafpid)
		}
		if p, ok, err := platform.Find(leafpid); err == nil && ok && !strings.HasPrefix(p.State, "Z") {
			return fmt.Errorf("leaf %d still visible in state %q after the reap", leafpid, p.State)
		}
		cfg.Emit("tree_cleaned", map[string]any{"leaf_pid": leafpid})
		if reason == "zombie_not_observed" {
			return fmt.Errorf("process scenario failed: leaf %d was killed but never observed as a zombie", leafpid)
		}
		if err := processScenarioFailure(reason); err != nil {
			return err
		}
		cfg.Emit("exited", map[string]any{"code": 0, "reason": reason, "uptime_ms": time.Since(start).Milliseconds()})
		cfg.Say("Reaped the corpse; Exit: 0")
		return nil
	}

	phase := zWaitGrace
	observedeadline := time.Time{}
	windowend := time.Time{}
	next := time.NewTimer(grace)
	defer next.Stop()
	for {
		select {
		case <-ctx.Done():
			return cleanup("interrupted")
		case <-runctx.Done():
			if ctx.Err() != nil {
				return cleanup("interrupted")
			}
			return cleanup("duration_elapsed")
		case res := <-done:
			got = &res
			// the leaf ended on its own before any kill was staged (only a
			// started reaper feeds this channel. a future corpse never
			// arrives here). the rehearsed cycle never happened.
			return cleanup(fmt.Sprintf("leaf_exited_early_%d", res.code))
		case <-next.C:
			switch phase {
			case zWaitGrace:
				if err := platform.SignalProcess(leafpid, syscall.SIGKILL); err != nil {
					return cleanup("leaf_pid_kill_failed")
				}
				cfg.Emit("leaf_killed", map[string]any{
					"leaf_pid": leafpid, "signal": "SIGKILL", "mode": "single_process", "unreaped": true,
				})
				cfg.Say(fmt.Sprintf("Killed leaf %d; corpse left unwaited for %s", leafpid, window))
				observedeadline = time.Now().Add(zombieObserveBudget)
				windowend = time.Now().Add(window)
				phase = zObserveZombie
				next.Reset(50 * time.Millisecond)
			case zObserveZombie:
				if p, ok, err := platform.Find(leafpid); err == nil && ok && strings.HasPrefix(p.State, "Z") {
					cfg.Emit("zombie_observed", map[string]any{
						"leaf_pid": leafpid, "state": p.State, "exit_status": p.ExitStatus,
					})
					cfg.Say("Unreaped corpse observed: a sampler that hits this window records how the process died")
					if rest := time.Until(windowend); rest > 0 {
						next.Reset(rest)
					} else {
						next.Reset(time.Millisecond)
					}
					phase = zHoldWindow
					continue
				}
				if time.Now().After(observedeadline) {
					return cleanup("zombie_not_observed")
				}
				next.Reset(50 * time.Millisecond)
			case zHoldWindow:
				// the window closed. now, and only now, reap: the kernel
				// replaces the zombie with an exit status and frees the PID.
				reapleaf()
				if _, ok := waitdone(); !ok {
					return cleanup("leaf_reap_timeout")
				}
				return cleanup("cycle_complete")
			}
		}
	}
}

type zombiePhase int

const (
	zWaitGrace zombiePhase = iota
	zObserveZombie
	zHoldWindow
)
