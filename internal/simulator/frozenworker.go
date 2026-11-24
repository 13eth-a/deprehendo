package simulator

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/platform"
)

// default frozen-worker phase timings. the whole cycle is short so a bare
// `deprehendo-sim frozen-worker` terminates quickly while still containing a real
// freeze -> observe window.
const (
	defaultFreezeAfter = 1500 * time.Millisecond
	defaultFreezeFor   = 2000 * time.Millisecond
	defaultGrace       = 1000 * time.Millisecond

	// observeTick is how often the runner snapshots the worker's ps state.
	observeTick = 100 * time.Millisecond

	// workerTail is headroom added to the worker's own runtime so the runner,
	// not the worker, always decides when the cycle ends.
	workerTail = 5 * time.Second

	// noResumeSettle is a short pause between the freeze and the kill when
	// --no-resume is set, so both observations are visible in the stream.
	noResumeSettle = 300 * time.Millisecond

	// phaseSlack extends the run-limit slightly past the phase total so that,
	// when everything is healthy, the final phase timer wins the select race
	// and the exit reason is truthful (cycle_complete, not duration_elapsed).
	// it is also the budget for cleanup if a phase never fires.
	phaseSlack = 2 * time.Second
)

// FrozenWorker is the first scenario with real OS untidiness: a runner and a
// worker where the worker is suspended (SIGSTOP), observed in the process
// table, then resumed (SIGCONT) and killed (SIGKILL) while the runner keeps
// going. it exercises the "worker stopped accepting work but never exited"
// signature.
type FrozenWorker struct {
	FreezeAfter time.Duration // run normally this long, then SIGSTOP
	FreezeFor   time.Duration // stay stopped this long
	Grace       time.Duration // after the resume, run this long before the kill
	NoResume    bool          // skip SIGCONT: go straight from frozen to killed
}

func init() { Register(&FrozenWorker{}) }

func (f *FrozenWorker) Name() string { return "frozen-worker" }

func (f *FrozenWorker) Description() string {
	return "runner/worker pair: worker is SIGSTOPed, observed, then resumed and killed"
}

func (f *FrozenWorker) RegisterFlags(fs *flag.FlagSet) {
	fs.DurationVar(&f.FreezeAfter, "freeze-after", defaultFreezeAfter, "runtime before the worker is SIGSTOPed")
	fs.DurationVar(&f.FreezeFor, "freeze-for", defaultFreezeFor, "how long the worker stays stopped")
	fs.DurationVar(&f.Grace, "grace", defaultGrace, "runtime between the resume and the kill")
	fs.BoolVar(&f.NoResume, "no-resume", false, "skip SIGCONT: go straight from frozen to killed")
}

type waitRes struct {
	code int
	kind string // "exited" | "signal" | "unknown"
	err  error
}

// phases returns the effective freeze-after / freeze-for / grace windows. A
// --duration shorter than the total scales the phases down proportionally, so
// tests and quick manual runs get the same relative shape in less time.
func (f *FrozenWorker) phases(cfgDur time.Duration) (time.Duration, time.Duration, time.Duration) {
	fa, ff, g := f.FreezeAfter, f.FreezeFor, f.Grace
	if fa <= 0 {
		fa = defaultFreezeAfter
	}
	if ff <= 0 {
		ff = defaultFreezeFor
	}
	if g <= 0 {
		g = defaultGrace
	}
	if f.NoResume {
		g = 0 // nothing to resume, no grace window
	}
	total := fa + ff + g
	if cfgDur > 0 && cfgDur < total {
		k := float64(cfgDur) / float64(total)
		fa = stretch(fa, k)
		ff = stretch(ff, k)
		if g > 0 {
			g = stretch(g, k)
		}
	}
	return fa, ff, g
}

func stretch(d time.Duration, k float64) time.Duration {
	return max(50*time.Millisecond, time.Duration(float64(d)*k))
}

// psStateKind buckets a raw ps state string.
func psStateKind(state string) string {
	switch {
	case strings.HasPrefix(state, "T"):
		return "stopped"
	case strings.HasPrefix(state, "Z"):
		return "zombie"
	case strings.HasPrefix(state, "R"):
		return "running"
	default:
		return "alive"
	}
}

func (f *FrozenWorker) Run(ctx context.Context, cfg Config) (retErr error) {
	fa, ff, g := f.phases(cfg.Duration)
	total := fa + ff + g

	start := time.Now()
	cfg.Emit("started", map[string]any{
		"runner_pid":      os.Getpid(),
		"freeze_after_ms": fa.Milliseconds(),
		"freeze_for_ms":   ff.Milliseconds(),
		"grace_ms":        g.Milliseconds(),
	})
	cfg.Say(fmt.Sprintf("Freeze after %s, frozen for %s, grace %s", fa, ff, g))

	budget := total + phaseSlack
	if cfg.Duration > 0 && cfg.Duration < budget {
		budget = cfg.Duration
	}
	runctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	bin, err := SimBinary()
	if err != nil {
		return fmt.Errorf("locate sim binary: %w", err)
	}
	worker, err := spawn(bin, HelperArgs("task", total+workerTail), "worker", true)
	if err != nil {
		return err
	}
	wpid := worker.PID()
	cfg.Emit("worker_spawned", map[string]any{"worker_pid": wpid, "spec": "task", "group": true})
	cfg.Say(fmt.Sprintf("Worker PID: %d", wpid))

	waitch := make(chan waitRes, 1)
	go func() {
		code, kind, werr := reap(worker.Cmd)
		waitch <- waitRes{code: code, kind: kind, err: werr}
	}()

	// every return after spawning owns teardown, including failed signals.
	workerreaped := false
	defer func() {
		if workerreaped {
			return
		}
		retErr = errors.Join(retErr, spawnGroupKill(worker, syscall.SIGKILL))
		select {
		case res := <-waitch:
			retErr = errors.Join(retErr, res.err)
		case <-time.After(3 * time.Second):
			retErr = errors.Join(retErr, fmt.Errorf("worker %d did not exit during final cleanup", wpid))
		}
	}()
	guard, err := spawn(bin, []string{"_guard", "--pid", strconv.Itoa(wpid), "--runner-pid", strconv.Itoa(os.Getpid()), "--hold", (total + workerTail + phaseSlack).String()}, "worker guard", true)
	if err != nil {
		return err
	}
	cfg.Emit("worker_guard_spawned", map[string]any{"worker_pid": wpid, "guard_pid": guard.PID()})
	defer func() {
		retErr = errors.Join(retErr, spawnGroupKill(guard, syscall.SIGKILL))
		_, _, err := reap(guard.Cmd)
		retErr = errors.Join(retErr, err)
	}()

	laststate := ""
	observe := func() {
		p, ok, err := platform.Find(wpid)
		if err != nil || !ok {
			return
		}
		if p.State == laststate {
			return
		}
		laststate = p.State
		cfg.Emit("worker_state", map[string]any{"worker_pid": wpid, "state": p.State, "kind": psStateKind(p.State)})
		if cfg.Verbose {
			cfg.Say(fmt.Sprintf("Worker state: %s (%s)", p.State, psStateKind(p.State)))
		}
	}

	cleanup := func(reason string) error {
		// A stopped process still dies to SIGKILL, but SIGCONT first so the
		// kill is unambiguous on every OS.
		if laststate != "" {
			_ = platform.SignalProcess(wpid, syscall.SIGCONT)
		}
		if err := spawnGroupKill(worker, syscall.SIGKILL); err != nil {
			return fmt.Errorf("kill worker group %d during cleanup: %w", wpid, err)
		}
		select {
		case res := <-waitch:
			workerreaped = true
			if res.err != nil {
				return res.err
			}
			cfg.Emit("worker_killed", map[string]any{
				"worker_pid": wpid, "exit_code": res.code, "exit_kind": res.kind,
			})
		case <-time.After(3 * time.Second):
			return fmt.Errorf("worker %d did not exit after SIGKILL", wpid)
		}
		cfg.Emit("exited", map[string]any{
			"code":      0,
			"reason":    reason,
			"uptime_ms": time.Since(start).Milliseconds(),
		})
		cfg.Say("Exit: 0")
		// keep the stopped-state observation available through the trigger's
		// post window. otherwise the simulator's immediate teardown can produce
		// another stopped->missing edge while the first capture is still active.
		// that second edge is a separate factual trigger but would collide with
		// the one-active-incident policy and obscure the intended freeze demo.
		return nil
	}

	finishearly := func(reason string) error {
		return processScenarioFailure(reason)
	}

	observe()

	stopped, resumed := false, false
	next := time.NewTimer(fa)
	defer next.Stop()
	tick := time.NewTicker(observeTick)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			observe()
			return cleanup("interrupted")
		case <-runctx.Done():
			observe()
			// A parent cancellation also fires the derived runCtx.
			if ctx.Err() != nil {
				return cleanup("interrupted")
			}
			return cleanup("duration_elapsed")
		case res := <-waitch:
			workerreaped = true
			if res.err != nil {
				return res.err
			}
			// the worker died before the runner acted on it. the reap channel
			// has already been consumed, so cleanup must not try to wait twice.
			cfg.Emit("worker_exited_early", map[string]any{
				"worker_pid": wpid, "exit_code": res.code, "exit_kind": res.kind,
				"stopped": stopped, "resumed": resumed,
			})
			return finishearly("worker_exited_early")
		case <-next.C:
			switch {
			case !stopped:
				stopped = true
				if err := platform.SignalProcess(wpid, syscall.SIGSTOP); err != nil {
					return fmt.Errorf("SIGSTOP worker %d: %w", wpid, err)
				}
				observe() // catch the T state close to the event
				cfg.Emit("worker_frozen", map[string]any{"worker_pid": wpid, "signal": "SIGSTOP"})
				cfg.Say(fmt.Sprintf("Freezing worker %d", wpid))
				if f.NoResume {
					next.Reset(noResumeSettle)
				} else {
					next.Reset(ff)
				}
			case stopped && !resumed && !f.NoResume:
				resumed = true
				if err := platform.SignalProcess(wpid, syscall.SIGCONT); err != nil {
					return fmt.Errorf("SIGCONT worker %d: %w", wpid, err)
				}
				cfg.Emit("worker_resumed", map[string]any{"worker_pid": wpid, "signal": "SIGCONT"})
				cfg.Say(fmt.Sprintf("Resuming worker %d", wpid))
				next.Reset(g)
			default:
				observe()
				return cleanup("cycle_complete")
			}
		case <-tick.C:
			observe()
		}
	}
}
