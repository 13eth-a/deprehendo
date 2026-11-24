package simulator

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/platform"
)

const (
	defaultOrphanTasks   = 2
	defaultOrphanGrace   = time.Second
	orphanObserveBudget  = 3 * time.Second
	orphanTeardownBudget = 3 * time.Second
)

type OrphanProcess struct {
	Tasks int
	Grace time.Duration
	Hold  time.Duration
}

func init()                           { Register(&OrphanProcess{}) }
func (o *OrphanProcess) Name() string { return "orphan-process" }
func (o *OrphanProcess) Description() string {
	return "runner -> worker -> tasks: kill only the worker, observe surviving orphans, then clean them up"
}
func (o *OrphanProcess) RegisterFlags(fs *flag.FlagSet) {
	fs.IntVar(&o.Tasks, "tasks", defaultOrphanTasks, "task children spawned by the worker (1..8)")
	fs.DurationVar(&o.Grace, "grace", defaultOrphanGrace, "runtime between observing the tree and killing the worker")
	fs.DurationVar(&o.Hold, "hold", 30*time.Second, "leaf lifetime, long enough to outlive the worker")
}

func workerSpec(tasks int) string {
	return "w(" + strings.TrimSuffix(strings.Repeat("task,", tasks), ",") + ")"
}

func (o *OrphanProcess) Run(ctx context.Context, cfg Config) error {
	tasks := o.Tasks
	if tasks == 0 {
		tasks = defaultOrphanTasks
	}
	if tasks < 1 || tasks > 8 {
		return fmt.Errorf("--tasks must be 1..8, got %d", tasks)
	}
	grace := o.Grace
	if grace <= 0 {
		grace = defaultOrphanGrace
	}
	hold := o.Hold
	if hold < grace+10*time.Second {
		hold = grace + 10*time.Second
	}
	spec := workerSpec(tasks)
	cycle := orphanObserveBudget + grace + orphanTeardownBudget + time.Second
	deadline := cycle
	if cfg.Duration > 0 && cfg.Duration < deadline {
		deadline = cfg.Duration
	}
	runctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	start := time.Now()
	workerpid := 0
	cfg.Emit("started", map[string]any{"runner_pid": os.Getpid(), "tasks": tasks, "grace_ms": grace.Milliseconds()})
	cfg.Say(fmt.Sprintf("Runner PID: %d; tasks=%d grace=%s hold=%s", os.Getpid(), tasks, grace, hold))

	bin, err := SimBinary()
	if err != nil {
		return fmt.Errorf("locate sim binary: %w", err)
	}
	worker, err := spawn(bin, HelperArgs(spec, hold), "worker", true)
	if err != nil {
		return err
	}
	workerpid = worker.PID()
	cfg.Emit("worker_spawned", map[string]any{"worker_pid": workerpid, "spec": spec, "pgid": workerpid})
	cfg.Say(fmt.Sprintf("Worker PID: %d", workerpid))

	waitch := make(chan waitRes, 1)
	go func() {
		code, kind, err := reap(worker.Cmd)
		waitch <- waitRes{code: code, kind: kind, err: err}
	}()
	var workerResult *waitRes
	workerreapedevent := false
	waitworker := func(wait time.Duration) (waitRes, bool) {
		if workerResult != nil {
			return *workerResult, true
		}
		select {
		case res := <-waitch:
			workerResult = &res
			return res, true
		case <-time.After(wait):
			return waitRes{}, false
		}
	}

	var taskPIDs []int
	cleanup := func(reason string) error {
		// kill the group, not merely the worker PID: its tasks have been
		// deliberately orphaned and still share the worker's PGID.
		if err := spawnGroupKill(worker, syscall.SIGKILL); err != nil {
			return fmt.Errorf("kill orphan process group %d: %w", workerpid, err)
		}
		if res, ok := waitworker(2 * time.Second); ok {
			if res.err != nil {
				return res.err
			}
			if !workerreapedevent {
				cfg.Emit("worker_reaped", map[string]any{"worker_pid": workerpid, "exit_code": res.code, "exit_kind": res.kind})
				workerreapedevent = true
			}
		} else {
			return fmt.Errorf("worker %d was not reaped after SIGKILL", workerpid)
		}
		missed := 0
		for _, pid := range taskPIDs {
			if !goneOrZombie(pid, orphanTeardownBudget) {
				missed++
			}
		}
		cfg.Emit("tree_cleaned", map[string]any{"targeted": taskPIDs, "still_alive": missed})
		if !groupGoneOrZombie(workerpid, orphanTeardownBudget) {
			return fmt.Errorf("orphan group %d still alive or cleanup could not be verified", workerpid)
		}
		if missed != 0 {
			return fmt.Errorf("%d orphan process(es) still alive after group cleanup", missed)
		}
		if err := processScenarioFailure(reason); err != nil {
			return err
		}
		cfg.Emit("exited", map[string]any{"code": 0, "reason": reason, "uptime_ms": time.Since(start).Milliseconds()})
		cfg.Say("Cleaned up orphan processes; Exit: 0")
		return nil
	}

	phase := observeChildren
	phasestarted := time.Now()
	next := time.NewTimer(50 * time.Millisecond)
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
		case res := <-waitch:
			workerResult = &res
			cfg.Emit("worker_exited_early", map[string]any{"worker_pid": workerpid, "exit_code": res.code, "exit_kind": res.kind})
			return cleanup("worker_exited_early")
		case <-next.C:
			switch phase {
			case observeChildren:
				kids, err := platform.Children(workerpid)
				if err != nil || len(kids) < tasks {
					if time.Since(phasestarted) > orphanObserveBudget {
						return cleanup("tree_observation_timeout")
					}
					next.Reset(50 * time.Millisecond)
					continue
				}
				kids = kids[:tasks]
				taskPIDs = childPIDs(kids)
				cfg.Emit("tree_recorded", map[string]any{"worker_pid": workerpid, "worker_pgid": workerpid, "task_pids": taskPIDs})
				cfg.Say(fmt.Sprintf("Observed worker %d -> tasks %v", workerpid, taskPIDs))
				phase = killWorker
				next.Reset(grace)
			case killWorker:
				// PID-only kill intentionally leaves the descendants alive.
				if err := platform.SignalProcess(workerpid, syscall.SIGKILL); err != nil {
					return cleanup("worker_pid_kill_failed")
				}
				cfg.Emit("worker_killed", map[string]any{"worker_pid": workerpid, "signal": "SIGKILL", "mode": "single_process"})
				if res, ok := waitworker(2 * time.Second); ok {
					cfg.Emit("worker_reaped", map[string]any{"worker_pid": workerpid, "exit_code": res.code, "exit_kind": res.kind})
					workerreapedevent = true
				} else {
					return cleanup("worker_reap_timeout")
				}
				// give the kernel a moment to reparent surviving tasks.
				time.Sleep(100 * time.Millisecond)
				alive, reparented := 0, 0
				for _, pid := range taskPIDs {
					p, ok, err := platform.Find(pid)
					if err != nil || !ok || strings.HasPrefix(p.State, "Z") {
						cfg.Emit("orphan_report", map[string]any{"task_pid": pid, "alive": false, "observed": false})
						continue
					}
					alive++
					if p.PPID != workerpid {
						reparented++
					}
					cfg.Emit("orphan_report", map[string]any{
						"task_pid": pid, "ppid_before": workerpid, "ppid_after": p.PPID,
						"pgid": p.PGID, "state": p.State, "alive": true, "observed": true,
					})
				}
				cfg.Emit("orphan_summary", map[string]any{"tasks_alive": alive, "task_count": len(taskPIDs), "tasks_reparented": reparented})
				cfg.Say(fmt.Sprintf("After worker PID kill: %d/%d tasks alive, %d reparented", alive, len(taskPIDs), reparented))
				if alive != tasks || reparented != tasks {
					return cleanup("orphan_observation_failed")
				}
				return cleanup("cycle_complete")
			}
		}
	}
}

type orphanPhase int

const (
	observeChildren orphanPhase = iota
	killWorker
)
