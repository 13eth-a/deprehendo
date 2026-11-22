package simulator

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"runopsy/internal/platform"
)

const (
	defaultTreeSettle  = 1200 * time.Millisecond
	defaultTreeBetween = 600 * time.Millisecond
	treeObserveBudget  = 3 * time.Second
	treeVerifyBudget   = 2 * time.Second
	workerChildren     = 2
)

// ProcessTree creates two independent process-group branches. it kills the
// worker branch by PGID (worker and children die together), then kills only
// the helper root by PID (its children survive and are observed as orphans),
// and finally group-kills the helper branch to clean it up.
type ProcessTree struct {
	Settle  time.Duration // before the worker-branch group kill
	Between time.Duration // between the worker and helper branch kills
	Hold    time.Duration // leaf lifetime passed to the _node helpers
}

func init() { Register(&ProcessTree{}) }

func (p *ProcessTree) Name() string { return "process-tree" }

func (p *ProcessTree) Description() string {
	return "compare process-group kill with PID-only kill, observe surviving children, then clean the tree"
}

func (p *ProcessTree) RegisterFlags(fs *flag.FlagSet) {
	fs.DurationVar(&p.Settle, "settle", defaultTreeSettle, "runtime before the worker branch is group-killed")
	fs.DurationVar(&p.Between, "between", defaultTreeBetween, "runtime between branch kills")
	fs.DurationVar(&p.Hold, "hold", 30*time.Second, "leaf lifetime, long enough to outlive the kills")
}

func (p *ProcessTree) Run(ctx context.Context, cfg Config) error {
	settle := p.Settle
	if settle <= 0 {
		settle = defaultTreeSettle
	}
	between := p.Between
	if between <= 0 {
		between = defaultTreeBetween
	}
	hold := p.Hold
	if minhold := settle + between + 10*time.Second; hold < minhold {
		hold = minhold
	}

	cycle := treeObserveBudget + settle + between + treeVerifyBudget + 2*time.Second
	deadline := cycle
	if cfg.Duration > 0 && cfg.Duration < deadline {
		deadline = cfg.Duration
	}
	runctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	start := time.Now()
	cfg.Emit("started", map[string]any{
		"runner_pid": os.Getpid(), "settle_ms": settle.Milliseconds(), "between_ms": between.Milliseconds(),
	})
	cfg.Say(fmt.Sprintf("Process tree: settle=%s between=%s", settle, between))

	bin, err := SimBinary()
	if err != nil {
		return fmt.Errorf("locate sim binary: %w", err)
	}
	branchspec := workerSpec(workerChildren)
	worker, err := spawn(bin, HelperArgs(branchspec, hold), "worker", true)
	if err != nil {
		return err
	}
	helper, err := spawn(bin, HelperArgs(branchspec, hold), "helper", true)
	if err != nil {
		_ = spawnGroupKill(worker, syscall.SIGKILL)
		_, _, _ = reap(worker.Cmd)
		return err
	}
	wpid, hpid := worker.PID(), helper.PID()
	cfg.Emit("worker_spawned", map[string]any{"worker_pid": wpid, "spec": branchspec, "pgid": wpid})
	cfg.Emit("helper_spawned", map[string]any{"helper_pid": hpid, "spec": branchspec, "pgid": hpid})
	cfg.Say(fmt.Sprintf("Runner PID: %d", os.Getpid()))
	cfg.Say(fmt.Sprintf("Worker branch: PID %d (PGID %d)", wpid, wpid))
	cfg.Say(fmt.Sprintf("Helper branch: PID %d (PGID %d)", hpid, hpid))

	workerch := make(chan waitRes, 1)
	helperch := make(chan waitRes, 1)
	go func() {
		code, kind, err := reap(worker.Cmd)
		workerch <- waitRes{code: code, kind: kind, err: err}
	}()
	go func() {
		code, kind, err := reap(helper.Cmd)
		helperch <- waitRes{code: code, kind: kind, err: err}
	}()

	var workerResult, helperResult *waitRes
	waitworker := func(within time.Duration) (waitRes, bool) {
		if workerResult != nil {
			return *workerResult, true
		}
		select {
		case res := <-workerch:
			workerResult = &res
			return res, true
		case <-time.After(within):
			return waitRes{}, false
		}
	}
	waithelper := func(within time.Duration) (waitRes, bool) {
		if helperResult != nil {
			return *helperResult, true
		}
		select {
		case res := <-helperch:
			helperResult = &res
			return res, true
		case <-time.After(within):
			return waitRes{}, false
		}
	}

	var workerTaskPIDs, helperTaskPIDs []int
	cleanup := func(reason string) error {
		var cleanupErr error
		if err := spawnGroupKill(worker, syscall.SIGKILL); err != nil {
			cleanupErr = fmt.Errorf("kill worker group %d: %w", wpid, err)
		}
		if err := spawnGroupKill(helper, syscall.SIGKILL); err != nil && cleanupErr == nil {
			cleanupErr = fmt.Errorf("kill helper group %d: %w", hpid, err)
		}
		if res, ok := waitworker(2 * time.Second); ok {
			cleanupErr = errors.Join(cleanupErr, res.err)
			cfg.Emit("worker_reaped", map[string]any{"worker_pid": wpid, "exit_code": res.code, "exit_kind": res.kind})
		} else if cleanupErr == nil {
			cleanupErr = fmt.Errorf("worker %d was not reaped after SIGKILL", wpid)
		}
		if res, ok := waithelper(2 * time.Second); ok {
			cleanupErr = errors.Join(cleanupErr, res.err)
			cfg.Emit("helper_reaped", map[string]any{"helper_pid": hpid, "exit_code": res.code, "exit_kind": res.kind})
		} else if cleanupErr == nil {
			cleanupErr = fmt.Errorf("helper %d was not reaped after SIGKILL", hpid)
		}

		alltasks := append(append([]int(nil), workerTaskPIDs...), helperTaskPIDs...)
		missed := 0
		for _, pid := range alltasks {
			if !goneOrZombie(pid, treeVerifyBudget) {
				missed++
			}
		}
		cfg.Emit("tree_cleaned", map[string]any{"targeted": alltasks, "still_alive": missed})
		if missed > 0 && cleanupErr == nil {
			cleanupErr = fmt.Errorf("%d process-tree task(s) remain alive after group cleanup", missed)
		}
		for _, pgid := range []int{wpid, hpid} {
			if !groupGoneOrZombie(pgid, treeVerifyBudget) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("process group %d still alive or cleanup could not be verified", pgid))
			}
		}
		if cleanupErr != nil {
			cfg.Emit("cleanup_incomplete", map[string]any{"detail": cleanupErr.Error()})
			return cleanupErr
		}
		if err := processScenarioFailure(reason); err != nil {
			return err
		}
		cfg.Emit("exited", map[string]any{"code": 0, "reason": reason, "uptime_ms": time.Since(start).Milliseconds()})
		cfg.Say("Whole tree verified gone; Exit: 0")
		return nil
	}

	phase := observeTree
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
		case res := <-workerch:
			workerResult = &res
			cfg.Emit("worker_exited_early", map[string]any{"worker_pid": wpid, "exit_code": res.code, "exit_kind": res.kind})
			return cleanup("worker_exited_early")
		case res := <-helperch:
			helperResult = &res
			cfg.Emit("helper_exited_early", map[string]any{"helper_pid": hpid, "exit_code": res.code, "exit_kind": res.kind})
			return cleanup("helper_exited_early")
		case <-next.C:
			switch phase {
			case observeTree:
				workerkids, werr := platform.Children(wpid)
				helperkids, herr := platform.Children(hpid)
				if werr == nil && herr == nil && len(workerkids) >= workerChildren && len(helperkids) >= workerChildren {
					workerTaskPIDs = childPIDs(workerkids[:workerChildren])
					helperTaskPIDs = childPIDs(helperkids[:workerChildren])
					cfg.Emit("tree_recorded", map[string]any{
						"worker_pid": wpid, "worker_pgid": wpid, "worker_task_pids": workerTaskPIDs,
						"helper_pid": hpid, "helper_pgid": hpid, "helper_task_pids": helperTaskPIDs,
					})
					cfg.Say(fmt.Sprintf("Tree recorded: worker %d -> %v; helper %d -> %v", wpid, workerTaskPIDs, hpid, helperTaskPIDs))
					phase = killWorkerBranch
					phasestarted = time.Now()
					next.Reset(settle)
					continue
				}
				if time.Since(phasestarted) >= treeObserveBudget {
					return cleanup("tree_observation_timeout")
				}
				next.Reset(50 * time.Millisecond)
			case killWorkerBranch:
				if err := platform.KillGroup(wpid, syscall.SIGKILL); err != nil {
					return cleanup("worker_group_kill_failed")
				}
				cfg.Emit("branch_killed", map[string]any{"branch": "worker", "mode": "process_group", "target_pid": wpid, "pgid": wpid})
				if res, ok := waitworker(2 * time.Second); ok {
					cfg.Emit("worker_reaped", map[string]any{"worker_pid": wpid, "exit_code": res.code, "exit_kind": res.kind})
				} else {
					return cleanup("worker_reap_timeout")
				}
				gone := countGone(workerTaskPIDs, treeVerifyBudget)
				cfg.Emit("branch_survey", map[string]any{
					"branch": "worker", "mode": "process_group", "tasks_gone": gone,
					"task_count": len(workerTaskPIDs), "helper_alive": platform.Alive(hpid),
				})
				if gone != len(workerTaskPIDs) || !platform.Alive(hpid) {
					return cleanup("worker_branch_survey_failed")
				}
				phase = killHelperPID
				phasestarted = time.Now()
				next.Reset(between)
			case killHelperPID:
				if err := platform.SignalProcess(hpid, syscall.SIGKILL); err != nil {
					return cleanup("helper_pid_kill_failed")
				}
				cfg.Emit("branch_killed", map[string]any{"branch": "helper", "mode": "single_process", "target_pid": hpid})
				if res, ok := waithelper(2 * time.Second); ok {
					cfg.Emit("helper_reaped", map[string]any{"helper_pid": hpid, "exit_code": res.code, "exit_kind": res.kind})
				} else {
					return cleanup("helper_reap_timeout")
				}
				alive, reparented := countAliveAndReparented(helperTaskPIDs, hpid)
				cfg.Emit("branch_survey", map[string]any{
					"branch": "helper", "mode": "single_process", "tasks_alive": alive,
					"task_count": len(helperTaskPIDs), "tasks_reparented": reparented,
				})
				if alive != len(helperTaskPIDs) || reparented != len(helperTaskPIDs) {
					return cleanup("helper_orphan_survey_failed")
				}
				phase = finalSweep
				next.Reset(50 * time.Millisecond)
			case finalSweep:
				return cleanup("cycle_complete")
			}
		}
	}
}

func childPIDs(children []platform.Process) []int {
	pids := make([]int, len(children))
	for i, child := range children {
		pids[i] = child.PID
	}
	return pids
}

func countGone(pids []int, timeout time.Duration) int {
	gone := 0
	for _, pid := range pids {
		if goneOrZombie(pid, timeout) {
			gone++
		}
	}
	return gone
}

func countAliveAndReparented(pids []int, oldParent int) (alive, reparented int) {
	for _, pid := range pids {
		p, ok, err := platform.Find(pid)
		if err == nil && ok && !strings.HasPrefix(p.State, "Z") {
			alive++
			if p.PPID != oldParent {
				reparented++
			}
		}
	}
	return alive, reparented
}

type treePhase int

const (
	observeTree treePhase = iota
	killWorkerBranch
	killHelperPID
	finalSweep
)
