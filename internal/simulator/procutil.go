package simulator

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"runopsy/internal/platform"
)

// child is one process a scenario spawned, remembered so cleanup can be
// systematic: spawning scenarios keep child values rather than re-deriving
// who is alive at cleanup time. the helper package's real children may spawn
// more processes; a Child.Group=true spawn makes that subtree its own process
// group so a group kill can reach it without ever touching the runner.
type Child struct {
	Cmd *exec.Cmd
	// group: the child was started with setpgid, so PID == its PGID.
	Group bool
	// desc is a stable human label used in events and logs.
	Desc string
	// spec remembers the helper spec (for _node children).
	Spec string
}

func (c Child) PID() int { return c.Cmd.Process.Pid }

// alive reports whether the process is still in the snapshot.
func (c Child) Alive() bool { return platform.Alive(c.PID()) }

// spawn starts bin with args. group=true makes the child a process-group
// leader (setpgid); it must be true for any child whose subtree the scenario
// may group-kill later.
//
// output is deliberately discarded: helpers have nothing useful to say and an
// undrained pipe would deadlock a chatty helper.
func spawn(bin string, args []string, spec string, group bool) (Child, error) {
	cmd := exec.Command(bin, args...)
	if group {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		return Child{}, fmt.Errorf("spawn %s: %w", spec, err)
	}
	return Child{Cmd: cmd, Group: group, Spec: spec}, nil
}

// simBinaryOverride points scenarios at a specific sim binary instead of the
// running process. Non-empty only in tests, which build ./cmd/runopsy-sim and
// route spawn() through it.
var simBinaryOverride string

// SimBinary returns the binary scenarios should spawn helpers and workers of:
// this process, or the test-built override.
func SimBinary() (string, error) {
	if simBinaryOverride != "" {
		return simBinaryOverride, nil
	}
	return os.Executable()
}

// HelperArgs builds the argv for a _node helper spawned from the sim binary.
func HelperArgs(spec string, hold time.Duration) []string {
	return []string{"_node", "--spec", spec, "--hold", hold.String(), "--runner-pid", strconv.Itoa(os.Getpid())}
}

// reap calls cmd.Wait once and translates the wait status into
// (exit code, how the process ended, error). A signaled death maps to the
// shell convention 128+signal so recorded numbers match what a user's
// pipeline would report for the same kill.
func reap(cmd *exec.Cmd) (int, string, error) {
	err := cmd.Wait()
	if err == nil {
		return 0, "exited", nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if ok && ws.Signaled() {
			return 128 + int(ws.Signal()), "signal", nil
		}
		if ok && ws.Exited() {
			return ws.ExitStatus(), "exited", nil
		}
		return -1, "unknown", err
	}
	return -1, "unknown", err
}

// goneOrZombie polls the snapshot until pid is absent, treating a zombie as
// gone: the runner cannot waitpid a grandchild, so once a killed non-child is
// a zombie its reaping belongs to whoever adopted it (launchd/init), not to
// the scenario. used for cleanup bookkeeping on adopted processes.
func goneOrZombie(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		p, ok, err := platform.Find(pid)
		if err != nil {
			return false // unable to verify cleanup is not the same as gone
		}
		if !ok || strings.HasPrefix(p.State, "Z") {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// spawnGroupKill kills the group of a child that was spawned with group=true
// (so PGID == PID) and reports whether it was reached at all.
func spawnGroupKill(c Child, sig syscall.Signal) error {
	if !c.Group {
		return fmt.Errorf("%s was not spawned as a group leader", c.Spec)
	}
	return platform.KillGroup(c.PID(), sig)
}

// groupGoneOrZombie also verifies descendants that were spawned before the
// first tree snapshot, so cancellation during startup cannot claim cleanup
// based on an empty list of recorded children.
func groupGoneOrZombie(pgid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		all, err := platform.Processes()
		if err != nil {
			return false
		}
		alive := false
		for _, p := range all {
			if p.PGID == pgid && !strings.HasPrefix(p.State, "Z") {
				alive = true
				break
			}
		}
		if !alive {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func processScenarioFailure(reason string) error {
	switch reason {
	case "cycle_complete", "duration_elapsed", "interrupted":
		return nil
	default:
		return fmt.Errorf("process scenario failed: %s", reason)
	}
}
