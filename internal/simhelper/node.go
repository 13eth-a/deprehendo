// package simhelper implements the hidden helper processes that scenarios use
// to build real process trees (orphan-process, process-tree). helpers are
// named with a leading underscore so deprehendo-sim --help never advertises them;
// only scenarios and tests launch them.
package simhelper

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/platform"
)

// usageText is written for bad invocations of hidden helpers.
const usageText = "Usage:\n  deprehendo-sim _node --spec <spec> --hold <dur>\n\nSpecs:\n  task            leaf process that stays alive for --hold, then exits 0\n  w(a,b,...)      node that spawns each child spec, waits, exits 0\n\nHelpers are internal: scenarios pid-listen rather than talk to them.\n"

// run dispatches one hidden helper invocation. args excludes the binary name.
func Run(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "_node":
		return runNode(args[1:], stderr)
	case "_cont":
		return runCont(args[1:], stderr)
	case "_guard":
		return runGuard(args[1:], stderr)
	}
	if IsGitHubHelper(args) {
		return RunGitHub(args, stderr)
	}
	switch args[0] {
	default:
		fmt.Fprintf(stderr, "simhelper: unknown helper %q\n%s", args[0], usageText)
		return 2
	}
}

func runNode(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_node", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		spec      string
		hold      time.Duration
		runnerPID int
	)
	fs.StringVar(&spec, "spec", "task", "task | w(<spec>,<spec>) process layout to materialize")
	fs.DurationVar(&hold, "hold", 30*time.Second, "leaf lifetime before exiting 0 on its own")
	fs.IntVar(&runnerPID, "runner-pid", 0, "runner PID whose lifetime bounds this helper subtree")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "_node: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	root, err := parseSpec(spec)
	if err != nil {
		fmt.Fprintf(stderr, "_node: bad --spec: %v\n", err)
		return 2
	}
	if runnerPID <= 0 {
		fmt.Fprintln(stderr, "_node: --runner-pid must be positive")
		return 2
	}
	return materialize(root, hold, runnerPID)
}

// materialize turns the parsed spec into real processes. A leaf parks for hold;
// a worker spawns every child spec, waits for them, and exits. contract with
// the runner scenarios:
//
//   - a leaf is *not* cancellable by its parent except through signals; the
//     runner scenario is expected to kill by process or process group.
//   - a worker does not shield its children: kill the worker and the children
//     survive as orphans with their thread id unchanged, which is exactly what
//     orphan-process and process-tree demonstrate.
func materialize(node *specNode, hold time.Duration, runnerPID int) int {
	// give the worker node itself a bounded self-exit so a blamed scenario
	// cannot leak this helper indefinitely: if the runner never kills us, the
	// leaf dies at hold and the worker exits right after.
	if node.leaf {
		return holdUntilRunnerOrTimeout(runnerPID, hold)
	}
	bin, err := os.Executable()
	if err != nil {
		return 1
	}
	children := make([]*exec.Cmd, 0, len(node.children))
	for _, child := range node.children {
		cmd := exec.Command(bin, "_node", "--spec", child.spec, "--hold", hold.String(), "--runner-pid", strconv.Itoa(runnerPID))
		if err := cmd.Start(); err != nil {
			for _, started := range children {
				_ = started.Process.Kill()
			}
			for _, started := range children {
				_ = started.Wait()
			}
			return 1
		}
		children = append(children, cmd)
	}
	code := 0
	for _, cmd := range children {
		if err := cmd.Wait(); err != nil {
			code = 1
		}
	}
	return code
}

// holdUntilRunnerOrTimeout bounds orphan lifetime even if the scenario runner
// is SIGKILLed. the original runner PID remains available after reparenting, so
// kill(pid, 0) no longer succeeds once that process has exited. the timeout is
// still the final safety net if the OS cannot provide a process query.
func holdUntilRunnerOrTimeout(runnerPID int, hold time.Duration) int {
	deadline := time.NewTimer(hold)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			return 0
		case <-ticker.C:
			if !processAlive(runnerPID) {
				return 0
			}
		}
	}
}

// runCont is the STOP-resume helper: sleep, then SIGCONT the named pid, then
// exit. it must be a separate process because a SIGSTOPed target cannot resume
// itself; the watcher keeps running while (or after) the target is frozen.
func runCont(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_cont", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		pid       int
		runnerPID int
		after     time.Duration
	)
	fs.IntVar(&pid, "pid", 0, "process to SIGCONT")
	fs.IntVar(&runnerPID, "runner-pid", 0, "runner whose lifetime bounds this watcher")
	fs.DurationVar(&after, "after", time.Second, "delay before the SIGCONT")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if pid <= 0 {
		fmt.Fprintln(stderr, "_cont: --pid must be positive")
		return 2
	}
	// do not start the delay until STOP is a kernel-observed fact: SIGCONT
	// delivered before SIGSTOP is lost, leaving the runner frozen forever.
	observedeadline := time.Now().Add(10 * time.Second)
	for {
		if !processAlive(pid) || (runnerPID > 0 && !processAlive(runnerPID)) {
			return 0
		}
		p, found, err := platform.Find(pid)
		if err == nil && found && strings.HasPrefix(p.State, "T") {
			break
		}
		if time.Now().After(observedeadline) {
			// A final CONT bounds residue if process observation failed.
			_ = syscall.Kill(pid, syscall.SIGCONT)
			fmt.Fprintln(stderr, "_cont: target did not become observably stopped")
			return 1
		}
		time.Sleep(10 * time.Millisecond)
	}
	deadline := time.NewTimer(after)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
				fmt.Fprintf(stderr, "_cont: SIGCONT %d: %v\n", pid, err)
				return 1
			}
			return 0
		case <-ticker.C:
			if runnerPID > 0 && !processAlive(runnerPID) {
				return 0
			}
		}
	}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return (err == nil || errors.Is(err, syscall.EPERM)) && !definitelyExited(pid)
}

// specNode is one node of a parsed --spec tree.
type specNode struct {
	leaf     bool
	spec     string
	children []*specNode
}

// parseSpec accepts "task" or "w(<spec>,<spec>)" recursively, so both this
// package and its callers produce the same canonical strings.
func parseSpec(s string) (*specNode, error) {
	s = strings.TrimSpace(s)
	if s == "task" {
		return &specNode{leaf: true, spec: s}, nil
	}
	if strings.HasPrefix(s, "w(") && strings.HasSuffix(s, ")") {
		inner := s[2 : len(s)-1]
		parts, err := splitTopLevel(inner)
		if err != nil {
			return nil, err
		}
		if len(parts) == 0 {
			return nil, fmt.Errorf("w() needs at least one child")
		}
		node := &specNode{spec: s}
		for _, part := range parts {
			child, err := parseSpec(part)
			if err != nil {
				return nil, err
			}
			node.children = append(node.children, child)
		}
		return node, nil
	}
	return nil, fmt.Errorf("unsupported spec %q", s)
}

// splitTopLevel splits on commas that are not inside a nested w(...).
func splitTopLevel(s string) ([]string, error) {
	var (
		out   []string
		depth int
		start int
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
		if depth < 0 {
			return nil, fmt.Errorf("unbalanced parentheses in %q", s)
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced parentheses in %q", s)
	}
	out = append(out, s[start:])
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out, nil
}
