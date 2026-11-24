package simhelper

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/platform"
)

// A stopped worker cannot run its own lifetime checks. this independent
// helper stays runnable and kills its group if the runner dies, even while
// the worker is stopped. the hold deadline also bounds observation failures.
func runGuard(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pid := fs.Int("pid", 0, "worker process group leader")
	runner := fs.Int("runner-pid", 0, "runner to watch")
	hold := fs.Duration("hold", 30*time.Second, "maximum guard lifetime")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *pid <= 0 || *runner <= 0 || *hold <= 0 || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "_guard: positive --pid, --runner-pid and --hold required, with no positional arguments")
		return 2
	}
	deadline := time.NewTimer(*hold)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	kill := func() int {
		if err := platform.KillGroup(*pid, syscall.SIGKILL); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	for {
		select {
		case <-deadline.C:
			return kill()
		case <-ticker.C:
			if definitelyExited(*pid) {
				return 0
			}
			if definitelyExited(*runner) {
				return kill()
			}
		}
	}
}

// kill(pid, 0) succeeds for zombies, including an unreaped killed runner.
// snapshot failures are not evidence of death.
func definitelyExited(pid int) bool {
	p, ok, err := platform.Find(pid)
	return err == nil && (!ok || strings.HasPrefix(p.State, "Z"))
}
