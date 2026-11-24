package simulator

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// exitCodeError is returned by scenarios that choose their own process exit
// code (e.g. the exit scenario). the CLI turns it into the process exit code
// instead of printing a failure.
type exitCodeError struct{ Code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("scenario exit code %d", e.Code) }

// ExitScenario ends the process with a caller-chosen code. it exists so the
// rest of deprehendo (and the future phase 1 recorder) can rehearse arbitrary
// termination outcomes, including the signal-shaped 128+N codes.
type ExitScenario struct {
	Code int
	Hold time.Duration
}

func init() { Register(&ExitScenario{}) }

func (e *ExitScenario) Name() string { return "exit" }

func (e *ExitScenario) Description() string {
	return "exit with a chosen code, e.g. --code 137 (128+N signal convention optional)"
}

func (e *ExitScenario) RegisterFlags(fs *flag.FlagSet) {
	fs.IntVar(&e.Code, "code", 0, "process exit code (0..255)")
	fs.DurationVar(&e.Hold, "hold", 0, "runtime before exiting; 0 means immediately")
}

func (e *ExitScenario) Run(ctx context.Context, cfg Config) error {
	if e.Code < 0 || e.Code > 255 {
		return fmt.Errorf("--code must be 0..255, got %d", e.Code)
	}
	hold := e.Hold
	if cfg.Duration > 0 {
		hold = cfg.Duration
	} else if hold <= 0 {
		hold = 200 * time.Millisecond // enough for the started event to flush
	}
	start := time.Now()

	pid := os.Getpid()
	cfg.Emit("started", map[string]any{"pid": pid, "code": e.Code, "hold_ms": hold.Milliseconds()})
	cfg.Say(fmt.Sprintf("PID: %d", pid))
	cfg.Say(fmt.Sprintf("Exiting with code %d after %s", e.Code, hold))

	select {
	case <-ctx.Done():
		cfg.Emit("exited", map[string]any{
			"code":      0,
			"reason":    "interrupted",
			"uptime_ms": time.Since(start).Milliseconds(),
		})
		return nil
	case <-time.After(hold):
	}

	cfg.Emit("exited", map[string]any{"code": e.Code, "reason": "exit_code_requested"})
	return exitCodeError{Code: e.Code}
}

// signalName resolves symbolic names and numeric forms of the five signals
// this scenario models. STOP and CONT numbers are OS-specific, so compare to
// the runtime syscall constants rather than hard-coding linux values.
func signalName(s string) (string, syscall.Signal, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "term", "terminate":
		return "TERM", syscall.SIGTERM, nil
	case "int", "interrupt":
		return "INT", syscall.SIGINT, nil
	case "kill":
		return "KILL", syscall.SIGKILL, nil
	case "stop":
		return "STOP", syscall.SIGSTOP, nil
	case "cont", "continue":
		return "CONT", syscall.SIGCONT, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err == nil {
		sig := syscall.Signal(n)
		switch sig {
		case syscall.SIGTERM:
			return "TERM", sig, nil
		case syscall.SIGINT:
			return "INT", sig, nil
		case syscall.SIGKILL:
			return "KILL", sig, nil
		case syscall.SIGSTOP:
			return "STOP", sig, nil
		case syscall.SIGCONT:
			return "CONT", sig, nil
		}
	}
	return "", 0, fmt.Errorf("unsupported signal %q (TERM, INT, KILL, STOP, CONT or their platform signal numbers)", s)
}

// SignalScenario raises a signal against its own process and records PID,
// signal, and timing in the event stream. TERM/INT/KILL are fatal by design:
// the stream ends with signal_sent, and the *caller* observes the exit code
// (128+N). STOP freezes the process; a _cont helper child resumes it after
// --resume-after. CONT on a running process is delivered and run continues.
//
// note: the CLI installs a SIGINT/SIGTERM handler for clean ctrl+C, so this
// scenario calls signal.Reset first to make the self-kill behave like an
// unsupervised process (real 143/130 exit status).
type SignalScenario struct {
	Signal      string
	ResumeAfter time.Duration
	Hold        time.Duration
}

func init() { Register(&SignalScenario{}) }

func (s *SignalScenario) Name() string { return "signal" }

func (s *SignalScenario) Description() string {
	return "raise a signal on this process (TERM INT KILL STOP CONT); fatal ones record the real 128+N status"
}

func (s *SignalScenario) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&s.Signal, "signal", "TERM", "signal to raise: TERM, INT, KILL, STOP, CONT (or their platform signal numbers)")
	fs.DurationVar(&s.ResumeAfter, "resume-after", time.Second, "only STOP: delay before SIGCONT")
	fs.DurationVar(&s.Hold, "hold", time.Second, "runtime before the signal is raised")
}

func (s *SignalScenario) Run(ctx context.Context, cfg Config) error {
	name, sig, err := signalName(s.Signal)
	if err != nil {
		return err
	}
	hold := s.Hold
	if cfg.Duration > 0 {
		hold = cfg.Duration
	} else if hold <= 0 {
		hold = time.Second
	}
	resumeAfter := s.ResumeAfter
	if resumeAfter <= 0 {
		resumeAfter = time.Second
	}

	pid := os.Getpid()
	cfg.Emit("started", map[string]any{"pid": pid, "signal": name, "hold_ms": hold.Milliseconds()})
	cfg.Say(fmt.Sprintf("PID: %d", pid))
	cfg.Say(fmt.Sprintf("Raising %s in %s", name, hold))

	select {
	case <-ctx.Done():
		cfg.Emit("exited", map[string]any{"code": 0, "reason": "interrupted", "signal": name})
		cfg.Say("Shutting down.")
		return nil
	case <-time.After(hold):
	}

	// A stopped main goroutine cannot resume itself; the _cont helper child
	// (still runnable while we are frozen) sends SIGCONT later.
	var watcher Child
	if sig == syscall.SIGSTOP {
		bin, berr := SimBinary()
		if berr != nil {
			return fmt.Errorf("locate sim binary: %w", berr)
		}
		watcher, err = spawn(bin, []string{"_cont", "--pid", strconv.Itoa(pid), "--runner-pid", strconv.Itoa(pid), "--after", resumeAfter.String()}, "cont", false)
		if err != nil {
			return err
		}
		cfg.Emit("watcher_spawned", map[string]any{"pid": watcher.PID(), "resume_after_ms": resumeAfter.Milliseconds()})
	}
	defer func() {
		if watcher.Cmd != nil {
			_ = watcher.Cmd.Process.Kill()
			_, _, _ = reap(watcher.Cmd)
		}
	}()

	// undo the CLI's graceful handler so the self-kill behaves like a process
	// nobody is watching: the death is by kernel default disposition.
	if sig == syscall.SIGTERM || sig == syscall.SIGINT {
		signal.Reset(sig)
	}

	cfg.Emit("signal_sent", map[string]any{"pid": pid, "signal": name})
	cfg.Say(fmt.Sprintf("Signal sent: %s", name))

	if err = syscall.Kill(pid, sig); err != nil {
		return fmt.Errorf("raise %s on %d: %w", name, pid, err)
	}

	// delivery is asynchronous: between the kill returning and the kernel
	// ending us, this goroutine could still run and emit a lying "exited"
	// event. never claim termination. only non-fatal signals reach the code
	// below: STOP (after the watcher's SIGCONT) and CONT.
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL:
		select {} // the kernel will end us; nothing may record a graceful exit
	}
	if sig == syscall.SIGSTOP {
		// kill(2) can return before STOP is delivered to every thread. wait
		// for the watcher to finish its observed-STOP/CONT sequence before
		// emitting resumed or running the deferred watcher cleanup.
		code, kind, waiterr := reap(watcher.Cmd)
		watcher.Cmd = nil // already reaped; deferred cleanup must not wait twice
		if waiterr != nil {
			return fmt.Errorf("wait for resume watcher: %w", waiterr)
		}
		if code != 0 || kind != "exited" {
			return fmt.Errorf("resume watcher ended with %s code %d", kind, code)
		}
		cfg.Emit("resumed", map[string]any{"pid": pid, "signal": "SIGCONT"})
		cfg.Say("Resumed by watcher SIGCONT")
	}
	cfg.Emit("exited", map[string]any{"code": 0, "reason": "signal_delivered", "signal": name})
	cfg.Say("Exit: 0")
	return nil
}
