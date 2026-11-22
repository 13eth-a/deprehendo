package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"runopsy/internal/trace"
)

// runTrace exposes the phase 6 tracer's debug surface (6.58/6.45/6.21):
//
//	runopsy-agent trace capabilities   forward capability report of runopsy-trace
//	runopsy-agent trace status         tracing-mode resolution, then the binary's probe
//	runopsy-agent trace replay FILE    decode a recorded trace stream (go decoder)
//
// status resolves the agent's own tracing configuration first, because the
// question an operator has is not "what can the binary do" but "what will this
// agent do, given its mode": an `ebpf` mode served by the proc connector is a
// configuration mismatch, not a healthy tracer. status/capabilities are the
// rust binary's own reports, resolved through the same resolver the supervisor
// uses. replay runs the go replay decoder so the decoding path used on live
// incident data is what a human inspects.
func runTrace(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "runopsy-agent trace: a subcommand is required (capabilities | status | replay)")
		return 2
	}
	switch args[0] {
	case "status":
		return runTraceStatus(args[1:], stdout, stderr)
	case "capabilities":
		return forwardTrace(args[1:], stdout, stderr)
	case "replay":
		return runTraceReplay(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "runopsy-agent trace: unknown subcommand %q\n", args[0])
		return 2
	}
}

// traceConfig resolves the tracing configuration the way every command and
// the recorder itself read it: environment first, then an explicit flag. it
// is the single parser behind --tracing, so the debug surface and the agent
// cannot disagree about which mode is in effect (6.21).
func traceConfig(modeFlag, binaryFlag string) (trace.Config, error) {
	cfg, err := trace.ConfigFromEnv(os.Getenv)
	if err != nil {
		return trace.Config{}, err
	}
	if modeFlag != "" {
		mode, err := trace.ParseMode(modeFlag)
		if err != nil {
			return trace.Config{}, err
		}
		cfg.Mode = mode
	}
	cfg.Binary = binaryFlag
	if err := cfg.Validate(); err != nil {
		return trace.Config{}, err
	}
	return cfg, nil
}

// runTraceStatus prints what this agent would do with its configured tracing
// mode, then asks the binary. A disabled mode never probes: the binary is not
// going to run, so its capabilities are not this agent's answer.
func runTraceStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent trace status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("tracing", "", "tracing mode: auto, ebpf, proc or disabled (default $RUNOPSY_TRACING or auto)")
	binary := fs.String("binary", "", "runopsy-trace path (default: sibling of this binary, then PATH)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "runopsy-agent trace status: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	cfg, err := traceConfig(*mode, *binary)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent trace status: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "tracing          %s\n", cfg.Mode.Describe())
	if !cfg.Mode.Enabled() {
		fmt.Fprintln(stdout, "tracer binary    not started (tracing disabled)")
		return 0
	}
	bin, why := trace.ResolveBinary(cfg.Binary)
	if why != "" {
		fmt.Fprintf(stdout, "tracer binary    not installed: %s\n", why)
		fmt.Fprintln(stdout, "                 the agent continues in polling-only mode")
		return 1
	}
	fmt.Fprintf(stdout, "tracer binary    %s\n", bin)
	return forwardResolved(bin, []string{"status"}, stdout, stderr)
}

// forwardTrace locates the tracer binary through the supervisor's resolver
// and forwards the subcommand. A missing binary is a degraded message, never
// a snapshot of unrelated state.
func forwardTrace(args []string, stdout, stderr io.Writer) int {
	bin, why := trace.ResolveBinary("")
	if why != "" {
		fmt.Fprintf(stderr, "runopsy-agent trace: %s\nBuild trace-rs/ and put runopsy-trace on PATH.\n", why)
		return 1
	}
	return forwardResolved(bin, args, stdout, stderr)
}

// forwardResolved runs one tracer subcommand on an already-resolved binary
// and maps its exit status, so a nonzero tracer result is never reported as a
// successful probe.
func forwardResolved(bin string, args []string, stdout, stderr io.Writer) int {
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "runopsy-agent trace: %v\n", err)
		return 1
	}
	return 0
}

func runTraceReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent trace replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "runopsy-agent trace replay: exactly one trace file required")
		return 2
	}
	path := fs.Arg(0)
	var lines strings.Builder
	stats, err := trace.ReplayFile(path, func(e trace.TraceEvent) {
		fmt.Fprintf(&lines, "seq=%d %s pid=%d mono=%d wall=%d\n", e.Sequence, e.Type, e.PID, e.MonotonicNs, e.WallUnixMs)
	})
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent trace replay: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%sframes=%d events=%d skipped_kinds=%d bad_samples=%d lost=%d last_sequence=%d\n",
		lines.String(), stats.Frames, stats.Events, stats.SkippedKinds, stats.BadSamples, stats.Lost, stats.LastSequence)
	return 0
}
