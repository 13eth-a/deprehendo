package simulator

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/events"
)

// RunCLI is the deprehendo-sim entrypoint, kept separate from main so it can be
// tested without spawning a process. it returns the process exit code.
//
// exit codes: 0 success (including a clean ctrl+C), 1 scenario failure,
// 2 usage error.
func RunCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText())
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usageText())
		return 0
	}

	if args[0] == "github" {
		return RunGitHubCLI(args[1:], stdout, stderr)
	}

	name := args[0]
	sc, ok := Lookup(name)
	if !ok {
		fmt.Fprintf(stderr, "deprehendo-sim: unknown scenario %q\n\n%s", name, usageText())
		return 2
	}

	fs := flag.NewFlagSet("deprehendo-sim "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		duration time.Duration
		verbose  bool
		jsonMode bool
	)
	fs.DurationVar(&duration, "duration", 0, "overall runtime; 0 means the scenario's default")
	fs.BoolVar(&verbose, "verbose", false, "include extra detail")
	fs.BoolVar(&jsonMode, "json", false, "emit newline-delimited JSON events on stdout")
	if flagged, ok := sc.(Flagged); ok {
		flagged.RegisterFlags(fs)
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "deprehendo-sim: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if duration < 0 {
		fmt.Fprintln(stderr, "deprehendo-sim: --duration must not be negative")
		return 2
	}

	// narration shares stdout with the event stream: JSON mode suppresses it,
	// so stdout is either readable text or pure JSON, never both.
	em := events.New(name, stdout, stdout, jsonMode)
	cfg := Config{Duration: duration, Verbose: verbose, JSON: jsonMode, Events: em}

	// ctrl+C cancels the scenario so it can clean up its children and sockets;
	// a second signal falls back to the default handler and kills the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		stop() // restore default handling while scenario cleanup runs
	}()
	defer func() {
		stop()
		<-stopped
	}()

	err := sc.Run(ctx, cfg)
	if ctx.Err() != nil && err == nil {
		cfg.Say("Interrupted; cleanup complete.")
	}
	var chosen exitCodeError
	if werr := em.Err(); werr != nil && (err == nil || errors.As(err, &chosen)) {
		err = fmt.Errorf("write event stream: %w", werr)
	}
	if errors.As(err, &chosen) {
		// the scenario picked its own process exit code (exit scenario); that
		// is a success path by definition, not a printed failure.
		return chosen.Code
	}
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-sim: %s: %v\n", name, err)
		return 1
	}
	return 0
}

func usageText() string {
	var b strings.Builder
	b.WriteString("Usage:\n  deprehendo-sim <scenario> [flags]\n\nScenarios:\n")
	for _, sc := range Scenarios() {
		fmt.Fprintf(&b, "  %-16s %s\n", sc.Name(), sc.Description())
	}
	b.WriteString("\nAdditional commands:\n")
	b.WriteString("  github <scenario>  fake GitHub Actions runner harness (`deprehendo-sim github --help`)\n")
	b.WriteString("\nFlags:\n")
	b.WriteString("  --duration DUR   overall runtime; 0 means the scenario's default\n")
	b.WriteString("  --verbose        include extra detail\n")
	b.WriteString("  --json           emit newline-delimited JSON events on stdout\n")
	b.WriteString("  -h, --help       show this help\n")
	b.WriteString("\nRun \"deprehendo-sim <scenario> --help\" for scenario-specific flags.\n")
	return b.String()
}
