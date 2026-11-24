// the `github` subcommand: discovery and offline interpretation against
// GitHub actions runners (phase 5 §11.3). discovery runs the provider's
// live half with the same HostView the recorder uses; interpretation takes
// a bundle and prints its generic translation for inspection.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	"deprehendo/internal/agent"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

func init() {
	if err := provider.Default.Register(github.GitHubProvider{}); err != nil {
		// registration is programmer error (duplicate name); panic loudly.
		panic(err)
	}
}

func runGitHub(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: deprehendo-agent github discover|doctor|watch|api-enrich|interpret [flags]")
		return 2
	}
	switch args[0] {
	case "discover":
		return runGitHubDiscover(args[1:], stdout, stderr)
	case "interpret":
		return runGitHubInterpret(args[1:], stdout, stderr)
	case "api-enrich":
		return runGitHubAPIEnrich(args[1:], stdout, stderr)
	case "doctor":
		return runGitHubDoctor(args[1:], stdout, stderr)
	case "watch":
		return runGitHubWatch(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "deprehendo-agent github: unknown command %q\n", args[0])
		return 2
	}
}

// runGitHubDiscover runs the two-fact supervisor classification (C2) on the
// live host and prints one line per runner. it also reports name-only
// candidates explicitly, tagged as such.
func runGitHubDiscover(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("deprehendo-agent github discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statedir := fs.String("state-dir", agent.DefaultStateDir(), "agent state directory (holds the identity salt)")
	timeout := fs.Duration("timeout", 10*time.Second, "discovery timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "deprehendo-agent github discover: unexpected arguments")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	host := agent.NewHostView(*statedir)
	prov := github.GitHubProvider{}
	detection, err := prov.Detect(ctx, host)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent github discover: detect: %v\n", err)
		return 1
	}
	if !detection.Present {
		fmt.Fprintln(stdout, "no GitHub Actions runner detected on this host")
		return 0
	}
	runners, err := prov.Discover(ctx, host)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent github discover: %v\n", err)
		return 1
	}
	sort.Slice(runners, func(i, j int) bool { return runners[i].Ref < runners[j].Ref })
	for _, run := range runners {
		name := run.Name
		if name.Value != "" {
			fmt.Fprintf(stdout, "runner %s  name=%s  version=%s  lifecycle=%s  supervisor pid=%d\n",
				run.Ref, name.Value, valueOr(run.Version, "unknown"), run.Lifecycle, run.Supervisor.PID)
		} else {
			fmt.Fprintf(stdout, "runner %s  name=UNKNOWN  version=%s  lifecycle=%s  supervisor pid=%d\n",
				run.Ref, valueOr(run.Version, "unknown"), run.Lifecycle, run.Supervisor.PID)
		}
	}
	return 0
}

func valueOr(t evidence.Text, fallback string) string {
	if t.Value == "" {
		return fallback
	}
	return t.Value
}

// runGitHubInterpret prints the offline generic translation of one bundle's
// provider sections (the §11.4 contract checks).
func runGitHubInterpret(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("deprehendo-agent github interpret", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: deprehendo-agent github interpret BUNDLE")
		return 2
	}
	bundle, err := incident.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent github interpret: %v\n", err)
		return 1
	}
	interp := provider.Default.InterpretAll(bundle.Incident.Providers, bundle.Incident)
	for _, one := range interp {
		fmt.Fprintf(stdout, "provider %s: %d generic events\n", one.Provider, len(one.Generic))
		for _, ge := range one.Generic {
			intent := ""
			if ge.Intent != "" {
				intent = " intent=" + string(ge.Intent)
			}
			fmt.Fprintf(stdout, "  %s %s%s\n", ge.Timestamp.UTC().Format(time.RFC3339), ge.Kind, intent)
		}
	}
	return 0
}
