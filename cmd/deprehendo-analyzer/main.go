// command deprehendo-analyzer is the phase 7 analyzer worker binary (contract
// docs/cloud/contract.md §5.4). default (child) mode: the bundle arrives on
// stdin, the deprehendo.analysis document leaves on stdout, and the exit code
// carries the job status:
//
//	0 READY       document on stdout
//	3 REJECTED    the hostile-input reader refused the bundle; reason on stderr
//	4 FAILED_LIMIT the child could not install its own resource limits
//	anything else FAILED_CRASH
//
// parent mode (`-parent`) runs one job from a file for local verification:
//
//	deprehendo-analyzer -parent -bundle incident.deprehendo -out analysis.json
//
// the storage-facing service that receives web's job calls is a later item
// (contract §9: needs the object store and the web upload flow first).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"deprehendo/internal/analyzer"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/github"
)

// the hosted analysis must interpret the same providers as the CLI, or a
// bundle captured on a GitHub runner analyzes differently in the cloud: no
// provider signatures (such as GITHUB_RUNNER_COMMUNICATION_STALL) and no
// cancellation or timeout intent for the causal engine. provider.Default is
// populated by each cmd/ binary; deprehendo-agent registers GitHub in
// cmd/deprehendo-agent/github.go, and this binary must do the same. found by the
// 7.62 real-runner demo, november 21, 2026; pinned by
// TestPhase7HostedAnalyzerInterpretsGitHub.
func init() {
	if err := provider.Default.Register(github.GitHubProvider{}); err != nil {
		// registration is programmer error (duplicate name); panic loudly.
		panic(err)
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "-parent" {
		return parentMode(args[1:])
	}
	if err := analyzer.InstallChildLimits(); err != nil {
		fmt.Fprintln(os.Stderr, "analyzer:", err)
		return analyzer.ExitLimited
	}
	return analyzer.Child(os.Stdin, os.Stdout, os.Stderr)
}

// timeSeconds converts the -timeout flag in seconds.
func timeSeconds(seconds *int) time.Duration {
	return time.Duration(*seconds) * time.Second
}

func parentMode(args []string) int {
	fs := flag.NewFlagSet("deprehendo-analyzer -parent", flag.ContinueOnError)
	bundle := fs.String("bundle", "", "bundle to analyze")
	out := fs.String("out", "-", "document output path (- for stdout)")
	timeoutseconds := fs.Int("timeout", 60, "job wall clock in seconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundle == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "deprehendo-analyzer: -parent requires -bundle FILE")
		return 2
	}
	raw, err := os.ReadFile(*bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deprehendo-analyzer:", err)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "deprehendo-analyzer:", err)
		return 1
	}
	runner := analyzer.NewRunner(self)
	runner.Timeout = timeSeconds(timeoutseconds)
	result, err := runner.Run(context.Background(), raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deprehendo-analyzer:", err)
		return 1
	}
	// report denials and boundary hits to stderr; write only READY documents.
	if result.Status != analyzer.StatusReady {
		fmt.Fprintf(os.Stderr, "deprehendo-analyzer: %s: %s\n", result.Status, result.Reason)
		return 1
	}
	if *out == "-" {
		if _, err := os.Stdout.Write(result.Document); err != nil {
			fmt.Fprintln(os.Stderr, "deprehendo-analyzer:", err)
			return 1
		}
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		fmt.Fprintln(os.Stderr, "deprehendo-analyzer:", err)
		return 1
	}
	if err := os.WriteFile(*out, result.Document, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "deprehendo-analyzer:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "deprehendo-analyzer: READY in %s\n", result.Duration.Truncate(1000*1000))
	return 0
}
