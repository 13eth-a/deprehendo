package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"deprehendo/internal/agent"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

func parsePIDList(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	pids := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		pid, err := strconv.Atoi(part)
		if err != nil || pid <= 0 {
			return nil, fmt.Errorf("invalid positive PID %q", part)
		}
		pids = append(pids, pid)
	}
	return uniquePIDs(pids), nil
}

func providerSupervisors(set *agent.ProviderSet) []incident.ProviderSupervisor {
	if set == nil {
		return nil
	}
	return set.Supervisors()
}

func textValue(value evidence.Text, fallback string) string {
	if value.Value == "" {
		return fallback
	}
	return value.Value
}

func uniquePIDs(pids []int) []int {
	seen := make(map[int]bool, len(pids))
	out := make([]int, 0, len(pids))
	for _, pid := range pids {
		if !seen[pid] {
			seen[pid] = true
			out = append(out, pid)
		}
	}
	return out
}

func runGitHubDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("deprehendo-agent github doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statedir := fs.String("state-dir", agent.DefaultStateDir(), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "deprehendo-agent github doctor: unexpected arguments")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider := github.GitHubProvider{}
	host := agent.NewHostView(*statedir)
	detection, err := provider.Detect(ctx, host)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent github doctor: discovery unavailable: %v\n", err)
		return 1
	}
	runners, err := provider.Discover(ctx, host)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent github doctor: discovery unavailable: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "GitHub Actions Runner")
	if len(runners) == 0 {
		fmt.Fprintf(stdout, "No verified Runner.Listener installation detected.\nCandidates       %d\nOverall          UNKNOWN\n", detection.Candidates)
		return 0
	}
	for _, runner := range runners {
		fmt.Fprintf(stdout, "\nRunner           %s\nVersion          %s\nListener PID     %d\nWorker PID        UNKNOWN (not sampled)\nState             UNKNOWN (discovery only)\nCommunication     UNKNOWN (live socket health requires recording)\n", textValue(runner.Name, "UNKNOWN"), textValue(runner.Version, "unknown"), runner.Supervisor.PID)
	}
	fmt.Fprintln(stdout, "Overall           UNKNOWN (run `deprehendo-agent github watch` to record live health)")
	return 0
}

func runGitHubWatch(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprintln(stdout, "Usage: deprehendo-agent github watch [start flags]\nDiscovers runner listener trees and runs the recorder in the foreground.")
			return 0
		}
		if strings.HasPrefix(arg, "--github-watch") {
			fmt.Fprintln(stderr, "deprehendo-agent github watch: --github-watch is selected automatically")
			return 2
		}
	}
	return runStart(append([]string{"--github-watch"}, args...), stdout, stderr)
}
