package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"runopsy/internal/incident"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github"
)

func runGitHubAPIEnrich(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent github api-enrich", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenfile := fs.String("token-file", "", "mode-0600 token file (default ~/.runopsy/github-token); RUNOPSY_GITHUB_TOKEN also supported")
	output := fs.String("output", "", "output bundle path (default: input path is not overwritten)")
	identifiers := fs.Bool("provider-identifiers", false, "opt in to naming provider identifiers in the output bundle")
	repo := fs.String("repo", "", "owner/name of the repository the recorded jobs ran in; finds each job by time and runner (G1)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: runopsy-agent github api-enrich [--token-file FILE] [--output FILE] [--provider-identifiers] [--repo OWNER/NAME] BUNDLE")
		return 2
	}
	if *repo != "" {
		// validate before any read or network call: a malformed value is a
		// usage error, not a degraded enrichment.
		var probe evidence.Section
		if _, _, err := (github.GitHubAPIEnricher{}).Locate(context.Background(), &probe, nil, *repo); err != nil {
			fmt.Fprintln(stderr, "runopsy-agent github api-enrich: --repo must be OWNER/NAME")
			return 2
		}
	}
	input := fs.Arg(0)
	if *output == "" {
		fmt.Fprintln(stderr, "runopsy-agent github api-enrich: --output is required; input bundles are never overwritten")
		return 2
	}
	inputpath, inputerr := filepath.Abs(input)
	outputpath, outputerr := filepath.Abs(*output)
	if inputerr != nil || outputerr != nil || filepath.Clean(inputpath) == filepath.Clean(outputpath) {
		fmt.Fprintln(stderr, "runopsy-agent github api-enrich: output must differ from input")
		return 2
	}
	bundle, err := incident.ReadFile(input)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent github api-enrich: %v\n", err)
		return 1
	}
	tokenSource := github.TokenSource{Path: *tokenfile}
	level := evidence.PrivacyConservative
	if *identifiers {
		level = evidence.PrivacyIdentifiers
	}
	found := false
	for index := range bundle.Incident.Providers {
		section := &bundle.Incident.Providers[index]
		if section.Provider != github.Name {
			continue
		}
		found = true
		if *repo != "" {
			located, health, _ := (github.GitHubAPIEnricher{}).Locate(context.Background(), section, tokenSource, *repo)
			fmt.Fprintf(stderr, "GitHub job location in %s: %d located, %d ambiguous, %d unmatched\n",
				*repo, located.Located, located.Ambiguous, located.Unmatched)
			for _, reason := range health.Reasons {
				fmt.Fprintf(stderr, "GitHub API job location unavailable: %s\n", reason)
			}
		}
		health := (github.GitHubAPIEnricher{}).Enrich(context.Background(), section, tokenSource)
		if health.State == evidence.HealthDegraded {
			for _, reason := range health.Reasons {
				fmt.Fprintf(stderr, "GitHub API enrichment unavailable: %s\n", reason)
			}
		}
		section.Privacy = level
		section.Redact(level)
	}
	if !found {
		fmt.Fprintln(stderr, "runopsy-agent github api-enrich: bundle has no GitHub provider section")
		return 1
	}
	bundle.Incident.Privacy.ProviderIdentifiers = *identifiers
	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil {
		fmt.Fprintf(stderr, "runopsy-agent github api-enrich: output unavailable\n")
		return 1
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent github api-enrich: output unavailable\n")
		return 1
	}
	defer file.Close()
	if err := incident.Encode(file, bundle.Incident, true); err != nil {
		_ = os.Remove(*output)
		fmt.Fprintf(stderr, "runopsy-agent github api-enrich: encode: %v\n", err)
		return 1
	}
	// read the output back through the public bundle decoder. this catches
	// privacy/schema mistakes at the exact artifact boundary used offline.
	if _, err := incident.ReadFile(*output); err != nil {
		_ = os.Remove(*output)
		fmt.Fprintf(stderr, "runopsy-agent github api-enrich: output validation failed: %v\n", err)
		return 1
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(*output)
		fmt.Fprintln(stderr, "runopsy-agent github api-enrich: output write failed")
		return 1
	}
	fmt.Fprintf(stdout, "Enriched bundle written: %s\n", *output)
	return 0
}
