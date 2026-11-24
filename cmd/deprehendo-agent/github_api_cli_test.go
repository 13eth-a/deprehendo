package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deprehendo/internal/incident"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

func TestGitHubAPIEnrichUnavailableStillWritesOfflineBundle(t *testing.T) {
	t.Setenv("DEPREHENDO_GITHUB_TOKEN", "")
	original, err := incident.ReadFile("../../internal/incident/testdata/v1-minimal.deprehendo")
	if err != nil {
		t.Fatal(err)
	}
	runner := evidence.Ref("rnr_0123456789abcdef")
	job := evidence.Ref("job_0123456789abcdef")
	original.Incident.Providers = []evidence.Section{{
		Provider: github.Name, SchemaVersion: evidence.SchemaVersion,
		Privacy: evidence.PrivacyConservative,
		Health:  evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref: runner, Name: evidence.UnknownText(evidence.ClassRunnerName),
			Version: evidence.UnknownText(evidence.ClassVersion), Labels: evidence.UnknownText(evidence.ClassLabels),
			Lifecycle: evidence.LifecycleUnknown,
		}},
		Jobs: []evidence.Job{{
			Ref: job, Runner: runner,
			Repository: evidence.UnknownText(evidence.ClassRepository),
			Workflow:   evidence.UnknownText(evidence.ClassWorkflow), Name: evidence.UnknownText(evidence.ClassJobName),
			RunID:   evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID},
			JobID:   evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID},
			Attempt: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt},
			Outcome: evidence.OutcomeUnknown,
		}},
	}}
	var input bytes.Buffer
	if err := incident.Encode(&input, original.Incident, true); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inputpath := filepath.Join(dir, "input.deprehendo")
	outputpath := filepath.Join(dir, "output.deprehendo")
	if err := os.WriteFile(inputpath, input.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"github", "api-enrich", "--output", outputpath, inputpath}, &stdout, &stderr); code != 0 {
		t.Fatalf("api-enrich exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "GitHub API enrichment unavailable") {
		t.Fatalf("missing unavailable-enrichment notice: %q", stderr.String())
	}
	gotinput, err := os.ReadFile(inputpath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotinput, input.Bytes()) {
		t.Fatal("api-enrich modified its input bundle")
	}
	bundle, err := incident.ReadFile(outputpath)
	if err != nil {
		t.Fatalf("offline bundle read failed: %v", err)
	}
	section := bundle.Incident.Providers[0]
	if section.Health.State != evidence.HealthDegraded || len(section.Health.Reasons) == 0 {
		t.Fatalf("unavailable API state not retained in bundle: %+v", section.Health)
	}
	if bundle.Incident.Privacy.ProviderIdentifiers {
		t.Fatal("default enrichment unexpectedly enabled provider identifiers")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"analyze", "--report", outputpath}, &stdout, &stderr); code != 0 {
		t.Fatalf("offline analyze exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "github-actions  health=DEGRADED") {
		t.Fatalf("offline report omitted provider health: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"timeline", outputpath}, &stdout, &stderr); code != 0 {
		t.Fatalf("offline timeline exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PROVIDER EVIDENCE") {
		t.Fatalf("default offline timeline omitted provider evidence: %s", stdout.String())
	}
}
