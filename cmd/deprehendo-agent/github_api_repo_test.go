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

// writeRepoTestBundle writes a minimal bundle with one GitHub job of unknown
// identity and returns its path.
func writeRepoTestBundle(t *testing.T, dir string) string {
	t.Helper()
	original, err := incident.ReadFile("../../internal/incident/testdata/v1-minimal.deprehendo")
	if err != nil {
		t.Fatal(err)
	}
	runner := evidence.Ref("rnr_0123456789abcdef")
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
			Ref: "job_0123456789abcdef", Runner: runner,
			Repository: evidence.UnknownText(evidence.ClassRepository),
			Workflow:   evidence.UnknownText(evidence.ClassWorkflow), Name: evidence.UnknownText(evidence.ClassJobName),
			RunID:   evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID},
			JobID:   evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID},
			Attempt: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt},
			Outcome: evidence.OutcomeUnknown,
		}},
	}}
	var buf bytes.Buffer
	if err := incident.Encode(&buf, original.Incident, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "input.deprehendo")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGitHubAPIEnrichRejectsMalformedRepo(t *testing.T) {
	dir := t.TempDir()
	input := writeRepoTestBundle(t, dir)
	output := filepath.Join(dir, "out.deprehendo")
	var stdout, stderr bytes.Buffer
	code := run([]string{"github", "api-enrich", "--repo", "acme/service/x", "--output", output, input}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--repo must be OWNER/NAME") {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("a usage error still wrote an output bundle")
	}
}

func TestGitHubAPIEnrichRepoWithoutTokenStillWritesBundle(t *testing.T) {
	t.Setenv("DEPREHENDO_GITHUB_TOKEN", "")
	dir := t.TempDir()
	input := writeRepoTestBundle(t, dir)
	output := filepath.Join(dir, "out.deprehendo")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"github", "api-enrich", "--repo", "acme/service", "--output", output, input}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "GitHub job location in acme/service:") {
		t.Fatalf("missing location summary: %q", stderr.String())
	}
	got, err := incident.ReadFile(output)
	if err != nil {
		t.Fatalf("output unreadable offline: %v", err)
	}
	if job := got.Incident.Providers[0].Jobs[0]; job.RunID.State == evidence.Known || job.Repository.State == evidence.Known {
		t.Fatalf("an unlocated job gained an identity: %+v", job)
	}
}
