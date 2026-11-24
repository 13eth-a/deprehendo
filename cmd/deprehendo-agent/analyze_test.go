package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

func TestMain(m *testing.M) {
	if _, ok := provider.Default.Get(github.Name); !ok {
		if err := provider.Default.Register(github.GitHubProvider{}); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func TestAnalyzeCLITextJSONExplainAndFlagOrdering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "healthy.deprehendo")
	if err := os.WriteFile(path, mustReadFixture(t), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"text flags after file", []string{"analyze", path, "--explain"}, "ROOT CAUSE"},
		{"text flags before file", []string{"analyze", "--explain", path}, "Unknown"},
		{"full report", []string{"analyze", path, "--report"}, "DEPREHENDO INCIDENT ANALYSIS"},
		{"json flags after file", []string{"analyze", path, "--json"}, `"analyzer_version"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit %d; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("output missing %q: %s", tc.want, stdout.String())
			}
			if strings.Contains(strings.Join(tc.args, " "), "--json") {
				var report diagnosis.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatalf("invalid JSON report: %v\n%s", err, stdout.String())
				}
				if !report.Unknown || report.IncidentID == "" || len(report.Rejections) == 0 {
					t.Errorf("missing analysis metadata: %+v", report)
				}
			}
		})
	}
}

func TestAnalyzeExplainShowsRejectedReasonsAndMissingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "healthy.deprehendo")
	if err := os.WriteFile(path, mustReadFixture(t), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"analyze", path, "--explain"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{"rejected:", "unavailable", "No known signature"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("explain output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestAnalyzeRejectsInvalidArguments(t *testing.T) {
	cases := [][]string{
		{"analyze"},
		{"analyze", "a", "b"},
		{"analyze", "does-not-exist.deprehendo"},
		{"analyze", "file", "--min-confidence", "1.1"},
		{"analyze", "file", "--min-confidence"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Errorf("run(%v) unexpectedly succeeded", args)
		}
	}
}

func TestAnalyzeMinimumConfidenceFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "healthy.deprehendo")
	if err := os.WriteFile(path, mustReadFixture(t), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"analyze", "--min-confidence", "0.8", path, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report diagnosis.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.MinConfidence != 0.8 {
		t.Errorf("min confidence = %v", report.MinConfidence)
	}
}

// TestAnalyzeDisableFlag exercises the user-facing registry enable/disable
// surface (3.20): disabled signatures are not evaluated, unknown IDs and
// malformed lists are rejected instead of silently ignored.
func TestAnalyzeDisableFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "healthy.deprehendo")
	if err := os.WriteFile(path, mustReadFixture(t), 0600); err != nil {
		t.Fatal(err)
	}
	analyzejson := func(t *testing.T, args ...string) diagnosis.Report {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"analyze", path, "--json"}, args...), &stdout, &stderr); code != 0 {
			t.Fatalf("exit code %d; stderr=%s", code, stderr.String())
		}
		var report diagnosis.Report
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("invalid JSON report: %v\n%s", err, stdout.String())
		}
		return report
	}
	t.Run("disabled signatures are not evaluated", func(t *testing.T) {
		report := analyzejson(t, "--disable", "FROZEN_PROCESS,CPU_SPIN")
		if want := len(diagnosis.DefaultSignatures()) - 2; len(report.Rejections) != want {
			t.Errorf("rejections = %d, want %d", len(report.Rejections), want)
		}
		for _, id := range []string{"FROZEN_PROCESS", "CPU_SPIN"} {
			for _, r := range report.Rejections {
				if r.SignatureID == diagnosis.SignatureID(id) {
					t.Errorf("disabled signature %s was still evaluated", id)
				}
			}
		}
	})
	t.Run("flag before the bundle path", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"analyze", "--disable", "FROZEN_PROCESS", path, "--json"}
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("exit code %d; stderr=%s", code, stderr.String())
		}
		var report diagnosis.Report
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if want := len(diagnosis.DefaultSignatures()) - 1; len(report.Rejections) != want {
			t.Errorf("rejections = %d, want %d", len(report.Rejections), want)
		}
	})
	t.Run("unknown signature id is rejected", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"analyze", path, "--disable", "NOT_A_SIGNATURE"}, &stdout, &stderr); code == 0 {
			t.Fatal("unknown disable ID was accepted")
		}
	})
	t.Run("empty token is rejected", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"analyze", path, "--disable", "FROZEN_PROCESS,,CPU_SPIN"}, &stdout, &stderr); code != 2 {
			t.Fatalf("empty disable token exit %d, want 2", code)
		}
	})
}

func TestAnalyzeReportIncludesProviderContextAndUnknowns(t *testing.T) {
	base, err := incident.ReadFile("../../internal/incident/testdata/v1-minimal.deprehendo")
	if err != nil {
		t.Fatal(err)
	}
	at := base.Incident.TriggeredAt
	// the report shows a job only when it ran during the capture, so the
	// fixture's job times are anchored to the capture window.
	window := base.Incident.CaptureStart
	runner := evidence.Ref("rnr_0123456789abcdef")
	job := evidence.Ref("job_0123456789abcdef")
	base.Incident.Providers = []evidence.Section{{
		Provider: github.Name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyConservative,
		Health:  evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{Ref: runner, Name: evidence.UnknownText(evidence.ClassRunnerName), Version: evidence.KnownText(evidence.ClassVersion, "2.320.0", evidence.SourceRunnerConfig), Labels: evidence.UnknownText(evidence.ClassLabels), Lifecycle: evidence.LifecycleUnknown}},
		Jobs:    []evidence.Job{{Ref: job, Runner: runner, Repository: evidence.Text{State: evidence.Withheld, Class: evidence.ClassRepository}, Workflow: evidence.UnknownText(evidence.ClassWorkflow), Name: evidence.UnknownText(evidence.ClassJobName), RunID: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID}, JobID: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID}, Attempt: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt}, Outcome: evidence.OutcomeUnknown, StartedAt: window.Add(time.Second), StartedAtSource: evidence.SourceProviderAPI, CompletedAt: window.Add(2 * time.Second), CompletedAtSource: evidence.SourceProviderAPI, RunStartedAt: window, RunStartedAtSource: evidence.SourceProviderAPI, RunCompletedAt: window.Add(3 * time.Second), RunCompletedAtSource: evidence.SourceProviderAPI}},
		Events:  []evidence.Event{{Timestamp: at, Type: github.EventJobAssigned, Runner: runner, Job: job, Source: evidence.SourceRunnerLog, Provenance: evidence.Provenance{File: 2, Offset: 128}}},
	}}
	var encoded bytes.Buffer
	if err := incident.Encode(&encoded, base.Incident, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider.deprehendo")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"analyze", "timeline"} {
		var stdout, stderr bytes.Buffer
		args := []string{command, path, "--report"}
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("%s = %d: %s", command, code, stderr.String())
		}
		for _, wanted := range []string{"GitHub Actions", "Runner        UNKNOWN", "Workflow      UNKNOWN", "GITHUB_JOB_ASSIGNED", "provenance=file:2@128", "GITHUB_JOB_STARTED", "GITHUB_JOB_COMPLETED", "source=PROVIDER_API", "Job started", "Run started", "Run completed", "Runner        UNKNOWN source=UNKNOWN"} {
			if !strings.Contains(stdout.String(), wanted) {
				t.Errorf("%s missing %q:\n%s", command, wanted, stdout.String())
			}
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"analyze", "--json", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyze json = %d: %s", code, stderr.String())
	}
	var output struct {
		Providers []provider.Interpretation `json:"providers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Providers) != 1 || output.Providers[0].Provider != github.Name {
		t.Fatalf("provider interpretations not present in offline JSON output: %+v", output)
	}
}

func mustReadFixture(t *testing.T) []byte {
	t.Helper()
	bundle, err := incident.ReadFile("../../internal/incident/testdata/v1-minimal.deprehendo")
	if err != nil {
		t.Fatal(err)
	}
	_ = bundle
	data, err := os.ReadFile("../../internal/incident/testdata/v1-minimal.deprehendo")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDiagnosisCLIRejectsNonFiniteThreshold(t *testing.T) {
	for _, command := range []string{"analyze", "evaluate"} {
		for _, value := range []string{"NaN", "+Inf", "-Inf"} {
			var out, errOut bytes.Buffer
			if code := run([]string{command, "missing", "--min-confidence", value}, &out, &errOut); code != 2 {
				t.Errorf("%s threshold %s: exit %d, want usage error: %s", command, value, code, errOut.String())
			}
		}
	}
}

func TestAmbiguityAlwaysVisibleInTextReport(t *testing.T) {
	report := &diagnosis.Report{
		Matches:   []diagnosis.SignatureMatch{{SignatureID: diagnosis.SignatureBrokerStall, Confidence: .7}, {SignatureID: diagnosis.SignatureNetworkFailure, Confidence: .7}},
		Ambiguous: []string{"BROKER_SOCKET_STALL vs NETWORK_PATH_FAILURE"},
	}
	var out bytes.Buffer
	writeTextReport(report, false, &out)
	if !strings.Contains(out.String(), "Ambiguous rival explanations") {
		t.Fatalf("default report conceals ambiguity: %s", out.String())
	}
}

type failedReportWriter struct{}

func (failedReportWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestTextReportPropagatesWriteFailure(t *testing.T) {
	if err := writeTextReport(&diagnosis.Report{Unknown: true}, false, failedReportWriter{}); err == nil {
		t.Fatal("report silently ignored output failure")
	}
	if err := diagnosis.WriteEvaluation(failedReportWriter{}, &diagnosis.Evaluation{}); err == nil {
		t.Fatal("evaluation silently ignored output failure")
	}
}

func TestExplainShowsFactsForRejectedCPUHypothesis(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"analyze", "../../testdata/incidents/cpu-spin.deprehendo", "--explain"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"CPU_SPIN rejected:", "Supporting observations (insufficient for diagnosis):", "CPU_SUSTAINED", "APPLICATION_PROGRESS_TELEMETRY"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in explained rejection: %s", want, out.String())
		}
	}
}
