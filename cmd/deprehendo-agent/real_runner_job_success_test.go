package main

import (
	"testing"

	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
)

// real self-hosted runner, run 41950041166 (2026-11-04): a job GitHub reports
// SUCCEEDED, with the proc-connector tracer active and lossless (280 traced
// exits). the job spawned a test process tree of its own; when the job ended
// the runner SIGKILLed the leftovers in their own process group (pgid 1434733)
// and the analyzer reported PROCESS_GROUP_TERMINATION at HIGH (0.80) /
// CRITICAL. A stated job outcome covers the job's whole tree, so that cleanup
// is context, not a failure: the S2 gate ("job correlated, no failure claim")
// must hold.
func TestRealRunnerSuccessfulJobIsNotAGroupKill(t *testing.T) {
	bundle, err := incident.ReadFile("../../testdata/github/selfhosted-e2e-job-success/incident.deprehendo")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	inc := bundle.Incident
	if inc.Tracing == nil || inc.Tracing.State != "active" {
		t.Fatalf("fixture lost its tracing evidence: %+v", inc.Tracing)
	}
	jobTree := false
	for _, cover := range intentCovers(provider.Default.InterpretAll(inc.Providers, inc)) {
		if cover.JobTree {
			jobTree = true
		}
	}
	if !jobTree {
		t.Fatal("the stated job outcome produced no job-tree cover")
	}
	report, err := diagnosis.Analyze(inc, diagnosisOptions(inc, diagnosis.DefaultMinConfidence, nil))
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, match := range report.Matches {
		if match.SignatureID == diagnosis.SignatureGroupKill {
			t.Fatalf("a successful job's cleanup was reported as a group kill: confidence=%.2f severity=%s",
				match.Confidence, match.Severity)
		}
	}
	if len(report.Matches) != 0 {
		for _, match := range report.Matches {
			t.Logf("unexpected match: %s %.2f", match.SignatureID, match.Confidence)
		}
		t.Fatalf("a SUCCEEDED job produced %d failure claim(s), want none", len(report.Matches))
	}
}
