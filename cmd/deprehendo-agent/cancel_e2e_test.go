package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"deprehendo/internal/causal"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

// cancelledJobBundle builds a bundle whose only process death is PID 8 killed
// by SIGKILL, optionally with a GitHub job-cancellation record naming PID 8.
func cancelledJobBundle(t *testing.T, withCancel bool) string {
	t.Helper()
	inc := timelineTestIncident()
	for i := range inc.Events {
		if inc.Events[i].Type == "PROCESS_EXITED" {
			inc.Events[i].ExitStatus = "signal:9"
		}
	}
	if withCancel {
		runner := evidence.Ref("rnr_0123456789abcdef")
		at := inc.CaptureStart.Add(time.Second)
		inc.Providers = []evidence.Section{{
			Provider: github.Name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyIdentifiers,
			Health:  evidence.Health{State: evidence.HealthAvailable},
			Runners: []evidence.Runner{{Ref: runner, Name: evidence.KnownText(evidence.ClassRunnerName, "runner-a", evidence.SourceRunnerConfig), Version: evidence.KnownText(evidence.ClassVersion, "2.320.0", evidence.SourceRunnerConfig), Labels: evidence.UnknownText(evidence.ClassLabels), Lifecycle: evidence.LifecycleUnknown}},
			Events: []evidence.Event{{
				Timestamp:  at,
				Type:       github.EventJobCancellation,
				Runner:     runner,
				Process:    &evidence.ProcessRef{PID: 8, StartTicks: 10},
				Source:     evidence.SourceRunnerLog,
				Provenance: evidence.Provenance{File: 1, Offset: 300},
			}},
		}}
	}
	return writeTimelineBundle(t, inc)
}

func timelineFailureAnchors(t *testing.T, path string) []causal.FailureAnalysis {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"timeline", "--json", "--causal", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("timeline --json --causal = %d: %s", code, stderr.String())
	}
	var output TimelineOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return output.Failures
}

// TestCancelledJobKillIsNotAFailureEndToEnd asserts the bundle-level contract:
// the same SIGKILL is a failure anchor on its own, but context once the
// provider has recorded an intended cancellation of that process.
func TestCancelledJobKillIsNotAFailureEndToEnd(t *testing.T) {
	anchorsfor := func(failures []causal.FailureAnalysis) int {
		n := 0
		for _, f := range failures {
			if f.AnchorType == causal.EventProcessExited {
				n++
			}
		}
		return n
	}

	plain := anchorsfor(timelineFailureAnchors(t, cancelledJobBundle(t, false)))
	if plain == 0 {
		t.Fatal("baseline SIGKILL without intent produced no PROCESS_EXITED failure anchor; fixture is not testing the cover")
	}
	cancelled := anchorsfor(timelineFailureAnchors(t, cancelledJobBundle(t, true)))
	if cancelled != 0 {
		t.Fatalf("cancelled job kill produced %d PROCESS_EXITED failure anchors, want 0", cancelled)
	}
}

// TestCancelledJobKillIsNotAFailureThroughAnalyze asserts the same contract on
// the analyze --json path, which now builds the causal graph too.
func TestCancelledJobKillIsNotAFailureThroughAnalyze(t *testing.T) {
	countexits := func(withCancel bool) int {
		var stdout, stderr bytes.Buffer
		path := cancelledJobBundle(t, withCancel)
		if code := run([]string{"analyze", "--json", path}, &stdout, &stderr); code != 0 {
			t.Fatalf("analyze --json = %d: %s", code, stderr.String())
		}
		var output struct {
			Failures []causal.FailureAnalysis `json:"failures"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		n := 0
		for _, f := range output.Failures {
			if f.AnchorType == causal.EventProcessExited {
				n++
			}
		}
		return n
	}
	if n := countexits(false); n == 0 {
		t.Fatal("baseline SIGKILL without intent produced no analyze failure anchor")
	}
	if n := countexits(true); n != 0 {
		t.Fatalf("analyze reported %d PROCESS_EXITED failure anchors for a cancelled job, want 0", n)
	}
}
