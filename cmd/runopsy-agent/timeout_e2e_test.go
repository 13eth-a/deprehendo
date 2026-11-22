package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"runopsy/internal/causal"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github"
)

// 5.45 timeout semantics, end to end: a job the runner states it timed out
// ("exceeded the maximum execution time") is ended on purpose, so the SIGKILL
// of its process is context, not a failure. the cover is bounded (T2): a
// timeout stated long after the kill explains nothing.

// timedOutJobBundle: the only death is PID 8 by SIGKILL; offset places the
// stated timeout relative to that exit (nil: no statement at all).
func timedOutJobBundle(t *testing.T, offset *time.Duration) string {
	t.Helper()
	inc := timelineTestIncident()
	var exitAt time.Time
	for i := range inc.Events {
		if inc.Events[i].Type == "PROCESS_EXITED" {
			inc.Events[i].ExitStatus = "signal:9"
			exitAt = inc.Events[i].Timestamp
		}
	}
	if exitAt.IsZero() {
		t.Fatal("fixture has no PROCESS_EXITED event")
	}
	if offset != nil {
		runner := evidence.Ref("rnr_0123456789abcdef")
		inc.Providers = []evidence.Section{{
			Provider: github.Name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyIdentifiers,
			Health:  evidence.Health{State: evidence.HealthAvailable},
			Runners: []evidence.Runner{{Ref: runner, Name: evidence.KnownText(evidence.ClassRunnerName, "runner-a", evidence.SourceRunnerConfig), Version: evidence.KnownText(evidence.ClassVersion, "2.320.0", evidence.SourceRunnerConfig), Labels: evidence.UnknownText(evidence.ClassLabels), Lifecycle: evidence.LifecycleUnknown}},
			Events: []evidence.Event{{
				Timestamp:  exitAt.Add(*offset),
				Type:       github.EventJobTimeout,
				Runner:     runner,
				Process:    &evidence.ProcessRef{PID: 8, StartTicks: 10},
				Source:     evidence.SourceRunnerLog,
				Provenance: evidence.Provenance{File: 1, Offset: 300},
			}},
		}}
	}
	return writeTimelineBundle(t, inc)
}

func exitAnchors(failures []causal.FailureAnalysis) int {
	n := 0
	for _, f := range failures {
		if f.AnchorType == causal.EventProcessExited {
			n++
		}
	}
	return n
}

func analyzeExitAnchors(t *testing.T, path string) int {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"analyze", "--json", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyze --json = %d: %s", code, stderr.String())
	}
	var output struct {
		Failures []causal.FailureAnalysis `json:"failures"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return exitAnchors(output.Failures)
}

func TestTimedOutJobKillIsNotAFailure(t *testing.T) {
	if n := exitAnchors(timelineFailureAnchors(t, timedOutJobBundle(t, nil))); n == 0 {
		t.Fatal("baseline SIGKILL without a stated timeout produced no failure anchor; fixture is not testing the cover")
	}
	stated := -500 * time.Millisecond // the runner states the timeout, then kills
	path := timedOutJobBundle(t, &stated)
	if n := exitAnchors(timelineFailureAnchors(t, path)); n != 0 {
		t.Fatalf("timeline: a stated timeout left %d PROCESS_EXITED failure anchors, want 0", n)
	}
	if n := analyzeExitAnchors(t, path); n != 0 {
		t.Fatalf("analyze: a stated timeout left %d PROCESS_EXITED failure anchors, want 0", n)
	}
}

func TestTimeoutStatedLongAfterTheKillDoesNotCover(t *testing.T) {
	late := 5 * time.Minute
	if n := exitAnchors(timelineFailureAnchors(t, timedOutJobBundle(t, &late))); n == 0 {
		t.Fatal("a timeout stated 5 minutes after the kill covered it; T2 bounds the cover")
	}
}
