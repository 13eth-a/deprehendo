package github

import (
	"testing"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// A stated SUCCEEDED job intends its worker's exit (the normal end of a job).
// A stated failure must not: it keeps normal failure semantics.
func TestJobCompletedIntentOnlyForStatedSuccess(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		outcome evidence.Outcome
		want    bool
	}{
		{evidence.OutcomeSucceeded, true},
		{evidence.OutcomeFailed, false},
	} {
		section := evidence.Section{Events: []evidence.Event{{
			Type: EventJobCompleted, Timestamp: at, Runner: "runner-a", Worker: "worker-1",
			Outcome: tc.outcome, Source: evidence.SourceRunnerLog,
		}}}
		out, err := interpret(section, nil)
		if err != nil {
			t.Fatalf("interpret: %v", err)
		}
		found := false
		for _, ge := range out.Generic {
			if ge.Kind == provider.GenericTerminationIntended && ge.Intent == provider.IntentJobSucceeded {
				found = true
			}
		}
		if found != tc.want {
			t.Errorf("outcome %s: JOB_SUCCEEDED intent = %v, want %v", tc.outcome, found, tc.want)
		}
	}
}
