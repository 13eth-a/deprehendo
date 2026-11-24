package diagnosis

import (
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
)

// resolveExclusions must suppress the weaker side of an excluded pair only
// when a margin separates them, and report ambiguity otherwise (3.21).
func TestExclusionWinnerByMargin(t *testing.T) {
	matches := []SignatureMatch{
		{SignatureID: SignatureBrokerStall, Confidence: 0.90},
		{SignatureID: SignatureNetworkFailure, Confidence: 0.60},
	}
	out, rejections, ambiguous := resolveExclusions(matches, nil)
	if len(out) != 1 || out[0].SignatureID != SignatureBrokerStall {
		t.Fatalf("expected the stronger match to survive, got %+v", out)
	}
	if len(rejections) != 1 || rejections[0].SignatureID != SignatureNetworkFailure {
		t.Fatalf("expected the weaker match demoted, got %+v", rejections)
	}
	if !strings.Contains(rejections[0].Rejected, "excluded by higher-confidence BROKER_SOCKET_STALL") {
		t.Errorf("rejection reason: %q", rejections[0].Rejected)
	}
	if len(ambiguous) != 0 {
		t.Errorf("clear winners are not ambiguous: %v", ambiguous)
	}
}

func TestExclusionAmbiguityUnderMargin(t *testing.T) {
	matches := []SignatureMatch{
		{SignatureID: SignatureNetworkFailure, Confidence: 0.75},
		{SignatureID: SignatureBrokerStall, Confidence: 0.80},
	}
	out, rejections, ambiguous := resolveExclusions(matches, nil)
	if len(out) != 2 {
		t.Fatalf("both must survive the ambiguity case, got %+v", out)
	}
	if len(rejections) != 0 {
		t.Fatalf("nothing under the margin may be demoted: %+v", rejections)
	}
	if len(ambiguous) != 1 || !strings.Contains(ambiguous[0], "BROKER_SOCKET_STALL vs NETWORK_PATH_FAILURE") {
		t.Errorf("ambiguous pair: %v", ambiguous)
	}
	if out[0].SignatureID != SignatureBrokerStall {
		t.Errorf("matches must be ordered by confidence then ID: %+v", out)
	}
}

// A threshold-below evaluation must be recorded as a rejection carrying its
// reason, never silently discarded: --explain reads those.
func TestRejectionsCarryEvidenceForExplain(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, time.Second*5, func(index int) collector.Snapshot {
		if index > 5 {
			return systemSnapshot(at(0), 30, 80) // memory/pressure section present, no process scan
		}
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "S", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(report.Rejections) == 0 {
		t.Fatalf("expected rejections to be recorded")
	}
	for _, rejection := range report.Rejections {
		if rejection.Rejected == "" {
			t.Errorf("rejection %s missing reason", rejection.SignatureID)
		}
	}
}

func TestOptionsDisable(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, time.Second*5, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "T", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{Disable: []SignatureID{SignatureFrozenProcess}})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, match := range report.Matches {
		if match.SignatureID == SignatureFrozenProcess {
			t.Errorf("disabled signature still matched")
		}
	}
	if report.Unknown != true {
		t.Errorf("only the frozen trigger existed; disabling must move to UNKNOWN")
	}
}

func TestCustomThreshold(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, time.Second*5, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "T", 0) // frozen at 0.75
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{MinConfidence: 0.80})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(report.Matches) != 0 {
		t.Errorf("0.75 must fall under a 0.80 threshold, got %+v", report.Matches)
	}
	if report.MinConfidence != 0.80 {
		t.Errorf("threshold not reflected: %v", report.MinConfidence)
	}
	if !report.Unknown {
		t.Errorf("no threshold crossings means UNKNOWN")
	}
}
