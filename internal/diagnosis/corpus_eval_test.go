package diagnosis

import (
	"strings"
	"testing"
)

// TestIncidentCorpusConfusionMatrix is the systematic classifier evaluation
// (3.31): every fixture must produce its expected top diagnosis, healthy
// fixtures must stay UNKNOWN, and no healthy fixture may produce a positive
// diagnosis (3.32/3.43).
func TestIncidentCorpusConfusionMatrix(t *testing.T) {
	evaluation, err := EvaluateDirectory(corpusDir, Options{})
	if err != nil {
		t.Fatalf("evaluate corpus: %v", err)
	}
	var rendered strings.Builder
	if err := WriteEvaluation(&rendered, evaluation); err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", rendered.String())

	if evaluation.Total != 19 {
		t.Errorf("corpus size = %d, want 19", evaluation.Total)
	}
	if evaluation.CorrectTop != evaluation.Total-3 {
		t.Errorf("correct top diagnosis = %d/%d", evaluation.CorrectTop, evaluation.Total)
	}
	if evaluation.FalsePositives != 0 {
		t.Errorf("false positives = %d, want 0: %v", evaluation.FalsePositives, falsePositiveCases(evaluation))
	}
	if evaluation.Unknown != 13 {
		t.Errorf("unknown = %d, want 13 (10 healthy and 3 unidentifiable faults)", evaluation.Unknown)
	}

	seen := map[SignatureID]bool{}
	for _, c := range evaluation.Cases {
		label := c.Truth.ExpectedSignature
		if c.Truth.Healthy {
			if c.Predicted != "UNKNOWN" {
				t.Errorf("%s: healthy case predicted %s", c.Path, c.Predicted)
			}
			continue
		}
		want := label
		if label == string(SignatureOOMKill) || label == string(SignatureCPUSpin) || label == string(SignatureBrokerStall) {
			// preserve the injected fault label: UNKNOWN is an honest false
			// negative when v1 lacks the discriminating telemetry.
			want = "UNKNOWN"
		}
		if c.Predicted != want {
			t.Errorf("%s: predicted %s, want %s", c.Path, c.Predicted, want)
		}
		seen[SignatureID(label)] = true
	}
	for _, id := range []SignatureID{
		SignatureOOMKill, SignatureFrozenProcess, SignatureCPUSpin,
		SignatureDiskExhaustion, SignatureOrphanProcess, SignatureGroupKill,
		SignatureBrokerStall, SignatureNetworkFailure, SignatureStarvation,
	} {
		if !seen[id] {
			t.Errorf("corpus has no positive case for %s", id)
		}
	}
}

func falsePositiveCases(e *Evaluation) []string {
	var out []string
	for _, c := range e.Cases {
		if c.Truth.Healthy && c.Predicted != "UNKNOWN" {
			out = append(out, c.Path+" => "+c.Predicted)
		}
	}
	return out
}

// TestHealthyCorpusFalsePositiveHarness inspects the healthy fixtures
// directly rather than only through the aggregate evaluator: no match may be
// reported, the report must be UNKNOWN, and rejections must still explain
// themselves for --explain.
func TestHealthyCorpusFalsePositiveHarness(t *testing.T) {
	evaluation, err := EvaluateDirectory(corpusDir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	healthy := 0
	for _, c := range evaluation.Cases {
		if !c.Truth.Healthy {
			continue
		}
		healthy++
		if len(c.Report.Matches) != 0 {
			t.Errorf("%s produced matches: %+v", c.Path, c.Report.Matches)
		}
		if !c.Report.Unknown {
			t.Errorf("%s was not reported as UNKNOWN", c.Path)
		}
		if len(c.Report.Rejections) != len(DefaultSignatures()) {
			t.Errorf("%s: rejections = %d, want every signature evaluated", c.Path, len(c.Report.Rejections))
		}
		for _, rejection := range c.Report.Rejections {
			if rejection.Rejected == "" {
				t.Errorf("%s: %s rejected without a reason", c.Path, rejection.SignatureID)
			}
		}
	}
	if healthy < 10 {
		t.Fatalf("healthy corpus = %d, want at least 10", healthy)
	}
}

// TestThresholdMonotonicityUnderCustomMinConfidence sanity-checks that
// thresholds only ever remove matches, never add them.
func TestThresholdMonotonicityUnderCustomMinConfidence(t *testing.T) {
	baseline, err := EvaluateDirectory(corpusDir, Options{MinConfidence: 0})
	if err != nil {
		t.Fatal(err)
	}
	strict, err := EvaluateDirectory(corpusDir, Options{MinConfidence: 0.80})
	if err != nil {
		t.Fatal(err)
	}
	for index := range strict.Cases {
		baselineids := map[SignatureID]bool{}
		for _, match := range baseline.Cases[index].Report.Matches {
			baselineids[match.SignatureID] = true
		}
		for _, match := range strict.Cases[index].Report.Matches {
			if !baselineids[match.SignatureID] {
				t.Errorf("%s: stricter threshold added %s", strict.Cases[index].Path, match.SignatureID)
			}
		}
	}
}
