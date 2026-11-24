package diagnosis

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

func writeEvaluationFixture(t *testing.T, dir, name string, i *incident.Incident, truth GroundTruth) string {
	t.Helper()
	var data bytes.Buffer
	if err := incident.Encode(&data, i, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".deprehendo")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	label, err := json.Marshal(truth)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".ground-truth.json", label, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEvaluateDirectoryGroundTruthConfusionAndOrdering(t *testing.T) {
	dir := t.TempDir()
	end := at(55 * time.Second)
	healthy := validIncident(t, at(0), end)
	healthy.Snapshots = sampleSeries(t, at(0), 12, 5*time.Second, func(index int) collector.Snapshot {
		return systemSnapshot(at(0), 30, 80)
	})
	mustValid(t, healthy)
	writeEvaluationFixture(t, dir, "z-healthy", healthy, GroundTruth{Healthy: true})

	frozen := validIncident(t, at(0), end)
	frozen.Trigger = incident.Trigger{Type: "process_stopped", PID: 100, StartTicks: 100}
	frozen.Snapshots = sampleSeries(t, at(0), 12, 5*time.Second, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "T", 0)
	})
	mustValid(t, frozen)
	writeEvaluationFixture(t, dir, "a-frozen", frozen, GroundTruth{ExpectedSignature: string(SignatureFrozenProcess)})

	result, err := EvaluateDirectory(dir, Options{})
	if err != nil {
		t.Fatalf("EvaluateDirectory: %v", err)
	}
	if result.Total != 2 || result.CorrectTop != 2 || result.Unknown != 1 || result.FalsePositives != 0 {
		t.Errorf("summary: %+v", result)
	}
	if len(result.Cases) != 2 || filepath.Base(result.Cases[0].Path) != "a-frozen.deprehendo" || filepath.Base(result.Cases[1].Path) != "z-healthy.deprehendo" {
		t.Errorf("cases not sorted: %+v", result.Cases)
	}
	if result.Confusion[string(SignatureFrozenProcess)][string(SignatureFrozenProcess)] != 1 || result.Confusion["NO_KNOWN_FAILURE"]["UNKNOWN"] != 1 {
		t.Errorf("confusion matrix: %+v", result.Confusion)
	}
}

func TestEvaluateRejectsMalformedOrMissingGroundTruth(t *testing.T) {
	for name, content := range map[string]string{
		"missing": "",
		"invalid": "{not json",
		"empty":   `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			end := at(time.Second)
			i := validIncident(t, at(0), end)
			i.Snapshots = []collector.Snapshot{systemSnapshot(at(0), 20, 80)}
			mustValid(t, i)
			path := writeEvaluationFixture(t, dir, "case", i, GroundTruth{Healthy: true})
			truthpath := path + ".ground-truth.json"
			if name == "missing" {
				if err := os.Remove(truthpath); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(truthpath, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := EvaluateDirectory(dir, Options{}); err == nil {
				t.Fatal("expected ground-truth error")
			}
		})
	}
}

func TestEvaluateNoFixtures(t *testing.T) {
	if _, err := EvaluateDirectory(t.TempDir(), Options{}); err == nil {
		t.Fatal("empty evaluation directory should fail")
	}
}

func TestEvaluationTextRendering(t *testing.T) {
	var out bytes.Buffer
	evaluation := &Evaluation{
		Total: 2, CorrectTop: 1, FalsePositives: 1, Unknown: 1, Accuracy: 0.5,
		Confusion: map[string]map[string]int{
			"CPU_SPIN":         {"UNKNOWN": 1},
			"NO_KNOWN_FAILURE": {"CPU_SPIN": 1},
		},
	}
	if err := WriteEvaluation(&out, evaluation); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 incidents analyzed", "Correct top diagnosis: 1/2", "False positives:       1", "Confusion matrix"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q: %s", want, out.String())
		}
	}
}
