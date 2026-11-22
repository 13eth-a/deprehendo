package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"runopsy/internal/diagnosis"
)

func TestEvaluateHealthyFixtureConfusionMatrix(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("../../internal/incident/testdata/v1-minimal.runopsy")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "healthy.runopsy")
	if err := os.WriteFile(fixture, data, 0600); err != nil {
		t.Fatal(err)
	}
	truth := []byte(`{"healthy":true}`)
	if err := os.WriteFile(fixture+".ground-truth.json", truth, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"evaluate", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("evaluate exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{"1 incidents analyzed", "Correct top diagnosis: 1/1", "False positives:       0", "UNKNOWN"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("evaluation output missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"evaluate", "--json", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("evaluate json exit %d: %s", code, stderr.String())
	}
	var result diagnosis.Evaluation
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.Total != 1 || result.Unknown != 1 || result.Confusion["NO_KNOWN_FAILURE"]["UNKNOWN"] != 1 || result.FalsePositives != 0 || result.CorrectTop != 1 {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestEvaluateMissingTruthFails(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("../../internal/incident/testdata/v1-minimal.runopsy")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "missing.runopsy"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"evaluate", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("missing ground truth should fail")
	}
	if !strings.Contains(stderr.String(), "ground truth") {
		t.Errorf("error should identify missing ground truth: %s", stderr.String())
	}
}

func TestEvaluateRejectsEmptyDirectory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"evaluate", t.TempDir()}, &stdout, &stderr); code == 0 {
		t.Fatal("empty directory should fail")
	}
}
