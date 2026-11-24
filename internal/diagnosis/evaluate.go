package diagnosis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"deprehendo/internal/incident"
)

// GroundTruth is test-corpus metadata. it is deliberately stored beside
// fixtures, never inside a production incident bundle (3.30).
type GroundTruth struct {
	ExpectedSignature string `json:"expected_signature"`
	Healthy           bool   `json:"healthy,omitempty"`
}

// EvaluationCase is one bundle and its out-of-band expected label.
type EvaluationCase struct {
	Path      string      `json:"path"`
	Truth     GroundTruth `json:"ground_truth"`
	Report    *Report     `json:"report"`
	Predicted string      `json:"predicted"`
}

// evaluation summarizes corpus predictions. confusion rows are expected
// labels, columns are predictions; UNKNOWN and NO_KNOWN_FAILURE are ordinary
// labels so healthy false positives and no-match cases stay visible.
type Evaluation struct {
	Cases          []EvaluationCase          `json:"cases"`
	Confusion      map[string]map[string]int `json:"confusion_matrix"`
	CorrectTop     int                       `json:"correct_top"`
	Total          int                       `json:"total"`
	FalsePositives int                       `json:"false_positives"`
	Unknown        int                       `json:"unknown"`
	Accuracy       float64                   `json:"accuracy"`
}

// EvaluateDirectory analyzes all top-level *.deprehendo files in dir with a
// neighboring <bundle>.ground-truth.json file. Test-only metadata is out of
// band; a missing or malformed label is an error. directory traversal is
// non-recursive and sorted so output is reproducible.
func EvaluateDirectory(dir string, options Options) (*Evaluation, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("diagnosis: read evaluation directory: %w", err)
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".deprehendo") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("diagnosis: no .deprehendo fixtures in %q", dir)
	}
	result := &Evaluation{Confusion: map[string]map[string]int{}}
	for _, path := range paths {
		truth, err := readGroundTruth(path + ".ground-truth.json")
		if err != nil {
			return nil, err
		}
		bundle, err := incident.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("diagnosis: fixture %s: %w", filepath.Base(path), err)
		}
		report, err := Analyze(bundle.Incident, options)
		if err != nil {
			return nil, fmt.Errorf("diagnosis: fixture %s: %w", filepath.Base(path), err)
		}
		predicted := "UNKNOWN"
		if len(report.Matches) > 0 {
			predicted = string(report.Matches[0].SignatureID)
		}
		want := truth.ExpectedSignature
		if truth.Healthy {
			want = "NO_KNOWN_FAILURE"
		}
		if want == "" {
			return nil, fmt.Errorf("diagnosis: fixture %s has empty expected_signature", filepath.Base(path))
		}
		result.Cases = append(result.Cases, EvaluationCase{Path: path, Truth: truth, Report: report, Predicted: predicted})
		result.Total++
		correct := predicted == want || (truth.Healthy && predicted == "UNKNOWN")
		if correct {
			result.CorrectTop++
		}
		if truth.Healthy && predicted != "NO_KNOWN_FAILURE" && predicted != "UNKNOWN" {
			result.FalsePositives++
		}
		if predicted == "UNKNOWN" {
			result.Unknown++
			// for an expected positive signature, UNKNOWN is an explicit false
			// negative rather than a wrong classifier label hidden as unknown.
			if !truth.Healthy {
				want = truth.ExpectedSignature
			}
		}
		if result.Confusion[want] == nil {
			result.Confusion[want] = map[string]int{}
		}
		result.Confusion[want][predicted]++
	}
	if result.Total > 0 {
		result.Accuracy = float64(result.CorrectTop) / float64(result.Total)
	}
	return result, nil
}

func readGroundTruth(path string) (GroundTruth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GroundTruth{}, fmt.Errorf("diagnosis: read ground truth %s: %w", filepath.Base(path), err)
	}
	var truth GroundTruth
	if err := json.Unmarshal(data, &truth); err != nil {
		return GroundTruth{}, fmt.Errorf("diagnosis: parse ground truth %s: %w", filepath.Base(path), err)
	}
	if truth.ExpectedSignature == "" && !truth.Healthy {
		return GroundTruth{}, fmt.Errorf("diagnosis: ground truth %s needs expected_signature or healthy=true", filepath.Base(path))
	}
	return truth, nil
}

// WriteEvaluation writes a deterministic text confusion matrix and summary.
func WriteEvaluation(out io.Writer, evaluation *Evaluation) error {
	if evaluation == nil {
		return fmt.Errorf("diagnosis: nil evaluation")
	}
	var rendered strings.Builder
	destination := out
	out = &rendered
	labels := map[string]bool{"UNKNOWN": true, "NO_KNOWN_FAILURE": true}
	for expected, predictions := range evaluation.Confusion {
		labels[expected] = true
		for predicted := range predictions {
			labels[predicted] = true
		}
	}
	ordered := make([]string, 0, len(labels))
	for label := range labels {
		ordered = append(ordered, label)
	}
	sort.Strings(ordered)
	fmt.Fprintf(out, "%d incidents analyzed\n", evaluation.Total)
	fmt.Fprintf(out, "Correct top diagnosis: %d/%d (%.1f%%)\n", evaluation.CorrectTop, evaluation.Total, evaluation.Accuracy*100)
	fmt.Fprintf(out, "False positives:       %d\n", evaluation.FalsePositives)
	fmt.Fprintf(out, "Unknown:               %d\n", evaluation.Unknown)
	fmt.Fprintln(out, "\nConfusion matrix (rows=expected, columns=predicted)")
	fmt.Fprintf(out, "%-30s", "expected \\ predicted")
	for _, label := range ordered {
		fmt.Fprintf(out, " %10s", compactLabel(label))
	}
	fmt.Fprintln(out)
	for _, expected := range ordered {
		fmt.Fprintf(out, "%-30s", compactLabel(expected))
		for _, predicted := range ordered {
			fmt.Fprintf(out, " %10d", evaluation.Confusion[expected][predicted])
		}
		fmt.Fprintln(out)
	}
	_, err := io.WriteString(destination, rendered.String())
	return err
}

func compactLabel(label string) string {
	if len(label) <= 10 {
		return label
	}
	return label[:10]
}
