package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"runopsy/internal/analysis"
	"runopsy/internal/incident"
)

// demoManifest is the dashboard fixture-mode corpus (7.41/7.42) at
// testdata/demo/manifest.json. it is data for the web app, not go: the test
// below is what keeps it honest, because a manifest that names a diagnosis the
// engine no longer reaches would put a fabricated screenshot on the README.
type demoManifest struct {
	Version     int            `json:"version"`
	BundleRoots []string       `json:"bundle_roots"`
	Scenarios   []demoScenario `json:"scenarios"`
}

type demoScenario struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Checklist     string `json:"checklist"`
	Source        string `json:"source"`
	Bundle        string `json:"bundle"`
	DeclaredLabel string `json:"declared_label"`
	EngineVerdict string `json:"engine_verdict"`
	// ProviderSignature, when set, is a provider finding the document must
	// carry. it is how a scenario whose generic verdict abstains (the real
	// communication stall) still states what was found.
	ProviderSignature string   `json:"provider_signature"`
	Headline          bool     `json:"headline"`
	Summary           string   `json:"summary"`
	Panels            []string `json:"panels"`
}

// demoBundleRoots maps each folder a demo bundle may come from to the source
// the manifest must declare for it: the checked-in evaluation corpus, or real
// GitHub runner captures (7.62). nothing else is allowed.
var demoBundleRoots = map[string]string{
	"testdata/incidents":               "fixture",
	"testdata/github/real-runner-demo": "real-runner",
}

// requiredDemoScenarios are the seven situations checklist 7.41 requires the
// dashboard to be seedable with. the manifest uses one stable id per situation
// so the web fixture loader never keys on a label.
var requiredDemoScenarios = map[string]string{
	"oom-kill":             "oom",
	"frozen-worker":        "frozen worker",
	"broker-stall":         "broker stall",
	"network-failure":      "network failure",
	"orphan-worker":        "orphan worker",
	"runner-self-kill":     "runner self-kill",
	"healthy-cancellation": "healthy cancellation",
}

// screenshotDemoScenarios is 7.42's chosen five: OOM kill, communication stall,
// runner self-termination, orphaned job and frozen worker.
var screenshotDemoScenarios = map[string]bool{
	"oom-kill":         true,
	"broker-stall":     true,
	"runner-self-kill": true,
	"orphan-worker":    true,
	"frozen-worker":    true,
}

var demoPanels = map[string]bool{
	"overview": true, "diagnosis": true, "causal": true, "timeline": true,
	"resources": true, "process-tree": true, "network": true, "events": true,
}

// TestDemoCorpusMatchesTheEngine validates the dashboard fixture corpus
// against the canonical engine: every scenario's bundle reads, renders a
// document, and produces exactly the verdict the manifest promises.
func TestDemoCorpusMatchesTheEngine(t *testing.T) {
	if testing.Short() {
		t.Skip("renders every demo bundle through the engine")
	}
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	manifestpath := filepath.Join(root, "testdata", "demo", "manifest.json")
	data, err := os.ReadFile(manifestpath)
	if err != nil {
		t.Fatalf("read demo manifest: %v", err)
	}
	var manifest demoManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("%s is not valid JSON: %v", manifestpath, err)
	}
	if manifest.Version != 2 {
		t.Errorf("manifest version = %d, want 2", manifest.Version)
	}
	if len(manifest.BundleRoots) != len(demoBundleRoots) {
		t.Errorf("bundle_roots = %q, want exactly the corpus and the real-runner captures", manifest.BundleRoots)
	}
	for _, r := range manifest.BundleRoots {
		if _, ok := demoBundleRoots[r]; !ok {
			t.Errorf("bundle_roots names %q, which is not an allowed demo folder", r)
		}
	}
	// Real-runner bundles carry a GitHub section; interpret it the way the
	// shipped binaries do, so provider_signature can be checked.
	registerGitHub(t)

	seen := map[string]bool{}
	headlines := 0
	for _, scenario := range manifest.Scenarios {
		scenario := scenario
		t.Run(scenario.ID, func(t *testing.T) {
			if scenario.ID == "" || seen[scenario.ID] {
				t.Fatalf("missing or duplicate scenario id %q", scenario.ID)
			}
			seen[scenario.ID] = true
			if scenario.Title == "" || scenario.Checklist == "" {
				t.Error("scenario needs a title and the checklist item it satisfies")
			}
			if len(scenario.Summary) < 40 {
				t.Errorf("summary is too short to explain the incident: %q", scenario.Summary)
			}
			if len(scenario.Panels) == 0 {
				t.Error("scenario lists no dashboard panels")
			}
			for _, panel := range scenario.Panels {
				if !demoPanels[panel] {
					t.Errorf("unknown panel %q", panel)
				}
			}

			// path discipline: the manifest may only reference a checked-in
			// demo folder, never a path that walks out of the repository, and
			// the declared source must match the folder.
			clean := filepath.Clean(scenario.Bundle)
			if clean != scenario.Bundle || strings.HasPrefix(clean, "..") {
				t.Fatalf("bundle %q is not a clean repository path", scenario.Bundle)
			}
			folder := filepath.ToSlash(filepath.Dir(clean))
			source, ok := demoBundleRoots[folder]
			if !ok {
				t.Fatalf("bundle %q is not inside an allowed demo folder", scenario.Bundle)
			}
			if scenario.Source != source {
				t.Errorf("source = %q, but bundles in %s are %q", scenario.Source, folder, source)
			}
			raw, err := os.ReadFile(filepath.Join(root, clean))
			if err != nil {
				t.Fatalf("read bundle: %v", err)
			}
			bundle, err := incident.Read(bytes.NewReader(raw), int64(len(raw)))
			if err != nil {
				t.Fatalf("bundle does not validate: %v", err)
			}
			doc, err := analysis.Run(bundle, analysis.SHA256OfBytes(raw), analysis.Options{})
			if err != nil {
				t.Fatalf("render document: %v", err)
			}
			verdict := "UNKNOWN"
			if len(doc.Diagnosis.Matches) > 0 {
				verdict = string(doc.Diagnosis.Matches[0].SignatureID)
			}
			if verdict != scenario.EngineVerdict {
				t.Errorf("engine verdict is %s, manifest says %s (update the manifest deliberately, not to make this pass)", verdict, scenario.EngineVerdict)
			}
			if scenario.DeclaredLabel == "" {
				t.Error("scenario needs the injected-fault label it came from")
			}
			if scenario.ProviderSignature != "" {
				found := false
				for _, interp := range doc.Providers {
					for _, sig := range interp.Signatures {
						if sig.Label == scenario.ProviderSignature {
							found = true
						}
					}
				}
				if !found {
					t.Errorf("provider_signature %s is not in the document's providers section", scenario.ProviderSignature)
				}
			}

			// the declared label is the corpus ground truth, out of band. A
			// mismatch means the manifest is describing a different incident
			// than the bundle it points at.
			truth, err := readDemoGroundTruth(filepath.Join(root, clean) + ".ground-truth.json")
			if err != nil {
				t.Fatalf("ground truth: %v", err)
			}
			want := truth.ExpectedSignature
			if truth.Healthy {
				want = "NO_KNOWN_FAILURE"
			}
			if scenario.DeclaredLabel != want {
				t.Errorf("declared_label = %q, ground truth says %q", scenario.DeclaredLabel, want)
			}

			// fixture mode exists so the dashboard has something to draw: a
			// scenario with no series or timeline would seed blank panels.
			if len(doc.Series) == 0 {
				t.Error("document has no resource series for the charts")
			}
			if len(doc.Timeline) == 0 {
				t.Error("document has no timeline")
			}
			if scenario.Headline {
				headlines++
			}
		})
	}

	for id, checklist := range requiredDemoScenarios {
		if !seen[id] {
			t.Errorf("checklist 7.41 scenario %q (%s) has no demo entry", checklist, id)
		}
	}
	for id := range seen {
		if _, ok := requiredDemoScenarios[id]; !ok {
			t.Errorf("scenario %q is not one of the seven 7.41 situations", id)
		}
	}
	if headlines < 3 || headlines > 5 {
		t.Errorf("%d headline demos, want 3-5 (7.42)", headlines)
	}
	for id := range screenshotDemoScenarios {
		found := false
		for _, scenario := range manifest.Scenarios {
			if scenario.ID == id {
				found = true
				if !scenario.Headline {
					t.Errorf("%q is a 7.42 demo but is not marked headline", id)
				}
			}
		}
		if !found {
			t.Errorf("7.42 demo %q is missing from the manifest", id)
		}
	}
}

func readDemoGroundTruth(path string) (struct {
	ExpectedSignature string `json:"expected_signature"`
	Healthy           bool   `json:"healthy"`
}, error) {
	var out struct {
		ExpectedSignature string `json:"expected_signature"`
		Healthy           bool   `json:"healthy"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(data, &out)
	return out, err
}
