package tests

// the hosted analyzer (deprehendo-analyzer, the child every cloud upload and
// re-analysis runs) must produce the same document as the CLI's
// `analyze --document` for a bundle captured on a GitHub runner. until
// november 21, 2026 it did not register the GitHub provider, so the cloud
// dropped provider signatures and intent from every real-runner incident while
// fixtures without provider data still matched byte for byte (7.62).

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPhase7HostedAnalyzerInterpretsGitHub(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "testdata", "github", "selfhosted-e2e-job-success", "incident.deprehendo")
	dir := t.TempDir()
	hosted := filepath.Join(dir, "hosted.json")
	local := filepath.Join(dir, "local.json")

	if out, err := exec.Command(analyzerPath, "-parent", "-bundle", bundle, "-out", hosted).CombinedOutput(); err != nil {
		t.Fatalf("deprehendo-analyzer -parent: %v\n%s", err, out)
	}
	if out, err := exec.Command(agentPath, "analyze", "--document", local, bundle).CombinedOutput(); err != nil {
		t.Fatalf("deprehendo-agent analyze --document: %v\n%s", err, out)
	}
	h, err := os.ReadFile(hosted)
	if err != nil {
		t.Fatal(err)
	}
	l, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}

	// without the provider registered, the section is copied in but never
	// interpreted: generic stays empty. require interpreted events.
	var doc struct {
		Providers []struct {
			Provider string
			Generic  []json.RawMessage
		} `json:"providers"`
	}
	if err := json.Unmarshal(h, &doc); err != nil {
		t.Fatalf("hosted document: %v", err)
	}
	interpreted := false
	for _, p := range doc.Providers {
		if p.Provider == "github-actions" && len(p.Generic) > 0 {
			interpreted = true
		}
	}
	if !interpreted {
		t.Fatal("the hosted document has no interpreted github-actions events: deprehendo-analyzer did not register the GitHub provider")
	}
	if !bytes.Equal(h, l) {
		t.Fatalf("the hosted document (%d bytes) differs from the CLI document (%d bytes) for a GitHub-runner bundle", len(h), len(l))
	}
}
