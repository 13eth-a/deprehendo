// phase 7 dashboard leg (7.61, integration lane).
//
// the server test compares the document the cloud serves with the document the
// CLI wrote, byte for byte. this test closes the last leg: it hands that
// document to the dashboard's own components and asserts the page shows the
// same diagnosis, the same incident and the same paging the document carries.
//
// it is skipped, not failed, where the web workspace is not installed: a go
// checkout that never ran `npm install` still has a green suite, and the skip
// says how to enable the check.
package tests

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type renderedDocument struct {
	DocumentVersion int     `json:"document_version"`
	IncidentID      string  `json:"incident_id"`
	Headline        string  `json:"headline"`
	ConfidenceBand  *string `json:"confidence_band"`
	Unknown         bool    `json:"unknown"`
	TimelineTotal   int     `json:"timeline_total"`
	PageRows        int     `json:"page_rows"`
	PageFirstID     *string `json:"page_first_id"`
	DOMNodes        int     `json:"dom_nodes"`
	HTMLBytes       int     `json:"html_bytes"`
}

func TestPhase7DashboardRendersTheCLIDocument(t *testing.T) {
	if testing.Short() {
		t.Skip("renders a stored document through the dashboard components")
	}
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	webdir := filepath.Join(root, "web")
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not on PATH: the dashboard leg needs it")
	}
	if _, err := os.Stat(filepath.Join(webdir, "node_modules", "react-dom")); err != nil {
		t.Skip("web/node_modules is not installed (cd web && npm install): the dashboard leg needs it")
	}

	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	docpath := filepath.Join(t.TempDir(), "document.json")
	out, code := runAgentCLI(t, "analyze", "--document", docpath, bundlepath)
	if code != 0 {
		t.Fatalf("analyze --document exited %d:\n%s", code, out)
	}
	raw, err := os.ReadFile(docpath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		DocumentVersion int `json:"document_version"`
		Bundle          struct {
			IncidentID string `json:"incident_id"`
		} `json:"bundle"`
		Diagnosis *struct {
			Unknown bool `json:"unknown"`
			Matches []struct {
				Signature      string `json:"signature"`
				ConfidenceBand string `json:"confidence_band"`
			} `json:"matches"`
		} `json:"diagnosis"`
		Timeline []json.RawMessage `json:"timeline"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse the CLI document: %v", err)
	}
	wantheadline := "NO KNOWN SIGNATURE"
	var wantBand *string
	if doc.Diagnosis != nil && len(doc.Diagnosis.Matches) > 0 {
		wantheadline = doc.Diagnosis.Matches[0].Signature
		band := doc.Diagnosis.Matches[0].ConfidenceBand
		wantBand = &band
	}

	cmd := exec.Command("node", "--import", "tsx", "test/render-document.tsx", docpath)
	cmd.Dir = webdir
	rendered, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("render the document: %v\n%s", err, rendered)
	}
	if bytes := strings.TrimSpace(string(rendered)); !strings.HasPrefix(bytes, "{") {
		t.Fatalf("renderer did not print a JSON line:\n%s", rendered)
	}
	var got renderedDocument
	line := lastLine(string(rendered))
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("parse the rendered summary: %v\n%s", err, rendered)
	}

	if got.DocumentVersion != 1 {
		t.Errorf("rendered document_version = %d, want 1", got.DocumentVersion)
	}
	if got.IncidentID != doc.Bundle.IncidentID {
		t.Errorf("rendered incident = %q, document = %q", got.IncidentID, doc.Bundle.IncidentID)
	}
	if got.Headline != wantheadline {
		t.Errorf("dashboard headline = %q, the document says %q", got.Headline, wantheadline)
	}
	if wantBand == nil {
		if got.ConfidenceBand != nil {
			t.Errorf("dashboard invented a confidence %q for an undiagnosed document", *got.ConfidenceBand)
		}
	} else if got.ConfidenceBand == nil || *got.ConfidenceBand != *wantBand {
		t.Errorf("dashboard confidence = %v, document = %q", got.ConfidenceBand, *wantBand)
	}
	if doc.Diagnosis != nil && got.Unknown != doc.Diagnosis.Unknown {
		t.Errorf("dashboard unknown = %v, document = %v", got.Unknown, doc.Diagnosis.Unknown)
	}
	if got.TimelineTotal != len(doc.Timeline) {
		t.Errorf("dashboard total = %d events, document has %d", got.TimelineTotal, len(doc.Timeline))
	}
	wantpage := len(doc.Timeline)
	if wantpage > 200 {
		wantpage = 200
	}
	if got.PageRows != wantpage {
		t.Errorf("dashboard rendered %d rows, want one page of %d", got.PageRows, wantpage)
	}
	if got.DOMNodes < 20 || got.HTMLBytes <= 0 {
		t.Errorf("the page rendered nothing (%d nodes, %d bytes)", got.DOMNodes, got.HTMLBytes)
	}

	// 7.32: an unsupported document is reported, never silently blank.
	badpath := filepath.Join(t.TempDir(), "unsupported.json")
	if err := os.WriteFile(badpath, []byte(`{"document_version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := exec.Command("node", "--import", "tsx", "test/render-document.tsx", badpath)
	bad.Dir = webdir
	badout, baderr := bad.CombinedOutput()
	if baderr == nil {
		t.Fatalf("the renderer accepted document_version 99:\n%s", badout)
	}
	if !strings.Contains(string(badout), "unsupported document") {
		t.Errorf("unsupported document was not explained:\n%s", badout)
	}
}

// lastLine is the renderer's JSON line; tsx prints nothing else on success.
func lastLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
