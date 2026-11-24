package analysis

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deprehendo/internal/incident"
)

// documentBytes renders one fixture the way both the CLI (--document) and the
// cloud worker do, from the same bundle bytes.
func documentBytes(t *testing.T, path string) ([]byte, *Document) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	bundle, err := incident.Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	doc, err := Run(bundle, SHA256OfBytes(raw), Options{})
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out.Bytes(), doc
}

// TestFixturesProduceStableDocuments is the 7.43 half that can run without a
// cloud: for every captured fixture, rendering twice produces identical bytes,
// and the document names the exact bundle bytes it analyzed. the cloud cannot
// be "more right" than this file, because the cloud stores exactly these bytes.
func TestFixturesProduceStableDocuments(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus render is not a short-mode test")
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "incidents", "*.deprehendo"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			first, doc := documentBytes(t, path)
			second, _ := documentBytes(t, path)
			if !bytes.Equal(first, second) {
				t.Fatalf("%s rendered differently on a second run", path)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Bundle.SHA256 != SHA256OfBytes(raw) {
				t.Errorf("document sha256 = %q, want the digest of the analyzed bytes", doc.Bundle.SHA256)
			}
			if doc.Bundle.IncidentID == "" {
				t.Error("document has no incident id")
			}
			if doc.DocumentVersion != DocumentVersion {
				t.Errorf("document version = %d", doc.DocumentVersion)
			}
		})
	}
}

// TestDocumentRecordsCompatibilityIdentity pins the fields 7.33 requires a
// viewer to keep: bundle schema, analyzer version, signature set and causal
// rule set. they are asserted by JSON name because the cloud reads JSON, not
// this go struct.
func TestDocumentRecordsCompatibilityIdentity(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "incidents", "cpu-spin.deprehendo")
	raw, _ := documentBytes(t, path)

	type formatShape struct {
		FormatVersion int `json:"format_version"`
		SchemaVersion int `json:"schema_version"`
	}
	type engineShape struct {
		AnalyzerVersion     string        `json:"analyzer_version"`
		SignatureVersion    int           `json:"signature_version"`
		SignatureSetVersion int           `json:"signature_set_version"`
		CausalRules         string        `json:"causal_rules"`
		PrivacyPolicy       string        `json:"privacy_policy"`
		BundleFormats       []formatShape `json:"bundle_formats"`
	}
	var shaped struct {
		DocumentVersion int                        `json:"document_version"`
		Engine          engineShape                `json:"engine"`
		Bundle          map[string]json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &shaped); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	if shaped.DocumentVersion != 1 {
		t.Errorf("document_version = %d, want 1", shaped.DocumentVersion)
	}
	for _, key := range []string{"sha256", "schema_version", "format_version", "incident_id"} {
		if _, ok := shaped.Bundle[key]; !ok {
			t.Errorf("bundle.%s missing from the document", key)
		}
	}

	engine := shaped.Engine
	if engine.AnalyzerVersion == "" || engine.SignatureVersion == 0 || engine.SignatureSetVersion == 0 {
		t.Errorf("engine identity incomplete: %+v", engine)
	}
	if len(engine.CausalRules) != 64 || strings.Trim(engine.CausalRules, "0123456789abcdef") != "" {
		t.Errorf("causal_rules = %q, want a sha256", engine.CausalRules)
	}
	if engine.PrivacyPolicy != incident.PrivacyPolicy {
		t.Errorf("privacy_policy = %q, want %q", engine.PrivacyPolicy, incident.PrivacyPolicy)
	}
	found := false
	for _, format := range engine.BundleFormats {
		if format.SchemaVersion == incident.SchemaVersion && format.FormatVersion == incident.FormatVersion {
			found = true
		}
	}
	if !found {
		t.Errorf("bundle_formats %+v does not declare the current format", engine.BundleFormats)
	}
}
