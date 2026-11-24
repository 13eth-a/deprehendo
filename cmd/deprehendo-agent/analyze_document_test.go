package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"deprehendo/internal/analysis"
	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
)

// TestAnalyzeDocumentMatchesWorkerPath is the 7.43/§3.4 local/cloud equality
// check on the CLI side: `analyze --document` must write the same bytes the
// analyzer worker would store for the same bundle, because both come from
// analysis.Run and analysis.WriteJSON.
func TestAnalyzeDocumentMatchesWorkerPath(t *testing.T) {
	const fixture = "../../testdata/incidents/frozen-worker.deprehendo"
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(raw) > incident.MaxArchiveSize {
		t.Fatalf("fixture exceeds archive budget")
	}
	sum := sha256.Sum256(raw)

	bundle, err := incident.Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	expected, err := analysis.Run(bundle, hex.EncodeToString(sum[:]), analysis.Options{MinConfidence: diagnosis.DefaultMinConfidence})
	if err != nil {
		t.Fatalf("analysis.Run: %v", err)
	}
	var want bytes.Buffer
	if err := analysis.WriteJSON(&want, expected); err != nil {
		t.Fatalf("analysis.WriteJSON: %v", err)
	}

	document := filepath.Join(t.TempDir(), "document.json")
	if code := runAnalyze([]string{"--document", document, fixture}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("runAnalyze exit %d", code)
	}
	got, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatal("CLI document differs from the analysis package's document: the cloud would store a different analysis than the CLI prints")
	}
}
