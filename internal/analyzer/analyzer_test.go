package analyzer

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// workerBinary builds the child once per test run.
func workerBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deprehendo-analyzer")
	build := exec.Command("go", "build", "-o", path, "deprehendo/cmd/deprehendo-analyzer")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build child: %v\n%s", err, out)
	}
	return path
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "incidents", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

// TestJobReady drives the contract's success path: bundle in, classified
// READY out, document on stdout, nothing from the bundle in the parent's
// stderr.
func TestJobReady(t *testing.T) {
	runner := NewRunner(workerBinary(t))
	result, err := runner.Run(t.Context(), fixture(t, "frozen-worker.deprehendo"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != StatusReady {
		t.Fatalf("status %s reason %q stderr %q", result.Status, result.Reason, result.Stderr)
	}
	var document struct {
		DocumentVersion int `json:"document_version"`
		Bundle          struct {
			SHA256     string `json:"sha256"`
			IncidentID string `json:"incident_id"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(result.Document, &document); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	if document.DocumentVersion != 1 || document.Bundle.SHA256 == "" || document.Bundle.IncidentID == "" {
		t.Fatalf("document incomplete: %+v", document)
	}
	if len(result.Stderr) != 0 {
		t.Fatalf("parent received diagnostics on a success: %q", result.Stderr)
	}
}

// TestJobRejected: hostile input produces the classified status, no document,
// and a bounded reason.
func TestJobRejected(t *testing.T) {
	runner := NewRunner(workerBinary(t))
	result, err := runner.Run(t.Context(), []byte("not a bundle at all — not even an archive header"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != StatusRejected {
		t.Fatalf("status %s reason %q", result.Status, result.Reason)
	}
	if len(result.Document) != 0 {
		t.Fatalf("rejected job produced output")
	}
	if got := len(result.Stderr); got > maxStderrBytes {
		t.Fatalf("stderr unbounded: %d bytes", got)
	}
}

// TestJobOversized drops the fast-fail budget: an attempt to stream more than
// the archive budget is rejected before any full allocation.
func TestJobOversized(t *testing.T) {
	runner := NewRunner(workerBinary(t))
	oversized := make([]byte, incidentMaxRead())
	oversized[0], oversized[1] = 'P', 'K'
	result, err := runner.Run(t.Context(), oversized)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != StatusRejected {
		t.Fatalf("status %s reason %q", result.Status, result.Reason)
	}
}

// TestJobWallClockLimit: a job that cannot finish inside the parent's wall
// clock ends as FAILED_LIMIT, the boundary the operator sees and can tune,
// not a crash.
func TestJobWallClockLimit(t *testing.T) {
	runner := NewRunner(workerBinary(t))
	runner.Timeout = time.Nanosecond
	result, err := runner.Run(t.Context(), fixture(t, "frozen-worker.deprehendo"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != StatusFailedLimit {
		t.Fatalf("status %s reason %q", result.Status, result.Reason)
	}
}

// TestJobNoDocumentChild: a child that exits 0 without a document is a
// broken deployment, not a decision: FAILED_CRASH.
func TestJobNoDocumentChild(t *testing.T) {
	runner := NewRunner("/bin/true")
	result, err := runner.Run(t.Context(), []byte("anything"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != StatusFailedCrash {
		t.Fatalf("status %s reason %q", result.Status, result.Reason)
	}
}

// TestChildHeightOnBytes: the child truncates whatever exits the parent with
// nonzero diagnostics so one hostile bundle cannot bloat the log stream.
func TestStderrTruncation(t *testing.T) {
	long := bytes.Repeat([]byte("a"), maxStderrBytes*4)
	got := truncateStderr(string(long))
	if len(got) > maxStderrBytes+32 || got == string(long) {
		t.Fatalf("truncation produced %d bytes", len(got))
	}
}

// incidentMaxRead is the size the oversized test builds against: one past
// what the child is allowed to read.
func incidentMaxRead() int {
	return maxStdinRead
}
