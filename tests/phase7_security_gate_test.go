// gated tests for the principal security-gate fixes that need a real
// postgres (DEPREHENDO_CLOUD_TEST_DSN; run with `make test-cloud`):
//
//   - deleting an incident removes every stored object it owns, including the
//     per-engine analysis documents (before the fix, the cascade removed the
//     analyses rows before their document keys were read, so the documents
//     outlived the user's delete);
//   - destroying evidence (delete) and changing what everyone sees (activate)
//     are owner-only, while a member keeps read access;
//   - the analysis limit is per organization per rolling hour, with
//     Retry-After on the 429.
//
// the database-free halves (storage POST streaming, job slots) are unit tests
// in internal/cloudserver/gate_test.go.
package tests

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/clouddb"
	"deprehendo/internal/cloudserver"
)

func TestPhase7DeleteRemovesEveryStoredObject(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, nil)
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.deprehendo")
	uploadid, incidentid := createAndStore(t, h, h.TokenA, bundlepath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadid, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s, want 200", status, body)
	}
	dockey := analysisDocumentKey(t, h, uploadid)
	if _, err := h.Store.Get(context.Background(), dockey); err != nil {
		t.Fatalf("analysis document %s not stored before delete: %v", dockey, err)
	}

	if code, body := deleteStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid); code != http.StatusOK {
		t.Fatalf("delete = %d %s, want 200", code, body)
	}

	prefix := "orgs/" + h.OrgA + "/"
	h.Store.mu.Lock()
	var left []string
	for key := range h.Store.objects {
		if strings.HasPrefix(key, prefix) {
			left = append(left, key)
		}
	}
	h.Store.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("delete left %d object(s) of the organization behind: %v", len(left), left)
	}
}

func TestPhase7MemberCannotDeleteOrActivate(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, nil)
	ctx := context.Background()

	// A member of org A, as a CI runner's agent token would be.
	memberuser := "member_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	if err := clouddb.EnsureMembership(ctx, h.DB, memberuser, h.OrgA, "member"); err != nil {
		t.Fatal(err)
	}
	membertoken, err := clouddb.CreateToken(ctx, h.DB, memberuser, h.OrgA, "member runner token")
	if err != nil {
		t.Fatal(err)
	}

	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.deprehendo")
	uploadid, incidentid := createAndStore(t, h, h.TokenA, bundlepath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadid, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s, want 200", status, body)
	}
	var analysisID string
	if err := h.DB.QueryRow(`SELECT active_analysis_id FROM incidents WHERE upload_id = $1`, uploadid).Scan(&analysisID); err != nil {
		t.Fatalf("active analysis: %v", err)
	}

	// reads stay open to every member.
	bearerGet(t, h.Endpoint, membertoken, "/api/incidents/"+incidentid+"/analysis", http.StatusOK)

	// destructive and diagnosis-changing actions are owner-only.
	if code, _ := deleteStatus(t, h.Endpoint, membertoken, "/api/incidents/"+incidentid); code != http.StatusForbidden {
		t.Errorf("member delete = %d, want 403", code)
	}
	if code := postActivate(t, h.Endpoint, membertoken, incidentid, analysisID); code != http.StatusForbidden {
		t.Errorf("member activate = %d, want 403", code)
	}
	// another organization still learns nothing: 404, not 403.
	if code := postActivate(t, h.Endpoint, h.TokenB, incidentid, analysisID); code != http.StatusNotFound {
		t.Errorf("org B activate = %d, want 404", code)
	}
	// the incident survived the member's attempts, and the owner can act.
	bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid+"/bundle", http.StatusOK)
	if code := postActivate(t, h.Endpoint, h.TokenA, incidentid, analysisID); code != http.StatusOK {
		t.Errorf("owner activate = %d, want 200", code)
	}
	if code, body := deleteStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid); code != http.StatusOK {
		t.Errorf("owner delete = %d %s, want 200", code, body)
	}
}

// the analysis limit is per organization per hour over a rolling window
// (contract §5.3; owner decision november 9, 2026). before migration 0003 the
// "per hour" setting was compared against a daily counter.
func TestPhase7AnalysisLimitIsPerOrganizationPerHour(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, func(c *cloudserver.Config) { c.MaxAnalysesPerHour = 1 })
	incidents := filepath.Join(root, "testdata", "incidents")

	first, _ := createAndStore(t, h, h.TokenA, filepath.Join(incidents, "frozen-worker.deprehendo"))
	if status, body := postComplete(t, h.Endpoint, h.TokenA, first, 90*time.Second); status != http.StatusOK {
		t.Fatalf("first complete = %d %s, want 200", status, body)
	}

	second, _ := createAndStore(t, h, h.TokenA, filepath.Join(incidents, "oom.deprehendo"))
	status, retryafter, body := completeWithHeaders(t, h.Endpoint, h.TokenA, second)
	if status != http.StatusTooManyRequests || apiErrorCode(t, body) != "RATE_LIMITED" {
		t.Fatalf("second complete in the same hour = %d %s, want 429 RATE_LIMITED", status, body)
	}
	if seconds, err := strconv.Atoi(retryafter); err != nil || seconds < 1 || seconds > 3600 {
		t.Errorf("Retry-After = %q, want 1..3600 seconds", retryafter)
	}

	// another organization has its own window.
	other, _ := createAndStore(t, h, h.TokenB, filepath.Join(incidents, "frozen-worker.deprehendo"))
	if status, body := postComplete(t, h.Endpoint, h.TokenB, other, 90*time.Second); status != http.StatusOK {
		t.Fatalf("org B complete = %d %s, want 200", status, body)
	}

	// once the hour has passed, the same organization may analyze again.
	if _, err := h.DB.Exec(
		`UPDATE upload_usage_minutes SET minute = minute - interval '2 hours' WHERE organization_id = $1`,
		h.OrgA); err != nil {
		t.Fatalf("age the window: %v", err)
	}
	if status, body := postComplete(t, h.Endpoint, h.TokenA, second, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete after the hour = %d %s, want 200", status, body)
	}
}

// completeWithHeaders is postComplete plus the Retry-After header.
func completeWithHeaders(t *testing.T, endpoint, token, uploadID string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint+"/api/uploads/"+uploadID+"/complete", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header.Get("Retry-After"), string(body)
}

// postActivate calls POST /api/incidents/{id}/activate and returns the status.
func postActivate(t *testing.T, endpoint, token, incidentID, analysisID string) int {
	t.Helper()
	body := bytes.NewBufferString(`{"analysis_id":"` + analysisID + `"}`)
	req, err := http.NewRequest(http.MethodPost, endpoint+"/api/incidents/"+incidentID+"/activate", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
