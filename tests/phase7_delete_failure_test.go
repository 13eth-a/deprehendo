package tests

// H1 (adversarial review of the principal gate, november 16, 2026): a storage delete that
// fails must not be answered as deleted, must keep the incident so the user can
// retry, and a retry must remove every object the organization owns.

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase7DeleteKeepsRecordWhenStorageFails(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, nil)
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	uploadid, incidentid := createAndStore(t, h, h.TokenA, bundlepath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadid, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s, want 200", status, body)
	}

	// storage refuses every delete: the request must fail, not report success.
	h.Store.setFailDelete(func(string) error { return errors.New("bucket unreachable") })
	if code, body := deleteStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid); code != http.StatusServiceUnavailable {
		t.Fatalf("delete with failing storage = %d %s, want 503", code, body)
	}

	// the incident is still there, so the user can retry.
	bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid+"/analysis", http.StatusOK)

	// storage recovers: a retry removes the incident and every object under the org.
	h.Store.setFailDelete(nil)
	if code, body := deleteStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid); code != http.StatusOK {
		t.Fatalf("retry delete = %d %s, want 200", code, body)
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
		t.Fatalf("retry left %d object(s) behind: %v", len(left), left)
	}
}
