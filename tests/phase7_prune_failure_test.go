package tests

// L1 (secondary review of the 7.60 gate, november 16, 2026): when the retention
// sweep cannot delete an object, it must stop with the upload's row intact so a
// rerun can retry, instead of deleting the row and leaving an object that
// nothing names. A rerun after storage recovers must remove everything.

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase7PruneKeepsRowWhenStorageFails(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, nil)
	ctx := context.Background()

	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	uploadid, incidentid := createAndStore(t, h, h.TokenA, bundlepath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadid, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s, want 200", status, body)
	}
	if _, err := h.DB.ExecContext(ctx,
		`UPDATE uploads SET uploaded_at = now() - interval '200 days' WHERE id = $1`, uploadid); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	cutoff := time.Now().Add(-100 * 24 * time.Hour)

	// the analysis document deletes fine; the bundle does not. the sweep must
	// stop on the bundle with the row still there.
	var bundleKey string
	if err := h.DB.QueryRowContext(ctx, `SELECT object_key FROM uploads WHERE id = $1`, uploadid).Scan(&bundleKey); err != nil {
		t.Fatal(err)
	}
	h.Store.setFailDelete(func(key string) error {
		if key == bundleKey {
			return errors.New("bucket unreachable")
		}
		return nil
	})
	stats, err := h.Server.PruneUploadsOlderThan(ctx, cutoff, 100)
	if err == nil {
		t.Fatalf("prune with failing storage returned no error (stats %+v)", stats)
	}
	if stats.Uploads != 0 {
		t.Fatalf("prune counted %d uploads deleted despite the storage failure", stats.Uploads)
	}
	var n int
	if err := h.DB.QueryRowContext(ctx, `SELECT count(*) FROM uploads WHERE id = $1`, uploadid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("upload row count after failed prune = %d, want 1 (kept for retry)", n)
	}
	if _, err := h.Store.Get(ctx, bundleKey); err != nil {
		t.Fatalf("bundle should remain after the failed delete: %v", err)
	}
	// the bundle is deleted first, so its failure stops the sweep before the
	// document: the incident's analysis still loads.
	bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentid+"/analysis", http.StatusOK)

	// storage recovers: a rerun removes the row and every object under the org.
	h.Store.setFailDelete(nil)
	stats, err = h.Server.PruneUploadsOlderThan(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("rerun prune: %v", err)
	}
	if stats.Uploads != 1 {
		t.Fatalf("rerun pruned %d uploads, want 1", stats.Uploads)
	}
	if err := h.DB.QueryRowContext(ctx, `SELECT count(*) FROM uploads WHERE id = $1`, uploadid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("upload row survived the rerun")
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
		t.Fatalf("rerun left %d object(s) behind: %v", len(left), left)
	}
}
