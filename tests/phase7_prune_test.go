// phase 7.58 retention sweep (MiMo review lane).
//
// the sweep is the only code path that destroys bundles by time, so it is
// tested against a real postgres and a real store rather than trusted: a dry
// run must delete nothing, a real run must remove rows and objects together,
// a stale never-completed upload must go, and a newer upload (and the shared
// per-org usage rows) must survive. gated on DEPREHENDO_CLOUD_TEST_DSN like the
// rest of the server suite; `make test-cloud` sets it.
package tests

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestPhase7PruneUploadsOlderThan(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, nil)
	ctx := context.Background()

	oldpath := filepath.Join(root, "testdata", "incidents", "frozen-worker.deprehendo")
	newpath := filepath.Join(root, "testdata", "incidents", "oom.deprehendo")
	pendingpath := filepath.Join(root, "testdata", "incidents", "healthy-idle.deprehendo")

	oldupload, oldincident := createAndStore(t, h, h.TokenA, oldpath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, oldupload, 60*time.Second); status != 200 {
		t.Fatalf("complete old = %d %s", status, body)
	}
	newupload, newincident := createAndStore(t, h, h.TokenA, newpath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, newupload, 60*time.Second); status != 200 {
		t.Fatalf("complete new = %d %s", status, body)
	}
	// pending: created and stored but never completed, which is the
	// PENDING-without-state case the sweep also has to clean up.
	pendingupload, _ := createAndStore(t, h, h.TokenA, pendingpath)

	if _, err := h.DB.ExecContext(ctx,
		`UPDATE uploads SET uploaded_at = now() - interval '200 days' WHERE id = ANY($1)`,
		[]string{oldupload, pendingupload}); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	cutoff := time.Now().Add(-100 * 24 * time.Hour)

	// A dry run reports the two aged uploads and deletes nothing.
	plan, err := h.Server.PlanPrune(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Stats.Uploads != 2 {
		t.Fatalf("plan selected %d uploads, want 2: %+v", plan.Stats.Uploads, plan.Entries)
	}
	for _, e := range plan.Entries {
		if e.UploadID == newupload {
			t.Fatalf("plan selected the newer upload %s", newupload)
		}
	}
	if plan.Stats.Objects < 2 {
		t.Fatalf("plan counted %d objects for 2 uploads, want at least 2", plan.Stats.Objects)
	}
	if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 2 {
		t.Fatalf("a dry run left %d incident rows, want 2", len(hits))
	}

	var oldBundleKey string
	if err := h.DB.QueryRowContext(ctx, `SELECT object_key FROM uploads WHERE id = $1`, oldupload).Scan(&oldBundleKey); err != nil {
		t.Fatal(err)
	}
	olddockey := analysisDocumentKey(t, h, oldupload)
	if _, err := h.Store.Get(ctx, oldBundleKey); err != nil {
		t.Fatalf("old bundle missing before the sweep: %v", err)
	}

	stats, err := h.Server.PruneUploadsOlderThan(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if stats.Uploads != 2 {
		t.Fatalf("pruned %d uploads, want 2", stats.Uploads)
	}
	if stats.Bytes <= 0 {
		t.Fatalf("pruned bundle bytes = %d, want the aged bundles' sizes", stats.Bytes)
	}

	// rows: the aged upload and its children are gone; the newer ones remain.
	for _, id := range []string{oldupload, pendingupload} {
		var n int
		if err := h.DB.QueryRowContext(ctx, `SELECT count(*) FROM uploads WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("upload %s survived the sweep", id)
		}
	}
	for table, id := range map[string]string{"analyses": oldupload, "incidents": oldupload} {
		var n int
		if err := h.DB.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE upload_id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%d %s rows survived the cascade", n, table)
		}
	}
	var survivors int
	if err := h.DB.QueryRowContext(ctx, `SELECT count(*) FROM uploads WHERE id = $1`, newupload).Scan(&survivors); err != nil {
		t.Fatal(err)
	}
	if survivors != 1 {
		t.Fatalf("the newer upload was pruned too")
	}
	// usage rows are per organization per day, shared by every incident that
	// day; deleting one incident must never erase another's accounting.
	var usage int
	if err := h.DB.QueryRowContext(ctx, `SELECT count(*) FROM upload_usage WHERE organization_id = $1`, h.OrgA).Scan(&usage); err != nil {
		t.Fatal(err)
	}
	if usage == 0 {
		t.Fatalf("the sweep deleted the organization's usage rows")
	}

	// objects: bundle and document gone, the newer upload intact.
	if _, err := h.Store.Get(ctx, oldBundleKey); err == nil {
		t.Errorf("old bundle object survived the sweep")
	}
	if _, err := h.Store.Get(ctx, olddockey); err == nil {
		t.Errorf("old analysis document %s survived the sweep", olddockey)
	}
	if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 1 {
		t.Fatalf("%d incident rows after the sweep, want 1", len(hits))
	}
	if code := getStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+oldincident+"/analysis"); code != 404 {
		t.Errorf("pruned incident /analysis = %d, want 404", code)
	}
	bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+newincident+"/analysis", 200)
}

// analysisDocumentKey reads the document key of one upload's READY analysis.
func analysisDocumentKey(t *testing.T, h *cloudHarness, uploadID string) string {
	t.Helper()
	var key string
	if err := h.DB.QueryRow(
		`SELECT document_key FROM analyses WHERE upload_id = $1 AND document_key IS NOT NULL`, uploadID).Scan(&key); err != nil {
		t.Fatalf("document key for %s: %v", uploadID, err)
	}
	return key
}
