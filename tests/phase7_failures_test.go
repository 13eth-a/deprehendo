// phase 7 failure combinations (7.61, integration QA lane).
//
// the CLI-only end-to-end test (phase7_e2e_test.go) covers the client half:
// network loss during the storage POST, an invalid bundle, a cloud that is not
// reachable. these are the server halves it cannot reach, the ones the QA
// brief names explicitly: "object store fails", "analyzer times out",
// "database succeeds but storage fails", "storage succeeds but DB fails" and
// "user changes organizations".
//
// gated on RUNOPSY_CLOUD_TEST_DSN like the rest of the server suite;
// `make test-cloud` starts a throwaway postgres and sets it.
package tests

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runopsy/internal/analyzer"
	"runopsy/internal/cloudclient"
	"runopsy/internal/clouddb"
	"runopsy/internal/cloudserver"
)

// testStore is the harness Store. it keeps bytes in memory so a test can
// inspect them and inject the failures an operator sees from a real object
// store: a read that fails, a write that fails, and a stored object changed
// out of band. it otherwise honours the store contract, including immutability
// (a second put is an error containing "already exists", like LocalStore).
type testStore struct {
	mu         sync.Mutex
	objects    map[string][]byte
	failGet    func(key string) error
	failPut    func(key string) error
	failDelete func(key string) error
}

func newTestStore() *testStore { return &testStore{objects: map[string][]byte{}} }

func (s *testStore) Put(_ context.Context, key string, data []byte) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failPut != nil {
		if err := s.failPut(key); err != nil {
			return 0, err
		}
	}
	if _, ok := s.objects[key]; ok {
		return 0, fmt.Errorf("cloudserver: object %q is immutable and already exists", key)
	}
	s.objects[key] = append([]byte(nil), data...)
	return int64(len(data)), nil
}

func (s *testStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGet != nil {
		if err := s.failGet(key); err != nil {
			return nil, err
		}
	}
	data, ok := s.objects[key]
	if !ok {
		return nil, cloudserver.ErrNoSuchObject
	}
	return append([]byte(nil), data...), nil
}

func (s *testStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failDelete != nil {
		if err := s.failDelete(key); err != nil {
			return err
		}
	}
	delete(s.objects, key)
	return nil
}

func (s *testStore) setFailDelete(fn func(key string) error) {
	s.mu.Lock()
	s.failDelete = fn
	s.mu.Unlock()
}

func (s *testStore) setFailGet(fn func(key string) error) {
	s.mu.Lock()
	s.failGet = fn
	s.mu.Unlock()
}

func (s *testStore) setFailPut(fn func(key string) error) {
	s.mu.Lock()
	s.failPut = fn
	s.mu.Unlock()
}

// tamper replaces a stored object, as a compromised or broken store would.
func (s *testStore) tamper(key string, data []byte) {
	s.mu.Lock()
	s.objects[key] = append([]byte(nil), data...)
	s.mu.Unlock()
}

// cloudHarness is one running server with two organizations, two tokens and a
// store the test can break on purpose.
type cloudHarness struct {
	Endpoint string
	TokenA   string
	TokenB   string
	UserA    string
	OrgA     string
	OrgB     string
	DB       *sql.DB
	Store    *testStore
	Server   *cloudserver.Server
}

func newCloudHarness(t *testing.T, dsn string, mutate func(*cloudserver.Config)) *cloudHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clouddb.Apply(ctx, dsn, filepath.Join(root, "db", "migrations")); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	db, err := clouddb.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	suffix := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	orgA, err := clouddb.CreateOrganization(ctx, db, "Org A "+suffix)
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := clouddb.CreateOrganization(ctx, db, "Org B "+suffix)
	if err != nil {
		t.Fatal(err)
	}
	userA, userb := "user_a_"+suffix, "user_b_"+suffix
	if err := clouddb.EnsureMembership(ctx, db, userA, orgA, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := clouddb.EnsureMembership(ctx, db, userb, orgB, "owner"); err != nil {
		t.Fatal(err)
	}
	tokenA, err := clouddb.CreateToken(ctx, db, userA, orgA, "harness a")
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := clouddb.CreateToken(ctx, db, userb, orgB, "harness b")
	if err != nil {
		t.Fatal(err)
	}

	store := newTestStore()
	cfg := cloudserver.Config{
		Database: db,
		Storage:  store,
		Analyzer: analyzer.NewRunner(analyzerPath),
		Logf:     t.Logf,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := cloudserver.New(cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	mux := http.NewServeMux()
	srv.Handler(mux)
	httpsrv := httptest.NewServer(mux)
	t.Cleanup(httpsrv.Close)

	return &cloudHarness{
		Endpoint: httpsrv.URL,
		TokenA:   tokenA,
		TokenB:   tokenB,
		UserA:    userA,
		OrgA:     orgA,
		OrgB:     orgB,
		DB:       db,
		Store:    store,
		Server:   srv,
	}
}

// fixedRunner is a JobRunner with a predetermined outcome, for the statuses a
// real child only reaches after minutes of work (or a crash).
type fixedRunner struct{ result analyzer.Result }

func (r fixedRunner) Run(context.Context, []byte) (analyzer.Result, error) { return r.result, nil }

// postComplete drives POST /api/uploads/{id}/complete without the client's
// error wrapping, so the test can assert the status and the error code.
func postComplete(t *testing.T, endpoint, token, uploadID string, timeout time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/uploads/"+uploadID+"/complete", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body)
}

// apiErrorCode reads the one error envelope's code, or "" for a success body.
func apiErrorCode(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return ""
	}
	return envelope.Error.Code
}

// createAndStore runs the create + storage half of the upload, leaving the
// complete call to the test.
func createAndStore(t *testing.T, h *cloudHarness, token, bundlePath string) (uploadID, incidentID string) {
	t.Helper()
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readBundleFile(t, bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := cloudclient.New(h.Endpoint, token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum := sha256.Sum256(raw)
	target, err := client.Create(ctx, cloudclient.CreateRequest{
		SHA256:        hex.EncodeToString(sum[:]),
		SizeBytes:     int64(len(raw)),
		IncidentID:    bundle.Manifest.IncidentID,
		SchemaVersion: bundle.Manifest.SchemaVersion,
		FormatVersion: bundle.Manifest.FormatVersion,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if target.Duplicate {
		t.Fatal("expected a fresh upload")
	}
	if err := client.PutObject(ctx, target.Upload, bundlePath); err != nil {
		t.Fatalf("storage put: %v", err)
	}
	return target.UploadID, bundle.Manifest.IncidentID
}

// TestPhase7AnalyzerOutcomesKeepAQueryableRow covers the three outcomes that
// are not READY. the timeout case uses the real child-process runner with an
// expired wall-clock deadline; each outcome must leave a useful status row.
func TestPhase7AnalyzerOutcomesKeepAQueryableRow(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")

	cases := []struct {
		name     string
		status   analyzer.Status
		reason   string
		wantHTTP int
		wantCode string
		timeout  bool
	}{
		{"rejected", analyzer.StatusRejected, "bundle rejected by the reader", http.StatusUnprocessableEntity, "INVALID_BUNDLE", false},
		{"limit", analyzer.StatusFailedLimit, "job exceeded a resource boundary", http.StatusRequestEntityTooLarge, "TOO_LARGE", false},
		{"timeout", analyzer.StatusFailedLimit, "", http.StatusRequestEntityTooLarge, "TOO_LARGE", true},
		{"crash", analyzer.StatusFailedCrash, "analyzer child crashed", http.StatusInternalServerError, "UNAVAILABLE", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCloudHarness(t, dsn, func(cfg *cloudserver.Config) {
				if tc.timeout {
					runner := analyzer.NewRunner(analyzerPath)
					runner.Timeout = time.Nanosecond
					cfg.Analyzer = runner
					return
				}
				cfg.Analyzer = fixedRunner{result: analyzer.Result{
					Status: tc.status, Reason: tc.reason, Duration: 3 * time.Millisecond,
				}}
			})
			uploadID, incidentID := createAndStore(t, h, h.TokenA, bundlepath)
			status, body := postComplete(t, h.Endpoint, h.TokenA, uploadID, 20*time.Second)
			if status != tc.wantHTTP {
				t.Fatalf("complete = %d %s, want %d", status, body, tc.wantHTTP)
			}
			if code := apiErrorCode(t, body); code != tc.wantCode {
				t.Errorf("error code = %q, want %q (%s)", code, tc.wantCode, body)
			}

			list := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents")
			if len(list) != 1 {
				t.Fatalf("%d incident rows after a %s analysis, want 1", len(list), tc.status)
			}
			if got, _ := list[0]["analysis_status"].(string); got != string(tc.status) {
				t.Errorf("analysis_status = %q, want %q", got, tc.status)
			}
			// A failed run must not be dressed up as a diagnosis.
			if sig := list[0]["primary_signature"]; sig != nil {
				t.Errorf("a %s analysis recorded a signature %v", tc.status, sig)
			}
			if code := getStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/analysis"); code != http.StatusAccepted {
				t.Errorf("analysis endpoint = %d, want 202 (status without a document)", code)
			}
			if code := getStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID); code != http.StatusOK {
				t.Errorf("incident metadata endpoint = %d, want 200", code)
			}
		})
	}
}

// TestPhase7StorageFailuresLeaveNoPhantomAnalysis covers "object store fails":
// the bundle cannot be read, and the document cannot be written. neither may
// leave an analysis or an incident visible, and both must be retryable.
func TestPhase7StorageFailuresLeaveNoPhantomAnalysis(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")

	t.Run("bundle read fails, then a retry succeeds", func(t *testing.T) {
		h := newCloudHarness(t, dsn, nil)
		uploadID, incidentID := createAndStore(t, h, h.TokenA, bundlepath)
		h.Store.setFailGet(func(key string) error {
			if strings.HasSuffix(key, ".runopsy") {
				return fmt.Errorf("injected bundle read failure")
			}
			return nil
		})
		status, body := postComplete(t, h.Endpoint, h.TokenA, uploadID, 30*time.Second)
		if status != http.StatusInternalServerError || apiErrorCode(t, body) != "UNAVAILABLE" {
			t.Fatalf("complete with a failing store = %d %s, want 500 UNAVAILABLE", status, body)
		}
		if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 0 {
			t.Fatalf("a read failure left %d incident rows", len(hits))
		}
		if stats := h.Server.Stats(); stats.StorageFailures < 1 {
			t.Errorf("telemetry did not count the storage failure: %+v", stats)
		}

		h.Store.setFailGet(nil)
		status, body = postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second)
		if status != http.StatusOK {
			t.Fatalf("retry after the store recovered = %d %s, want 200", status, body)
		}
		if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 1 {
			t.Fatalf("%d incident rows after a successful retry, want 1", len(hits))
		}
		bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/analysis", http.StatusOK)
	})

	t.Run("document write fails, then a retry succeeds", func(t *testing.T) {
		h := newCloudHarness(t, dsn, nil)
		uploadID, incidentID := createAndStore(t, h, h.TokenA, bundlepath)
		h.Store.setFailPut(func(key string) error {
			if strings.Contains(key, "/documents/") {
				return fmt.Errorf("injected document write failure")
			}
			return nil
		})
		status, body := postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second)
		if status != http.StatusInternalServerError || apiErrorCode(t, body) != "UNAVAILABLE" {
			t.Fatalf("complete with a failing document write = %d %s, want 500 UNAVAILABLE", status, body)
		}
		// the analysis row is written after the document, so a failed document
		// write must leave neither an analysis nor an incident behind.
		if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 0 {
			t.Fatalf("a document write failure left %d incident rows", len(hits))
		}

		h.Store.setFailPut(nil)
		status, body = postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second)
		if status != http.StatusOK {
			t.Fatalf("retry after the store recovered = %d %s, want 200", status, body)
		}
		hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents")
		if len(hits) != 1 {
			t.Fatalf("%d incident rows after a successful retry, want 1", len(hits))
		}
		if sig := hits[0]["primary_signature"]; sig == nil {
			t.Errorf("the repaired incident has no signature: %v", hits[0])
		}
		bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/analysis", http.StatusOK)
	})
}

// TestPhase7CompleteRepairsAMissingIncidentRow is "storage succeeds but DB
// fails": the analysis row and its document land, then the searchable view
// cannot be written. the upload is not listed, and a retry must repair the row
// instead of answering 200 with a URL that 404s.
//
// making exactly that statement fail deterministically needs the table out of
// the way; renaming it is the only lever that does not depend on timing, and
// it is restored before any other assertion or test runs.
func TestPhase7CompleteRepairsAMissingIncidentRow(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	h := newCloudHarness(t, dsn, nil)
	uploadID, incidentID := createAndStore(t, h, h.TokenA, bundlepath)

	ctx := context.Background()
	if _, err := h.DB.ExecContext(ctx, "ALTER TABLE incidents RENAME TO incidents_unavailable"); err != nil {
		t.Fatalf("suspend the incidents table: %v", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := h.DB.ExecContext(ctx, "ALTER TABLE incidents_unavailable RENAME TO incidents"); err != nil {
			t.Errorf("restore the incidents table: %v", err)
		}
	}
	t.Cleanup(restore)

	status, body := postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second)
	if status != http.StatusInternalServerError || apiErrorCode(t, body) != "UNAVAILABLE" {
		t.Fatalf("complete whose view insert failed = %d %s, want 500 UNAVAILABLE", status, body)
	}
	restore()

	// the analysis is final even though the view is missing.
	var ready int
	if err := h.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM analyses WHERE upload_id = $1 AND status = 'READY'`, uploadID).Scan(&ready); err != nil {
		t.Fatalf("count analyses: %v", err)
	}
	if ready != 1 {
		t.Fatalf("READY analyses = %d, want 1", ready)
	}
	if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 0 {
		t.Fatalf("a missing incident row was listed: %v", hits)
	}

	// the retry must repair the view. before the repair in complete.go this
	// returned 200 with a dashboard URL that 404'd.
	status, body = postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second)
	if status != http.StatusOK {
		t.Fatalf("retry complete = %d %s, want 200", status, body)
	}
	bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID, http.StatusOK)
	analysisbody := bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/analysis", http.StatusOK)
	var doc struct {
		DocumentVersion int `json:"document_version"`
	}
	if err := json.Unmarshal(analysisbody, &doc); err != nil || doc.DocumentVersion != 1 {
		t.Errorf("repaired incident has no readable document: %v (%d bytes)", err, len(analysisbody))
	}
	if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 1 {
		t.Fatalf("%d incident rows after the repair, want 1", len(hits))
	}
}

// TestPhase7SchemaRefusesReadyAnalysisWithoutDocument pins the P2 correction
// from the 7.56 review (docs/cloud/db-review.md): a READY analysis must carry
// its document key, because the API would otherwise answer 404 the first time
// a user opens it. the CHECK is in db/migrations/0001_init.up.sql.
func TestPhase7SchemaRefusesReadyAnalysisWithoutDocument(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	h := newCloudHarness(t, dsn, nil)
	uploadID, _ := createAndStore(t, h, h.TokenA, bundlepath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s, want 200", status, body)
	}

	var analysisID string
	if err := h.DB.QueryRowContext(context.Background(),
		`SELECT id FROM analyses WHERE upload_id = $1 AND status = 'READY'`, uploadID).Scan(&analysisID); err != nil {
		t.Fatalf("find the READY analysis: %v", err)
	}
	_, err = h.DB.ExecContext(context.Background(),
		`UPDATE analyses SET document_key = NULL WHERE id = $1`, analysisID)
	if err == nil {
		t.Fatal("schema accepted a READY analysis with no document key")
	}
	if !strings.Contains(err.Error(), "analyses_document_key_iff_ready") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestPhase7OrganizationChangeRevokesEveryPath covers "user changes
// organizations": the token stays valid, membership is what grants access, and
// every access path must agree. another organization's token keeps seeing 404
// (never 403), so an incident id is not an existence oracle.
func TestPhase7OrganizationChangeRevokesEveryPath(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	h := newCloudHarness(t, dsn, nil)
	uploadID, incidentID := createAndStore(t, h, h.TokenA, bundlepath)
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadID, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s, want 200", status, body)
	}

	paths := []string{
		"/api/incidents",
		"/api/incidents/" + incidentID,
		"/api/incidents/" + incidentID + "/analysis",
		"/api/incidents/" + incidentID + "/bundle",
	}
	for _, path := range paths {
		bearerGet(t, h.Endpoint, h.TokenA, path, http.StatusOK)
	}

	ctx := context.Background()
	if _, err := h.DB.ExecContext(ctx,
		`DELETE FROM memberships WHERE user_id = $1 AND organization_id = $2`,
		h.UserA, h.OrgA); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	for _, path := range paths {
		if code := getStatus(t, h.Endpoint, h.TokenA, path); code != http.StatusForbidden {
			t.Errorf("%s after leaving the organization = %d, want 403", path, code)
		}
	}
	if code, _ := deleteStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID); code != http.StatusForbidden {
		t.Errorf("delete after leaving the organization = %d, want 403", code)
	}
	// the incident itself was not damaged by the membership change.
	if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenB, "/api/incidents"); len(hits) != 0 {
		t.Errorf("org B lists %d incidents belonging to org A", len(hits))
	}

	if err := clouddb.EnsureMembership(ctx, h.DB, h.UserA, h.OrgA, "owner"); err != nil {
		t.Fatalf("restore membership: %v", err)
	}
	for _, path := range paths {
		bearerGet(t, h.Endpoint, h.TokenA, path, http.StatusOK)
	}

	for _, path := range []string{
		"/api/incidents/" + incidentID,
		"/api/incidents/" + incidentID + "/analysis",
		"/api/incidents/" + incidentID + "/bundle",
	} {
		bearerGet(t, h.Endpoint, h.TokenB, path, http.StatusNotFound)
	}
	if code, _ := deleteStatus(t, h.Endpoint, h.TokenB, "/api/incidents/"+incidentID); code != http.StatusNotFound {
		t.Errorf("org B delete = %d, want 404", code)
	}
}
