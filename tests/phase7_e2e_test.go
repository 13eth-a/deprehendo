package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runopsy/internal/analysis"
	"runopsy/internal/incident"
)

// phase 7's end-to-end half (checklist 7.61): the bundle a real agent froze
// travels through the real CLI and the real upload client into a reference
// cloud, and the dashboard document that comes back is byte-identical to the
// one the laptop produced. capture itself (simulator -> recorder -> frozen
// bundle) is proven by tests/phase2_e2e_test.go and tests/phase3_e2e_test.go;
// this file starts where that one ends, at a validated bundle on disk.
//
// the reference cloud implements docs/cloud/upload-api.md v1 and nothing else:
// create -> presigned POST -> complete, dedupe by SHA-256, and a read endpoint
// that serves the stored document. it is deliberately *not* the server engineering is
// building. it is the fixture that proves the client contract and the
// local/cloud equality invariant from the client's side, and it must be
// replaced by the real deployment's test target when one exists (7.62).

const referenceToken = "rps_test_0123456789abcdef"

type referenceObject struct {
	id         string
	objectKey  string
	digest     string
	incidentID string
	// body is the stored original. it is set once by the storage POST and
	// never rewritten, which is contract L4 (a bundle is never re-encoded).
	body []byte
	// document is the analysis the worker stored for those bytes.
	document []byte
}

type referenceCloud struct {
	t      *testing.T
	mu     sync.Mutex
	server *httptest.Server
	order  []string
	byID   map[string]*referenceObject
	bySHA  map[string]string

	analyses int
	// failStorage makes the next storage POST drop the connection, which is
	// what the CLI sees when the network dies mid-upload.
	failStorage int
	// storageAuth records every authorization header the storage endpoint
	// received; the token must never appear among them.
	storageAuth []string
}

func newReferenceCloud(t *testing.T) *referenceCloud {
	t.Helper()
	c := &referenceCloud{t: t, byID: map[string]*referenceObject{}, bySHA: map[string]string{}}
	c.server = httptest.NewServer(http.HandlerFunc(c.route))
	t.Cleanup(c.server.Close)
	return c
}

func (c *referenceCloud) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/uploads" && r.Method == http.MethodPost:
		c.create(w, r)
	case r.URL.Path == "/storage" && r.Method == http.MethodPost:
		c.storeObject(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/uploads/") && strings.HasSuffix(r.URL.Path, "/complete") && r.Method == http.MethodPost:
		c.complete(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/incidents/") && r.Method == http.MethodGet:
		c.readIncident(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (c *referenceCloud) authorized(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+referenceToken
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeAPIJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// create implements upload-api.md §1, including the duplicate reply the CLI
// reports as "already uploaded" (7.30: return the existing incident).
func (c *referenceCloud) create(w http.ResponseWriter, r *http.Request) {
	if !c.authorized(r) {
		writeAPIError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "token required")
		return
	}
	var req struct {
		SHA256        string `json:"sha256"`
		SizeBytes     int64  `json:"size_bytes"`
		IncidentID    string `json:"incident_id"`
		SchemaVersion int    `json:"schema_version"`
		FormatVersion int    `json:"format_version"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid create body")
		return
	}
	if len(req.SHA256) != 64 || req.SizeBytes <= 0 {
		writeAPIError(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "create needs a sha256 and a positive size")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.bySHA[req.SHA256]; ok {
		existing := c.byID[id]
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"upload_id":   existing.id,
			"duplicate":   true,
			"incident_id": existing.incidentID,
			"url":         "https://app.example.com/incidents/" + existing.incidentID,
		})
		return
	}
	object := &referenceObject{
		id:         fmt.Sprintf("upl_%032x", len(c.order)+1),
		objectKey:  fmt.Sprintf("orgs/org_reference/bundles/%s.runopsy", req.SHA256),
		digest:     req.SHA256,
		incidentID: req.IncidentID,
	}
	c.byID[object.id] = object
	c.bySHA[req.SHA256] = object.id
	c.order = append(c.order, object.id)
	writeAPIJSON(w, http.StatusCreated, map[string]any{
		"upload_id":  object.id,
		"object_key": object.objectKey,
		"upload": map[string]any{
			"url":    c.server.URL + "/storage",
			"fields": map[string]string{"key": object.objectKey, "policy": "reference-v1"},
		},
	})
}

// storeObject implements upload-api.md §2: multipart fields then the file, and
// no authorization header. the URL is already signed.
func (c *referenceCloud) storeObject(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.storageAuth = append(c.storageAuth, r.Header.Get("Authorization"))
	fail := c.failStorage > 0
	if fail {
		c.failStorage--
	}
	c.mu.Unlock()
	if fail {
		// drop the connection the way a dead network does, so the client sees
		// a transport error rather than an HTTP status it might retry.
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		http.Error(w, "storage unavailable", http.StatusBadGateway)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid multipart form", http.StatusBadRequest)
		return
	}
	key := r.FormValue("key")
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file part", http.StatusBadRequest)
		return
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, incident.MaxArchiveSize+1))
	if err != nil {
		http.Error(w, "read file part", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, object := range c.byID {
		if object.objectKey == key {
			if object.body != nil {
				http.Error(w, "object already stored", http.StatusConflict)
				return
			}
			object.body = body
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.Error(w, "unknown object key", http.StatusNotFound)
}

// complete implements upload-api.md §3: verify the stored bytes, run the
// canonical analyzer, store the document, return the dashboard URL.
func (c *referenceCloud) complete(w http.ResponseWriter, r *http.Request) {
	if !c.authorized(r) {
		writeAPIError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "token required")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/uploads/")
	id := strings.TrimSuffix(rest, "/complete")
	c.mu.Lock()
	object := c.byID[id]
	c.mu.Unlock()
	if object == nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "no such upload")
		return
	}
	if len(object.body) == 0 {
		writeAPIError(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "nothing was uploaded for this id")
		return
	}

	// the digest is recomputed from the stored bytes: the client's claim is
	// not trusted (contract §2.1).
	sum := sha256.Sum256(object.body)
	if hex.EncodeToString(sum[:]) != object.digest {
		writeAPIError(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "checksum mismatch")
		return
	}
	bundle, err := incident.Read(bytes.NewReader(object.body), int64(len(object.body)))
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", err.Error())
		return
	}
	doc, err := analysis.Run(bundle, object.digest, analysis.Options{})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis failed")
		return
	}
	var document bytes.Buffer
	if err := analysis.WriteJSON(&document, doc); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "UNAVAILABLE", "document write failed")
		return
	}

	c.mu.Lock()
	object.document = document.Bytes()
	object.incidentID = bundle.Manifest.IncidentID
	c.analyses++
	incidentID := object.incidentID
	c.mu.Unlock()

	writeAPIJSON(w, http.StatusOK, map[string]any{
		"upload_id":   object.id,
		"incident_id": incidentID,
		"url":         "https://app.example.com/incidents/" + incidentID,
		"duplicate":   false,
	})
}

// readIncident is the 7.35 read path the dashboard uses: the stored document,
// verbatim.
func (c *referenceCloud) readIncident(w http.ResponseWriter, r *http.Request) {
	wanted := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, object := range c.byID {
		if object.incidentID == wanted && object.document != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(object.document)
			return
		}
	}
	http.NotFound(w, r)
}

func (c *referenceCloud) failNextStorage() {
	c.mu.Lock()
	c.failStorage++
	c.mu.Unlock()
}

func (c *referenceCloud) snapshot() (analyses int, object referenceObject, storageAuth []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.order) == 0 {
		return c.analyses, referenceObject{}, append([]string(nil), c.storageAuth...)
	}
	last := c.byID[c.order[len(c.order)-1]]
	copied := *last
	copied.body = append([]byte(nil), last.body...)
	copied.document = append([]byte(nil), last.document...)
	return c.analyses, copied, append([]string(nil), c.storageAuth...)
}

// runAgentCLI runs the built agent binary and returns combined output and the
// process exit code.
func runAgentCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentPath, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode()
	}
	t.Fatalf("run %v: %v (%s)", args, err, out)
	return "", -1
}

func requireOutput(t *testing.T, output string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q:\n%s", want, output)
		}
	}
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TestPhase7BundleToDashboardExactBytes is 7.61 for the part of the pipeline
// that exists today, plus the four failure combinations integration owns that can
// be exercised without the web app: duplicate upload, network loss during the
// storage POST, an invalid bundle, and a cloud that is not reachable at all.
func TestPhase7BundleToDashboardExactBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the CLI against a reference cloud")
	}
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	cloud := newReferenceCloud(t)
	dir := t.TempDir()
	configpath := filepath.Join(dir, "config.json")
	tokenpath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenpath, []byte(referenceToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 7.11/7.12: login stores the credential, and nothing about it is world
	// readable.
	out, code := runAgentCLI(t, "login", "-endpoint", cloud.server.URL, "-token-file", tokenpath, "-config", configpath)
	if code != 0 {
		t.Fatalf("login exited %d:\n%s", code, out)
	}
	requireOutput(t, out, "Credentials saved to")
	info, err := os.Stat(configpath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credential file is %04o, want 0600", perm)
	}

	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	localdocpath := filepath.Join(dir, "local.json")
	out, code = runAgentCLI(t, "analyze", "--document", localdocpath, bundlepath)
	if code != 0 {
		t.Fatalf("analyze exited %d:\n%s", code, out)
	}
	localdoc, err := os.ReadFile(localdocpath)
	if err != nil {
		t.Fatal(err)
	}
	wantdigest := digestOf(t, bundlepath)

	// the upload a user runs by hand (7.11).
	out, code = runAgentCLI(t, "upload", "-config", configpath, bundlepath)
	if code != 0 {
		t.Fatalf("upload exited %d:\n%s", code, out)
	}
	requireOutput(t, out, "Uploading incident inc_", "Validated", "Uploaded")
	if strings.Contains(out, referenceToken) {
		t.Fatal("the CLI printed the API token")
	}

	analyses, object, storageauth := cloud.snapshot()
	if analyses != 1 {
		t.Fatalf("cloud ran %d analyses, want 1", analyses)
	}
	// L4: the stored original is the exact file the user has.
	raw, err := os.ReadFile(bundlepath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(object.body, raw) {
		t.Fatalf("cloud stored %d bytes that differ from the %d-byte bundle", len(object.body), len(raw))
	}
	if object.digest != wantdigest {
		t.Errorf("cloud digest = %s, want %s", object.digest, wantdigest)
	}
	// 7.43/7.61: the dashboard's document is the laptop's document, byte for
	// byte. the cloud is wrong by definition if these differ (contract §3.4).
	if !bytes.Equal(object.document, localdoc) {
		t.Fatalf("cloud document (%d bytes) differs from the CLI document (%d bytes)", len(object.document), len(localdoc))
	}
	// the signed storage POST carries no bearer token.
	for _, header := range storageauth {
		if header != "" {
			t.Errorf("storage endpoint received Authorization %q", header)
		}
	}

	// 7.35: the read endpoint serves those stored bytes unchanged.
	response, err := http.Get(cloud.server.URL + "/api/incidents/" + object.incidentID)
	if err != nil {
		t.Fatal(err)
	}
	served, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(served, localdoc) {
		t.Errorf("incident read endpoint served %d bytes, document is %d", len(served), len(localdoc))
	}

	// 7.30: re-uploading the same bytes returns the existing incident and
	// does not re-analyze anything.
	out, code = runAgentCLI(t, "upload", "-config", configpath, bundlepath)
	if code != 0 {
		t.Fatalf("duplicate upload exited %d:\n%s", code, out)
	}
	requireOutput(t, out, "Already uploaded")
	if analyses, _, _ = cloud.snapshot(); analyses != 1 {
		t.Errorf("duplicate upload triggered a second analysis")
	}

	// break combination: the network dies during the storage POST. the CLI
	// fails, nothing is analyzed, and the local bundle is untouched (L3).
	cloud.failNextStorage()
	otherbundle := filepath.Join(root, "testdata", "incidents", "network-failure.runopsy")
	before := digestOf(t, otherbundle)
	out, code = runAgentCLI(t, "upload", "-config", configpath, otherbundle)
	if code == 0 {
		t.Fatalf("upload succeeded although storage dropped the connection:\n%s", out)
	}
	requireOutput(t, out, "storage upload")
	if n, _, _ := cloud.snapshot(); n != 1 {
		t.Errorf("cloud ran %d analyses, want 1: a failed storage POST must not analyse", n)
	}
	if after := digestOf(t, otherbundle); after != before {
		t.Fatal("a failed upload modified the local bundle")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".runopsy-") || strings.HasSuffix(entry.Name(), ".queue") {
			t.Errorf("failed upload left a temporary or queue artifact: %s", entry.Name())
		}
	}

	// break combination: a corrupt archive is refused before any network call,
	// so the server never sees it.
	corrupt := filepath.Join(dir, "corrupt.runopsy")
	if err := os.WriteFile(corrupt, raw[:100], 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runAgentCLI(t, "upload", "-config", configpath, corrupt)
	if code == 0 {
		t.Fatalf("upload accepted a truncated bundle:\n%s", out)
	}
	requireOutput(t, out, "not a valid bundle")
	if n, _, _ := cloud.snapshot(); n != 1 {
		t.Errorf("invalid bundle reached the analyzer")
	}

	// L1/L3: with the cloud unreachable, analysis still works and the upload
	// fails without touching anything local. the config is rewritten to a
	// closed port rather than a fake host, so no DNS is involved.
	offlineconfig := filepath.Join(dir, "offline.json")
	if err := os.WriteFile(offlineconfig, []byte(fmt.Sprintf("{\"endpoint\":%q,\"token\":%q}\n", "http://127.0.0.1:1", referenceToken)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runAgentCLI(t, "upload", "-config", offlineconfig, bundlepath)
	if code == 0 {
		t.Fatalf("upload succeeded with an unreachable cloud:\n%s", out)
	}
	if strings.Contains(out, "panic") {
		t.Fatalf("offline upload panicked:\n%s", out)
	}
	out, code = runAgentCLI(t, "analyze", "--document", localdocpath, bundlepath)
	if code != 0 {
		t.Fatalf("local analysis needs the cloud (L1):\n%s", out)
	}
	if digestOf(t, bundlepath) != wantdigest {
		t.Fatal("offline analysis or upload modified the bundle")
	}
}
