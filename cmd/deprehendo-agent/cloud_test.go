package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"deprehendo/internal/uploadqueue"
)

// cloudStub is the smallest server that satisfies docs/cloud/upload-api.md,
// with call counters so a test can prove "no network call" for local failures.
type cloudStub struct {
	t           *testing.T
	createCalls atomic.Int32
	uploadCalls atomic.Int32
	doneCalls   atomic.Int32
	duplicate   bool
	status      int // when non-zero, create fails with this status
	incidentID  string
	digest      string
	sizeBytes   int64
	uploaded    []byte
}

func (s *cloudStub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/uploads", func(w http.ResponseWriter, r *http.Request) {
		s.createCalls.Add(1)
		if s.status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHENTICATED","message":"bad token"}}`))
			return
		}
		var req struct {
			SHA256     string `json:"sha256"`
			SizeBytes  int64  `json:"size_bytes"`
			IncidentID string `json:"incident_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.digest, s.sizeBytes, s.incidentID = req.SHA256, req.SizeBytes, req.IncidentID
		if s.duplicate {
			writeStubJSON(w, http.StatusOK, map[string]any{
				"upload_id": "upl_old", "duplicate": true,
				"incident_id": req.IncidentID,
				"url":         "https://app.test/incidents/" + req.IncidentID,
			})
			return
		}
		writeStubJSON(w, http.StatusCreated, map[string]any{
			"upload_id":  "upl_new",
			"object_key": "orgs/org_1/bundles/" + req.SHA256 + ".deprehendo",
			"upload": map[string]any{
				"url":    "http://" + r.Host + "/storage",
				"fields": map[string]string{"key": "orgs/org_1/bundles/x.deprehendo"},
			},
		})
	})
	mux.HandleFunc("/storage", func(w http.ResponseWriter, r *http.Request) {
		s.uploadCalls.Add(1)
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			s.t.Errorf("storage content type: %v", err)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				s.t.Errorf("storage part: %v", err)
				return
			}
			if part.FormName() == "file" {
				s.uploaded, _ = io.ReadAll(part)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/uploads/upl_new/complete", func(w http.ResponseWriter, r *http.Request) {
		s.doneCalls.Add(1)
		writeStubJSON(w, http.StatusOK, map[string]any{
			"upload_id": "upl_new", "incident_id": s.incidentID,
			"url": "https://app.test/incidents/" + s.incidentID,
		})
	})
	return mux
}

func writeStubJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fixtureBundle(t *testing.T) string {
	t.Helper()
	path := "../../testdata/incidents/cpu-spin.deprehendo"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return path
}

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func TestLoginStoresEndpointAndTokenAt0600(t *testing.T) {
	dir := t.TempDir()
	configpath := filepath.Join(dir, "nested", "config.json")
	stdin = strings.NewReader("tok_abc123\n")
	defer func() { stdin = os.Stdin }()

	stdout, stderr, code := runCLI(t, "login", "-endpoint", "https://cloud.test/", "-config", configpath)
	if code != 0 {
		t.Fatalf("login exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "https://cloud.test") {
		t.Errorf("login output = %q", stdout)
	}
	info, err := os.Stat(configpath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode = %04o, want 0600", perm)
	}
	dirinfo, err := os.Stat(filepath.Dir(configpath))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirinfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("config directory mode = %04o, want 0700", perm)
	}
	data, _ := os.ReadFile(configpath)
	var cfg cloudConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "https://cloud.test" || cfg.Token != "tok_abc123" {
		t.Errorf("stored config = %+v", cfg)
	}
}

func TestLoginFromTokenFileStripsBearerPrefix(t *testing.T) {
	dir := t.TempDir()
	tokenfile := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(tokenfile, []byte("Bearer tok_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configpath := filepath.Join(dir, "config.json")
	if _, stderr, code := runCLI(t, "login", "-endpoint", "https://cloud.test", "-token-file", tokenfile, "-config", configpath); code != 0 {
		t.Fatalf("login exit %d: %s", code, stderr)
	}
	data, err := os.ReadFile(configpath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"token": "tok_file"`) {
		t.Errorf("config = %s", data)
	}
}

func TestLoginRejectsPlainHTTPAndEmptyToken(t *testing.T) {
	stdin = strings.NewReader("tok\n")
	defer func() { stdin = os.Stdin }()
	if _, stderr, code := runCLI(t, "login", "-endpoint", "http://cloud.example.com", "-config", t.TempDir()+"/c.json"); code == 0 {
		t.Error("plain-http endpoint accepted")
	} else if !strings.Contains(stderr, "https") {
		t.Errorf("stderr = %q", stderr)
	}

	stdin = strings.NewReader("   \n")
	if _, _, code := runCLI(t, "login", "-endpoint", "http://127.0.0.1:8787", "-config", t.TempDir()+"/c.json"); code == 0 {
		t.Error("empty token accepted")
	}
}

func TestUploadEndToEnd(t *testing.T) {
	stub := &cloudStub{t: t}
	server := httptest.NewServer(stub.handler())
	defer server.Close()

	configpath := filepath.Join(t.TempDir(), "config.json")
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: server.URL, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	bundle := fixtureBundle(t)
	want, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "upload", "-config", configpath, bundle)
	if code != 0 {
		t.Fatalf("upload exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Uploading incident inc_") || !strings.Contains(stdout, "Validated") || !strings.Contains(stdout, "Uploaded") {
		t.Errorf("progress output = %q", stdout)
	}
	if !strings.Contains(stdout, "https://app.test/incidents/") {
		t.Errorf("missing dashboard URL in %q", stdout)
	}
	if stub.createCalls.Load() != 1 || stub.uploadCalls.Load() != 1 || stub.doneCalls.Load() != 1 {
		t.Errorf("calls create=%d upload=%d complete=%d", stub.createCalls.Load(), stub.uploadCalls.Load(), stub.doneCalls.Load())
	}
	if !bytes.Equal(stub.uploaded, want) {
		t.Errorf("uploaded %d bytes, want the exact %d bundle bytes", len(stub.uploaded), len(want))
	}
	if stub.sizeBytes != int64(len(want)) || len(stub.digest) != 64 {
		t.Errorf("server saw size=%d digest=%q", stub.sizeBytes, stub.digest)
	}
}

func TestUploadDuplicateDoesNotUploadBytes(t *testing.T) {
	stub := &cloudStub{t: t, duplicate: true}
	server := httptest.NewServer(stub.handler())
	defer server.Close()

	configpath := filepath.Join(t.TempDir(), "config.json")
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: server.URL, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLI(t, "upload", "-config", configpath, fixtureBundle(t))
	if code != 0 {
		t.Fatalf("upload exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Already uploaded") {
		t.Errorf("output = %q", stdout)
	}
	if stub.uploadCalls.Load() != 0 {
		t.Error("duplicate upload re-sent the bundle bytes")
	}
}

func TestUploadRefusesCorruptBundleBeforeNetwork(t *testing.T) {
	stub := &cloudStub{t: t}
	server := httptest.NewServer(stub.handler())
	defer server.Close()

	configpath := filepath.Join(t.TempDir(), "config.json")
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: server.URL, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(t.TempDir(), "bad.deprehendo")
	if err := os.WriteFile(corrupt, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, "upload", "-config", configpath, corrupt)
	if code == 0 {
		t.Fatal("corrupt bundle uploaded")
	}
	if !strings.Contains(stderr, "not a valid bundle") {
		t.Errorf("stderr = %q", stderr)
	}
	if stub.createCalls.Load() != 0 {
		t.Error("a locally invalid bundle reached the network")
	}
}

func TestUploadWithoutLoginExplainsLogin(t *testing.T) {
	_, stderr, code := runCLI(t, "upload", "-config", filepath.Join(t.TempDir(), "missing.json"), fixtureBundle(t))
	if code == 0 {
		t.Fatal("upload succeeded without credentials")
	}
	if !strings.Contains(stderr, "login") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestUploadRejectsWorldReadableConfig(t *testing.T) {
	configpath := filepath.Join(t.TempDir(), "config.json")
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: "http://127.0.0.1:1", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configpath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, "upload", "-config", configpath, fixtureBundle(t))
	if code == 0 {
		t.Fatal("world-readable credential file was used")
	}
	if !strings.Contains(stderr, "0600") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestLoginAutoUploadIsAnOptIn(t *testing.T) {
	dir := t.TempDir()
	configpath := filepath.Join(dir, "config.json")
	stdin = strings.NewReader("tok_abc123\n")
	defer func() { stdin = os.Stdin }()

	stdout, stderr, code := runCLI(t, "login", "-endpoint", "https://cloud.test", "-config", configpath)
	if code != 0 {
		t.Fatalf("login exit %d: %s", code, stderr)
	}
	if strings.Contains(stdout, "Auto-upload: on") {
		t.Fatalf("auto-upload was on without the flag:\n%s", stdout)
	}
	if cfg, err := readCloudConfig(configpath); err != nil || cfg.AutoUpload {
		t.Fatalf("default config = %+v, %v", cfg, err)
	}

	stdin = strings.NewReader("tok_abc123\n")
	stdout, stderr, code = runCLI(t, "login", "-endpoint", "https://cloud.test", "-config", configpath, "-auto-upload")
	if code != 0 {
		t.Fatalf("login -auto-upload exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Auto-upload: on") || !strings.Contains(stdout, "queue.json") {
		t.Fatalf("stdout does not explain auto-upload:\n%s", stdout)
	}
	cfg, err := readCloudConfig(configpath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoUpload {
		t.Fatal("auto_upload was not recorded")
	}
	if want := filepath.Join(dir, "queue.json"); defaultQueuePath(configpath) != want {
		t.Errorf("queue path = %q, want %q", defaultQueuePath(configpath), want)
	}
}

func TestAutoUploadHookIsOffUnlessConfigured(t *testing.T) {
	dir := t.TempDir()
	configpath := filepath.Join(dir, "config.json")

	// no credential file at all: nothing to do and nothing to warn about.
	if hook, err := newAutoUpload(configpath, nil); err != nil || hook != nil {
		t.Fatalf("absent config: hook=%v err=%v", hook, err)
	}
	// credentials without the opt-in stay manual.
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: "https://cloud.test", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	if hook, err := newAutoUpload(configpath, nil); err != nil || hook != nil {
		t.Fatalf("manual config: hook=%v err=%v", hook, err)
	}

	// opted in: the hook exists, and a completed incident is queued.
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: "https://cloud.test", Token: "tok", AutoUpload: true}); err != nil {
		t.Fatal(err)
	}
	hook, err := newAutoUpload(configpath, nil)
	if err != nil || hook == nil {
		t.Fatalf("auto config: hook=%v err=%v", hook, err)
	}
	bundle := fixtureBundle(t)
	hook.OnSaved("inc_test", bundle)
	if s := hook.queue.Summary(); s.Pending != 1 {
		t.Fatalf("queue summary = %+v, want one pending entry", s)
	}
	// A second save of the same path (a repeated trigger) does not double it.
	hook.OnSaved("inc_test", bundle)
	if s := hook.queue.Summary(); s.Pending != 1 {
		t.Fatalf("queue summary after a repeat save = %+v", s)
	}
}

func TestQueueDefersWhenCloudIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	configpath := filepath.Join(dir, "config.json")
	// port 1 on loopback: the connection is refused immediately, which is the
	// offline case 7.49 describes.
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: "http://127.0.0.1:1", Token: "tok_offline", AutoUpload: true}); err != nil {
		t.Fatal(err)
	}
	queuepath := filepath.Join(dir, "queue.json")
	bundle := fixtureBundle(t)
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := uploadqueue.Open(queuepath, uploadqueue.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue(bundle); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	stdout, stderr, code := runCLI(t, "queue", "-config", configpath, "-queue", queuepath)
	if code != 0 {
		t.Fatalf("queue exit %d (offline is not an error): %s", code, stderr)
	}
	for _, want := range []string{"pending 1", "deferred 1", "Upload deferred"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	// the local incident is untouched and still queued for a later attempt.
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatalf("bundle is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the queue modified the bundle")
	}
	reopened, err := uploadqueue.Open(queuepath, uploadqueue.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	entries := reopened.Entries()
	if len(entries) != 1 || entries[0].State != uploadqueue.Pending || entries[0].Attempts != 1 {
		t.Fatalf("queue after the failed attempt = %+v", entries)
	}
	if entries[0].LastError == "" {
		t.Error("the deferred entry keeps no reason")
	}

	// --no-drain reports the queue without attempting anything.
	stdout, stderr, code = runCLI(t, "queue", "-config", configpath, "-queue", queuepath, "-no-drain")
	if code != 0 {
		t.Fatalf("queue -no-drain exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "pending 1") {
		t.Errorf("no-drain summary = %q", stdout)
	}
}

func TestUploadMaps401ToLoginHint(t *testing.T) {
	stub := &cloudStub{t: t, status: http.StatusUnauthorized}
	server := httptest.NewServer(stub.handler())
	defer server.Close()

	configpath := filepath.Join(t.TempDir(), "config.json")
	if err := writeCloudConfig(configpath, cloudConfig{Endpoint: server.URL, Token: "expired"}); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, "upload", "-config", configpath, fixtureBundle(t))
	if code == 0 {
		t.Fatal("401 was treated as success")
	}
	if !strings.Contains(stderr, "login") {
		t.Errorf("stderr = %q", stderr)
	}
}
