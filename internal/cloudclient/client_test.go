package cloudclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"https://deprehendo.example.com/", "https://deprehendo.example.com", false},
		{"https://deprehendo.example.com/api/", "https://deprehendo.example.com/api", false},
		{"http://127.0.0.1:8787", "http://127.0.0.1:8787", false},
		{"http://localhost:8787/", "http://localhost:8787", false},
		{"http://[::1]:8787", "http://[::1]:8787", false},
		{"http://deprehendo.example.com", "", true},
		{"ftp://deprehendo.example.com", "", true},
		{"deprehendo.example.com", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := NormalizeEndpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeEndpoint(%q) accepted a bad endpoint as %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeEndpoint(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewRejectsEmptyTokenAndHostlessEndpoint(t *testing.T) {
	if _, err := New("https://example.com", ""); err == nil {
		t.Error("empty token accepted")
	}
	if _, err := New("https://", "tok"); err == nil {
		t.Error("hostless endpoint accepted")
	}
}

// F1 (docs/cloud/secrets-audit.md): endpoint errors must not echo userinfo.
func TestNormalizeEndpointErrorHidesUserinfo(t *testing.T) {
	for _, in := range []string{"http://user:secret@deprehendo.example.com", "https://user:secret@deprehendo.example.com:9/oops", "ftp://user:secret@deprehendo.example.com"} {
		_, err := NormalizeEndpoint(in)
		if err == nil {
			t.Errorf("NormalizeEndpoint(%q) accepted", in)
			continue
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user:") {
			t.Errorf("error %q leaks endpoint userinfo", err)
		}
		if !strings.Contains(err.Error(), "deprehendo.example.com") {
			t.Errorf("error %q lost the redacted host", err)
		}
	}
	// the normalized endpoint keeps no credentials.
	if got, err := NormalizeEndpoint("https://deprehendo.example.com/api/"); err != nil || got != "https://deprehendo.example.com/api" {
		t.Errorf("NormalizeEndpoint clean endpoint = %q, %v", got, err)
	}
	// hostless garbage cannot echo the input either.
	_, err := NormalizeEndpoint("deprehendo.example.com user:secret")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error %q leaked input", err)
	}
}

// F2: the presigned-storage POST carries a signature in its URL; a transport
// failure must not surface that URL through the wrapped error.
func TestStorageFailureDoesNotLeakPresignedURL(t *testing.T) {
	target := &Target{URL: "http://127.0.0.1:1/bucket/signature=SECRET", Fields: map[string]string{"key": "k"}}
	c, _ := New("http://127.0.0.1:1", "tok")
	path := filepath.Join(t.TempDir(), "incident.deprehendo")
	if err := os.WriteFile(path, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := c.PutObject(context.Background(), target, path)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error %q leaks the presignature", err)
	}
}

// F3: server-supplied text is made safe for a terminal.
func TestSanitizeServerText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"all fine", "all fine"},
		{"tab\tkept", "tab\tkept"},
		{"evil\x1b[31mred\rflagged", "evil[31mredflagged"},
		{"del\x7fchar", "delchar"},
	}
	for _, tc := range cases {
		if got := SanitizeServerText(tc.in); got != tc.want {
			t.Errorf("SanitizeServerText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("x", maxServerMessage)
	if got := SanitizeServerText(long + "+tail"); len(got) > maxServerMessage+3 {
		t.Errorf("sanitized message is %d bytes", len(got))
	}
	// the error type applies the same rule to its message.
	e := &Error{Status: 429, Code: "RATE_LIMITED", Message: "60 analyses per hour\x1b"}
	if strings.Contains(e.Error(), "\x1b") {
		t.Errorf("Error() printed a control character: %q", e.Error())
	}
}

// fakeCloud is a minimal server implementing the three calls of
// docs/cloud/upload-api.md around a presigned storage target on the same host.
type fakeCloud struct {
	t *testing.T

	mu           struct{}
	create       CreateRequest
	completeID   string
	storageBody  []byte
	storageField map[string]string
	storageAuth  string
	duplicate    bool
	failStorage  bool
}

func (f *fakeCloud) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/uploads", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			f.t.Errorf("create method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			f.t.Errorf("create Authorization = %q", got)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			f.t.Errorf("create Content-Type = %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &f.create); err != nil {
			f.t.Errorf("create body: %v", err)
		}
		if f.duplicate {
			writeJSON(w, http.StatusOK, Upload{
				UploadID:   "upl_existing",
				IncidentID: f.create.IncidentID,
				URL:        "https://app.example.com/incidents/" + f.create.IncidentID,
				Duplicate:  true,
			})
			return
		}
		scheme := "http://" + r.Host
		writeJSON(w, http.StatusCreated, Upload{
			UploadID:  "upl_new",
			ObjectKey: "orgs/org_1/bundles/" + f.create.SHA256 + ".deprehendo",
			Upload: &Target{
				URL:    scheme + "/storage",
				Fields: map[string]string{"key": "orgs/org_1/bundles/x.deprehendo", "policy": "c2lnbmVk"},
			},
		})
	})
	mux.HandleFunc("/storage", func(w http.ResponseWriter, r *http.Request) {
		f.storageAuth = r.Header.Get("Authorization")
		mediatype, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediatype != "multipart/form-data" {
			f.t.Errorf("storage Content-Type = %q (%v)", r.Header.Get("Content-Type"), err)
			http.Error(w, "bad type", http.StatusBadRequest)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		f.storageField = map[string]string{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.t.Errorf("storage part: %v", err)
				return
			}
			data, _ := io.ReadAll(part)
			if part.FormName() == "file" {
				f.storageBody = data
				if part.FileName() == "" {
					f.t.Error("file part has no filename")
				}
				continue
			}
			f.storageField[part.FormName()] = string(data)
		}
		if f.failStorage {
			writeError(w, http.StatusForbidden, "SIGNATURE_MISMATCH", "policy expired")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/uploads/upl_new/complete", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			f.t.Errorf("complete Authorization = %q", got)
		}
		f.completeID = "upl_new"
		writeJSON(w, http.StatusOK, Upload{
			UploadID:   "upl_new",
			IncidentID: f.create.IncidentID,
			URL:        "https://app.example.com/incidents/" + f.create.IncidentID,
		})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func testBundleFile(t *testing.T) (string, []byte) {
	t.Helper()
	data := []byte("deprehendo bundle bytes")
	path := filepath.Join(t.TempDir(), "incident.deprehendo")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func TestUploadRoundTrip(t *testing.T) {
	fake := &fakeCloud{t: t}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	client, err := New(server.URL, "token-123")
	if err != nil {
		t.Fatal(err)
	}
	path, data := testBundleFile(t)

	upload, err := client.Create(context.Background(), CreateRequest{
		SHA256: strings.Repeat("a", 64), SizeBytes: int64(len(data)),
		IncidentID: "inc_1", SchemaVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if upload.Duplicate || upload.UploadID != "upl_new" {
		t.Fatalf("unexpected create reply: %+v", upload)
	}
	if fake.create.SHA256 != strings.Repeat("a", 64) || fake.create.IncidentID != "inc_1" {
		t.Errorf("server saw create request %+v", fake.create)
	}

	if err := client.PutObject(context.Background(), upload.Upload, path); err != nil {
		t.Fatalf("put: %v", err)
	}
	if string(fake.storageBody) != string(data) {
		t.Errorf("stored %q, want %q", fake.storageBody, data)
	}
	if fake.storageAuth != "" {
		t.Errorf("storage request carried Authorization %q; the signed URL must not receive the token", fake.storageAuth)
	}
	if fake.storageField["policy"] != "c2lnbmVk" || fake.storageField["key"] != "orgs/org_1/bundles/x.deprehendo" {
		t.Errorf("storage fields = %v", fake.storageField)
	}

	done, err := client.Complete(context.Background(), upload.UploadID)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if done.IncidentID != "inc_1" || !strings.Contains(done.URL, "inc_1") {
		t.Errorf("complete reply = %+v", done)
	}
	if fake.completeID != "upl_new" {
		t.Errorf("complete called with %q", fake.completeID)
	}
}

func TestCreateReportsDuplicateWithoutUpload(t *testing.T) {
	fake := &fakeCloud{t: t, duplicate: true}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	client, err := New(server.URL, "token-123")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := client.Create(context.Background(), CreateRequest{
		SHA256: strings.Repeat("b", 64), SizeBytes: 42, IncidentID: "inc_dup",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !upload.Duplicate || upload.Upload != nil || upload.URL == "" {
		t.Errorf("duplicate reply = %+v", upload)
	}
}

func TestAPIErrorCarriesServerCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "60 analyses per hour")
	}))
	defer server.Close()

	client, err := New(server.URL, "token-123")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Create(context.Background(), CreateRequest{SHA256: strings.Repeat("c", 64), SizeBytes: 10, IncidentID: "inc_x"})
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if apiErr.Status != 429 || apiErr.Code != "RATE_LIMITED" || apiErr.Message != "60 analyses per hour" {
		t.Errorf("error = %+v", apiErr)
	}
	if strings.Contains(err.Error(), "token-123") {
		t.Error("error text leaked the token")
	}
}

func TestStorageFailureIsAnError(t *testing.T) {
	fake := &fakeCloud{t: t, failStorage: true}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	client, err := New(server.URL, "token-123")
	if err != nil {
		t.Fatal(err)
	}
	path, data := testBundleFile(t)
	upload, err := client.Create(context.Background(), CreateRequest{
		SHA256: strings.Repeat("d", 64), SizeBytes: int64(len(data)), IncidentID: "inc_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.PutObject(context.Background(), upload.Upload, path)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("storage failure = %v", err)
	}
}

func TestCrossHostRedirectIsRefused(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("redirect target received Authorization %q", got)
		}
		writeJSON(w, http.StatusOK, Upload{UploadID: "upl_elsewhere"})
	}))
	defer target.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/uploads", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client, err := New(server.URL, "token-123")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Create(context.Background(), CreateRequest{SHA256: strings.Repeat("f", 64), SizeBytes: 10, IncidentID: "inc_x"})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("cross-host redirect error = %v", err)
	}
	if targetHits != 0 {
		t.Errorf("redirect target was contacted %d times", targetHits)
	}
}

func TestMissingStorageTargetIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, Upload{UploadID: "upl_1"})
	}))
	defer server.Close()

	client, err := New(server.URL, "token-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(context.Background(), CreateRequest{SHA256: strings.Repeat("e", 64), SizeBytes: 10, IncidentID: "inc_x"}); err == nil {
		t.Error("a create reply with no target was accepted")
	}
}
