// unit tests for the 7.60 security-gate fixes that need no database: the
// storage POST reads nothing past the policy fields until a policy verifies,
// and analyzer job slots honour a server-wide cap and the request context.
// the database-backed halves (owner-only actions, delete removing every
// document) live in tests/phase7_security_gate_test.go.
package cloudserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingReader counts the bytes the handler actually pulled from the body.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func gateServer(t *testing.T) *Server {
	t.Helper()
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Server{secret: []byte("gate-test-secret"), storage: store, logf: t.Logf}
}

// multipartBody writes the named fields in order, with the file part at
// position filePos (len(fields) means last, as every client sends it).
func multipartBody(t *testing.T, fields [][2]string, filePos int, file []byte) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	writefile := func() {
		part, err := w.CreateFormFile("file", "bundle.runopsy")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file); err != nil {
			t.Fatal(err)
		}
	}
	for i, f := range fields {
		if i == filePos {
			writefile()
		}
		if err := w.WriteField(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	if filePos >= len(fields) {
		writefile()
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, w.FormDataContentType()
}

func postStorage(s *Server, body io.Reader, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/storage", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	s.storagePost(rec, req)
	return rec
}

func policyFields(s *Server, data []byte) (string, [][2]string) {
	sum := sha256.Sum256(data)
	key, fields := mintUploadPolicy(safeTestOrg, hex.EncodeToString(sum[:]), s.secret)
	return key, [][2]string{
		{"key", fields["key"]},
		{"policy", fields["policy"]},
		{"x-amz-signature", fields["x-amz-signature"]},
	}
}

// an unauthenticated body with no policy must be refused after the server has
// read only its first part headers, not the file: before 7.60 the whole form
// was parsed (up to the 65 MiB archive budget, in memory and temp files)
// before the policy was even looked at.
func TestStoragePostReadsNothingPastAMissingPolicy(t *testing.T) {
	s := gateServer(t)
	big := bytes.Repeat([]byte("x"), 8<<20)
	body, ctype := multipartBody(t, nil, 0, big)
	counter := &countingReader{r: body}
	rec := postStorage(s, counter, ctype)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if read := counter.n.Load(); read > 1<<20 {
		t.Fatalf("handler read %d bytes of an unauthorized body; it must stop at the policy check", read)
	}
}

// A huge non-file field is refused after its first few KiB, not read to the end.
func TestStoragePostStopsReadingAnOversizedField(t *testing.T) {
	s := gateServer(t)
	body, ctype := multipartBody(t, [][2]string{{"policy", strings.Repeat("p", 8<<20)}}, 1, []byte("x"))
	counter := &countingReader{r: body}
	rec := postStorage(s, counter, ctype)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if read := counter.n.Load(); read > 1<<20 {
		t.Fatalf("handler read %d bytes of an oversized field", read)
	}
}

// the file part must come after a valid policy; a file sent first is refused
// even when a valid policy follows it, and nothing is stored.
func TestStoragePostRefusesFileBeforePolicy(t *testing.T) {
	s := gateServer(t)
	data := bytes.Repeat([]byte("b"), 64)
	key, fields := policyFields(s, data)
	body, ctype := multipartBody(t, fields, 0, data)
	if rec := postStorage(s, body, ctype); rec.Code != http.StatusForbidden {
		t.Fatalf("file-first status = %d, want 403", rec.Code)
	}
	if _, err := s.storage.Get(context.Background(), key); err == nil {
		t.Fatal("a refused upload left an object behind")
	}
	// the same bytes in the client's order (fields, then file) are accepted.
	body, ctype = multipartBody(t, fields, len(fields), data)
	if rec := postStorage(s, body, ctype); rec.Code != http.StatusNoContent {
		t.Fatalf("fields-first status = %d (%s), want 204", rec.Code, rec.Body.String())
	}
	if got, err := s.storage.Get(context.Background(), key); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stored object = %q, %v", got, err)
	}
}

func TestStoragePostBoundsPolicyFields(t *testing.T) {
	s := gateServer(t)
	data := bytes.Repeat([]byte("c"), 64)
	_, fields := policyFields(s, data)

	oversized := append([][2]string{{"padding", strings.Repeat("p", maxPolicyFieldBytes+1)}}, fields...)
	body, ctype := multipartBody(t, oversized, len(oversized), data)
	if rec := postStorage(s, body, ctype); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized field status = %d, want 400", rec.Code)
	}

	var many [][2]string
	for i := 0; i < maxPolicyFields+1; i++ {
		many = append(many, [2]string{"f" + string(rune('a'+i)), "v"})
	}
	body, ctype = multipartBody(t, many, len(many), data)
	if rec := postStorage(s, body, ctype); rec.Code != http.StatusBadRequest {
		t.Fatalf("too many fields status = %d, want 400", rec.Code)
	}

	dup := append(append([][2]string{}, fields...), fields[0])
	body, ctype = multipartBody(t, dup, len(dup), data)
	if rec := postStorage(s, body, ctype); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate field status = %d, want 400", rec.Code)
	}
}

func slotServer(perOrg, total int) *Server {
	return &Server{
		cfg:   Config{MaxConcurrentPerOrg: perOrg, MaxConcurrentTotal: total},
		busy:  map[string]int{},
		freed: make(chan struct{}),
	}
}

func TestAcquireJobHonoursTheServerWideCap(t *testing.T) {
	s := slotServer(2, 1)
	release, err := s.acquireJob(context.Background(), "org_a")
	if err != nil {
		t.Fatal(err)
	}
	// another organization is under its own limit but the server is full.
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.acquireJob(short, "org_b"); err == nil {
		t.Fatal("a second job ran past the server-wide cap")
	}
	// A waiter gets the slot as soon as it is released.
	got := make(chan error, 1)
	go func() {
		rel, err := s.acquireJob(context.Background(), "org_b")
		if err == nil {
			rel()
		}
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	release()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("waiter: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter was not woken by the release")
	}
	if s.running != 0 || len(s.busy) != 0 {
		t.Fatalf("slots leaked: running=%d busy=%v", s.running, s.busy)
	}
}

func TestAcquireJobHonoursThePerOrganizationCap(t *testing.T) {
	s := slotServer(1, 4)
	release, err := s.acquireJob(context.Background(), "org_a")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.acquireJob(short, "org_a"); err == nil {
		t.Fatal("an organization ran past its own limit")
	}
	other, err := s.acquireJob(context.Background(), "org_b")
	if err != nil {
		t.Fatalf("another organization was blocked: %v", err)
	}
	other()
}
