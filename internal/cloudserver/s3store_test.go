package cloudserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSigV4GetVanilla checks the signer against the AWS signature version 4
// test suite case "get-vanilla" (GET / on example.amazonaws.com).
func TestSigV4GetVanilla(t *testing.T) {
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	headers := map[string]string{
		"host":       "example.amazonaws.com",
		"x-amz-date": "20150830T123600Z",
	}
	got := sigV4Authorization("GET", "/", headers, []string{"host", "x-amz-date"},
		sha256Hex(nil), when, "us-east-1", "service", "AKIDEXAMPLE",
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Fatalf("signature mismatch\n got: %s\nwant: %s", got, want)
	}
}

// fakeProvider is a minimal path-style S3 endpoint. it recomputes the signature
// of every request with the secret it was given, and refuses requests that do
// not match. it also enforces conditional writes.
type fakeProvider struct {
	mu        sync.Mutex
	bucket    string
	accessKey string
	secretKey string
	objects   map[string][]byte
	requests  int
	// failStatus answers the next requests with these statuses, in order,
	// before doing anything else (a provider's transient 5xx or 429).
	failStatus []int
	// storeThenFail makes the next PUTs store the object and then answer 500,
	// as when the provider's reply is lost after the write took effect.
	storeThenFail int
}

func (f *fakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if len(f.failStatus) > 0 {
		code := f.failStatus[0]
		f.failStatus = f.failStatus[1:]
		w.WriteHeader(code)
		return
	}
	prefix := "/" + f.bucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "wrong bucket", http.StatusNotFound)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	body, _ := io.ReadAll(r.Body)

	if !f.signatureValid(r, body) {
		http.Error(w, "signature", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPut:
		if r.Header.Get("If-None-Match") != "*" {
			http.Error(w, "conditional header missing", http.StatusBadRequest)
			return
		}
		if _, exists := f.objects[key]; exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		f.objects[key] = body
		if f.storeThenFail > 0 {
			f.storeThenFail--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		data, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// signatureValid rebuilds the signed string from the request as received and
// compares it with the authorization header the client sent.
func (f *fakeProvider) signatureValid(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	const marker = "SignedHeaders="
	i := strings.Index(auth, marker)
	if i < 0 {
		return false
	}
	rest := auth[i+len(marker):]
	signedlist := rest[:strings.Index(rest, ",")]
	signed := strings.Split(signedlist, ";")
	headers := map[string]string{"host": r.Host}
	for _, name := range signed {
		if name == "host" {
			continue
		}
		headers[name] = r.Header.Get(name)
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload != sha256Hex(body) {
		return false
	}
	when, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return false
	}
	want := sigV4Authorization(r.Method, r.URL.EscapedPath(), headers, signed, payload, when,
		"eu-west-1", "s3", f.accessKey, f.secretKey)
	return want == auth
}

func newTestStore(t *testing.T, secret string) (*s3Store, *fakeProvider, *httptest.Server) {
	t.Helper()
	fake := &fakeProvider{
		bucket:    "deprehendo-test",
		accessKey: "AKIATESTKEY",
		secretKey: "test-secret-value",
		objects:   map[string][]byte{},
	}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	store, err := NewS3Store(S3Config{
		Endpoint:  srv.URL,
		Region:    "eu-west-1",
		Bucket:    "deprehendo-test",
		AccessKey: "AKIATESTKEY",
		SecretKey: secret,
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	s := store.(*s3Store)
	s.now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	s.backoff = []time.Duration{0, 0, 0} // same retry count as production, no waiting
	return s, fake, srv
}

const testKey = "orgs/org_a1/bundles/" + "0000000000000000000000000000000000000000000000000000000000000000" + ".deprehendo"

func TestS3StoreRoundTrip(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	ctx := context.Background()
	data := []byte("bundle bytes")
	n, err := store.Put(ctx, testKey, data)
	if err != nil || n != int64(len(data)) {
		t.Fatalf("Put: n=%d err=%v", n, err)
	}
	got, err := store.Get(ctx, testKey)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("Get: %q err=%v", got, err)
	}
	if fake.requests != 2 {
		t.Fatalf("expected two signed requests, got %d", fake.requests)
	}
}

func TestS3StoreIsImmutable(t *testing.T) {
	store, _, _ := newTestStore(t, "test-secret-value")
	ctx := context.Background()
	if _, err := store.Put(ctx, testKey, []byte("first")); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	_, err := store.Put(ctx, testKey, []byte("second"))
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("second Put should be refused as immutable, got %v", err)
	}
	got, _ := store.Get(ctx, testKey)
	if string(got) != "first" {
		t.Fatalf("original was overwritten: %q", got)
	}
}

func TestS3StoreMissingAndDelete(t *testing.T) {
	store, _, _ := newTestStore(t, "test-secret-value")
	ctx := context.Background()
	if _, err := store.Get(ctx, testKey); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("missing Get should be ErrNoSuchObject, got %v", err)
	}
	if err := store.Delete(ctx, testKey); err != nil {
		t.Fatalf("delete of a missing object should succeed, got %v", err)
	}
	if _, err := store.Put(ctx, testKey, []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, testKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, testKey); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("Get after Delete should be ErrNoSuchObject, got %v", err)
	}
}

func TestS3StoreWrongSecretIsRefused(t *testing.T) {
	store, _, _ := newTestStore(t, "not-the-secret")
	if _, err := store.Put(context.Background(), testKey, []byte("x")); err == nil {
		t.Fatal("a request signed with the wrong secret must be refused")
	}
}

func TestS3StoreRefusesUnsafeKeysBeforeNetwork(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	ctx := context.Background()
	for _, key := range []string{"../etc/passwd.deprehendo", "orgs/../x.deprehendo", "/abs.deprehendo", "no-dot-name", "orgs/A/x.deprehendo"} {
		if _, err := store.Put(ctx, key, []byte("x")); err == nil {
			t.Errorf("Put accepted unsafe key %q", key)
		}
		if _, err := store.Get(ctx, key); err == nil {
			t.Errorf("Get accepted unsafe key %q", key)
		}
	}
	if fake.requests != 0 {
		t.Fatalf("unsafe keys reached the network (%d requests)", fake.requests)
	}
}

func TestNewS3StoreValidatesConfig(t *testing.T) {
	good := S3Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "deprehendo-assets",
		AccessKey: "AK", SecretKey: "SK",
	}
	if _, err := NewS3Store(good); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	cases := map[string]S3Config{}
	plain := good
	plain.Endpoint = "http://s3.example.com"
	cases["plain http to a remote host"] = plain
	userinfo := good
	userinfo.Endpoint = "https://user:hunter2@s3.example.com"
	cases["userinfo in endpoint"] = userinfo
	nokey := good
	nokey.SecretKey = ""
	cases["missing secret"] = nokey
	badbucket := good
	badbucket.Bucket = "Bad_Bucket"
	cases["bad bucket name"] = badbucket
	badregion := good
	badregion.Region = "US East"
	cases["bad region"] = badregion
	for name, cfg := range cases {
		if _, err := NewS3Store(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error echoes the password", name)
		}
	}
	loopback := good
	loopback.Endpoint = "http://127.0.0.1:9000"
	if _, err := NewS3Store(loopback); err != nil {
		t.Errorf("loopback http should be allowed for tests: %v", err)
	}
}

// A 409 ConditionalRequestConflict is what S3 returns when two conditional
// writes race. it must be reported as the duplicate case, not a server error.
func TestS3StoreConflictIsImmutable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()
	store, err := NewS3Store(S3Config{
		Endpoint: srv.URL, Region: "eu-west-1", Bucket: "deprehendo-test",
		AccessKey: "AK", SecretKey: "SK",
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	_, err = store.Put(context.Background(), testKey, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("409 should map to the immutable error, got %v", err)
	}
}

// A redirect must not be followed: the replayed PUT would carry a signature
// made for this host. the target must receive no requests.
func TestS3StoreDoesNotFollowRedirects(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	store, err := NewS3Store(S3Config{
		Endpoint: redirector.URL, Region: "eu-west-1", Bucket: "deprehendo-test",
		AccessKey: "AK", SecretKey: "SK",
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	if _, err := store.Put(context.Background(), testKey, []byte("x")); err == nil {
		t.Fatal("a 307 must surface as an error")
	}
	if targetHits != 0 {
		t.Fatalf("redirect was followed to the target %d times", targetHits)
	}
}
