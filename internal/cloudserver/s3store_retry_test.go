package cloudserver

// retries (7.59 cost load, november 19, 2026): about 1 in 20 writes to the
// railway bucket failed with a server error under steady load, and each one
// failed a user's upload. these tests pin the retry rules.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestS3StoreRetriesTransientPutFailures(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	fake.failStatus = []int{http.StatusServiceUnavailable, http.StatusInternalServerError}
	ctx := context.Background()
	data := []byte("bundle bytes")
	if _, err := store.Put(ctx, testKey, data); err != nil {
		t.Fatalf("Put should succeed after two transient failures: %v", err)
	}
	if fake.requests != 3 {
		t.Fatalf("expected 3 PUT attempts, got %d", fake.requests)
	}
	if got, err := store.Get(ctx, testKey); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("Get after retried Put: %q err=%v", got, err)
	}
}

// the first PUT stores the object but its answer is lost (500). the retry is
// refused as a duplicate; reading the object back shows it is ours, so the
// write succeeded.
func TestS3StorePutRetryAfterLostAnswerSucceeds(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	fake.storeThenFail = 1
	data := []byte("bundle bytes")
	n, err := store.Put(context.Background(), testKey, data)
	if err != nil || n != int64(len(data)) {
		t.Fatalf("Put after a lost answer: n=%d err=%v", n, err)
	}
	if fake.requests != 3 {
		t.Fatalf("expected PUT, PUT (412), GET = 3 requests, got %d", fake.requests)
	}
}

// A retry must not turn a real duplicate into a success: when the key already
// holds different bytes, the immutable error stands and the original is kept.
func TestS3StoreRetryDoesNotHideARealDuplicate(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	fake.objects[testKey] = []byte("original")
	fake.failStatus = []int{http.StatusServiceUnavailable}
	_, err := store.Put(context.Background(), testKey, []byte("other"))
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("Put over different bytes must be refused as immutable, got %v", err)
	}
	if got := string(fake.objects[testKey]); got != "original" {
		t.Fatalf("original was overwritten: %q", got)
	}
}

// A first-attempt duplicate is answered without a read-back: nothing was retried.
func TestS3StoreFirstAttemptDuplicateNeedsNoReadBack(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	fake.objects[testKey] = []byte("bundle bytes")
	_, err := store.Put(context.Background(), testKey, []byte("bundle bytes"))
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("first-attempt duplicate should stay the immutable error, got %v", err)
	}
	if fake.requests != 1 {
		t.Fatalf("expected a single PUT, got %d requests", fake.requests)
	}
}

func TestS3StoreGivesUpAfterRetries(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	fake.failStatus = []int{503, 503, 503, 503, 503, 503}
	_, err := store.Put(context.Background(), testKey, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("persistent 503 should surface its status, got %v", err)
	}
	if want := 1 + len(store.backoff); fake.requests != want {
		t.Fatalf("expected %d attempts, got %d", want, fake.requests)
	}
}

func TestS3StoreDoesNotRetryClientErrors(t *testing.T) {
	store, fake, _ := newTestStore(t, "not-the-secret") // every request answers 403
	if _, err := store.Put(context.Background(), testKey, []byte("x")); err == nil {
		t.Fatal("a 403 must fail")
	}
	if fake.requests != 1 {
		t.Fatalf("a 403 must not be retried, got %d requests", fake.requests)
	}
	fake.requests = 0
	fake.failStatus = []int{http.StatusBadRequest}
	if _, err := store.Get(context.Background(), testKey); err == nil || errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("a 400 must fail as an error, got %v", err)
	}
	if fake.requests != 1 {
		t.Fatalf("a 400 must not be retried, got %d requests", fake.requests)
	}
}

func TestS3StoreRetriesGetAndDelete(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	ctx := context.Background()
	fake.objects[testKey] = []byte("doc")
	fake.failStatus = []int{http.StatusServiceUnavailable}
	if got, err := store.Get(ctx, testKey); err != nil || string(got) != "doc" {
		t.Fatalf("Get after a 503: %q err=%v", got, err)
	}
	fake.failStatus = []int{http.StatusTooManyRequests}
	if err := store.Delete(ctx, testKey); err != nil {
		t.Fatalf("Delete after a 429: %v", err)
	}
	if _, ok := fake.objects[testKey]; ok {
		t.Fatal("object survived the retried Delete")
	}
}

// A dropped connection (no HTTP answer at all) is retried like a 5xx.
func TestS3StoreRetriesDroppedConnections(t *testing.T) {
	fake := &fakeProvider{bucket: "runopsy-test", accessKey: "AKIATESTKEY", secretKey: "test-secret-value", objects: map[string][]byte{}}
	var mu sync.Mutex
	drops := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		drop := drops > 0
		if drop {
			drops--
		}
		mu.Unlock()
		if drop {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer srv.Close()
	st, err := NewS3Store(S3Config{Endpoint: srv.URL, Region: "eu-west-1", Bucket: "runopsy-test", AccessKey: "AKIATESTKEY", SecretKey: "test-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	s := st.(*s3Store)
	s.backoff = []time.Duration{0, 0, 0}
	if _, err := s.Put(context.Background(), testKey, []byte("x")); err != nil {
		t.Fatalf("Put after a dropped connection: %v", err)
	}
	if string(fake.objects[testKey]) != "x" {
		t.Fatal("object was not stored")
	}
}

// cancelling the request stops the retries at once instead of sleeping on.
func TestS3StoreRetryHonoursContext(t *testing.T) {
	store, fake, _ := newTestStore(t, "test-secret-value")
	store.backoff = []time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second}
	fake.failStatus = []int{503, 503, 503, 503}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := store.Put(ctx, testKey, []byte("x"))
	if err == nil {
		t.Fatal("Put should fail when the context ends")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("retry kept sleeping after the context ended (%s)", elapsed)
	}
}
