package cloudserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jwksServer serves a mutable key set and counts fetches.
type jwksServer struct {
	mu      sync.Mutex
	keys    map[string]ed25519.PublicKey
	fetches atomic.Int32
	srv     *httptest.Server
}

func newJWKSServer(t *testing.T) *jwksServer {
	t.Helper()
	j := &jwksServer{keys: map[string]ed25519.PublicKey{}}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		j.fetches.Add(1)
		j.mu.Lock()
		defer j.mu.Unlock()
		var set struct {
			Keys []map[string]string `json:"keys"`
		}
		for kid, pub := range j.keys {
			set.Keys = append(set.Keys, map[string]string{
				"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			})
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) addKey(t *testing.T, kid string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	j.keys[kid] = pub
	j.mu.Unlock()
	return priv
}

func (j *jwksServer) authURL() string { return j.srv.URL + "/auth" }

// signJWT builds a compact JWS. header and claims are marshalled as given, so
// tests can produce every malformed variant.
func signJWT(t *testing.T, priv ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func goodClaims(origin string, now time.Time) map[string]any {
	return map[string]any{
		"sub": "usr_AbC123", "iss": origin, "aud": origin,
		"iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
		"email": "a@example.com", "o": nil,
	}
}

func newTestBrowserAuth(t *testing.T, j *jwksServer) *BrowserAuth {
	t.Helper()
	b, err := NewBrowserAuth(BrowserAuthConfig{AuthURL: j.authURL()})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBrowserAuthAcceptsAValidToken(t *testing.T) {
	j := newJWKSServer(t)
	priv := j.addKey(t, "k1")
	b := newTestBrowserAuth(t, j)
	now := time.Now()
	tok := signJWT(t, priv, map[string]any{"alg": "EdDSA", "kid": "k1", "typ": "JWT"}, goodClaims(j.srv.URL, now))
	sub, err := b.Verify(context.Background(), tok)
	if err != nil || sub != "usr_AbC123" {
		t.Fatalf("Verify = %q, %v", sub, err)
	}
	// aud as an array (RFC 7519) is accepted too.
	c := goodClaims(j.srv.URL, now)
	c["aud"] = []string{"https://other.example", j.srv.URL}
	if _, err := b.Verify(context.Background(), signJWT(t, priv, map[string]any{"alg": "EdDSA", "kid": "k1"}, c)); err != nil {
		t.Fatalf("array aud refused: %v", err)
	}
	if j.fetches.Load() != 1 {
		t.Fatalf("key set fetched %d times, want 1 (cached)", j.fetches.Load())
	}
}

func TestBrowserAuthRefusesBadTokens(t *testing.T) {
	j := newJWKSServer(t)
	priv := j.addKey(t, "k1")
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	b := newTestBrowserAuth(t, j)
	now := time.Now()
	ok := map[string]any{"alg": "EdDSA", "kid": "k1"}
	with := func(edit func(map[string]any)) map[string]any {
		c := goodClaims(j.srv.URL, now)
		edit(c)
		return c
	}
	cases := map[string]string{
		"alg none":         signJWT(t, priv, map[string]any{"alg": "none", "kid": "k1"}, goodClaims(j.srv.URL, now)),
		"alg HS256":        signJWT(t, priv, map[string]any{"alg": "HS256", "kid": "k1"}, goodClaims(j.srv.URL, now)),
		"no kid":           signJWT(t, priv, map[string]any{"alg": "EdDSA"}, goodClaims(j.srv.URL, now)),
		"foreign key":      signJWT(t, stranger, ok, goodClaims(j.srv.URL, now)),
		"expired":          signJWT(t, priv, ok, with(func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() })),
		"no exp":           signJWT(t, priv, ok, with(func(c map[string]any) { delete(c, "exp") })),
		"not yet valid":    signJWT(t, priv, ok, with(func(c map[string]any) { c["nbf"] = now.Add(5 * time.Minute).Unix() })),
		"wrong issuer":     signJWT(t, priv, ok, with(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"wrong audience":   signJWT(t, priv, ok, with(func(c map[string]any) { c["aud"] = "https://evil.example" })),
		"no audience":      signJWT(t, priv, ok, with(func(c map[string]any) { delete(c, "aud") })),
		"empty sub":        signJWT(t, priv, ok, with(func(c map[string]any) { c["sub"] = "" })),
		"sub with quote":   signJWT(t, priv, ok, with(func(c map[string]any) { c["sub"] = "x'; DROP TABLE memberships;--" })),
		"two segments":     "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0",
		"garbage segments": "a.b.c",
		"oversized":        strings.Repeat("a", maxBrowserJWTSize) + ".b.c",
	}
	// A valid token with one byte of the payload changed.
	good := signJWT(t, priv, ok, goodClaims(j.srv.URL, now))
	parts := strings.Split(good, ".")
	tampered := []byte(parts[1])
	tampered[len(tampered)/2] ^= 1
	cases["tampered payload"] = parts[0] + "." + string(tampered) + "." + parts[2]

	for name, tok := range cases {
		if sub, err := b.Verify(context.Background(), tok); err == nil {
			t.Errorf("%s: accepted (sub %q)", name, sub)
		}
	}
}

// rotation: a token signed with a key the cache has never seen triggers one
// re-fetch, and a flood of unknown kids cannot hammer the auth service.
func TestBrowserAuthPicksUpRotatedKeysWithoutHammering(t *testing.T) {
	j := newJWKSServer(t)
	priv1 := j.addKey(t, "k1")
	b := newTestBrowserAuth(t, j)
	clock := time.Now()
	b.now = func() time.Time { return clock }
	hdr := func(kid string) map[string]any { return map[string]any{"alg": "EdDSA", "kid": kid} }

	if _, err := b.Verify(context.Background(), signJWT(t, priv1, hdr("k1"), goodClaims(j.srv.URL, clock))); err != nil {
		t.Fatal(err)
	}
	// the service rotates to k2. thirty seconds later a k2 token arrives.
	priv2 := j.addKey(t, "k2")
	clock = clock.Add(31 * time.Second)
	if _, err := b.Verify(context.Background(), signJWT(t, priv2, hdr("k2"), goodClaims(j.srv.URL, clock))); err != nil {
		t.Fatalf("rotated key refused: %v", err)
	}
	if got := j.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2 (initial + rotation)", got)
	}
	// unknown kids inside the 30 s window cause no further fetches.
	for i := 0; i < 20; i++ {
		_, _ = b.Verify(context.Background(), signJWT(t, priv2, hdr("bogus"), goodClaims(j.srv.URL, clock)))
	}
	if got := j.fetches.Load(); got != 2 {
		t.Fatalf("unknown kids caused %d extra fetches", got-2)
	}
}

// if the key service is down, keys already fetched keep working.
func TestBrowserAuthKeepsLastGoodKeysWhenTheServiceFails(t *testing.T) {
	j := newJWKSServer(t)
	priv := j.addKey(t, "k1")
	b := newTestBrowserAuth(t, j)
	clock := time.Now()
	b.now = func() time.Time { return clock }
	tok := func() string {
		return signJWT(t, priv, map[string]any{"alg": "EdDSA", "kid": "k1"}, goodClaims(j.srv.URL, clock))
	}
	if _, err := b.Verify(context.Background(), tok()); err != nil {
		t.Fatal(err)
	}
	j.srv.Close() // the auth service goes away
	clock = clock.Add(jwksMaxAge + time.Minute)
	if _, err := b.Verify(context.Background(), tok()); err != nil {
		t.Fatalf("stale but valid key refused during an outage: %v", err)
	}
}

func TestNewBrowserAuthValidatesConfig(t *testing.T) {
	for name, cfg := range map[string]BrowserAuthConfig{
		"empty":            {},
		"plain http":       {AuthURL: "http://auth.example.com/auth"},
		"userinfo":         {AuthURL: "https://u:p@auth.example.com/auth"},
		"query":            {AuthURL: "https://auth.example.com/auth?x=1"},
		"plain http jwks":  {AuthURL: "https://auth.example.com/auth", JWKSURL: "http://auth.example.com/jwks"},
		"not a url at all": {AuthURL: "::::"},
	} {
		if _, err := NewBrowserAuth(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	b, err := NewBrowserAuth(BrowserAuthConfig{AuthURL: "https://ep-xx.aws.neon.tech/neondb/auth"})
	if err != nil {
		t.Fatal(err)
	}
	// neon's managed better auth: iss and aud are the auth URL's origin.
	if b.issuer != "https://ep-xx.aws.neon.tech" || b.audience != "https://ep-xx.aws.neon.tech" ||
		b.jwksURL != "https://ep-xx.aws.neon.tech/neondb/auth/.well-known/jwks.json" {
		t.Fatalf("defaults: iss=%s aud=%s jwks=%s", b.issuer, b.audience, b.jwksURL)
	}
}

// an invalid session JWT is refused with 401 before any database lookup, and
// personal tokens (no dots) never take the JWT path.
func TestRequireTokenRefusesBadBrowserTokensBeforeTheDatabase(t *testing.T) {
	j := newJWKSServer(t)
	j.addKey(t, "k1")
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{logf: t.Logf}
	s.cfg.BrowserAuth = newTestBrowserAuth(t, j)
	called := false
	h := s.requireToken(func(http.ResponseWriter, *http.Request, identity) { called = true })

	forged := signJWT(t, stranger, map[string]any{"alg": "EdDSA", "kid": "k1"}, goodClaims(j.srv.URL, time.Now()))
	req := httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	rec := httptest.NewRecorder()
	h(rec, req) // s.db is nil: reaching the database would panic
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("forged JWT: status %d, handler called %v", rec.Code, called)
	}
	if !strings.Contains(rec.Body.String(), "UNAUTHENTICATED") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
