// gated test (DEPREHENDO_CLOUD_TEST_DSN; `make test-cloud`) for browser sign-in
// (contract §8.2: better auth session JWTs accepted beside personal tokens).
// A local JWKS server stands in for the auth service; the tokens are real
// Ed25519 JWTs in the shape neon's managed better auth issues.
package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/clouddb"
	"deprehendo/internal/cloudserver"
)

func TestPhase7BrowserSessionsUseMembershipsAndOrganizationHeader(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}

	// the stand-in auth service.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "kid": "test-key", "alg": "EdDSA",
			"x": base64.RawURLEncoding.EncodeToString(pub),
		}}})
	}))
	defer jwks.Close()
	browserAuth, err := cloudserver.NewBrowserAuth(cloudserver.BrowserAuthConfig{AuthURL: jwks.URL + "/auth"})
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, func(c *cloudserver.Config) { c.BrowserAuth = browserAuth })
	ctx := context.Background()

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	user := "usr_browser_" + hex.EncodeToString(suffix)
	session := func(sub string) string {
		now := time.Now()
		return testJWT(t, priv, map[string]any{"alg": "EdDSA", "kid": "test-key"}, map[string]any{
			"sub": sub, "iss": jwks.URL, "aud": jwks.URL,
			"iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
		})
	}
	jwt := session(user)

	// not yet a member of anything.
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, ""); code != http.StatusForbidden {
		t.Fatalf("non-member list = %d, want 403", code)
	}

	// member of org A, owner of org B; org A has one incident.
	if err := clouddb.EnsureMembership(ctx, h.DB, user, h.OrgA, "member"); err != nil {
		t.Fatal(err)
	}
	if err := clouddb.EnsureMembership(ctx, h.DB, user, h.OrgB, "owner"); err != nil {
		t.Fatal(err)
	}
	uploadid, incidentid := createAndStore(t, h, h.TokenA, filepath.Join(root, "testdata", "incidents", "frozen-worker.deprehendo"))
	if status, body := postComplete(t, h.Endpoint, h.TokenA, uploadid, 90*time.Second); status != http.StatusOK {
		t.Fatalf("complete = %d %s", status, body)
	}

	// /api/me lists both organizations without needing the header.
	code, body := browserCall(t, h.Endpoint, http.MethodGet, "/api/me", jwt, "")
	if code != http.StatusOK || !strings.Contains(body, h.OrgA) || !strings.Contains(body, h.OrgB) || !strings.Contains(body, `"auth":"browser"`) {
		t.Fatalf("/api/me = %d %s", code, body)
	}

	// two memberships and no header: the caller must choose.
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, ""); code != http.StatusBadRequest {
		t.Fatalf("ambiguous list = %d, want 400", code)
	}
	// org A shows its incident; org B does not.
	if code, body := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, h.OrgA); code != http.StatusOK || !strings.Contains(body, incidentid) {
		t.Fatalf("org A list = %d %s", code, body)
	}
	if code, body := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, h.OrgB); code != http.StatusOK || strings.Contains(body, incidentid) {
		t.Fatalf("org B list = %d %s (must not contain org A's incident)", code, body)
	}
	// org A's incident is invisible from org B: 404, not 403.
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents/"+incidentid+"/analysis", jwt, h.OrgB); code != http.StatusNotFound {
		t.Fatalf("cross-org read = %d, want 404", code)
	}
	// roles apply to browser users exactly as to tokens: a member cannot delete.
	if code, _ := browserCall(t, h.Endpoint, http.MethodDelete, "/api/incidents/"+incidentid, jwt, h.OrgA); code != http.StatusForbidden {
		t.Fatalf("member delete = %d, want 403", code)
	}
	// an organization the user does not belong to, and a malformed header.
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, "org_"+strings.Repeat("f", 32)); code != http.StatusForbidden {
		t.Fatalf("foreign org header = %d, want 403", code)
	}
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, "org_BAD'"); code != http.StatusBadRequest {
		t.Fatalf("malformed org header = %d, want 400", code)
	}

	// removing a membership takes effect on the next request, while the JWT is
	// still valid; with one membership left, the header becomes optional.
	if _, err := h.DB.Exec(`DELETE FROM memberships WHERE user_id = $1 AND organization_id = $2`, user, h.OrgB); err != nil {
		t.Fatal(err)
	}
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, h.OrgB); code != http.StatusForbidden {
		t.Fatalf("after removal = %d, want 403", code)
	}
	if code, body := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", jwt, ""); code != http.StatusOK || !strings.Contains(body, incidentid) {
		t.Fatalf("single-org default = %d %s", code, body)
	}

	// A token from another signer is refused; personal tokens still work.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	forged := testJWT(t, stranger, map[string]any{"alg": "EdDSA", "kid": "test-key"}, map[string]any{
		"sub": user, "iss": jwks.URL, "aud": jwks.URL, "exp": time.Now().Add(time.Minute).Unix(),
	})
	if code, _ := browserCall(t, h.Endpoint, http.MethodGet, "/api/incidents", forged, h.OrgA); code != http.StatusUnauthorized {
		t.Fatalf("forged session = %d, want 401", code)
	}
	if code, body := browserCall(t, h.Endpoint, http.MethodGet, "/api/me", h.TokenA, ""); code != http.StatusOK || !strings.Contains(body, `"auth":"token"`) {
		t.Fatalf("token /api/me = %d %s", code, body)
	}
}

func testJWT(t *testing.T, priv ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signing)))
}

// browserCall sends one request with a bearer and an optional organization
// header, returning the status and up to 64 KiB of body.
func browserCall(t *testing.T, endpoint, method, path, bearer, org string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if org != "" {
		req.Header.Set("X-Deprehendo-Organization", org)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(body)
}
