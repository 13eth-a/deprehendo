// browser sign-in (contract §8.2, decided november 12, 2026: neon's managed
// better auth). the dashboard signs users in with better auth; when it calls
// this API it sends the session's short-lived JWT as an ordinary bearer token.
// this file verifies those tokens with the standard library only:
//
//   - better auth's JWT plugin signs with EdDSA (Ed25519). that is the only
//     algorithm accepted, so "none", HMAC and RSA confusion attacks have no
//     path in.
//   - public keys come from the auth service's JWKS document
//     (<auth URL>/.well-known/jwks.json), cached, refreshed every 10 minutes,
//     and re-fetched early (at most once per 30 s) when a token names a key id
//     the cache does not hold, which is how key rotation shows up.
//   - iss and aud must both equal the configured values. neon's managed better
//     auth sets both to the origin of the auth URL. exp is required and
//     enforced with a 60 s leeway.
//   - sub is the better auth user id. it is what memberships.user_id stores,
//     so organizations and roles stay in deprehendo's tables, never in the token
//     (the token's own "o" active-organization claim is ignored).
//
// personal API tokens for the CLI are unchanged: requireToken tries a JWT
// only when the bearer has the three-part JWT shape and browser auth is
// configured.
package cloudserver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BrowserAuthConfig names the auth service whose tokens the API accepts.
type BrowserAuthConfig struct {
	// AuthURL is the better auth base URL, e.g. the neon auth URL
	// https://ep-xx.aws.neon.tech/neondb/auth. https is required except for
	// loopback hosts (tests).
	AuthURL string
	// JWKSURL defaults to AuthURL + "/.well-known/jwks.json".
	JWKSURL string
	// issuer and audience default to the origin (scheme://host) of AuthURL,
	// which is what neon's managed better auth sets.
	Issuer   string
	Audience string
	// HTTPClient is optional; a 10 s client that refuses redirects is used.
	HTTPClient *http.Client
}

// BrowserAuth verifies better auth session JWTs.
type BrowserAuth struct {
	jwksURL  string
	issuer   string
	audience string
	client   *http.Client
	now      func() time.Time

	mu          sync.Mutex
	keys        map[string]ed25519.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

const (
	jwksMaxAge        = 10 * time.Minute
	jwksMinRefetch    = 30 * time.Second
	jwksMaxBytes      = 64 << 10
	jwksMaxKeys       = 20
	jwtLeeway         = 60 * time.Second
	maxBrowserJWTSize = 8 << 10
)

// userIDRE bounds what a token's sub may be before it reaches SQL or a log
// line. better auth ids are random alphanumeric strings.
var userIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// NewBrowserAuth validates the configuration. it makes no network call; the
// key set is fetched on the first token.
func NewBrowserAuth(cfg BrowserAuthConfig) (*BrowserAuth, error) {
	base, err := parseAuthEndpoint(cfg.AuthURL)
	if err != nil {
		return nil, fmt.Errorf("cloudserver: browser auth URL: %w", err)
	}
	jwks := strings.TrimSpace(cfg.JWKSURL)
	if jwks == "" {
		jwks = strings.TrimRight(base.String(), "/") + "/.well-known/jwks.json"
	} else if _, err := parseAuthEndpoint(jwks); err != nil {
		return nil, fmt.Errorf("cloudserver: browser auth JWKS URL: %w", err)
	}
	origin := base.Scheme + "://" + base.Host
	issuer, audience := strings.TrimSpace(cfg.Issuer), strings.TrimSpace(cfg.Audience)
	if issuer == "" {
		issuer = origin
	}
	if audience == "" {
		audience = origin
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &BrowserAuth{
		jwksURL:  jwks,
		issuer:   issuer,
		audience: audience,
		client:   client,
		now:      time.Now,
		keys:     map[string]ed25519.PublicKey{},
	}, nil
}

// parseAuthEndpoint accepts https URLs, or http to a loopback host, with no
// userinfo, query or fragment.
func parseAuthEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("not a plain absolute URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return nil, errors.New("must use https")
	}
	return u, nil
}

// looksLikeJWT reports whether a bearer has the compact JWS shape. personal
// tokens never contain a dot.
func looksLikeJWT(raw string) bool {
	return strings.Count(raw, ".") == 2
}

// errBrowserToken is the one error a caller sees for any invalid token, so
// responses never say which check failed.
var errBrowserToken = errors.New("browser session token is invalid or expired")

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Sub string          `json:"sub"`
	Iss string          `json:"iss"`
	Aud json.RawMessage `json:"aud"`
	Exp *float64        `json:"exp"`
	Nbf *float64        `json:"nbf"`
}

// verify checks one compact JWS and returns its user id. any failure returns
// errBrowserToken; operational detail (a JWKS fetch failure) is wrapped so the
// server can log it, but it is never sent to the client.
func (b *BrowserAuth) Verify(ctx context.Context, raw string) (string, error) {
	if len(raw) > maxBrowserJWTSize || !looksLikeJWT(raw) {
		return "", errBrowserToken
	}
	parts := strings.Split(raw, ".")
	headerjson, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payloadjson, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(sig) != ed25519.SignatureSize {
		return "", errBrowserToken
	}
	var h jwtHeader
	if json.Unmarshal(headerjson, &h) != nil || h.Alg != "EdDSA" || h.Kid == "" {
		return "", errBrowserToken
	}
	key, err := b.key(ctx, h.Kid)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return "", errBrowserToken
	}
	var c jwtClaims
	if json.Unmarshal(payloadjson, &c) != nil {
		return "", errBrowserToken
	}
	now := b.now()
	if c.Exp == nil || now.After(time.Unix(int64(*c.Exp), 0).Add(jwtLeeway)) {
		return "", errBrowserToken
	}
	if c.Nbf != nil && now.Add(jwtLeeway).Before(time.Unix(int64(*c.Nbf), 0)) {
		return "", errBrowserToken
	}
	if c.Iss != b.issuer || !audienceMatches(c.Aud, b.audience) {
		return "", errBrowserToken
	}
	if !userIDRE.MatchString(c.Sub) {
		return "", errBrowserToken
	}
	return c.Sub, nil
}

// audienceMatches accepts aud as a string or an array of strings (RFC 7519).
func audienceMatches(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// key returns the public key for kid, refreshing the cached key set when it
// is stale or does not hold kid (rotation), at most once per jwksMinRefetch.
func (b *BrowserAuth) key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	key, ok := b.keys[kid]
	stale := now.Sub(b.fetchedAt) > jwksMaxAge
	if ok && !stale {
		return key, nil
	}
	if now.Sub(b.lastAttempt) < jwksMinRefetch && !b.lastAttempt.IsZero() {
		if ok {
			return key, nil // stale but usable; a refresh was just tried
		}
		return nil, errBrowserToken
	}
	b.lastAttempt = now
	keys, err := b.fetchKeys(ctx)
	if err != nil {
		if ok {
			return key, nil // keep serving the last good key set
		}
		return nil, fmt.Errorf("%w: %v", errBrowserToken, err)
	}
	b.keys, b.fetchedAt = keys, now
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, errBrowserToken
}

type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	} `json:"keys"`
}

func (b *BrowserAuth) fetchKeys(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", transportError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes+1))
	if err != nil || len(body) > jwksMaxBytes {
		return nil, errors.New("jwks fetch: body unreadable or too large")
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, errors.New("jwks fetch: not a JWK set")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if len(keys) >= jwksMaxKeys {
			break
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" ||
			(k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "EdDSA") {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks fetch: no Ed25519 signing keys")
	}
	return keys, nil
}
