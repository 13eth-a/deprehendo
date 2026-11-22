// package cloudserver is the phase 7 backend implementation of
// docs/cloud/upload-api.md v1 (checklist 7.10): create an upload, PUT the
// bundle into object storage through a signed policy, complete the upload
// through the canonical analyzer, and read incidents back. it is the real
// counterpart of internal/cloudclient; the reference server in
// tests/phase7_e2e_test.go remains the client's contract fixture.
//
// invariants (docs/cloud/contract.md):
//
//   - diagnosis happens in the unmodified go analyzer, never here (7.9).
//   - every query that touches incident data is scoped by organization_id
//     from the token (§2.3); there is no load-by-id-then-check path.
//   - the original bytes are never re-encoded and are immutable per key (L4).
//   - tokens are looked up by hash, never logged (7.12, secrets-audit).
//
// storage is abstracted behind store: the MVP store is a local directory
// (LocalStore) whose keys follow the §6 layout exactly; an S3-compatible
// implementation can replace it without touching the handlers.
package cloudserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"runopsy/internal/analysis"
	"runopsy/internal/analyzer"
)

// JobRunner is what complete uses to analyze one bundle. production passes
// analyzer.NewRunner(childBinary) (one child process per bundle); tests can
// substitute the in-process Child.
type JobRunner interface {
	Run(ctx context.Context, bundle []byte) (analyzer.Result, error)
}

// config configures one server. database and storage are required; analyzer
// may be nil only when serve never completes an upload (-analyzer absent),
// in which case complete answers UNAVAILABLE instead of running a job.
type Config struct {
	Database *sql.DB
	Storage  Store
	// analyzer runs one bundle through the canonical engine. required in the
	// MVP: without it, completed uploads have no analysis path.
	Analyzer JobRunner
	// SigningSecret signs storage POST policies; policies minted under a
	// different secret fail verification. empty means a random per-process
	// secret (restarts invalidate pending policies, safe default).
	SigningSecret []byte
	// ExternalURL is the base URL returned to clients for incident links and
	// storage POSTs. requests are served on whatever address configured the
	// process; leave empty to derive both from the request's host (loopback
	// and reverse-proxy deployments).
	ExternalURL string

	// abuse limits (§5.3). zero takes the §5.3 default.
	MaxAnalysesPerHour    int
	MaxParseSecondsPerDay float64
	MaxConcurrentPerOrg   int
	// MaxConcurrentTotal bounds analyzer children across every organization.
	// the contract's memory bound assumes one job per container (§5.3–5.4);
	// when serve runs the children in its own container, as on railway, this
	// cap is what keeps several organizations from exhausting it together.
	MaxConcurrentTotal int
	// BrowserAuth, when set, also accepts better auth session JWTs from the
	// dashboard (contract §8.2). nil keeps the API token-only.
	BrowserAuth *BrowserAuth
	// MaxCreateBodyBytes bounds the create JSON body.
	MaxCreateBodyBytes int64

	Logf func(format string, args ...any)
}

// server implements the upload API and the org-scoped read endpoints.
type Server struct {
	cfg       Config
	secret    []byte
	db        *sql.DB
	storage   Store
	logf      func(format string, args ...any)
	maxCreate int64
	// engine is the identity document this server's analyzer produces (§4);
	// engineKey is its canonical JSON, the analyses.engine_key of every row
	// this deployment writes. both are fixed at new, so a server restart
	// with a different analyzer is a different engine key (7.34).
	engine    analysis.Engine
	engineKey string

	mu      sync.Mutex
	busy    map[string]int // organization -> running jobs
	running int            // running jobs across every organization
	// freed is closed (and replaced) whenever a job slot is released, so
	// waiters can also watch their request context.
	freed chan struct{}

	// startedAt and telemetry back the 7.55 operational counters.
	startedAt time.Time
	telemetry telemetry
}

// limits as §5.3 defaults; the owner adjusts by configuration.
const (
	defaultAnalysesPerHour    = 60
	defaultParseSecondsPerDay = 1800
	defaultConcurrentPerOrg   = 2
	// defaultConcurrentTotal: each child may use ~1 GiB (GOMEMLIMIT), so two
	// children fit a modest container alongside the server.
	defaultConcurrentTotal = 2
)

// new builds a server. no route is installed until handler is called; the
// database is not pinged here so a broken server can still print its config.
func New(cfg Config) (*Server, error) {
	if cfg.Database == nil {
		return nil, errors.New("cloudserver: config needs a database")
	}
	if cfg.Storage == nil {
		return nil, errors.New("cloudserver: config needs storage")
	}
	if cfg.MaxAnalysesPerHour <= 0 {
		cfg.MaxAnalysesPerHour = defaultAnalysesPerHour
	}
	if cfg.MaxParseSecondsPerDay <= 0 {
		cfg.MaxParseSecondsPerDay = defaultParseSecondsPerDay
	}
	if cfg.MaxConcurrentPerOrg <= 0 {
		cfg.MaxConcurrentPerOrg = defaultConcurrentPerOrg
	}
	if cfg.MaxConcurrentTotal <= 0 {
		cfg.MaxConcurrentTotal = defaultConcurrentTotal
	}
	if cfg.MaxCreateBodyBytes <= 0 {
		cfg.MaxCreateBodyBytes = 64 << 10
	}
	if cfg.SigningSecret == nil {
		seed := make([]byte, 32)
		if _, err := readFullRandom(seed); err != nil {
			return nil, fmt.Errorf("cloudserver: signing secret: %w", err)
		}
		cfg.SigningSecret = seed
	}
	if cfg.Analyzer == nil {
		return nil, errors.New("cloudserver: config needs an analyzer job runner")
	}
	s := &Server{
		cfg: cfg, db: cfg.Database, storage: cfg.Storage,
		logf: cfg.Logf, secret: cfg.SigningSecret,
		maxCreate: cfg.MaxCreateBodyBytes,
		busy:      make(map[string]int),
		startedAt: time.Now(),
	}
	if s.logf == nil {
		// A server without a log function is still servable, silently; keep
		// the logf=discard default so calls never nil-deref.
		s.logf = func(string, ...any) {}
	}
	s.engine = analysis.EngineIdentity()
	data, err := json.Marshal(s.engine)
	if err != nil {
		return nil, fmt.Errorf("cloudserver: engine identity: %w", err)
	}
	s.engineKey = string(data)
	s.freed = make(chan struct{})
	return s, nil
}

// analyzerRun executes one analyzer job with the runner's own timeout as a
// safety net beyond the request context.
func (s *Server) analyzerRun(ctx context.Context, bundle []byte) (analyzer.Result, error) {
	return s.cfg.Analyzer.Run(ctx, bundle)
}

// handler installs the routes on mux. the storage POST path is on the same
// server in the MVP deployment; LocalStore policies always point here, and an
// S3-backed store replaces the fields' meaning, not this route's presence.
func (s *Server) Handler(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("POST /api/uploads", s.requireToken(s.create))
	mux.HandleFunc("POST /storage", s.storagePost)
	mux.HandleFunc("POST /api/uploads/{id}/complete", s.requireToken(s.complete))
	mux.HandleFunc("GET /api/incidents", s.requireToken(s.listIncidents))
	mux.HandleFunc("GET /api/incidents/{id}", s.requireToken(s.getIncident))
	mux.HandleFunc("GET /api/incidents/{id}/analysis", s.requireToken(s.getAnalysis))
	mux.HandleFunc("GET /api/incidents/{id}/bundle", s.requireToken(s.getBundle))
	mux.HandleFunc("GET /api/incidents/{id}/analyses", s.requireToken(s.listAnalyses))
	mux.HandleFunc("POST /api/incidents/{id}/reanalyze", s.requireToken(s.reanalyze))
	mux.HandleFunc("POST /api/incidents/{id}/activate", s.requireToken(s.activate))
	mux.HandleFunc("DELETE /api/incidents/{id}", s.requireToken(s.deleteIncident))
}

// identity is the authenticated caller: the token row (empty for a browser
// session) and its organization. every incident query a handler builds starts
// from this organization id; there is deliberately no path that loads
// incident data without one (§2.3).
type identity struct {
	TokenID string
	UserID  string
	OrgID   string
	Role    string
}

// organizationHeader selects which of a browser user's organizations a request
// acts on. personal tokens are bound to one organization and ignore it.
const organizationHeader = "X-Runopsy-Organization"

var organizationIDRE = regexp.MustCompile(`^org_[a-z0-9]{1,64}$`)

// bearer parses "authorization: bearer …" strictly: one separator, no
// whitespace inside the token, and the header is never echoed anywhere. the
// bound fits a browser session JWT; personal tokens are far shorter.
func bearer(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || strings.ContainsAny(raw, " \t\r\n") || raw == "" || len(raw) > maxBrowserJWTSize {
		return "", false
	}
	return raw, true
}

// browserUser verifies a dashboard session JWT and returns its user id, or
// answers 401 itself. which check failed is logged only for operational
// failures (the key set could not be fetched), never sent to the client.
func (s *Server) browserUser(w http.ResponseWriter, r *http.Request, raw string) (string, bool) {
	userID, err := s.cfg.BrowserAuth.Verify(r.Context(), raw)
	if err != nil {
		if err != errBrowserToken {
			s.logf("browser auth: %v", err)
		}
		s.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "browser session is invalid or expired")
		return "", false
	}
	return userID, true
}

// browserIdentity resolves a dashboard caller to one membership. the
// organization comes from organizationHeader; a user with exactly one
// membership may omit it. membership is read on every request, so removing a
// member takes effect at once, without waiting for the token to expire.
func (s *Server) browserIdentity(w http.ResponseWriter, r *http.Request, raw string) (identity, bool) {
	userID, ok := s.browserUser(w, r, raw)
	if !ok {
		return identity{}, false
	}
	orgID := strings.TrimSpace(r.Header.Get(organizationHeader))
	if orgID != "" {
		if !organizationIDRE.MatchString(orgID) {
			s.error(w, http.StatusBadRequest, "BAD_REQUEST", organizationHeader+" is not an organization id")
			return identity{}, false
		}
		var role string
		err := s.db.QueryRowContext(r.Context(),
			`SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2`,
			userID, orgID).Scan(&role)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			s.error(w, http.StatusForbidden, "FORBIDDEN", "you are not a member of that organization")
			return identity{}, false
		case err != nil:
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "authentication failed")
			s.logf("browser membership lookup: %v", err)
			return identity{}, false
		}
		return identity{UserID: userID, OrgID: orgID, Role: role}, true
	}
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT organization_id, role FROM memberships WHERE user_id = $1 ORDER BY organization_id LIMIT 2`,
		userID)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "authentication failed")
		s.logf("browser membership lookup: %v", err)
		return identity{}, false
	}
	defer rows.Close()
	var found []identity
	for rows.Next() {
		id := identity{UserID: userID}
		if err := rows.Scan(&id.OrgID, &id.Role); err != nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "authentication failed")
			s.logf("browser membership scan: %v", err)
			return identity{}, false
		}
		found = append(found, id)
	}
	if err := rows.Err(); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "authentication failed")
		s.logf("browser membership rows: %v", err)
		return identity{}, false
	}
	switch len(found) {
	case 0:
		s.error(w, http.StatusForbidden, "FORBIDDEN", "you are not a member of any organization yet")
		return identity{}, false
	case 1:
		return found[0], true
	default:
		s.error(w, http.StatusBadRequest, "BAD_REQUEST", "choose an organization with the "+organizationHeader+" header")
		return identity{}, false
	}
}

// requireToken resolves the caller before the handler runs: a personal API
// token, or (when browser auth is configured) a dashboard session JWT.
// failures use the upload-api.md §4 envelope.
func (s *Server) requireToken(next func(w http.ResponseWriter, r *http.Request, id identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			s.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authorization must be a Bearer token")
			return
		}
		if s.cfg.BrowserAuth != nil && looksLikeJWT(raw) {
			if id, ok := s.browserIdentity(w, r, raw); ok {
				next(w, r, id)
			}
			return
		}
		var (
			tokenID, userID, orgID, role sql.NullString
		)
		err := s.db.QueryRowContext(r.Context(), `
			SELECT pt.id, pt.user_id, pt.organization_id, m.role
			FROM personal_tokens pt
			LEFT JOIN memberships m
			  ON m.user_id = pt.user_id AND m.organization_id = pt.organization_id
			WHERE pt.token_hash = $1 AND pt.revoked_at IS NULL
		`, tokenHash(raw)).Scan(&tokenID, &userID, &orgID, &role)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			s.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "token is unknown or revoked")
			return
		case err != nil:
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "authentication failed")
			s.logf("auth lookup: %v", err)
			return
		}
		if !role.Valid {
			// the token's user is no longer a member of its organization
			// (or never was): the token is valid but grants nothing.
			s.error(w, http.StatusForbidden, "FORBIDDEN", "the token's user is not a member of its organization")
			return
		}
		// the hash index finds the token; last_used_at is best-effort and
		// never blocks the request.
		_, _ = s.db.ExecContext(r.Context(),
			"UPDATE personal_tokens SET last_used_at = now() WHERE id = $1", tokenID.String)
		next(w, r, identity{TokenID: tokenID.String, UserID: userID.String, OrgID: orgID.String, Role: role.String})
	}
}

func tokenHash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// --- error envelope (upload-api.md §4) ---

// error writes the one envelope every non-2xx API response uses. the message
// is sanitized before it leaves the process: control characters go, the
// length is capped, and callers must never pass raw request data in.
func (s *Server) error(w http.ResponseWriter, status int, code, message string) {
	s.telemetry.recordStatus(status)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": sanitizeText(message),
		},
	})
}

// sanitizeText makes server-produced text safe for any terminal that prints
// it (the CLI renders it verbatim): strips control characters other than TAB
// and caps the length.
func sanitizeText(s string) string {
	const max = 512
	if len(s) > max {
		s = s[:max] + "…"
	}
	clean := true
	for _, r := range s {
		if r != '\t' && (r < 0x20 || r == 0x7f || r == unicode.ReplacementChar) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || (r >= 0x20 && r != 0x7f && r != unicode.ReplacementChar) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// --- job slots (§5.3: concurrent analyses per organization) ---

// acquireJob waits until both the organization and the whole server are below
// their limits of running jobs, or until ctx ends. the reservation is released
// by the returned func. A waiter whose client has gone away gives up instead
// of running a job nobody will read (and holding its bundle in memory while it
// waits).
func (s *Server) acquireJob(ctx context.Context, orgID string) (func(), error) {
	for {
		s.mu.Lock()
		if s.busy[orgID] < s.cfg.MaxConcurrentPerOrg && s.running < s.cfg.MaxConcurrentTotal {
			s.busy[orgID]++
			s.running++
			s.mu.Unlock()
			return func() { s.releaseJob(orgID) }, nil
		}
		freed := s.freed
		s.mu.Unlock()
		select {
		case <-freed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *Server) releaseJob(orgID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy[orgID]--
	if s.busy[orgID] <= 0 {
		delete(s.busy, orgID)
	}
	s.running--
	close(s.freed)
	s.freed = make(chan struct{})
}

// --- decode helpers ---

// decodeJSON reads one strict JSON body of at most limit bytes: unknown
// fields are an error, so a newer client cannot silently upload a wider
// request shape than this server agreed to.
func decodeJSON(r io.Reader, limit int64, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("is not valid JSON of the required shape: %w", err)
	}
	if dec.More() {
		return errors.New("body has trailing content")
	}
	return nil
}

// sha256HexRE is the strict lowercase-hex digest format the client claims.
var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// idRE is what database ids look like when they leave this package
// (prefix_hex, lowercase); a value outside it never reaches a storage key.
var idRE = regexp.MustCompile(`^[a-z]+_[0-9a-f]{32}$`)

func validSHA256(s string) bool { return sha256HexRE.MatchString(s) }

// --- request metadata ---

// externalURLFor picks the base for links: the configured value when set,
// else the request's own host (loopback deployments).
func (s *Server) externalURLFor(r *http.Request) string {
	if s.cfg.ExternalURL != "" {
		return strings.TrimRight(s.cfg.ExternalURL, "/")
	}
	scheme := "http"
	if r != nil {
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		return scheme + "://" + r.Host
	}
	return "http://localhost"
}

// dashboardURL is the incident page the CLI prints.
func (s *Server) dashboardURL(r *http.Request, incidentID string) string {
	return s.externalURLFor(r) + "/incidents/" + incidentID
}

// isDuplicateObjectError reports a Store.Put rejection for an object that
// already exists; for a bundle or a document under this server's key layout
// the existing bytes are identical by construction.
func isDuplicateObjectError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}
