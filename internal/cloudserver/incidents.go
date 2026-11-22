// cloudserver incident upsert and read/delete handlers (checklists 7.6,
// 7.28–7.29, 7.35). every query here is scoped by organization_id; deleting
// removes the database rows, the bundle object and the derived document.
package cloudserver

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// upsertIncident writes the incidents row for one upload. it is an upsert,
// not an append: one upload is one incident, and a later completion of the
// same upload refreshes the view (the analyses rows keep the full history,
// 7.34).
func (s *Server) upsertIncident(r *http.Request, org, uploadID, analysisID string, m dbIncidentMetadata) error {
	// the external incident id comes from the upload row; complete has
	// already confirmed it against the bundle manifest.
	var externalID string
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT incident_id FROM uploads WHERE id = $1 AND organization_id = $2`,
		uploadID, org).Scan(&externalID); err != nil {
		return err
	}

	var triggered any
	if m.TriggeredAt != nil {
		if t, err := time.Parse(time.RFC3339Nano, *m.TriggeredAt); err == nil {
			triggered = t
		}
	}
	var runID any
	if m.RunID != nil {
		runID = *m.RunID
	}
	var confidence any
	if m.Confidence != nil {
		confidence = *m.Confidence
	}

	_, err := s.db.ExecContext(r.Context(), `
		INSERT INTO incidents
		  (upload_id, organization_id, external_incident_id,
		   active_analysis_id, original_analysis_id, triggered_at,
		   primary_signature, confidence, severity,
		   runner_name, runner_version, repository, workflow, job, run_id,
		   platform, architecture, confidence_band)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (upload_id) DO UPDATE SET
		  active_analysis_id = EXCLUDED.active_analysis_id,
		  triggered_at       = COALESCE(EXCLUDED.triggered_at, incidents.triggered_at),
		  primary_signature  = COALESCE(EXCLUDED.primary_signature, incidents.primary_signature),
		  confidence         = COALESCE(EXCLUDED.confidence, incidents.confidence),
		  confidence_band    = COALESCE(EXCLUDED.confidence_band, incidents.confidence_band),
		  severity           = COALESCE(EXCLUDED.severity, incidents.severity),
		  runner_name        = COALESCE(EXCLUDED.runner_name, incidents.runner_name),
		  runner_version     = COALESCE(EXCLUDED.runner_version, incidents.runner_version),
		  repository         = COALESCE(EXCLUDED.repository, incidents.repository),
		  workflow           = COALESCE(EXCLUDED.workflow, incidents.workflow),
		  job                = COALESCE(EXCLUDED.job, incidents.job),
		  run_id             = COALESCE(EXCLUDED.run_id, incidents.run_id),
		  platform           = COALESCE(EXCLUDED.platform, incidents.platform),
		  architecture       = COALESCE(EXCLUDED.architecture, incidents.architecture)`,
		uploadID, org, externalID, analysisID, triggered,
		nullable(m.PrimarySignature), confidence, nullable(m.Severity),
		nullable(m.RunnerName), nullable(m.RunnerVersion),
		nullable(m.Repository), nullable(m.Workflow), nullable(m.Job), runID,
		nullable(m.Platform), nullable(m.Architecture), nullable(m.ConfidenceBand))
	return err
}

// nullable turns an empty string into a NULL column.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------------------------------------------------------------------------
// read endpoints (7.35)
// ---------------------------------------------------------------------------

// listColumns are the selected columns, each with its scan slot; read-only
// contract for both the filtered and the plain list.
const listColumns = `
		SELECT i.external_incident_id, i.created_at, i.triggered_at,
		       i.primary_signature, i.confidence, i.severity,
		       i.runner_name, i.repository, i.workflow, i.job, i.platform,
		       a.status, i.confidence_band
		FROM incidents i
		JOIN analyses a ON a.id = i.active_analysis_id`

// listIncidents answers GET /api/incidents: metadata only, newest first,
// optional filters, a free-text search and a bounded page (7.6, 7.13, 7.25).
func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request, id identity) {
	filter, err := parseListFilter(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	query, args := filter.query(id.OrgID)
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "listing failed")
		s.logf("incident list: %v", err)
		return
	}
	defer rows.Close()
	if err := writeIncidentRows(w, rows); err != nil {
		s.logf("incident list: %v", err)
	}
}

// placeholder renders a 1-based PostgreSQL argument.
func placeholder(n int) string { return "$" + strconv.Itoa(n) }

// listFilter is one parsed list request. every value becomes a query
// argument: column names come from this package's constant table, never from
// the request, so a filter cannot name a column or widen the organization
// predicate.
type listFilter struct {
	PageSize int
	Offset   int
	// equality holds (column, value) pairs matched with =.
	equality [][2]string
	// from/to bound created_at: from inclusive, to exclusive.
	from, to *time.Time
	// search is the 7.25 free-text term, matched case-insensitively against
	// the metadata columns a person would type (incident id, signature,
	// runner, repository, workflow, job).
	search string
}

// maxSearchTerm bounds the free-text term; longer input is a client error
// rather than a slow pattern.
const maxSearchTerm = 128

// equalityFilters is the sorted list of accepted ?param= names and their
// columns. `id` is the external incident id the CLI and URLs show.
var equalityFilters = []struct{ param, column string }{
	{"id", "external_incident_id"},
	{"signature", "primary_signature"},
	{"severity", "severity"},
	{"runner", "runner_name"},
	{"repository", "repository"},
	{"workflow", "workflow"},
	{"job", "job"},
	{"platform", "platform"},
}

// searchColumns are matched by ?q= (7.25).
var searchColumns = []string{
	"external_incident_id", "primary_signature", "runner_name",
	"runner_version", "repository", "workflow", "job",
}

// parseListFilter validates the query string. anything malformed is reported
// to the caller: a silently ignored filter would show unfiltered incidents.
func parseListFilter(r *http.Request) (listFilter, error) {
	q := r.URL.Query()
	f := listFilter{PageSize: 50}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil {
		f.PageSize = min(max(n, 1), 200)
	} else if q.Get("limit") != "" {
		return f, errors.New("limit must be an integer")
	}
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		f.Offset = n
	} else if q.Get("offset") != "" && n < 0 {
		return f, errors.New("offset must be zero or positive")
	}
	for _, e := range equalityFilters {
		if v := q.Get(e.param); v != "" {
			f.equality = append(f.equality, [2]string{e.column, v})
		}
	}
	from, err := parseListTime("from", q.Get("from"), false)
	if err != nil {
		return f, err
	}
	to, err := parseListTime("to", q.Get("to"), true)
	if err != nil {
		return f, err
	}
	f.from, f.to = from, to
	term := strings.TrimSpace(q.Get("q"))
	if len(term) > maxSearchTerm {
		return f, fmt.Errorf("q must be at most %d characters", maxSearchTerm)
	}
	f.search = term
	return f, nil
}

// parseListTime accepts RFC 3339 or a bare date. A bare `to` date means the
// whole day, so the bound is the start of the next day.
func parseListTime(name, value string, endOfDay bool) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return &t, nil
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		if endOfDay {
			t = t.AddDate(0, 0, 1)
		}
		return &t, nil
	}
	return nil, fmt.Errorf("%s must be an RFC 3339 timestamp or YYYY-MM-DD", name)
}

// query renders the SQL and its arguments for one organization.
func (f listFilter) query(org string) (string, []any) {
	conds := []string{"i.organization_id = $1"}
	args := []any{org}
	for _, e := range f.equality {
		conds = append(conds, "i."+e[0]+" = "+placeholder(len(args)+1))
		args = append(args, e[1])
	}
	if f.from != nil {
		conds = append(conds, "i.created_at >= "+placeholder(len(args)+1))
		args = append(args, *f.from)
	}
	if f.to != nil {
		conds = append(conds, "i.created_at < "+placeholder(len(args)+1))
		args = append(args, *f.to)
	}
	if f.search != "" {
		// one ILIKE per searchable column, OR-ed: no expression index is
		// needed at MVP scale and every column stays visible to the planner.
		pattern := placeholder(len(args) + 1)
		args = append(args, "%"+escapeLike(f.search)+"%")
		or := make([]string, 0, len(searchColumns))
		for _, column := range searchColumns {
			or = append(or, "i."+column+" ILIKE "+pattern+" ESCAPE '\\'")
		}
		conds = append(conds, "("+strings.Join(or, " OR ")+")")
	}
	args = append(args, f.PageSize, f.Offset)
	return strings.Join([]string{listColumns,
		"WHERE " + strings.Join(conds, " AND "),
		"ORDER BY i.created_at DESC",
		"LIMIT " + placeholder(len(args)-1),
		"OFFSET " + placeholder(len(args)),
	}, " "), args
}

// escapeLike neutralizes LIKE metacharacters so a search for "100%" matches
// the literal text instead of every row. the query pairs this with ESCAPE '\\'.
func escapeLike(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// incidentSummary is one row of the list.
type incidentSummary struct {
	IncidentID       string     `json:"incident_id"`
	CreatedAt        time.Time  `json:"created_at"`
	TriggeredAt      *time.Time `json:"triggered_at,omitempty"`
	PrimarySignature *string    `json:"primary_signature,omitempty"`
	Confidence       *float64   `json:"confidence,omitempty"`
	ConfidenceBand   *string    `json:"confidence_band,omitempty"`
	Severity         *string    `json:"severity,omitempty"`
	RunnerName       *string    `json:"runner_name,omitempty"`
	Repository       *string    `json:"repository,omitempty"`
	Workflow         *string    `json:"workflow,omitempty"`
	Job              *string    `json:"job,omitempty"`
	Platform         *string    `json:"platform,omitempty"`
	AnalysisStatus   string     `json:"analysis_status"`
}

// writeIncidentRows scans and writes the list.
func writeIncidentRows(w http.ResponseWriter, rows *sql.Rows) error {
	out := []incidentSummary{}
	for rows.Next() {
		var e incidentSummary
		var signature, severity, runner, repository, workflow, job, platform, band sql.NullString
		var confidence sql.NullFloat64
		var triggered sql.NullTime
		if err := rows.Scan(&e.IncidentID, &e.CreatedAt, &triggered,
			&signature, &confidence, &severity,
			&runner, &repository, &workflow, &job, &platform, &e.AnalysisStatus, &band); err != nil {
			return err
		}
		e.TriggeredAt = nullTime(triggered)
		e.PrimarySignature = nullString(signature)
		e.Confidence = nullFloat(confidence)
		e.ConfidenceBand = nullString(band)
		e.Severity = nullString(severity)
		e.RunnerName = nullString(runner)
		e.Repository = nullString(repository)
		e.Workflow = nullString(workflow)
		e.Job = nullString(job)
		e.Platform = nullString(platform)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func nullString(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

func nullFloat(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	return &n.Float64
}

func nullTime(n sql.NullTime) *time.Time {
	if !n.Valid {
		return nil
	}
	return &n.Time
}

// ownIncidentRow is what the read/delete paths need from one incident row.
type ownIncidentRow struct {
	IncidentID       string
	UploadID         string
	CreatedAt        time.Time
	TriggeredAt      *time.Time
	PrimarySignature *string
	Confidence       *float64
	ConfidenceBand   *string
	Severity         *string
	RunnerName       *string
	RunnerVersion    *string
	Repository       *string
	Workflow         *string
	Job              *string
	RunID            *int64
	HostnameHash     *string
	Platform         *string
	Architecture     *string
	Digest           []byte
	BundleKey        string
	BundleSize       int64
	DocumentKey      sql.NullString
	AnalysisStatus   string
}

// loadOwnIncident fetches one incident row scoped by organization and
// external incident id. ok=false means the row does not exist; an error is a
// server failure reported through the handler.
func (s *Server) loadOwnIncident(r *http.Request, org, externalID string) (*ownIncidentRow, bool) {
	if externalID == "" {
		return nil, false
	}
	const query = `
		SELECT i.external_incident_id, i.upload_id, i.created_at, i.triggered_at,
		       i.primary_signature, i.confidence, i.severity,
		       i.runner_name, i.runner_version, i.repository, i.workflow, i.job,
		       i.run_id, i.hostname_hash, i.platform, i.architecture,
		       u.sha256, u.object_key, u.size_bytes,
		       a.document_key, a.status, i.confidence_band
		FROM incidents i
		JOIN uploads u ON u.id = i.upload_id AND u.organization_id = i.organization_id
		JOIN analyses a ON a.id = i.active_analysis_id
		WHERE i.organization_id = $1 AND i.external_incident_id = $2`
	var row ownIncidentRow
	var signature, severity, runner, runnerVersion, repository, workflow, job,
		hostname, platform, architecture, band sql.NullString
	var confidence sql.NullFloat64
	var runID sql.NullInt64
	var triggered sql.NullTime
	err := s.db.QueryRowContext(r.Context(), query, org, externalID).Scan(
		&row.IncidentID, &row.UploadID, &row.CreatedAt, &triggered,
		&signature, &confidence, &severity,
		&runner, &runnerVersion, &repository, &workflow, &job,
		&runID, &hostname, &platform, &architecture,
		&row.Digest, &row.BundleKey, &row.BundleSize,
		&row.DocumentKey, &row.AnalysisStatus, &band)
	if noRow(err) {
		return nil, false
	}
	if err != nil {
		s.logf("incident load: %v", err)
		return nil, false
	}
	row.TriggeredAt = nullTime(triggered)
	row.PrimarySignature = nullString(signature)
	row.Confidence = nullFloat(confidence)
	row.ConfidenceBand = nullString(band)
	row.Severity = nullString(severity)
	row.RunnerName = nullString(runner)
	row.RunnerVersion = nullString(runnerVersion)
	row.Repository = nullString(repository)
	row.Workflow = nullString(workflow)
	row.Job = nullString(job)
	if runID.Valid && runID.Int64 > 0 {
		id := runID.Int64
		row.RunID = &id
	}
	row.HostnameHash = nullString(hostname)
	row.Platform = nullString(platform)
	row.Architecture = nullString(architecture)
	return &row, true
}

// missing marks the response after a failed lookup.
func (s *Server) missing(w http.ResponseWriter) {
	s.error(w, http.StatusNotFound, "NOT_FOUND", "no such incident")
}

// getIncident answers GET /api/incidents/{id}: one row's metadata.
func (s *Server) getIncident(w http.ResponseWriter, r *http.Request, id identity) {
	i, ok := s.loadOwnIncident(r, id.OrgID, r.PathValue("id"))
	if !ok {
		s.missing(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id":       i.IncidentID,
		"upload_id":         i.UploadID,
		"created_at":        i.CreatedAt,
		"triggered_at":      i.TriggeredAt,
		"primary_signature": i.PrimarySignature,
		"confidence":        i.Confidence,
		"confidence_band":   i.ConfidenceBand,
		"severity":          i.Severity,
		"runner_name":       i.RunnerName,
		"runner_version":    i.RunnerVersion,
		"repository":        i.Repository,
		"workflow":          i.Workflow,
		"job":               i.Job,
		"run_id":            i.RunID,
		"hostname_hash":     i.HostnameHash,
		"platform":          i.Platform,
		"architecture":      i.Architecture,
		"bundle_size":       i.BundleSize,
		"analysis_status":   i.AnalysisStatus,
	})
}

// getAnalysis answers GET /api/incidents/{id}/analysis with the stored
// document verbatim, the bytes the engine wrote, not a re-render (7.43).
func (s *Server) getAnalysis(w http.ResponseWriter, r *http.Request, id identity) {
	i, ok := s.loadOwnIncident(r, id.OrgID, r.PathValue("id"))
	if !ok {
		s.missing(w)
		return
	}
	if !i.DocumentKey.Valid {
		// A failed analysis has no document; the status answers instead of a
		// blank page (7.32).
		s.error(w, http.StatusAccepted, "PROCESSING", i.AnalysisStatus)
		return
	}
	data, err := s.storage.Get(r.Context(), i.DocumentKey.String)
	if err != nil {
		if errors.Is(err, ErrNoSuchObject) {
			s.error(w, http.StatusNotFound, "NOT_FOUND", "analysis document is missing")
			return
		}
		s.telemetry.storageFailures.Add(1)
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "document read failed")
		s.logf("document read: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// getBundle answers GET /api/incidents/{id}/bundle (7.29): the exact original
// bytes after integrity verification against the stored digest.
func (s *Server) getBundle(w http.ResponseWriter, r *http.Request, id identity) {
	i, ok := s.loadOwnIncident(r, id.OrgID, r.PathValue("id"))
	if !ok {
		s.missing(w)
		return
	}
	bundle, err := s.storage.Get(r.Context(), i.BundleKey)
	if err != nil {
		if errors.Is(err, ErrNoSuchObject) {
			s.error(w, http.StatusNotFound, "NOT_FOUND", "bundle object is missing")
			return
		}
		s.telemetry.storageFailures.Add(1)
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "bundle read failed")
		s.logf("bundle read: %v", err)
		return
	}
	sum := sha256.Sum256(bundle)
	if !equalDigest(sum[:], i.Digest) {
		// A bundle that no longer matches its recorded digest is
		// unreproducible evidence: refuse rather than serve changed bytes.
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE",
			"bundle integrity verification failed; refusing to serve")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.runopsy"`, i.IncidentID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

// deleteIncident answers DELETE /api/incidents/{id} (7.28): database rows
// first (the cascade removes analyses), then the objects. A failed storage
// delete leaves no dangling metadata; the orphan object is logged.
func (s *Server) deleteIncident(w http.ResponseWriter, r *http.Request, id identity) {
	i, ok := s.loadOwnIncident(r, id.OrgID, r.PathValue("id"))
	if !ok {
		s.missing(w)
		return
	}
	// deleting destroys the immutable original, so it is owner-only
	// (authz-matrix case 9). agent tokens on CI runners are member tokens;
	// a leaked one must not be able to erase the organization's evidence.
	// the org check above runs first, so another organization still sees 404.
	if !requireOwner(s, w, id) {
		return
	}
	// every document key is read BEFORE the rows go: the cascade below
	// removes the analyses rows that name them, and a key nothing records any
	// more can never be found again (7.28, 7.60). A failed read stops the
	// delete instead of stranding documents.
	dockeys, err := s.documentKeys(r.Context(), i.UploadID, id.OrgID)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "delete failed")
		s.logf("incident delete history: %v", err)
		return
	}
	keys := []string{i.BundleKey}
	seen := map[string]bool{i.BundleKey: true}
	for _, k := range append(dockeys, documentKeyFor(id.OrgID, i.UploadID)) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	// objects go first, and rows last. A storage failure other than "already
	// gone" stops here with the rows intact, so the keys stay recorded and the
	// user can retry; the request is never answered as deleted while an object
	// may remain. removing the rows first would leave an object that nothing
	// names, which no retry or sweep could ever find (7.27, 7.60, H1).
	for _, key := range keys {
		if err := s.storage.Delete(r.Context(), key); err != nil && !errors.Is(err, ErrNoSuchObject) {
			s.telemetry.storageFailures.Add(1)
			s.logf("incident delete, object %s: %v", key, err)
			s.error(w, http.StatusServiceUnavailable, "UNAVAILABLE", "delete failed; the incident is kept, try again")
			return
		}
	}
	if _, err := s.db.ExecContext(r.Context(),
		`DELETE FROM uploads WHERE id = $1 AND organization_id = $2`,
		i.UploadID, id.OrgID); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "delete failed")
		s.logf("incident delete: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "incident_id": i.IncidentID})
}

// requireOwner answers 403 FORBIDDEN unless the caller is an owner of its
// organization, and reports whether the handler may continue. callers check
// the organization first, so a foreign incident is still 404, never 403.
func requireOwner(s *Server, w http.ResponseWriter, id identity) bool {
	if id.Role == "owner" {
		return true
	}
	s.error(w, http.StatusForbidden, "FORBIDDEN", "this action needs the owner role")
	return false
}

// documentKeyFor names the derived analysis document of one upload. the
// layout matches the §6 spirit: org-scoped, one object per upload.
func documentKeyFor(org, uploadID string) string {
	return "orgs/" + org + "/documents/" + uploadID + ".json"
}
