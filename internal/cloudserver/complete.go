// cloudserver complete handler (upload-api.md §3, checklist 7.10): verify the
// stored bytes against the recomputed digest, run the canonical go analyzer
// (7.9: one bundle interpretation implementation), record the analysis
// (append-only, 7.34) and the searchable incident row (7.6), and return the
// dashboard URL. abuse counters (§5.3) charge parse seconds per organization.
package cloudserver

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"runopsy/internal/analyzer"
)

// loadOwnUpload fetches one upload row scoped to the caller's organization
// (§2.3: every incident query starts from organization_id; there is no
// load-by-id-then-check path).
func (s *Server) loadOwnUpload(r *http.Request, org, uploadID string) (*uploadRow, error) {
	const query = `
		SELECT id, sha256, object_key, size_bytes, incident_id
		FROM uploads
		WHERE organization_id = $1 AND id = $2`
	var u uploadRow
	err := s.db.QueryRowContext(r.Context(), query, org, uploadID).
		Scan(&u.ID, &u.sha256, &u.bundleKey, &u.sizeBytes, &u.IncidentID)
	if noRow(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// uploadRow is the upload data complete needs.
type uploadRow struct {
	ID         string
	sha256     []byte
	bundleKey  string
	sizeBytes  int64
	IncidentID string
}

// analysisRow is the state of the upload's existing analysis, if any.
type analysisRow struct {
	ID          string
	Status      string
	DocumentKey sql.NullString
	EngineKey   string
}

// loadExistingAnalysis fetches this upload's analysis under the given engine
// key, if one exists.
func (s *Server) loadExistingAnalysis(r *http.Request, uploadID, engineKey string) (*analysisRow, error) {
	const query = `
		SELECT a.id, a.status, a.document_key, a.engine_key
		FROM analyses a
		WHERE a.upload_id = $1 AND a.engine_key = $2`
	var row analysisRow
	err := s.db.QueryRowContext(r.Context(), query, uploadID, engineKey).
		Scan(&row.ID, &row.Status, &row.DocumentKey, &row.EngineKey)
	if noRow(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// complete implements POST /api/uploads/{id}/complete.
func (s *Server) complete(w http.ResponseWriter, r *http.Request, id identity) {
	uploadid := r.PathValue("id")
	if uploadid == "" {
		s.error(w, http.StatusNotFound, "NOT_FOUND", "no such upload")
		return
	}
	upload, err := s.loadOwnUpload(r, id.OrgID, uploadid)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "upload lookup failed")
		s.logf("upload lookup: %v", err)
		return
	}
	if upload == nil {
		s.error(w, http.StatusNotFound, "NOT_FOUND", "no such upload")
		return
	}

	// usage counters (§5.3) are checked before any analyzer work.
	if limit := s.checkUsage(r, id.OrgID); limit != nil {
		s.writeUsageLimit(w, limit)
		return
	}

	// A finished analysis of the same bundle by the same engine is answered
	// without a second run: complete is idempotent and never charges twice.
	engineKey := s.engineKey
	existing, err := s.loadExistingAnalysis(r, upload.ID, engineKey)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis lookup failed")
		s.logf("analysis lookup: %v", err)
		return
	}
	if existing != nil && existing.Status == string(analyzer.StatusReady) {
		// the analysis is final, but the searchable view may be missing when
		// its insert failed after the analysis row landed. answering without
		// repairing it would return a dashboard URL that 404s, so repair from
		// the stored document before answering (7.32, 7.61).
		if err := s.ensureIncidentRow(r, id.OrgID, upload.ID, *existing); err != nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident record failed")
			s.logf("ensure incident record: %v", err)
			return
		}
		s.writeComplete(w, r, upload.ID, upload.IncidentID, false)
		return
	}

	// the stored bytes are the only input (contract §5.4): the digest is
	// recomputed from them, never taken from the client's claim.
	bundle, err := s.storage.Get(r.Context(), upload.bundleKey)
	if err != nil {
		if errors.Is(err, ErrNoSuchObject) {
			s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "nothing was uploaded for this id")
			return
		}
		s.telemetry.storageFailures.Add(1)
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "storage read failed")
		s.logf("storage get: %v", err)
		return
	}
	sum := sha256.Sum256(bundle)
	if !equalDigest(sum[:], upload.sha256) {
		s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE",
			"stored checksum does not match the registered digest")
		return
	}

	// concurrency per organization (§5.3).
	release, err := s.acquireJob(r.Context(), id.OrgID)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, "UNAVAILABLE", "no analysis slot became free before the request ended")
		return
	}
	defer release()

	result, runerr := s.analyzerRun(r.Context(), bundle)
	if runerr != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis could not start")
		s.logf("analyzer run: %v", runerr)
		return
	}
	s.telemetry.recordAnalysis(result.Duration)
	if result.Status != analyzer.StatusReady {
		// REJECTED and FAILED_* are the parser failures an operator watches:
		// a rise means hostile or incompatible bundles, not user error.
		s.telemetry.parseFailures.Add(1)
	}
	s.chargeParseSeconds(r, id.OrgID, float64(result.Duration)/float64(time.Second))

	// ANALYSES: append-only (7.34). two completes racing under the same
	// engine key are one row; a loser keeps the winner's identity and status.
	analysisid := newID("ana")
	status := string(result.Status)
	var documentKey sql.NullString
	if result.Status == analyzer.StatusReady {
		dockey := documentKeyForEngine(id.OrgID, upload.ID, engineKey)
		if _, err := s.storage.Put(r.Context(), dockey, result.Document); err != nil {
			if !isDuplicateObjectError(err) {
				s.telemetry.storageFailures.Add(1)
				s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "document storage failed")
				s.logf("storage put document: %v", err)
				return
			}
			// same bytes plus same engine means the same document; the
			// existing object is identical by construction.
		}
		documentKey = sql.NullString{String: dockey, Valid: true}
	}
	inserted, err := s.db.ExecContext(r.Context(), `
		INSERT INTO analyses
		  (id, upload_id, engine, engine_key, status, error_class, document_key, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (upload_id, engine_key) DO NOTHING`,
		analysisid, upload.ID, s.engine, engineKey, status,
		result.Reason, documentKey, int(result.Duration/time.Millisecond))
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis record failed")
		s.logf("insert analysis: %v", err)
		return
	}
	if count, _ := inserted.RowsAffected(); count == 0 {
		loser, err := s.loadExistingAnalysis(r, upload.ID, engineKey)
		if err != nil || loser == nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis record failed")
			s.logf("reload analysis: %v", err)
			return
		}
		analysisid = loser.ID
		status = loser.Status
		documentKey = loser.DocumentKey
	}

	// INCIDENTS: the searchable view (7.6). metadata is extracted only from a
	// ready document; a failed analysis keeps a queryable row with unknown
	// metadata instead of a blank page (7.32).
	metadata := dbIncidentMetadata{}
	if documentKey.Valid {
		data, err := s.storage.Get(r.Context(), documentKey.String)
		if err != nil {
			s.telemetry.storageFailures.Add(1)
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "document read failed")
			s.logf("storage get document: %v", err)
			return
		}
		metadata = metadataFromDocument(data)
	}
	if err := s.upsertIncident(r, id.OrgID, upload.ID, analysisid, metadata); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident record failed")
		s.logf("upsert incident: %v", err)
		return
	}

	switch status {
	case string(analyzer.StatusReady):
		s.telemetry.uploadsCompleted.Add(1)
		s.writeComplete(w, r, upload.ID, upload.IncidentID, false)
	case string(analyzer.StatusRejected):
		s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", result.Reason)
	case string(analyzer.StatusFailedLimit):
		s.error(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", result.Reason)
	default:
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", result.Reason)
	}
}

// writeComplete answers the §3 body.
func (s *Server) writeComplete(w http.ResponseWriter, r *http.Request, uploadID, incidentID string, duplicate bool) {
	writeJSON(w, http.StatusOK, map[string]any{
		"upload_id":   uploadID,
		"incident_id": incidentID,
		"url":         s.dashboardURL(r, incidentID),
		"duplicate":   duplicate,
	})
}

// ensureIncidentRow guarantees the searchable incident row exists for one
// READY analysis. it is a no-op on the normal path; when the view insert
// failed earlier it rebuilds the row from the already-stored document, which
// is the same metadata source the first attempt used (no re-analysis, no
// clock, nothing re-run).
func (s *Server) ensureIncidentRow(r *http.Request, org, uploadID string, analysis analysisRow) error {
	var one int
	err := s.db.QueryRowContext(r.Context(),
		`SELECT 1 FROM incidents WHERE upload_id = $1 AND organization_id = $2`,
		uploadID, org).Scan(&one)
	if err == nil {
		return nil
	}
	if !noRow(err) {
		return err
	}
	metadata := dbIncidentMetadata{}
	if analysis.DocumentKey.Valid {
		data, geterr := s.storage.Get(r.Context(), analysis.DocumentKey.String)
		if geterr != nil {
			s.telemetry.storageFailures.Add(1)
			return geterr
		}
		metadata = metadataFromDocument(data)
	}
	return s.upsertIncident(r, org, uploadID, analysis.ID, metadata)
}

// equalDigest compares two 32-byte digests so a mismatch is decided over
// every byte, not the first difference.
func equalDigest(a, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
