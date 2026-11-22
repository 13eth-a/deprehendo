// cloudserver re-analysis (checklist 7.34, contract §7.1): the analyses table
// is append-only and incidents keeps active/original pointers. complete writes
// the first row; this file adds the explicit re-analysis actions that cannot
// rewrite history: re-run the current engine over the stored bytes, list the
// history of one incident, and switch the active analysis to an existing row.
package cloudserver

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"runopsy/internal/analyzer"
)

// documentKeyForEngine names one engine's document for one upload. it is
// deterministic per (upload, engine) so a retried re-analysis under the same
// engine reuses the key (the put is immutable and dedupes), while a new
// engine gets its own object instead of overwriting history. the suffix is
// hex so the key stays inside safeKey.
func documentKeyForEngine(org, uploadID, engineKey string) string {
	sum := sha256.Sum256([]byte(engineKey))
	return "orgs/" + org + "/documents/" + uploadID + "-" + hex.EncodeToString(sum[:])[:16] + ".json"
}

// analysisHistoryRow is one row of the history listing.
type analysisHistoryRow struct {
	ID          string    `json:"analysis_id"`
	EngineKey   string    `json:"engine_key"`
	Engine      any       `json:"engine"`
	Status      string    `json:"status"`
	ErrorClass  *string   `json:"error_class,omitempty"`
	DocumentKey *string   `json:"document_key,omitempty"`
	DurationMs  *int      `json:"duration_ms,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Active      bool      `json:"active"`
	Original    bool      `json:"original"`
}

// loadIncidentPointers returns the upload id plus the active/original analysis
// ids for one external incident, org-scoped.
func (s *Server) loadIncidentPointers(r *http.Request, org, externalID string) (uploadID, activeID, originalID string, ok bool, err error) {
	var active, original sql.NullString
	err = s.db.QueryRowContext(r.Context(),
		`SELECT upload_id, active_analysis_id, original_analysis_id FROM incidents WHERE organization_id = $1 AND external_incident_id = $2`,
		org, externalID).Scan(&uploadID, &active, &original)
	if noRow(err) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	if active.Valid {
		activeID = active.String
	}
	if original.Valid {
		originalID = original.String
	}
	return uploadID, activeID, originalID, true, nil
}

// listAnalyses answers GET /api/incidents/{id}/analyses: every analysis row
// for the incident's upload, oldest first, with active/original flags.
func (s *Server) listAnalyses(w http.ResponseWriter, r *http.Request, id identity) {
	uploadid, activeid, originalid, ok, err := s.loadIncidentPointers(r, id.OrgID, r.PathValue("id"))
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "history lookup failed")
		s.logf("history lookup: %v", err)
		return
	}
	if !ok {
		s.missing(w)
		return
	}
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT id, engine, engine_key, status, error_class, document_key, duration_ms, created_at
		 FROM analyses WHERE upload_id = $1 ORDER BY created_at ASC, id ASC`, uploadid)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "history lookup failed")
		s.logf("history query: %v", err)
		return
	}
	defer rows.Close()
	out := []analysisHistoryRow{}
	for rows.Next() {
		var row analysisHistoryRow
		var engineRaw []byte
		var errorClass, documentKey sql.NullString
		var durationMs sql.NullInt64
		if err := rows.Scan(&row.ID, &engineRaw, &row.EngineKey, &row.Status, &errorClass, &documentKey, &durationMs, &row.CreatedAt); err != nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "history lookup failed")
			s.logf("history scan: %v", err)
			return
		}
		var engine any
		if err := json.Unmarshal(engineRaw, &engine); err == nil {
			row.Engine = engine
		} else {
			row.Engine = string(engineRaw)
		}
		if errorClass.Valid && errorClass.String != "" {
			v := errorClass.String
			row.ErrorClass = &v
		}
		if documentKey.Valid {
			v := documentKey.String
			row.DocumentKey = &v
		}
		if durationMs.Valid {
			v := int(durationMs.Int64)
			row.DurationMs = &v
		}
		row.Active = row.ID == activeid
		row.Original = row.ID == originalid
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "history lookup failed")
		s.logf("history rows: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// reanalyze answers POST /api/incidents/{id}/reanalyze: run the server's
// current engine over the stored bundle bytes and append the analysis.
// running the same engine twice is a no-op (UNIQUE(upload_id, engine_key));
// a new engine appends a row and moves active_analysis_id, never touching
// original_analysis_id or any stored document.
func (s *Server) reanalyze(w http.ResponseWriter, r *http.Request, id identity) {
	externalid := r.PathValue("id")
	uploadid, activeid, originalid, ok, err := s.loadIncidentPointers(r, id.OrgID, externalid)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident lookup failed")
		s.logf("reanalyze lookup: %v", err)
		return
	}
	if !ok {
		s.missing(w)
		return
	}
	upload, err := s.loadOwnUpload(r, id.OrgID, uploadid)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "upload lookup failed")
		s.logf("reanalyze upload: %v", err)
		return
	}
	if upload == nil {
		s.missing(w)
		return
	}
	if limit := s.checkUsage(r, id.OrgID); limit != nil {
		s.writeUsageLimit(w, limit)
		return
	}
	engineKey := s.engineKey
	existing, err := s.loadExistingAnalysis(r, upload.ID, engineKey)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis lookup failed")
		s.logf("reanalyze existing: %v", err)
		return
	}
	if existing != nil && existing.Status == string(analyzer.StatusReady) {
		if err := s.ensureIncidentRow(r, id.OrgID, upload.ID, *existing); err != nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident record failed")
			s.logf("reanalyze repair: %v", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"upload_id": upload.ID, "incident_id": upload.IncidentID,
			"analysis_id": existing.ID, "status": existing.Status,
			"reanalyzed":         false,
			"active_analysis_id": activeid, "original_analysis_id": originalid,
			"url": s.dashboardURL(r, upload.IncidentID),
		})
		return
	}
	bundle, err := s.storage.Get(r.Context(), upload.bundleKey)
	if err != nil {
		if errors.Is(err, ErrNoSuchObject) {
			s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "nothing was uploaded for this id")
			return
		}
		s.telemetry.storageFailures.Add(1)
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "storage read failed")
		s.logf("reanalyze get: %v", err)
		return
	}
	sum := sha256.Sum256(bundle)
	if !equalDigest(sum[:], upload.sha256) {
		s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE",
			"stored checksum does not match the registered digest")
		return
	}
	release, err := s.acquireJob(r.Context(), id.OrgID)
	if err != nil {
		s.error(w, http.StatusServiceUnavailable, "UNAVAILABLE", "no analysis slot became free before the request ended")
		return
	}
	defer release()
	result, runerr := s.analyzerRun(r.Context(), bundle)
	if runerr != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis could not start")
		s.logf("reanalyze run: %v", runerr)
		return
	}
	s.telemetry.recordAnalysis(result.Duration)
	if result.Status != analyzer.StatusReady {
		s.telemetry.parseFailures.Add(1)
	}
	s.chargeParseSeconds(r, id.OrgID, float64(result.Duration)/float64(time.Second))

	analysisID := newID("ana")
	status := string(result.Status)
	var documentKey sql.NullString
	if result.Status == analyzer.StatusReady {
		dockey := documentKeyForEngine(id.OrgID, upload.ID, engineKey)
		if _, err := s.storage.Put(r.Context(), dockey, result.Document); err != nil {
			if !isDuplicateObjectError(err) {
				s.telemetry.storageFailures.Add(1)
				s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "document storage failed")
				s.logf("reanalyze put document: %v", err)
				return
			}
		}
		documentKey = sql.NullString{String: dockey, Valid: true}
	}
	inserted, err := s.db.ExecContext(r.Context(), `
		INSERT INTO analyses
		  (id, upload_id, engine, engine_key, status, error_class, document_key, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (upload_id, engine_key) DO NOTHING`,
		analysisID, upload.ID, s.engine, engineKey, status,
		result.Reason, documentKey, int(result.Duration/time.Millisecond))
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis record failed")
		s.logf("reanalyze insert: %v", err)
		return
	}
	if count, _ := inserted.RowsAffected(); count == 0 {
		loser, err := s.loadExistingAnalysis(r, upload.ID, engineKey)
		if err != nil || loser == nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis record failed")
			s.logf("reanalyze reload: %v", err)
			return
		}
		analysisID = loser.ID
		status = loser.Status
		documentKey = loser.DocumentKey
	}
	metadata := dbIncidentMetadata{}
	if documentKey.Valid {
		data, err := s.storage.Get(r.Context(), documentKey.String)
		if err != nil {
			s.telemetry.storageFailures.Add(1)
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "document read failed")
			s.logf("reanalyze get document: %v", err)
			return
		}
		metadata = metadataFromDocument(data)
	}
	if err := s.upsertIncident(r, id.OrgID, upload.ID, analysisID, metadata); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident record failed")
		s.logf("reanalyze upsert: %v", err)
		return
	}
	_, activeid, originalid, _, _ = s.loadIncidentPointers(r, id.OrgID, externalid)
	if status == string(analyzer.StatusReady) {
		s.telemetry.uploadsCompleted.Add(1)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"upload_id": upload.ID, "incident_id": upload.IncidentID,
		"analysis_id": analysisID, "status": status,
		"reanalyzed":         true,
		"active_analysis_id": activeid, "original_analysis_id": originalid,
		"url": s.dashboardURL(r, upload.IncidentID),
	})
}

// activateBody is the POST /api/incidents/{id}/activate shape.
type activateBody struct {
	AnalysisID string `json:"analysis_id"`
}

// activate answers POST /api/incidents/{id}/activate: move active_analysis_id
// to an existing analysis of the same upload. history is untouched; the
// original pointer is preserved when present.
func (s *Server) activate(w http.ResponseWriter, r *http.Request, id identity) {
	externalid := r.PathValue("id")
	uploadid, activeid, originalid, ok, err := s.loadIncidentPointers(r, id.OrgID, externalid)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident lookup failed")
		s.logf("activate lookup: %v", err)
		return
	}
	if !ok {
		s.missing(w)
		return
	}
	// moving the active analysis changes what every member sees as the
	// diagnosis, so it is owner-only (authz-matrix case 7).
	if !requireOwner(s, w, id) {
		return
	}
	var req activateBody
	if err := decodeJSON(r.Body, 4<<10, &req); err != nil {
		s.error(w, http.StatusBadRequest, "BAD_REQUEST", "analysis_id "+err.Error())
		return
	}
	if req.AnalysisID == "" {
		s.error(w, http.StatusBadRequest, "BAD_REQUEST", "analysis_id is required")
		return
	}
	var target struct {
		id       string
		status   string
		docKey   sql.NullString
		uploadID string
	}
	err = s.db.QueryRowContext(r.Context(),
		`SELECT a.id, a.status, a.document_key, a.upload_id FROM analyses a
		 JOIN uploads u ON u.id = a.upload_id AND u.organization_id = $1
		 WHERE a.id = $2 AND a.upload_id = $3`,
		id.OrgID, req.AnalysisID, uploadid).Scan(&target.id, &target.status, &target.docKey, &target.uploadID)
	if noRow(err) {
		s.error(w, http.StatusNotFound, "NOT_FOUND", "no such analysis for this incident")
		return
	}
	if err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "analysis lookup failed")
		s.logf("activate target: %v", err)
		return
	}
	metadata := dbIncidentMetadata{}
	if target.docKey.Valid {
		data, err := s.storage.Get(r.Context(), target.docKey.String)
		if err != nil {
			if !errors.Is(err, ErrNoSuchObject) {
				s.telemetry.storageFailures.Add(1)
			}
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "document read failed")
			s.logf("activate get document: %v", err)
			return
		}
		metadata = metadataFromDocument(data)
	}
	if err := s.upsertIncident(r, id.OrgID, uploadid, target.id, metadata); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "incident record failed")
		s.logf("activate upsert: %v", err)
		return
	}
	_, activeid, originalid, _, _ = s.loadIncidentPointers(r, id.OrgID, externalid)
	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id": externalid, "analysis_id": target.id, "status": target.status,
		"active_analysis_id": activeid, "original_analysis_id": originalid,
		"url": s.dashboardURL(r, externalid),
	})
}
