// cloudserver create handler (upload-api.md §1, checklist 7.10): authenticate,
// authorize, check for a duplicate, insert the upload row and mint one signed
// storage policy. the client's sha256/size claims are recorded, not trusted:
// the digest is recomputed from stored bytes at complete time.
package cloudserver

import (
	"database/sql"
	"net/http"
	"regexp"
)

// incidentIDRE is what an external incident id may look like: the agent
// writes it, it reaches URLs and display fields, so it stays short,
// printable and free of path material. the bundle's manifest remains the
// authority at complete time; create only rejects obvious nonsense.
var incidentIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{3,64}$`)

// createBody is the strict §1 request shape.
type createBody struct {
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	IncidentID    string `json:"incident_id"`
	SchemaVersion int    `json:"schema_version"`
	FormatVersion int    `json:"format_version"`
}

// existingUpload carries what the dedupe answer needs from the upload row.
type existingUpload struct {
	UploadID    string
	IncidentID  string
	BundleKey   string
	DocumentKey sql.NullString
	Ready       bool
}

// findUploadByDigest answers 7.30: same organization, same bytes. readiness
// follows the active analysis (inferred below); the caller returns the
// incident for a ready upload and lets the client know a non-ready upload can
// still be completed again.
func (s *Server) findUploadByDigest(r *http.Request, org, sha256hex string) (*existingUpload, error) {
	const query = `
		SELECT u.id, u.incident_id, u.object_key,
		       a.document_key,
		       a.status = 'READY'
		FROM uploads u
		LEFT JOIN incidents i
		  ON i.upload_id = u.id AND i.organization_id = u.organization_id
		LEFT JOIN analyses a
		  ON a.id = i.active_analysis_id
		WHERE u.organization_id = $1 AND u.sha256 = $2`
	var row existingUpload
	var ready sql.NullBool
	err := s.db.QueryRowContext(r.Context(), query, org, digestBytes(sha256hex)).
		Scan(&row.UploadID, &row.IncidentID, &row.BundleKey, &row.DocumentKey, &ready)
	switch {
	case noRow(err):
		return nil, nil
	case err != nil:
		return nil, err
	}
	row.Ready = ready.Valid && ready.Bool
	return &row, nil
}

// digestBytes decodes a lowercase hex sha256 into the BYTEA the schema keeps.
func digestBytes(sha256hex string) []byte {
	raw := make([]byte, 32)
	for i := 0; i < 32; i++ {
		raw[i] = hexNib(sha256hex[2*i])<<4 | hexNib(sha256hex[2*i+1])
	}
	return raw
}

func hexNib(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	default:
		return c - 'a' + 10
	}
}

// create implements POST /api/uploads: validate the claim, dedupe by
// (organization, sha256), then mint the one storage policy for the bundle.
func (s *Server) create(w http.ResponseWriter, r *http.Request, id identity) {
	var req createBody
	if err := decodeJSON(r.Body, s.maxCreate, &req); err != nil {
		s.error(w, http.StatusBadRequest, "BAD_REQUEST", "create body "+err.Error())
		return
	}
	if !validSHA256(req.SHA256) {
		s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "sha256 must be lowercase hex sha256")
		return
	}
	if req.SizeBytes < 22 {
		s.error(w, http.StatusUnprocessableEntity, "INVALID_BUNDLE", "bundle size below the 22-byte minimum")
		return
	}
	if req.SizeBytes > maxUploadBodyBytes {
		s.error(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", "bundle size above the archive budget")
		return
	}
	if !incidentIDRE.MatchString(req.IncidentID) {
		s.error(w, http.StatusBadRequest, "BAD_REQUEST", "incident_id is missing or malformed")
		return
	}

	if existing, err := s.findUploadByDigest(r, id.OrgID, req.SHA256); err != nil {
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "duplicate lookup failed")
		s.logf("duplicate lookup: %v", err)
		return
	} else if existing != nil {
		s.telemetry.uploadsDuplicate.Add(1)
		s.writeDuplicate(w, r, existing.UploadID, existing.IncidentID)
		return
	}

	// INSERT carries both the row insert and the dedupe invariant: a second
	// concurrent create with the same digest violates the (organization_id,
	// sha256) UNIQUE and is a duplicate in any race, never an error.
	uploadID := newUploadID()
	objectkey, fields := mintUploadPolicy(id.OrgID, req.SHA256, s.secret)
	_, err := s.db.ExecContext(r.Context(), `
		INSERT INTO uploads
		  (id, organization_id, sha256, object_key, size_bytes, incident_id,
		   schema_version, format_version, uploaded_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uploadID, id.OrgID, digestBytes(req.SHA256), objectkey,
		req.SizeBytes, req.IncidentID, req.SchemaVersion, req.FormatVersion, id.UserID)
	if err != nil {
		if isUniqueViolation(err) {
			if existing, lookuperr := s.findUploadByDigest(r, id.OrgID, req.SHA256); lookuperr == nil && existing != nil {
				s.telemetry.uploadsDuplicate.Add(1)
				s.writeDuplicate(w, r, existing.UploadID, existing.IncidentID)
				return
			}
		}
		s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "upload could not be created")
		s.logf("insert upload: %v", err)
		return
	}

	s.telemetry.uploadsCreated.Add(1)
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_id":  uploadID,
		"object_key": objectkey,
		"upload": map[string]any{
			"url":    s.externalURLFor(r) + "/storage",
			"fields": fields,
		},
	})
}

// writeDuplicate answers 7.30 with 200 + duplicate:true and the existing
// incident's dashboard URL, including what read access needs (the CLI only
// reports the URL, read authorization still applies).
func (s *Server) writeDuplicate(w http.ResponseWriter, r *http.Request, uploadID, incidentID string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"upload_id":   uploadID,
		"duplicate":   true,
		"incident_id": incidentID,
		"url":         s.dashboardURL(r, incidentID),
	})
}

// newUploadID is ids for uploads (upl_ + unguessable hex).
func newUploadID() string { return newID("upl") }
