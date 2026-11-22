package cloudserver

import (
	"database/sql"
	"errors"
	"net/http"
)

type meOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type meResponse struct {
	UserID        string           `json:"user_id"`
	Auth          string           `json:"auth"` // "browser" or "token"
	Organizations []meOrganization `json:"organizations"`
}

// maxMeOrganizations bounds the listing; a user in more organizations than
// this is not a case the MVP supports.
const maxMeOrganizations = 100

// me answers GET /api/me: who the caller is and which organizations it may
// act on. the dashboard calls it after sign-in to choose the
// X-Runopsy-Organization header for later requests, so for a browser session
// it does not require one. A personal token sees only its own organization.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearer(r)
	if ok && s.cfg.BrowserAuth != nil && looksLikeJWT(raw) {
		userID, ok := s.browserUser(w, r, raw)
		if !ok {
			return
		}
		rows, err := s.db.QueryContext(r.Context(), `
			SELECT m.organization_id, o.name, m.role
			FROM memberships m
			JOIN organizations o ON o.id = m.organization_id
			WHERE m.user_id = $1
			ORDER BY o.name, m.organization_id
			LIMIT $2`, userID, maxMeOrganizations)
		if err != nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "lookup failed")
			s.logf("me lookup: %v", err)
			return
		}
		defer rows.Close()
		resp := meResponse{UserID: userID, Auth: "browser", Organizations: []meOrganization{}}
		for rows.Next() {
			var o meOrganization
			if err := rows.Scan(&o.ID, &o.Name, &o.Role); err != nil {
				s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "lookup failed")
				s.logf("me scan: %v", err)
				return
			}
			resp.Organizations = append(resp.Organizations, o)
		}
		if err := rows.Err(); err != nil {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "lookup failed")
			s.logf("me rows: %v", err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	s.requireToken(func(w http.ResponseWriter, r *http.Request, id identity) {
		var name string
		err := s.db.QueryRowContext(r.Context(),
			`SELECT name FROM organizations WHERE id = $1`, id.OrgID).Scan(&name)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.error(w, http.StatusInternalServerError, "UNAVAILABLE", "lookup failed")
			s.logf("me organization: %v", err)
			return
		}
		writeJSON(w, http.StatusOK, meResponse{
			UserID: id.UserID,
			Auth:   "token",
			Organizations: []meOrganization{
				{ID: id.OrgID, Name: name, Role: id.Role},
			},
		})
	})(w, r)
}
