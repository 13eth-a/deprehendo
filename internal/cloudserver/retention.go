// cloudserver retention sweep (checklist 7.58): manual delete is the
// minimum and already exists (DELETE /api/incidents/{id}); this file adds the
// optional time-based control as an operator-run sweep, not a background
// daemon. the schema keeps uploaded_at per upload, so no migration was needed
// for correctness; 0002 adds the index the sweep reads.
package cloudserver

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PruneStats counts one sweep. bytes is the original-bundle bytes the sweep
// removed (from uploads.size_bytes); documents are counted as objects because
// the store interface has no stat call, and no size is invented for them.
type PruneStats struct {
	Uploads int   `json:"uploads"`
	Objects int   `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

// uploadlist is one upload the sweep selected, for a dry run's report.
type PruneEntry struct {
	UploadID       string    `json:"upload_id"`
	OrganizationID string    `json:"organization_id"`
	UploadedAt     time.Time `json:"uploaded_at"`
	SizeBytes      int64     `json:"size_bytes"`
}

// PrunePlan is what a dry run would delete. the sweep refuses to delete
// anything without one: a mistyped age (`90h` for `90d`) is otherwise a silent
// data loss, and this is the only code path that destroys bundles by time.
type PrunePlan struct {
	Cutoff  time.Time    `json:"cutoff"`
	Entries []PruneEntry `json:"uploads"`
	Stats   PruneStats   `json:"stats"`
}

// PlanPrune lists the uploads a sweep at cutoff would delete, up to limit
// rows when limit is positive. it reads only.
func (s *Server) PlanPrune(ctx context.Context, cutoff time.Time, limit int) (PrunePlan, error) {
	plan := PrunePlan{Cutoff: cutoff, Entries: []PruneEntry{}}
	rows, err := s.selectUploads(ctx, cutoff, limit)
	if err != nil {
		return plan, err
	}
	for _, u := range rows {
		plan.Entries = append(plan.Entries, PruneEntry{
			UploadID: u.id, OrganizationID: u.org, UploadedAt: u.uploadedAt, SizeBytes: u.size,
		})
		plan.Stats.Uploads++
		plan.Stats.Bytes += u.size
		// objects: the bundle plus the legacy per-upload document plus one
		// document per analysis that has one.
		plan.Stats.Objects++
		keys, err := s.documentKeys(ctx, u.id, u.org)
		if err != nil {
			return plan, err
		}
		plan.Stats.Objects += len(keys)
	}
	return plan, nil
}

// PruneUploadsOlderThan deletes uploads (and, by cascade, their analyses and
// incident rows) older than cutoff, oldest first, up to limit rows when limit
// is positive. stale never-completed uploads (no incident row) are pruned by
// the same rule, which is what makes this the cleanup for the
// PENDING-without-state case contract §2.1 names.
//
// objects go first and the row last, as in the manual delete (H1, L1). an
// object that is already gone counts as deleted. any other storage failure
// stops the sweep with that upload's row intact, so the keys stay recorded and
// a rerun retries them; an object is never left behind with nothing naming it.
// the stats returned with the error count what was finished before it.
//
// work is per upload, not one transaction over the whole sweep: a crash
// mid-sweep leaves the remaining uploads untouched and a rerun continues where
// it stopped. A concurrent re-analysis can insert between the key read and the
// row delete; the cascade then refuses its insert and it answers UNAVAILABLE,
// leaving one orphan document. that race is inherent to deleting an upload
// someone is analyzing, and it fails closed (no row, no incident).
func (s *Server) PruneUploadsOlderThan(ctx context.Context, cutoff time.Time, limit int) (PruneStats, error) {
	var stats PruneStats
	rows, err := s.selectUploads(ctx, cutoff, limit)
	if err != nil {
		return stats, err
	}
	for _, u := range rows {
		// collect every derived document key before the cascade removes the
		// rows that name them.
		dockeys, err := s.documentKeys(ctx, u.id, u.org)
		if err != nil {
			// without the history keys the sweep would strand documents that
			// nothing can find afterwards; stop instead of guessing.
			return stats, err
		}
		keys := append([]string{u.key}, dockeys...)
		for _, key := range keys {
			err := s.storage.Delete(ctx, key)
			if err == nil {
				stats.Objects++
				continue
			}
			if errors.Is(err, ErrNoSuchObject) {
				continue
			}
			s.telemetry.storageFailures.Add(1)
			return stats, fmt.Errorf("upload %s: delete object %s: %w (row kept; rerun to retry)", u.id, key, err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE id = $1`, u.id); err != nil {
			return stats, err
		}
		stats.Uploads++
		stats.Bytes += u.size
	}
	return stats, nil
}

// documentKeys is every document key the upload owns, deduplicated. older
// builds wrote one document per upload (`documentKeyFor`), which is the only
// key an upload with no analysis row can have; newer ones write one per engine
// and each analysis row names its own. A read failure is returned, never
// swallowed: the caller decides whether losing the keys is acceptable (it is
// not, before a delete).
func (s *Server) documentKeys(ctx context.Context, uploadID, org string) ([]string, error) {
	legacy := documentKeyFor(org, uploadID)
	keys := []string{}
	seen := map[string]bool{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT document_key FROM analyses WHERE upload_id = $1 AND document_key IS NOT NULL`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return []string{legacy}, nil
	}
	return keys, nil
}

// pruneRow is one selected upload.
type pruneRow struct {
	id         string
	org        string
	key        string
	size       int64
	uploadedAt time.Time
}

func (s *Server) selectUploads(ctx context.Context, cutoff time.Time, limit int) ([]pruneRow, error) {
	query := `SELECT id, organization_id, object_key, size_bytes, uploaded_at
		FROM uploads WHERE uploaded_at < $1 ORDER BY uploaded_at ASC`
	args := []any{cutoff}
	if limit > 0 {
		query += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pruneRow
	for rows.Next() {
		var r pruneRow
		if err := rows.Scan(&r.id, &r.org, &r.key, &r.size, &r.uploadedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
