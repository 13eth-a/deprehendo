// cloudserver usage accounting (upload-api.md §4 / contract §5.3, checklist
// 7.37): every analyzer run charges its organization one counted job and its
// analyzer wall-clock time in parse seconds. limits are consulted before any
// work is dispatched, so a hostile client pays for rejections but is stopped
// before running them.
//
// two windows (contract §5.3, owner decision november 9, 2026):
//
//   - analyses per organization per hour: a rolling 60-minute window over
//     per-minute counters (upload_usage_minutes, migration 0003), so the
//     limit cannot be doubled by bursting across a clock-hour boundary;
//   - parse-seconds per organization per day: the daily row in upload_usage,
//     which also keeps the per-day analysis count for reporting.
package cloudserver

import (
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"strconv"
)

// usageRow is one day of counters.
type usageRow struct {
	AnalysesCount int
	ParseSeconds  float64
}

// usageLimit is checkUsage's answer when a limit is hit.
type usageLimit struct {
	Status     int
	Message    string
	RetryAfter int // seconds; 0 when unknown
}

// checkUsage reports the limit the organization has hit, or nil. lookup
// failures fail open: a usage-count failure must not disable uploads, and the
// per-org and server-wide concurrency caps still apply.
func (s *Server) checkUsage(r *http.Request, org string) *usageLimit {
	var (
		recent     int
		retryAfter sql.NullFloat64
	)
	err := s.db.QueryRowContext(r.Context(), `
		SELECT COALESCE(SUM(analyses_count), 0),
		       EXTRACT(EPOCH FROM (MIN(minute) + interval '1 hour' - now()))
		FROM upload_usage_minutes
		WHERE organization_id = $1 AND minute > now() - interval '1 hour'`, org).
		Scan(&recent, &retryAfter)
	if err != nil {
		s.logf("usage lookup (hourly): %v", err)
	} else if recent >= s.cfg.MaxAnalysesPerHour {
		// the window frees capacity when its oldest minute ages out.
		wait := 60
		if retryAfter.Valid {
			wait = int(math.Ceil(retryAfter.Float64))
		}
		if wait < 1 {
			wait = 1
		}
		return &usageLimit{
			Status:     http.StatusTooManyRequests,
			Message:    fmt.Sprintf("%d analyses per hour", s.cfg.MaxAnalysesPerHour),
			RetryAfter: wait,
		}
	}

	var u usageRow
	err = s.db.QueryRowContext(r.Context(), `
		SELECT analyses_count, parse_seconds
		FROM upload_usage
		WHERE organization_id = $1 AND day = current_date`, org).
		Scan(&u.AnalysesCount, &u.ParseSeconds)
	if noRow(err) {
		return nil
	}
	if err != nil {
		s.logf("usage lookup (daily): %v", err)
		return nil
	}
	if u.ParseSeconds >= s.cfg.MaxParseSecondsPerDay {
		return &usageLimit{
			Status:  http.StatusTooManyRequests,
			Message: "daily analyzer budget exhausted",
		}
	}
	return nil
}

// writeUsageLimit answers a hit limit with the §4 envelope and, when known,
// Retry-After (upload-api.md §4: the CLI prints it).
func (s *Server) writeUsageLimit(w http.ResponseWriter, limit *usageLimit) {
	if limit.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(limit.RetryAfter))
	}
	s.error(w, limit.Status, "RATE_LIMITED", limit.Message)
}

// chargeParseSeconds charges one analyzer run: one job in the current minute
// (the hourly window) and its duration in the day's parse seconds. the upserts
// initialize their rows, so the counters exist for reporting too.
func (s *Server) chargeParseSeconds(r *http.Request, org string, seconds float64) {
	if seconds <= 0 {
		seconds = 0.001
	}
	// charging is best-effort bookkeeping; the next request's checkUsage read
	// is the limit that matters, and a failed upsert leaves the previous
	// value, which undercharges, never overcharges.
	if _, err := s.db.ExecContext(r.Context(), `
		INSERT INTO upload_usage (organization_id, day, analyses_count, parse_seconds)
		VALUES ($1, current_date, 1, $2)
		ON CONFLICT (organization_id, day) DO UPDATE SET
		  analyses_count = upload_usage.analyses_count + 1,
		  parse_seconds  = upload_usage.parse_seconds + EXCLUDED.parse_seconds`,
		org, seconds); err != nil {
		s.logf("usage charge (daily): %v", err)
	}
	if _, err := s.db.ExecContext(r.Context(), `
		INSERT INTO upload_usage_minutes (organization_id, minute, analyses_count)
		VALUES ($1, date_trunc('minute', now()), 1)
		ON CONFLICT (organization_id, minute) DO UPDATE SET
		  analyses_count = upload_usage_minutes.analyses_count + 1`,
		org); err != nil {
		s.logf("usage charge (hourly): %v", err)
	}
	// minute rows only matter for an hour; keep a day for reporting and drop
	// the rest so the table stays at most ~1,440 rows per organization.
	if _, err := s.db.ExecContext(r.Context(), `
		DELETE FROM upload_usage_minutes
		WHERE organization_id = $1 AND minute < now() - interval '1 day'`,
		org); err != nil {
		s.logf("usage trim (hourly): %v", err)
	}
}
