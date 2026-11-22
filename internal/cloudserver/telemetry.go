// cloudserver operational telemetry (checklist 7.55): counters for the things
// an operator needs to see (uploads, parser failures, API errors, analysis
// latency and storage failures) and nothing about users.
//
// the counters are process-local and monotonic; `serve` prints one summary
// line per interval on the server's log and nothing else. there is no public
// metrics endpoint, no per-user dimension, no bundle content, no token and no
// incident identifier in any of these numbers (see docs/cloud/secrets-audit.md).
package cloudserver

import (
	"sync/atomic"
	"time"
)

// telemetry is the counter set. fields are atomics so the handlers can charge
// them without a lock on the request path.
type telemetry struct {
	uploadsCreated   atomic.Uint64
	uploadsDuplicate atomic.Uint64
	uploadsCompleted atomic.Uint64

	analysisRuns     atomic.Uint64
	parseFailures    atomic.Uint64
	analysisNanos    atomic.Uint64
	analysisMaxNanos atomic.Uint64

	apiErrors4xx atomic.Uint64
	apiErrors5xx atomic.Uint64

	storageFailures atomic.Uint64
}

// telemetry is the JSON view of the counters, returned by Server.Stats.
type Telemetry struct {
	StartedAt        time.Time `json:"started_at"`
	UptimeSeconds    float64   `json:"uptime_seconds"`
	UploadsCreated   uint64    `json:"uploads_created"`
	UploadsDuplicate uint64    `json:"uploads_duplicate"`
	UploadsCompleted uint64    `json:"uploads_completed"`
	AnalysisRuns     uint64    `json:"analysis_runs"`
	ParseFailures    uint64    `json:"parse_failures"`
	// AnalysisSecondsTotal is analyzer wall clock over all runs;
	// AnalysisSecondsMax is the slowest single run (the number that tells an
	// operator whether the 60 s job budget is close).
	AnalysisSecondsTotal float64 `json:"analysis_seconds_total"`
	AnalysisSecondsMax   float64 `json:"analysis_seconds_max"`
	APIErrorsClient      uint64  `json:"api_errors_client"` // 4xx: bad tokens, bad bundles, limits
	APIErrorsServer      uint64  `json:"api_errors_server"` // 5xx: our fault
	StorageFailures      uint64  `json:"storage_failures"`
}

// stats snapshots the counters. safe to call while requests are in flight.
func (s *Server) Stats() Telemetry {
	return Telemetry{
		StartedAt:            s.startedAt,
		UptimeSeconds:        time.Since(s.startedAt).Seconds(),
		UploadsCreated:       s.telemetry.uploadsCreated.Load(),
		UploadsDuplicate:     s.telemetry.uploadsDuplicate.Load(),
		UploadsCompleted:     s.telemetry.uploadsCompleted.Load(),
		AnalysisRuns:         s.telemetry.analysisRuns.Load(),
		ParseFailures:        s.telemetry.parseFailures.Load(),
		AnalysisSecondsTotal: float64(s.telemetry.analysisNanos.Load()) / float64(time.Second),
		AnalysisSecondsMax:   float64(s.telemetry.analysisMaxNanos.Load()) / float64(time.Second),
		APIErrorsClient:      s.telemetry.apiErrors4xx.Load(),
		APIErrorsServer:      s.telemetry.apiErrors5xx.Load(),
		StorageFailures:      s.telemetry.storageFailures.Load(),
	}
}

// RecordAnalysis charges one analyzer run and its duration. exported through
// stats only; handlers call the unexported helpers below.
func (t *telemetry) recordAnalysis(d time.Duration) {
	nanos := uint64(d)
	if d < 0 {
		nanos = 0
	}
	t.analysisRuns.Add(1)
	t.analysisNanos.Add(nanos)
	for {
		previous := t.analysisMaxNanos.Load()
		if nanos <= previous || t.analysisMaxNanos.CompareAndSwap(previous, nanos) {
			return
		}
	}
}

// recordStatus classifies one non-2xx API response.
func (t *telemetry) recordStatus(status int) {
	switch {
	case status >= 500:
		t.apiErrors5xx.Add(1)
	case status >= 400:
		t.apiErrors4xx.Add(1)
	}
}

// LogStats writes one summary line through the server's log function. the
// line is fixed-shape and count-only: an operator can graph it, and it never
// carries a token, a bundle, an incident id or a raw runner log.
func (s *Server) LogStats() {
	st := s.Stats()
	s.logf("telemetry uptime_s=%.1f uploads_created=%d uploads_duplicate=%d uploads_completed=%d "+
		"analysis_runs=%d parse_failures=%d analysis_seconds_total=%.3f analysis_seconds_max=%.3f "+
		"api_errors_client=%d api_errors_server=%d storage_failures=%d",
		st.UptimeSeconds, st.UploadsCreated, st.UploadsDuplicate, st.UploadsCompleted,
		st.AnalysisRuns, st.ParseFailures, st.AnalysisSecondsTotal, st.AnalysisSecondsMax,
		st.APIErrorsClient, st.APIErrorsServer, st.StorageFailures)
}
