// checklist 7.55: the counters record what an operator needs and never carry
// request data. these tests exercise the counter surface directly; the handler
// paths that charge it are covered by the gated server suite.
package cloudserver

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"runopsy/internal/analyzer"
)

// countingAnalyzer is a JobRunner that never runs: the counter tests charge
// the telemetry directly.
type countingAnalyzer struct{}

func (countingAnalyzer) Run(context.Context, []byte) (analyzer.Result, error) {
	return analyzer.Result{Status: analyzer.StatusRejected}, nil
}

// newCountingServer builds the smallest server the counters need: no database
// is queried and no storage is touched.
func newCountingServer(t *testing.T) (*Server, *[]string) {
	t.Helper()
	var lines []string
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	srv, err := New(Config{
		Database: new(sql.DB),
		Storage:  store,
		Analyzer: countingAnalyzer{},
		Logf:     func(format string, args ...any) { lines = append(lines, format) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, &lines
}

func TestStatsCountsTheOperationalEvents(t *testing.T) {
	srv, _ := newCountingServer(t)

	srv.telemetry.uploadsCreated.Add(2)
	srv.telemetry.uploadsDuplicate.Add(1)
	srv.telemetry.uploadsCompleted.Add(1)
	srv.telemetry.parseFailures.Add(3)
	srv.telemetry.storageFailures.Add(1)
	srv.telemetry.recordAnalysis(1500 * time.Millisecond)
	srv.telemetry.recordAnalysis(500 * time.Millisecond)
	srv.telemetry.recordStatus(404)
	srv.telemetry.recordStatus(401)
	srv.telemetry.recordStatus(503)

	st := srv.Stats()
	if st.UploadsCreated != 2 || st.UploadsDuplicate != 1 || st.UploadsCompleted != 1 {
		t.Errorf("uploads = %+v", st)
	}
	if st.AnalysisRuns != 2 || st.ParseFailures != 3 {
		t.Errorf("analyses = %+v", st)
	}
	if st.AnalysisSecondsTotal != 2 || st.AnalysisSecondsMax != 1.5 {
		t.Errorf("latency total/max = %v/%v, want 2/1.5", st.AnalysisSecondsTotal, st.AnalysisSecondsMax)
	}
	if st.APIErrorsClient != 2 || st.APIErrorsServer != 1 {
		t.Errorf("api errors 4xx/5xx = %d/%d, want 2/1", st.APIErrorsClient, st.APIErrorsServer)
	}
	if st.StorageFailures != 1 {
		t.Errorf("storage failures = %d", st.StorageFailures)
	}
	if st.StartedAt.IsZero() || st.UptimeSeconds < 0 {
		t.Errorf("uptime view = %+v", st)
	}
}

func TestStatsMaxLatencyNeverDecreases(t *testing.T) {
	srv, _ := newCountingServer(t)
	srv.telemetry.recordAnalysis(2 * time.Second)
	srv.telemetry.recordAnalysis(10 * time.Millisecond)
	if got := srv.Stats().AnalysisSecondsMax; got != 2 {
		t.Fatalf("max latency = %v, want 2", got)
	}
	srv.telemetry.recordAnalysis(3 * time.Second)
	if got := srv.Stats().AnalysisSecondsMax; got != 3 {
		t.Fatalf("max latency after a slower run = %v, want 3", got)
	}
}

func TestLogStatsPrintsCountsOnly(t *testing.T) {
	srv, lines := newCountingServer(t)
	srv.telemetry.uploadsCreated.Add(1)
	srv.LogStats()
	if len(*lines) != 1 {
		t.Fatalf("log lines = %d, want 1", len(*lines))
	}
	line := (*lines)[0]
	for _, want := range []string{"telemetry", "uploads_created=", "parse_failures=", "storage_failures="} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q lacks %q", line, want)
		}
	}
	// the line is a fixed format string: no request value can reach it.
	if strings.Contains(line, "%!") {
		t.Errorf("log line has a formatting error: %q", line)
	}
}

func TestRecordStatusIgnoresSuccess(t *testing.T) {
	srv, _ := newCountingServer(t)
	srv.telemetry.recordStatus(200)
	srv.telemetry.recordStatus(204)
	if st := srv.Stats(); st.APIErrorsClient != 0 || st.APIErrorsServer != 0 {
		t.Fatalf("a 2xx was counted as an error: %+v", st)
	}
}
