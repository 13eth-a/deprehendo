package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"runopsy/internal/provider/evidence"
)

// G1: locate a recorded job in a named repository by time (and runner name
// when known), unique match or nothing.

var locateT = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const (
	locateRunner = evidence.Ref("rnr_0123456789abcdef")
	locateJob    = evidence.Ref("job_0123456789abcdef")
	locateWorker = evidence.Ref("wkr_0123456789abcdef")
	locateToken  = "ghp_LOCATEcanary000000000000000000000000"
)

// locateSection is a recorded bundle's view: worker started at locateT, job
// identity unknown. runnerName "" leaves the name UNKNOWN (conservative).
func locateSection(runnerName string) evidence.Section {
	name := evidence.UnknownText(evidence.ClassRunnerName)
	if runnerName != "" {
		name = evidence.KnownText(evidence.ClassRunnerName, runnerName, evidence.SourceRunnerConfig)
	}
	return evidence.Section{
		Provider: Name, SchemaVersion: evidence.SchemaVersion,
		Privacy: evidence.PrivacyIdentifiers,
		Health:  evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref: locateRunner, Name: name,
			Version: evidence.UnknownText(evidence.ClassVersion), Labels: evidence.UnknownText(evidence.ClassLabels),
			Lifecycle: evidence.LifecycleUnknown,
		}},
		Workers: []evidence.Worker{{Ref: locateWorker, Runner: locateRunner, Process: evidence.ProcessRef{PID: 200, StartTicks: 20}, Job: locateJob, Started: locateT}},
		Jobs: []evidence.Job{{
			Ref: locateJob, Runner: locateRunner,
			Repository: evidence.UnknownText(evidence.ClassRepository),
			Workflow:   evidence.UnknownText(evidence.ClassWorkflow), Name: evidence.UnknownText(evidence.ClassJobName),
			RunID:   evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID},
			JobID:   evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID},
			Attempt: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt},
			Outcome: evidence.OutcomeUnknown,
		}},
	}
}

type fakeLocateAPI struct {
	total int // total_count reported for the run listing; 0 means len(runs)
	runs  []int64
	jobs  map[int64][]map[string]any
	mu    sync.Mutex
	paths []string
	auth  []string
}

func (f *fakeLocateAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.RequestURI())
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/repos/acme/service/actions/runs")
		switch {
		case path == "":
			var runs []map[string]any
			for _, id := range f.runs {
				runs = append(runs, map[string]any{
					"id": id, "run_started_at": locateT.Add(-time.Minute).Format(time.RFC3339),
					"created_at": locateT.Add(-2 * time.Minute).Format(time.RFC3339),
					"updated_at": locateT.Add(10 * time.Minute).Format(time.RFC3339),
				})
			}
			total := f.total
			if total == 0 {
				total = len(runs)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": total, "workflow_runs": runs})
		case strings.HasSuffix(path, "/jobs"):
			var id int64
			fmt.Sscanf(strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/jobs"), "%d", &id)
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": f.jobs[id]})
		default:
			var id int64
			fmt.Sscanf(strings.TrimPrefix(path, "/"), "%d", &id)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "name": "CI", "status": "completed", "conclusion": "success",
				"repository": map[string]any{"full_name": "acme/service"},
			})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func apiJobAt(id, run int64, offset time.Duration, runner string) map[string]any {
	return map[string]any{
		"id": id, "run_id": run, "name": "build", "status": "completed", "conclusion": "success",
		"started_at": locateT.Add(offset).Format(time.RFC3339), "run_attempt": 1, "runner_name": runner,
	}
}

func TestLocateUniqueMatchFillsIdentity(t *testing.T) {
	api := &fakeLocateAPI{runs: []int64{11}, jobs: map[int64][]map[string]any{
		11: {apiJobAt(101, 11, 2*time.Second, "r1"), apiJobAt(102, 11, 10*time.Minute, "r1")},
	}}
	srv := api.server(t)
	section := locateSection("")
	result, health, err := (GitHubAPIEnricher{BaseURL: srv.URL}).Locate(context.Background(), &section, fixedCredentials(locateToken), "acme/service")
	if err != nil || health.State != evidence.HealthAvailable {
		t.Fatalf("locate err=%v health=%+v", err, health)
	}
	if result != (LocateResult{Located: 1}) {
		t.Fatalf("result = %+v", result)
	}
	job := section.Jobs[0]
	if job.RunID.Value != 11 || job.JobID.Value != 101 || job.Attempt.Value != 1 || job.Repository.Value != "acme/service" {
		t.Fatalf("identity not filled: %+v", job)
	}
	if job.RunID.Source != evidence.SourceProviderAPI || job.Repository.Source != evidence.SourceProviderAPI {
		t.Fatalf("located identity must carry PROVIDER_API provenance: %+v", job)
	}
	if !strings.Contains(api.paths[0], "created=") || !strings.Contains(api.paths[0], "per_page=100") {
		t.Fatalf("run listing not bounded by creation window: %s", api.paths[0])
	}
	// enrichment now has something to look up, which was G1.
	if h := (GitHubAPIEnricher{BaseURL: srv.URL}).Enrich(context.Background(), &section, fixedCredentials(locateToken)); h.State != evidence.HealthAvailable {
		t.Fatalf("enrich after locate: %+v", h)
	}
	if section.Jobs[0].Name.Value != "build" || section.Jobs[0].Workflow.Value != "CI" {
		t.Fatalf("enrich did not fill names after locate: %+v", section.Jobs[0])
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("located section invalid: %v", err)
	}
	dump, _ := json.Marshal(section)
	if strings.Contains(string(dump), "LOCATEcanary") {
		t.Fatal("token reached the section")
	}
}

func TestLocateTwoFitsWithoutRunnerNameIsAmbiguous(t *testing.T) {
	api := &fakeLocateAPI{runs: []int64{11, 12}, jobs: map[int64][]map[string]any{
		11: {apiJobAt(101, 11, time.Second, "r1")},
		12: {apiJobAt(201, 12, 3*time.Second, "r2")},
	}}
	srv := api.server(t)
	section := locateSection("")
	result, _, err := (GitHubAPIEnricher{BaseURL: srv.URL}).Locate(context.Background(), &section, fixedCredentials(locateToken), "acme/service")
	if err != nil || result != (LocateResult{Ambiguous: 1}) {
		t.Fatalf("result = %+v err=%v, want one ambiguous", result, err)
	}
	if section.Jobs[0].RunID.State != evidence.Unknown || section.Jobs[0].JobID.State != evidence.Unknown || section.Jobs[0].Repository.State != evidence.Unknown {
		t.Fatalf("ambiguous job was given an identity: %+v", section.Jobs[0])
	}
}

func TestLocateRunnerNameDisambiguates(t *testing.T) {
	api := &fakeLocateAPI{runs: []int64{11, 12}, jobs: map[int64][]map[string]any{
		11: {apiJobAt(101, 11, time.Second, "r1")},
		12: {apiJobAt(201, 12, 3*time.Second, "r2")},
	}}
	srv := api.server(t)
	section := locateSection("r2")
	result, _, err := (GitHubAPIEnricher{BaseURL: srv.URL}).Locate(context.Background(), &section, fixedCredentials(locateToken), "acme/service")
	if err != nil || result != (LocateResult{Located: 1}) || section.Jobs[0].JobID.Value != 201 {
		t.Fatalf("result = %+v job=%+v err=%v", result, section.Jobs[0], err)
	}
}

func TestLocateTruncatedListingIsAmbiguous(t *testing.T) {
	// only one run is listed, but the API says 500 matched the window: a
	// second fit may exist unseen, so even a single match is not trusted.
	api := &fakeLocateAPI{total: 500, runs: []int64{11}, jobs: map[int64][]map[string]any{
		11: {apiJobAt(101, 11, time.Second, "r1")},
	}}
	srv := api.server(t)
	section := locateSection("")
	result, _, _ := (GitHubAPIEnricher{BaseURL: srv.URL}).Locate(context.Background(), &section, fixedCredentials(locateToken), "acme/service")
	if result != (LocateResult{Ambiguous: 1}) || section.Jobs[0].JobID.State != evidence.Unknown {
		t.Fatalf("result = %+v job=%+v", result, section.Jobs[0])
	}
}

func TestLocateNoFitIsUnmatched(t *testing.T) {
	api := &fakeLocateAPI{runs: []int64{11}, jobs: map[int64][]map[string]any{
		11: {apiJobAt(101, 11, 5*time.Minute, "r1")},
	}}
	srv := api.server(t)
	section := locateSection("")
	result, _, _ := (GitHubAPIEnricher{BaseURL: srv.URL}).Locate(context.Background(), &section, fixedCredentials(locateToken), "acme/service")
	if result != (LocateResult{Unmatched: 1}) || section.Jobs[0].JobID.State != evidence.Unknown {
		t.Fatalf("result = %+v job=%+v", result, section.Jobs[0])
	}
}

func TestLocateRejectsMalformedRepository(t *testing.T) {
	section := locateSection("")
	for _, repo := range []string{"", "acme", "acme/service/extra", "acme/ser vice?x=1", "../etc/passwd"} {
		if _, _, err := (GitHubAPIEnricher{}).Locate(context.Background(), &section, fixedCredentials(locateToken), repo); !errors.Is(err, ErrInvalidRepository) {
			t.Fatalf("repo %q accepted (err=%v)", repo, err)
		}
	}
}

func TestLocateWithoutTokenIsDegradedNotFatal(t *testing.T) {
	section := locateSection("")
	result, health, err := (GitHubAPIEnricher{BaseURL: "http://127.0.0.1:1"}).Locate(context.Background(), &section, fixedCredentials(""), "acme/service")
	if err != nil || health.State != evidence.HealthDegraded || result != (LocateResult{Unmatched: 1}) {
		t.Fatalf("result=%+v health=%+v err=%v", result, health, err)
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("section invalid: %v", err)
	}
}
