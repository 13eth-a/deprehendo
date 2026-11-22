package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

type fixedCredentials string

func (c fixedCredentials) Token(context.Context) (string, error) { return string(c), nil }

func apiTestSection() evidence.Section {
	return evidence.Section{
		Provider: Name, SchemaVersion: evidence.SchemaVersion,
		Privacy: evidence.PrivacyIdentifiers,
		Health:  evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref: "rnr_0123456789abcdef", Name: evidence.UnknownText(evidence.ClassRunnerName),
			Version: evidence.UnknownText(evidence.ClassVersion), Labels: evidence.UnknownText(evidence.ClassLabels),
			Lifecycle: evidence.LifecyclePersistent, Supervisors: []evidence.ProcessRef{{PID: 10, StartTicks: 1}},
		}},
		Jobs: []evidence.Job{{
			Ref: "job_0123456789abcdef", Runner: "rnr_0123456789abcdef",
			Repository: evidence.KnownText(evidence.ClassRepository, "acme/service", evidence.SourceRunnerLog),
			Workflow:   evidence.UnknownText(evidence.ClassWorkflow), Name: evidence.UnknownText(evidence.ClassJobName),
			RunID:   evidence.Int64{State: evidence.Known, Class: evidence.ClassRunID, Value: 42, Source: evidence.SourceRunnerLog},
			JobID:   evidence.Int64{State: evidence.Known, Class: evidence.ClassJobID, Value: 84, Source: evidence.SourceRunnerLog},
			Attempt: evidence.Int64{State: evidence.Known, Class: evidence.ClassAttempt, Value: 1, Source: evidence.SourceRunnerLog},
			Outcome: evidence.OutcomeUnknown,
		}},
	}
}

func apiHandler(t *testing.T, runStatus, runConclusion, jobStatus, jobConclusion string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer canary-token" {
			t.Errorf("authorization = %q", got)
		}
		if r.URL.Path == "/repos/acme/service/actions/runs/42" {
			fmt.Fprintf(w, `{"id":42,"name":"CI","status":%q,"conclusion":%q,"created_at":"2026-10-28T12:00:00Z","run_started_at":"2026-10-28T12:00:01Z","completed_at":"2026-10-28T12:03:00Z","repository":{"full_name":"acme/service"}}`, runStatus, runConclusion)
			return
		}
		if r.URL.Path == "/repos/acme/service/actions/runs/42/jobs" {
			fmt.Fprintf(w, `{"jobs":[{"id":84,"run_id":42,"name":"linux-tests","status":%q,"conclusion":%q,"started_at":"2026-10-28T12:00:02Z","completed_at":"2026-10-28T12:02:00Z","run_attempt":1}]}`, jobStatus, jobConclusion)
			return
		}
		http.NotFound(w, r)
	}))
}

// annotationHandler serves a cancelled job and the given check-run
// annotations. A negative annotationsStatus makes the annotations call fail.
func annotationHandler(t *testing.T, annotations string, annotationsStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/service/actions/runs/42":
			fmt.Fprint(w, `{"id":42,"name":"CI","status":"completed","conclusion":"cancelled","repository":{"full_name":"acme/service"}}`)
		case "/repos/acme/service/actions/runs/42/jobs":
			fmt.Fprint(w, `{"jobs":[{"id":84,"run_id":42,"name":"linux-tests","status":"completed","conclusion":"cancelled","run_attempt":1}]}`)
		case "/repos/acme/service/check-runs/84/annotations":
			if annotationsStatus != 0 {
				w.WriteHeader(annotationsStatus)
				return
			}
			fmt.Fprint(w, annotations)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAPITimeLimitAnnotationMarksJobTimedOut(t *testing.T) {
	server := annotationHandler(t, `[{"message":"The job has exceeded the maximum execution time of 1m0s"}]`, 0)
	defer server.Close()
	section := apiTestSection()
	// the runner log stated CANCELLED; only the API annotation knows the limit.
	section.Jobs[0].Outcome = evidence.OutcomeCancelled
	section.Jobs[0].OutcomeSource = evidence.SourceRunnerLog
	section.Jobs[0].OutcomeObservedAt = time.Date(2026, 10, 28, 12, 0, 4, 0, time.UTC)
	(GitHubAPIEnricher{BaseURL: server.URL}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
	job := section.Jobs[0]
	if got := job.Outcome; got != evidence.OutcomeTimedOut {
		t.Fatalf("outcome = %v, want TIMED_OUT", got)
	}
	// the timeout is the API's statement, not the runner log's: the log line
	// that reached this job said cancelled (§5.47).
	if job.OutcomeSource != evidence.SourceProviderAPI {
		t.Errorf("outcome source = %q, want PROVIDER_API", job.OutcomeSource)
	}
	if !job.OutcomeObservedAt.After(time.Date(2026, 10, 28, 12, 0, 4, 0, time.UTC)) {
		t.Errorf("outcome observed at = %v, want the enrichment time", job.OutcomeObservedAt)
	}
}

func TestAPIUserCancelWithoutTimeAnnotationStaysCancelled(t *testing.T) {
	for name, tc := range map[string]struct {
		annotations string
		status      int
	}{
		"no annotations":      {annotations: `[]`},
		"other annotation":    {annotations: `[{"message":"Process completed with exit code 1"}]`},
		"annotations failing": {status: http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			server := annotationHandler(t, tc.annotations, tc.status)
			defer server.Close()
			section := apiTestSection()
			(GitHubAPIEnricher{BaseURL: server.URL}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
			if got := section.Jobs[0].Outcome; got != evidence.OutcomeCancelled {
				t.Fatalf("outcome = %v, want CANCELLED", got)
			}
		})
	}
}

func TestAPIEnrichmentAddsJobAndRunFactsWithoutWorkflowConclusionLeak(t *testing.T) {
	server := apiHandler(t, "completed", "failure", "completed", "success")
	defer server.Close()
	section := apiTestSection()
	health := (GitHubAPIEnricher{BaseURL: server.URL}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
	if health.State != evidence.HealthAvailable {
		t.Fatalf("health = %+v", health)
	}
	job := section.Jobs[0]
	if job.Workflow.State != evidence.Known || job.Workflow.Value != "CI" || job.Workflow.Source != evidence.SourceProviderAPI {
		t.Errorf("workflow = %+v", job.Workflow)
	}
	if job.Name.State != evidence.Known || job.Name.Value != "linux-tests" || job.Name.Source != evidence.SourceProviderAPI {
		t.Errorf("job name = %+v", job.Name)
	}
	if job.Outcome != evidence.OutcomeSucceeded || job.OutcomeSource != evidence.SourceProviderAPI || job.OutcomeObservedAt.IsZero() {
		t.Errorf("job outcome = %+v", job)
	}
	if job.RunStartedAtSource != evidence.SourceProviderAPI || job.RunCompletedAtSource != evidence.SourceProviderAPI || job.StartedAtSource != evidence.SourceProviderAPI || job.CompletedAtSource != evidence.SourceProviderAPI {
		t.Errorf("timestamps lack API provenance: %+v", job)
	}
	if len(section.Conflicts) != 0 {
		t.Errorf("unexpected conflicts: %+v", section.Conflicts)
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("enriched section invalid: %v", err)
	}
}

func TestAPIEnrichmentNeverOverridesLocalOutcomeAndRecordsConflict(t *testing.T) {
	server := apiHandler(t, "completed", "failure", "completed", "failure")
	defer server.Close()
	section := apiTestSection()
	section.Jobs[0].Outcome = evidence.OutcomeRunning
	section.Jobs[0].OutcomeSource = evidence.SourceRunnerLog
	section.Jobs[0].OutcomeObservedAt = time.Date(2026, 10, 28, 12, 0, 4, 0, time.UTC)
	section.Events = []evidence.Event{{Timestamp: section.Jobs[0].OutcomeObservedAt, Type: EventJobAccepted, Runner: section.Runners[0].Ref, Job: section.Jobs[0].Ref, Source: evidence.SourceRunnerLog}}
	health := (GitHubAPIEnricher{BaseURL: server.URL}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
	if health.State != evidence.HealthAvailable {
		t.Fatalf("health = %+v", health)
	}
	if section.Jobs[0].Outcome != evidence.OutcomeRunning || section.Jobs[0].OutcomeSource != evidence.SourceRunnerLog {
		t.Fatalf("API overwrote local outcome: %+v", section.Jobs[0])
	}
	if len(section.Conflicts) != 1 || section.Conflicts[0].Question != ConflictTopicJobState || len(section.Conflicts[0].Claims) != 2 {
		t.Fatalf("conflict = %+v", section.Conflicts)
	}
	if section.Conflicts[0].Claims[0].Source != evidence.SourceProviderAPI || section.Conflicts[0].Claims[1].Source != evidence.SourceRunnerLog {
		t.Fatalf("claim provenance = %+v", section.Conflicts[0].Claims)
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("conflicted section invalid: %v", err)
	}
}

func TestAPIEnrichmentFailuresAreHealthNotFatalAndDoNotLeakCanary(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want evidence.Reason
	}{
		{"unauthorized", http.StatusUnauthorized, evidence.ReasonAPIUnauthorized},
		{"forbidden", http.StatusForbidden, evidence.ReasonAPIUnauthorized},
		{"rate limited", http.StatusTooManyRequests, evidence.ReasonAPIRateLimited},
		{"server error", http.StatusInternalServerError, evidence.ReasonAPIUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = fmt.Fprint(w, "canary-token error body")
			}))
			defer server.Close()
			section := apiTestSection()
			health := (GitHubAPIEnricher{BaseURL: server.URL}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
			if health.State != evidence.HealthDegraded || len(health.Reasons) != 1 || health.Reasons[0] != tc.want {
				t.Fatalf("health = %+v, want degraded %s", health, tc.want)
			}
			if section.Health.State != evidence.HealthDegraded {
				t.Errorf("section health not degraded: %+v", section.Health)
			}
			if strings.Contains(fmt.Sprint(health, section), "canary-token") {
				t.Fatal("token leaked into returned health or provider evidence")
			}
		})
	}
}

func TestAPIEnrichmentUnavailableWithoutCredentialsAndOfflineDataRemainsValid(t *testing.T) {
	section := apiTestSection()
	health := (GitHubAPIEnricher{}).Enrich(context.Background(), &section, nil)
	if health.State != evidence.HealthDegraded || health.Reasons[0] != evidence.ReasonAPIUnavailable {
		t.Fatalf("health = %+v", health)
	}
	if section.Jobs[0].RunID.Value != 42 || section.Jobs[0].Outcome != evidence.OutcomeUnknown {
		t.Fatalf("enrichment failure damaged local evidence: %+v", section.Jobs[0])
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("offline section invalid: %v", err)
	}
}

func TestDecodeJobsResponseMatchesJobRunAndAttempt(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"jobs":[{"id":84,"run_id":42,"run_attempt":1},{"id":84,"run_id":42,"run_attempt":2},{"id":85,"run_id":42,"run_attempt":1},{"id":84,"run_id":99,"run_attempt":1}]}`))}
	jobs, reason := decodeJobsResponse(response, 84, 42, 1)
	if reason != "" || len(jobs) != 1 || jobs[0].RunAttempt != 1 {
		t.Fatalf("jobs=%+v reason=%s", jobs, reason)
	}
}

func TestDecodeJobsResponseRejectsMissingRunAttemptAndDuplicateMatches(t *testing.T) {
	for _, body := range []string{
		`{"jobs":[{"id":84,"run_id":42}]}`,
		`{"jobs":[{"id":84,"run_id":42,"run_attempt":1},{"id":84,"run_id":42,"run_attempt":1}]}`,
	} {
		response := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
		jobs, reason := decodeJobsResponse(response, 84, 42, 1)
		if len(jobs) != 0 || reason != evidence.ReasonAPIUnavailable {
			t.Errorf("body=%s: jobs=%+v reason=%s; want no match with API_UNAVAILABLE", body, jobs, reason)
		}
	}
}

func TestAPIClientCapsCallerTimeoutAndRefusesCrossOriginRedirect(t *testing.T) {
	var leakedAuthorization string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedAuthorization = r.Header.Get("Authorization")
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()
	section := apiTestSection()
	client := &http.Client{Timeout: time.Minute}
	health := (GitHubAPIEnricher{BaseURL: origin.URL, Client: client}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
	if health.State != evidence.HealthDegraded || health.Reasons[0] != evidence.ReasonAPIUnavailable {
		t.Fatalf("health = %+v", health)
	}
	if leakedAuthorization != "" {
		t.Fatalf("Authorization crossed origin redirect: %q", leakedAuthorization)
	}
	if client.Timeout != time.Minute {
		t.Fatalf("caller client was mutated: timeout=%s", client.Timeout)
	}
}

// the hop cap must hold even when the caller supplies its own CheckRedirect:
// a same-origin redirect loop must stop, not follow forever.
func TestAPIClientCapsRedirectsWithCallerCheckRedirect(t *testing.T) {
	hops := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, server.URL+"/loop", http.StatusFound)
	}))
	defer server.Close()
	section := apiTestSection()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	health := (GitHubAPIEnricher{BaseURL: server.URL, Client: client}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
	if health.State != evidence.HealthDegraded {
		t.Fatalf("health = %+v", health)
	}
	if hops > 11 {
		t.Fatalf("redirect loop followed %d times with caller CheckRedirect", hops)
	}
}

var _ provider.Credentials = fixedCredentials("")
