package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

const (
	apiBaseURL       = "https://api.github.com"
	apiTimeout       = 5 * time.Second
	apiBodyLimit     = 1 << 20
	apiPreview       = "application/vnd.github+json"
	apiVersionHeader = "2022-11-28"
)

// GitHubAPIEnricher uses the GitHub REST API only as optional identity and
// state enrichment. it never overrides local process or runner-log facts.
type GitHubAPIEnricher struct {
	Client  *http.Client
	BaseURL string // test seam; empty uses the GitHub API origin
}

func (e GitHubAPIEnricher) Enrich(ctx context.Context, section *evidence.Section, credentials provider.Credentials) evidence.Health {
	health := e.enrich(ctx, section, credentials)
	if section != nil && health.State == evidence.HealthDegraded {
		section.Health.State = evidence.HealthDegraded
		for _, reason := range health.Reasons {
			found := false
			for _, existing := range section.Health.Reasons {
				if existing == reason {
					found = true
					break
				}
			}
			if !found && len(section.Health.Reasons) < evidence.MaxReasons {
				section.Health.Reasons = append(section.Health.Reasons, reason)
			}
		}
		sort.Slice(section.Health.Reasons, func(i, j int) bool { return section.Health.Reasons[i] < section.Health.Reasons[j] })
	}
	return health
}

func (e GitHubAPIEnricher) enrich(ctx context.Context, section *evidence.Section, credentials provider.Credentials) evidence.Health {
	if section == nil || credentials == nil {
		return degraded(evidence.ReasonAPIUnavailable)
	}
	if section.Provider != Name || len(section.Jobs) == 0 {
		return evidence.Health{State: evidence.HealthAvailable}
	}
	token, err := credentials.Token(ctx)
	if err != nil || token == "" {
		return degraded(evidence.ReasonAPIUnavailable)
	}
	client, parsedbase, ok := e.apiClient()
	if !ok {
		return degraded(evidence.ReasonAPIUnavailable)
	}
	var unavailable evidence.Reason
	for index := range section.Jobs {
		job := &section.Jobs[index]
		if job.RunID.State != evidence.Known || job.JobID.State != evidence.Known || job.RunID.Value <= 0 || job.JobID.Value <= 0 || job.Repository.State != evidence.Known || !safeRepository(job.Repository.Value) {
			continue
		}
		parts := strings.Split(job.Repository.Value, "/")
		basepath := strings.TrimSuffix(parsedbase.Path, "/") + "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/actions/runs/" + strconv.FormatInt(job.RunID.Value, 10)
		request := func(path string) (*http.Response, evidence.Reason) {
			apiurl := *parsedbase
			apiurl.Path = basepath + path
			if strings.HasSuffix(path, "/jobs") {
				apiurl.RawQuery = "per_page=100"
			}
			requestctx, cancel := context.WithTimeout(ctx, apiTimeout)
			defer cancel()
			req, reqerr := http.NewRequestWithContext(requestctx, http.MethodGet, apiurl.String(), nil)
			if reqerr != nil {
				return nil, evidence.ReasonAPIUnavailable
			}
			req.Header.Set("Accept", apiPreview)
			req.Header.Set("X-GitHub-Api-Version", apiVersionHeader)
			req.Header.Set("Authorization", "Bearer "+token)
			response, reqerr := client.Do(req)
			if reqerr != nil {
				return nil, evidence.ReasonAPIUnavailable
			}
			return response, ""
		}
		runresponse, reason := request("")
		if reason != "" {
			unavailable = reason
			continue
		}
		runfetchedat := time.Now().UTC()
		run, runreason := decodeRunResponse(runresponse, job.RunID.Value)
		if runreason != "" {
			unavailable = runreason
			continue
		}
		applyAPIRun(job, run, runfetchedat)
		jobsresponse, reason := request("/jobs")
		if reason != "" {
			unavailable = reason
			continue
		}
		claims, responsereason := decodeJobsResponse(jobsresponse, job.JobID.Value, job.RunID.Value, job.Attempt.Value)
		if responsereason == "" && len(claims) == 0 {
			responsereason = evidence.ReasonAPIUnavailable
		}
		if responsereason != "" {
			if unavailable == "" || responsereason == evidence.ReasonAPIUnauthorized || responsereason == evidence.ReasonAPIRateLimited {
				unavailable = responsereason
			}
			continue
		}
		jobsfetchedat := time.Now().UTC()
		for _, claim := range claims {
			apistate := apiClaimValue(claimStatus(claim))
			if localstate, source, observedAt := localClaim(*section, *job); localstate != "" && apistate != "UNKNOWN" && !claimsAgree(localstate, apistate) && len(section.Conflicts) < evidence.MaxConflicts {
				section.Conflicts = append(section.Conflicts, evidence.Conflict{
					Question: ConflictTopicJobState, Runner: job.Runner, Job: job.Ref,
					Claims: []evidence.Claim{
						{Source: evidence.SourceProviderAPI, Value: apistate, ObservedAt: jobsfetchedat},
						{Source: source, Value: localstate, ObservedAt: observedAt},
					},
				})
			}
			applyAPIJob(job, claim, jobsfetchedat)
		}
		// A timed-out job is reported by GitHub as cancelled, and the runner logs
		// say "canceled" for it too; only the job annotation names the limit.
		// the upgrade also changes who stated the outcome: the log never said
		// "timed out", so the record must credit the API (5.47). Real-runner S4
		// kept `outcome=TIMED_OUT source=RUNNER_LOG` while every log line said
		// cancelled, so an offline reader could check the log and find no such
		// statement.
		if job.Outcome == evidence.OutcomeCancelled && job.JobID.State == evidence.Known {
			if annotationTimedOut(ctx, client, parsedbase, token, parts[0], parts[1], job.JobID.Value) {
				job.Outcome = evidence.OutcomeTimedOut
				job.OutcomeSource = evidence.SourceProviderAPI
				job.OutcomeObservedAt = time.Now().UTC()
			}
		}
	}
	if unavailable != "" {
		return degraded(unavailable)
	}
	return evidence.Health{State: evidence.HealthAvailable}
}

// apiClient builds the HTTP client and base URL every API call uses. API
// credentials are only intended for api.github.com: TLS is required on the
// real service, and redirects to a different origin are refused, so a
// compromised endpoint never receives the bearer token. ok is false when the
// base URL is not acceptable.
func (e GitHubAPIEnricher) apiClient() (*http.Client, *url.URL, bool) {
	base := e.BaseURL
	if base == "" {
		base = apiBaseURL
	}
	parsedbase, err := url.Parse(base)
	if err != nil || (parsedbase.Scheme != "https" && parsedbase.Scheme != "http") || parsedbase.Host == "" || parsedbase.User != nil || parsedbase.RawQuery != "" || parsedbase.Fragment != "" {
		return nil, nil, false
	}
	if strings.EqualFold(parsedbase.Hostname(), "api.github.com") && parsedbase.Scheme != "https" {
		return nil, nil, false
	}
	if strings.EqualFold(parsedbase.Hostname(), "api.github.com") && parsedbase.Port() != "" && parsedbase.Port() != "443" {
		return nil, nil, false
	}
	client := &http.Client{Timeout: apiTimeout}
	if e.Client != nil {
		copyclient := *e.Client
		if copyclient.Timeout == 0 || copyclient.Timeout > apiTimeout {
			copyclient.Timeout = apiTimeout
		}
		client = &copyclient
	}
	previousredirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && (!sameAPIOrigin(req.URL, parsedbase) || !sameAPIOrigin(via[0].URL, req.URL)) {
			return fmt.Errorf("github: refusing cross-origin API redirect")
		}
		if len(via) >= 10 {
			return fmt.Errorf("github: too many API redirects")
		}
		if previousredirect != nil {
			return previousredirect(req, via)
		}
		return nil
	}
	return client, parsedbase, true
}

// apiGet issues one authenticated GET. transport errors are a reason, never
// an error string, so no URL or token text can leave through it.
func apiGet(ctx context.Context, client *http.Client, target url.URL, token string) (*http.Response, evidence.Reason) {
	requestctx, cancel := context.WithTimeout(ctx, apiTimeout)
	req, err := http.NewRequestWithContext(requestctx, http.MethodGet, target.String(), nil)
	if err != nil {
		cancel()
		return nil, evidence.ReasonAPIUnavailable
	}
	req.Header.Set("Accept", apiPreview)
	req.Header.Set("X-GitHub-Api-Version", apiVersionHeader)
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, evidence.ReasonAPIUnavailable
	}
	response.Body = cancelOnClose{response.Body, cancel}
	return response, ""
}

// cancelOnClose releases the request context once the body is closed, so a
// response can be read after apiGet returns.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func sameAPIOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) {
		return false
	}
	lefthost, righthost := strings.ToLower(left.Hostname()), strings.ToLower(right.Hostname())
	if lefthost != righthost {
		return false
	}
	leftport, rightport := left.Port(), right.Port()
	if leftport == "" {
		if strings.EqualFold(left.Scheme, "https") {
			leftport = "443"
		} else {
			leftport = "80"
		}
	}
	if rightport == "" {
		if strings.EqualFold(right.Scheme, "https") {
			rightport = "443"
		} else {
			rightport = "80"
		}
	}
	return leftport == rightport
}

func degraded(reason evidence.Reason) evidence.Health {
	return evidence.Health{State: evidence.HealthDegraded, Reasons: []evidence.Reason{reason}}
}

type apiRun struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Conclusion  string `json:"conclusion"`
	CreatedAt   string `json:"created_at"`
	RunStarted  string `json:"run_started_at"`
	UpdatedAt   string `json:"updated_at"`
	CompletedAt string `json:"completed_at"`
	Repository  struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type apiJob struct {
	ID          int64    `json:"id"`
	RunID       int64    `json:"run_id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Conclusion  string   `json:"conclusion"`
	StartedAt   string   `json:"started_at"`
	CompletedAt string   `json:"completed_at"`
	Labels      []string `json:"labels"`
	RunAttempt  int64    `json:"run_attempt"`
	// RunnerName is read only to match a job to a local runner (G1). it is
	// never copied into the section.
	RunnerName string `json:"runner_name"`
}

type jobsPage struct {
	Jobs []apiJob `json:"jobs"`
}

func decodeRunResponse(response *http.Response, runID int64) (apiRun, evidence.Reason) {
	if response == nil || response.Body == nil {
		return apiRun{}, evidence.ReasonAPIUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, apiBodyLimit+1))
	if err != nil || len(body) > apiBodyLimit {
		return apiRun{}, evidence.ReasonAPIUnavailable
	}
	if reason := responseFailure(response); reason != "" {
		return apiRun{}, reason
	}
	var run apiRun
	if err := json.Unmarshal(body, &run); err != nil || run.ID != runID {
		return apiRun{}, evidence.ReasonAPIUnavailable
	}
	return run, ""
}

func responseFailure(response *http.Response) evidence.Reason {
	if response == nil {
		return evidence.ReasonAPIUnavailable
	}
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return evidence.ReasonAPIUnauthorized
	case http.StatusForbidden:
		if response.Header.Get("X-RateLimit-Remaining") == "0" {
			return evidence.ReasonAPIRateLimited
		}
		return evidence.ReasonAPIUnauthorized
	case http.StatusTooManyRequests:
		return evidence.ReasonAPIRateLimited
	default:
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return evidence.ReasonAPIUnavailable
		}
	}
	return ""
}

func decodeJobsResponse(response *http.Response, jobID, runID, attempt int64) ([]apiJob, evidence.Reason) {
	if response == nil || response.Body == nil {
		return nil, evidence.ReasonAPIUnavailable
	}
	defer response.Body.Close()
	body, readerr := io.ReadAll(io.LimitReader(response.Body, apiBodyLimit+1))
	if readerr != nil || len(body) > apiBodyLimit {
		return nil, evidence.ReasonAPIUnavailable
	}
	if reason := responseFailure(response); reason != "" {
		return nil, reason
	}
	var page jobsPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, evidence.ReasonAPIUnavailable
	}
	var found []apiJob
	matchingids := 0
	for _, candidate := range page.Jobs {
		if candidate.ID != jobID || candidate.RunID != runID {
			continue
		}
		matchingids++
		if attempt > 0 && candidate.RunAttempt <= 0 {
			return nil, evidence.ReasonAPIUnavailable
		}
		if attempt <= 0 || candidate.RunAttempt == attempt {
			found = append(found, candidate)
		}
	}
	if matchingids > 0 && len(found) == 0 {
		return nil, evidence.ReasonAPIUnavailable
	}
	if len(found) > 1 {
		return nil, evidence.ReasonAPIUnavailable
	}
	return found, ""
}

func parseAPITime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func applyAPIRun(job *evidence.Job, run apiRun, fetchedAt time.Time) {
	if job.Repository.State != evidence.Known && safeRepository(run.Repository.FullName) {
		job.Repository = evidence.KnownText(evidence.ClassRepository, run.Repository.FullName, evidence.SourceProviderAPI)
	}
	if job.Workflow.State != evidence.Known && safeIdentifier(run.Name) {
		job.Workflow = evidence.KnownText(evidence.ClassWorkflow, run.Name, evidence.SourceProviderAPI)
	}
	// Workflow-level status/conclusion can differ from this job's result.
	// only the run-jobs endpoint is authoritative for a job outcome.
	if job.RunStartedAt.IsZero() {
		if started := parseAPITime(run.RunStarted); !started.IsZero() {
			job.RunStartedAt, job.RunStartedAtSource = started, evidence.SourceProviderAPI
		} else if started := parseAPITime(run.CreatedAt); !started.IsZero() {
			job.RunStartedAt, job.RunStartedAtSource = started, evidence.SourceProviderAPI
		}
	}
	if job.RunCompletedAt.IsZero() {
		if completed := parseAPITime(run.CompletedAt); !completed.IsZero() {
			job.RunCompletedAt, job.RunCompletedAtSource = completed, evidence.SourceProviderAPI
		}
	}
}

// timeLimitAnnotation is the wording GitHub uses in a job annotation when the
// job stopped at its time limit ("the job has exceeded the maximum execution
// time of 1m0s").
var timeLimitAnnotation = regexp.MustCompile(`(?i)exceeded the maximum execution time`)

// annotationTimedOut reports whether the check run for job (the job ID is the
// check-run ID) carries a time-limit annotation. any failure answers false,
// which keeps the job CANCELLED rather than guessing.
func annotationTimedOut(ctx context.Context, client *http.Client, base *url.URL, token, owner, repo string, jobID int64) bool {
	apiurl := *base
	apiurl.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/check-runs/" + strconv.FormatInt(jobID, 10) + "/annotations"
	requestctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestctx, http.MethodGet, apiurl.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", apiPreview)
	req.Header.Set("X-GitHub-Api-Version", apiVersionHeader)
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if responseFailure(response) != "" {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, apiBodyLimit+1))
	if err != nil || len(body) > apiBodyLimit {
		return false
	}
	var annotations []struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &annotations); err != nil {
		return false
	}
	for _, a := range annotations {
		if timeLimitAnnotation.MatchString(a.Message) {
			return true
		}
	}
	return false
}

func applyAPIJob(job *evidence.Job, api apiJob, fetchedAt time.Time) {
	if safeIdentifier(api.Name) && job.Name.State != evidence.Known {
		job.Name = evidence.KnownText(evidence.ClassJobName, api.Name, evidence.SourceProviderAPI)
	}
	if job.StartedAt.IsZero() {
		if started := parseAPITime(api.StartedAt); !started.IsZero() {
			job.StartedAt, job.StartedAtSource = started, evidence.SourceProviderAPI
		}
	}
	if job.CompletedAt.IsZero() {
		if completed := parseAPITime(api.CompletedAt); !completed.IsZero() {
			job.CompletedAt, job.CompletedAtSource = completed, evidence.SourceProviderAPI
		}
	}
	if job.Attempt.State != evidence.Known && api.RunAttempt > 0 {
		job.Attempt = evidence.Int64{State: evidence.Known, Class: evidence.ClassAttempt, Value: api.RunAttempt, Source: evidence.SourceProviderAPI}
	}
	if job.Outcome != evidence.OutcomeUnknown {
		return // API enrichment never rewrites a local/log-derived outcome.
	}
	if strings.EqualFold(api.Status, "completed") {
		switch strings.ToLower(api.Conclusion) {
		case "success":
			job.Outcome = evidence.OutcomeSucceeded
		case "failure", "action_required", "stale":
			job.Outcome = evidence.OutcomeFailed
		case "cancelled":
			job.Outcome = evidence.OutcomeCancelled
		case "timed_out":
			job.Outcome = evidence.OutcomeTimedOut
		}
	} else if strings.EqualFold(api.Status, "in_progress") || strings.EqualFold(api.Status, "queued") {
		job.Outcome = evidence.OutcomeRunning
	}
	if job.Outcome != evidence.OutcomeUnknown {
		job.OutcomeSource = evidence.SourceProviderAPI
		job.OutcomeObservedAt = fetchedAt
	}
}

func claimStatus(job apiJob) string {
	if strings.EqualFold(job.Status, "completed") && job.Conclusion != "" {
		return job.Conclusion
	}
	return job.Status
}

func localClaim(section evidence.Section, job evidence.Job) (string, evidence.Source, time.Time) {
	var latest *evidence.Event
	for i := range section.Events {
		event := &section.Events[i]
		if event.Job == job.Ref && event.Source != evidence.SourceProviderAPI && (latest == nil || event.Timestamp.After(latest.Timestamp)) {
			latest = event
		}
	}
	if latest != nil {
		switch latest.Type {
		case EventJobAssigned:
			return "ASSIGNED", latest.Source, latest.Timestamp
		case EventJobAccepted:
			return "RUNNING", latest.Source, latest.Timestamp
		case EventJobCompleted:
			return "COMPLETED", latest.Source, latest.Timestamp
		case EventJobCancellation:
			return "CANCELLED", latest.Source, latest.Timestamp
		case EventJobTimeout:
			return "TIMED_OUT", latest.Source, latest.Timestamp
		}
	}
	if job.Outcome != evidence.OutcomeUnknown {
		at := job.OutcomeObservedAt
		if at.IsZero() {
			for i := range section.Events {
				event := &section.Events[i]
				if event.Job == job.Ref && event.Source != evidence.SourceProviderAPI && (at.IsZero() || event.Timestamp.After(at)) {
					at = event.Timestamp
				}
			}
		}
		// claims carry the provider's registered claim vocabulary (audit
		// R13: a local SUCCEEDED/FAILED outcome used to be written verbatim,
		// which the section validator rejects, so enrichment of a finished
		// job failed with "output validation failed").
		value := ""
		switch job.Outcome {
		case evidence.OutcomeSucceeded, evidence.OutcomeFailed:
			value = "COMPLETED"
		case evidence.OutcomeRunning, evidence.OutcomeCancelled, evidence.OutcomeTimedOut:
			value = string(job.Outcome)
		}
		if value == "" {
			return "", "", time.Time{}
		}
		return value, job.OutcomeSource, at
	}
	return "", "", time.Time{}
}

func claimsAgree(local, remote string) bool {
	if local == remote {
		return true
	}
	if (local == "ASSIGNED" || local == "QUEUED") && (remote == "ASSIGNED" || remote == "QUEUED") {
		return true
	}
	if local == "COMPLETED" && (remote == "SUCCEEDED" || remote == "FAILED" || remote == "COMPLETED") {
		return true
	}
	return false
}

func apiClaimValue(state string) string {
	switch strings.ToUpper(state) {
	case "QUEUED", "REQUESTED", "WAITING":
		return "QUEUED"
	case "IN_PROGRESS":
		return "RUNNING"
	case "SUCCESS", "SUCCEEDED", "FAILURE", "FAILED", "ACTION_REQUIRED", "STALE", "COMPLETED":
		return "COMPLETED"
	case "CANCELLED", "CANCELED":
		return "CANCELLED"
	case "TIMED_OUT":
		return "TIMED_OUT"
	default:
		return "UNKNOWN"
	}
}

func safeRepository(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	return safeIdentifier(parts[0]) && safeIdentifier(parts[1])
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 100 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_. ", r)) {
			return false
		}
	}
	return true
}

var _ provider.Enricher = GitHubAPIEnricher{}
