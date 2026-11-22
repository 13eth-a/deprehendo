package github

// job location for API enrichment (phase 5 gap G1). local capture never
// learns a job's repository or its numeric run and job IDs (the runner log
// carries GUIDs), so enrich had nothing to look up on a recorded bundle. the
// operator names the repository (`github api-enrich --repo owner/name`); this
// file then finds the job in that repository by time, and by runner name when
// the bundle knows it.
//
// the rule is "unique match or nothing": a job gets IDs only when exactly one
// API job fits. ambiguity is reported as a count, never resolved by guessing,
// and the job keeps its UNKNOWN identity (P2: the API is enrichment, not
// authority). nothing read here is copied into the section except the
// matched repository and numeric IDs.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

const (
	// locateLookback is how far before the local job start a run may have
	// been created. A re-run attempt keeps its run's original creation time,
	// so an attempt of a run created earlier than this is not found.
	locateLookback = 24 * time.Hour
	// locateStartTolerance bounds |API started_at - local start|. the API
	// time is when the runner took the job; the local time is the worker's
	// observed start or the runner's own record.
	locateStartTolerance = 30 * time.Second
	// locateMaxRuns caps the per-run job requests of one locate pass. A
	// busier window is reported as ambiguous rather than paged through.
	locateMaxRuns = 30
)

// ErrInvalidRepository is returned for a --repo value that is not owner/name.
var ErrInvalidRepository = errors.New("github: repository must be owner/name")

// LocateResult counts what a locate pass did. jobs that already carry known
// IDs are not counted.
type LocateResult struct {
	Located   int // exactly one API job matched; IDs filled in
	Ambiguous int // more than one API job matched; left UNKNOWN
	Unmatched int // no API job matched, or no local start time; left UNKNOWN
}

type apiRunsPage struct {
	TotalCount   int64 `json:"total_count"`
	WorkflowRuns []struct {
		ID           int64  `json:"id"`
		RunStartedAt string `json:"run_started_at"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
	} `json:"workflow_runs"`
}

// locate fills repository, RunID, JobID and attempt for jobs of section whose
// IDs are unknown, from the named repository. it returns degraded health on
// API failure (the same reasons as enrich) and never fails the caller.
func (e GitHubAPIEnricher) Locate(ctx context.Context, section *evidence.Section, credentials provider.Credentials, repository string) (LocateResult, evidence.Health, error) {
	var result LocateResult
	if !safeRepository(repository) {
		return result, evidence.Health{}, ErrInvalidRepository
	}
	if section == nil || section.Provider != Name {
		return result, evidence.Health{State: evidence.HealthAvailable}, nil
	}
	type pending struct {
		index int
		start time.Time
		name  string
	}
	var jobs []pending
	var earliest, latest time.Time
	for index, job := range section.Jobs {
		if job.RunID.State == evidence.Known && job.JobID.State == evidence.Known {
			continue
		}
		start := localJobStart(*section, job)
		if start.IsZero() {
			result.Unmatched++
			continue
		}
		jobs = append(jobs, pending{index: index, start: start, name: knownRunnerName(*section, job.Runner)})
		if earliest.IsZero() || start.Before(earliest) {
			earliest = start
		}
		if latest.IsZero() || start.After(latest) {
			latest = start
		}
	}
	if len(jobs) == 0 {
		return result, evidence.Health{State: evidence.HealthAvailable}, nil
	}
	if credentials == nil {
		result.Unmatched += len(jobs)
		return result, degraded(evidence.ReasonAPIUnavailable), nil
	}
	token, err := credentials.Token(ctx)
	if err != nil || token == "" {
		result.Unmatched += len(jobs)
		return result, degraded(evidence.ReasonAPIUnavailable), nil
	}
	client, base, ok := e.apiClient()
	if !ok {
		result.Unmatched += len(jobs)
		return result, degraded(evidence.ReasonAPIUnavailable), nil
	}
	parts := strings.Split(repository, "/")
	repopath := strings.TrimSuffix(base.Path, "/") + "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/actions/runs"

	// one run listing covers every pending job.
	listurl := *base
	listurl.Path = repopath
	listurl.RawQuery = url.Values{
		"created":  {earliest.Add(-locateLookback).UTC().Format(time.RFC3339) + ".." + latest.Add(time.Minute).UTC().Format(time.RFC3339)},
		"per_page": {"100"},
	}.Encode()
	response, reason := apiGet(ctx, client, listurl, token)
	if reason != "" {
		result.Unmatched += len(jobs)
		return result, degraded(reason), nil
	}
	runs, reason := decodeRunsPage(response)
	if reason != "" {
		result.Unmatched += len(jobs)
		return result, degraded(reason), nil
	}
	truncated := runs.TotalCount > int64(len(runs.WorkflowRuns))

	jobcache := map[int64][]apiJob{}
	fetchjobs := func(runID int64) ([]apiJob, evidence.Reason) {
		if cached, ok := jobcache[runID]; ok {
			return cached, ""
		}
		jobsurl := *base
		jobsurl.Path = repopath + "/" + strconv.FormatInt(runID, 10) + "/jobs"
		jobsurl.RawQuery = url.Values{"filter": {"all"}, "per_page": {"100"}}.Encode()
		response, reason := apiGet(ctx, client, jobsurl, token)
		if reason != "" {
			return nil, reason
		}
		page, reason := decodeAllJobs(response)
		if reason != "" {
			return nil, reason
		}
		jobcache[runID] = page
		return page, ""
	}

	for i, want := range jobs {
		// only runs that could have been executing at the local start.
		var candidates []int64
		for _, run := range runs.WorkflowRuns {
			if run.ID <= 0 {
				continue
			}
			started := parseAPITime(run.RunStartedAt)
			if started.IsZero() {
				started = parseAPITime(run.CreatedAt)
			}
			updated := parseAPITime(run.UpdatedAt)
			if !started.IsZero() && started.After(want.start.Add(locateStartTolerance)) {
				continue
			}
			if !updated.IsZero() && updated.Before(want.start.Add(-locateStartTolerance)) {
				continue
			}
			candidates = append(candidates, run.ID)
		}
		if len(candidates) > locateMaxRuns {
			result.Ambiguous++
			continue
		}
		var matches []apiJob
		for _, runID := range candidates {
			page, reason := fetchjobs(runID)
			if reason != "" {
				result.Unmatched += len(jobs) - i
				return result, degraded(reason), nil
			}
			for _, candidate := range page {
				if candidate.ID <= 0 || candidate.RunID != runID {
					continue
				}
				started := parseAPITime(candidate.StartedAt)
				if started.IsZero() || absDuration(started.Sub(want.start)) > locateStartTolerance {
					continue
				}
				if want.name != "" && candidate.RunnerName != want.name {
					continue
				}
				matches = append(matches, candidate)
			}
		}
		switch {
		case len(matches) == 1 && !truncated:
			match := matches[0]
			job := &section.Jobs[want.index]
			job.Repository = evidence.KnownText(evidence.ClassRepository, repository, evidence.SourceProviderAPI)
			job.RunID = evidence.Int64{State: evidence.Known, Class: evidence.ClassRunID, Value: match.RunID, Source: evidence.SourceProviderAPI}
			job.JobID = evidence.Int64{State: evidence.Known, Class: evidence.ClassJobID, Value: match.ID, Source: evidence.SourceProviderAPI}
			if match.RunAttempt > 0 {
				job.Attempt = evidence.Int64{State: evidence.Known, Class: evidence.ClassAttempt, Value: match.RunAttempt, Source: evidence.SourceProviderAPI}
			}
			result.Located++
		case len(matches) == 0 && !truncated:
			result.Unmatched++
		default:
			// more than one fit, or the run listing was cut off so a second
			// fit may exist unseen. either way the job is not identified.
			result.Ambiguous++
		}
	}
	return result, evidence.Health{State: evidence.HealthAvailable}, nil
}

// localJobStart is the best local start time for job: its worker's observed
// start, else the runner's accepted or assigned record for it.
func localJobStart(section evidence.Section, job evidence.Job) time.Time {
	if worker, ok := workerFor(section, job.Ref); ok && !worker.Started.IsZero() {
		return worker.Started
	}
	for _, typ := range []string{EventJobAccepted, EventJobAssigned} {
		var at time.Time
		for _, ev := range section.Events {
			if ev.Job == job.Ref && ev.Type == typ && (at.IsZero() || ev.Timestamp.Before(at)) {
				at = ev.Timestamp
			}
		}
		if !at.IsZero() {
			return at
		}
	}
	return time.Time{}
}

// knownRunnerName is the runner's name when the bundle holds it (identifiers
// privacy level); empty otherwise, and then matching is by time alone.
func knownRunnerName(section evidence.Section, runner evidence.Ref) string {
	for _, r := range section.Runners {
		if r.Ref == runner && r.Name.State == evidence.Known {
			return r.Name.Value
		}
	}
	return ""
}

func decodeRunsPage(response *http.Response) (apiRunsPage, evidence.Reason) {
	var page apiRunsPage
	if response == nil || response.Body == nil {
		return page, evidence.ReasonAPIUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, apiBodyLimit+1))
	if err != nil || len(body) > apiBodyLimit {
		return page, evidence.ReasonAPIUnavailable
	}
	if reason := responseFailure(response); reason != "" {
		return page, reason
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return apiRunsPage{}, evidence.ReasonAPIUnavailable
	}
	return page, ""
}

func decodeAllJobs(response *http.Response) ([]apiJob, evidence.Reason) {
	if response == nil || response.Body == nil {
		return nil, evidence.ReasonAPIUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, apiBodyLimit+1))
	if err != nil || len(body) > apiBodyLimit {
		return nil, evidence.ReasonAPIUnavailable
	}
	if reason := responseFailure(response); reason != "" {
		return nil, reason
	}
	var page jobsPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, evidence.ReasonAPIUnavailable
	}
	return page.Jobs, ""
}
