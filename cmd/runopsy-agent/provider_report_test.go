package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github"
)

// A section keeps the runner's recent job history across captures, so the
// incident header must not present a previous job's outcome as this capture's.
func TestReportShowsTheJobThatRanDuringTheCapture(t *testing.T) {
	from := time.Date(2026, 11, 2, 20, 36, 0, 0, time.UTC)
	to := from.Add(2 * time.Minute)
	stale := evidence.Job{
		Ref: "job_aaaaaaaaaaaaaaaa", Outcome: evidence.OutcomeSucceeded, OutcomeSource: evidence.SourceRunnerLog,
		OutcomeObservedAt: from.Add(-30 * time.Second),
	}
	current := evidence.Job{
		Ref: "job_bbbbbbbbbbbbbbbb", Outcome: evidence.OutcomeFailed, OutcomeSource: evidence.SourceRunnerLog,
		OutcomeObservedAt: from.Add(90 * time.Second),
	}
	got := jobsForWindow([]evidence.Job{stale, current}, from, to)
	if len(got) != 1 || got[0].Ref != current.Ref {
		t.Fatalf("jobsForWindow = %+v, want only %s", got, current.Ref)
	}

	section := evidence.Section{
		Provider: github.Name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyConservative,
		Health: evidence.Health{State: evidence.HealthAvailable},
		Jobs:   []evidence.Job{stale, current},
	}
	var out bytes.Buffer
	if err := renderGitHubSummary(&out, []evidence.Section{section}, from, to); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Job outcome   FAILED") {
		t.Errorf("report does not state the capture's job outcome:\n%s", out.String())
	}
	if strings.Contains(out.String(), "SUCCEEDED") {
		t.Errorf("report presents a previous job's outcome:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "ref="+string(current.Ref)) {
		t.Errorf("report does not name the job it describes:\n%s", out.String())
	}
}

// A job that started before the capture and never reported an end was still
// running while the capture ran, so it belongs to the incident.
func TestRunningJobFromBeforeTheCaptureIsKept(t *testing.T) {
	from := time.Date(2026, 11, 2, 20, 36, 0, 0, time.UTC)
	running := evidence.Job{Ref: "job_cccccccccccccccc", StartedAt: from.Add(-5 * time.Minute)}
	if !jobInWindow(running, from, from.Add(time.Minute)) {
		t.Fatal("a job running into the capture was dropped from the report")
	}
	finished := evidence.Job{Ref: "job_dddddddddddddddd", StartedAt: from.Add(-5 * time.Minute), CompletedAt: from.Add(-4 * time.Minute)}
	if jobInWindow(finished, from, from.Add(time.Minute)) {
		t.Fatal("a job that ended before the capture was kept")
	}
}

// two jobs inside the same capture are ordered oldest first, so the report
// reads chronologically regardless of section order.
func TestJobsInWindowAreOrderedOldestFirst(t *testing.T) {
	from := time.Date(2026, 11, 2, 20, 36, 0, 0, time.UTC)
	to := from.Add(10 * time.Minute)
	newer := evidence.Job{Ref: "job_eeeeeeeeeeeeeeee", OutcomeObservedAt: from.Add(8 * time.Minute), Outcome: evidence.OutcomeSucceeded}
	older := evidence.Job{Ref: "job_ffffffffffffffff", OutcomeObservedAt: from.Add(time.Minute), Outcome: evidence.OutcomeFailed}
	got := jobsForWindow([]evidence.Job{newer, older}, from, to)
	if len(got) != 2 || got[0].Ref != older.Ref || got[1].Ref != newer.Ref {
		t.Fatalf("jobsForWindow order = %+v", got)
	}
}

// without a usable window the section is rendered unchanged: older bundles and
// hand-built sections keep their output.
func TestJobsForWindowKeepsSectionsWithoutAWindow(t *testing.T) {
	job := evidence.Job{Ref: "job_aaaaaaaaaaaaaaaa", OutcomeObservedAt: time.Date(2026, 11, 2, 20, 0, 0, 0, time.UTC)}
	if got := jobsForWindow([]evidence.Job{job}, time.Time{}, time.Time{}); len(got) != 1 {
		t.Fatalf("jobsForWindow dropped the only record: %+v", got)
	}
}

// A capture with no job of its own (a runner idle, shutting down or updating)
// reports no job block rather than the last job the runner ever ran.
func TestReportOmitsAJobOutsideTheCapture(t *testing.T) {
	from := time.Date(2026, 11, 2, 17, 43, 0, 0, time.UTC)
	to := from.Add(4 * time.Minute)
	section := evidence.Section{
		Provider: github.Name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyConservative,
		Health: evidence.Health{State: evidence.HealthAvailable},
		Jobs: []evidence.Job{{
			Ref: "job_aaaaaaaaaaaaaaaa", Outcome: evidence.OutcomeFailed, OutcomeSource: evidence.SourceRunnerLog,
			OutcomeObservedAt: time.Date(2026, 11, 1, 22, 47, 57, 0, time.UTC),
		}},
	}
	var out bytes.Buffer
	if err := renderGitHubSummary(&out, []evidence.Section{section}, from, to); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Job outcome") {
		t.Errorf("report presents a job that did not run in the capture:\n%s", out.String())
	}
}

// principal review of L6: a job known only from local evidence (no API timestamps)
// is in the window when its events or its worker's lifetime are, and a
// worker still running at the window start keeps its job in the header. A
// job whose evidence is all from an earlier day stays out.
func TestJobsForSectionWindowUsesLocalEvidence(t *testing.T) {
	from := time.Date(2026, 11, 2, 21, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Minute)
	runner := evidence.Ref("rnr_0123456789abcdef")
	job := func(ref evidence.Ref) evidence.Job {
		return evidence.Job{Ref: ref, Runner: runner, Outcome: evidence.OutcomeUnknown}
	}
	section := evidence.Section{
		Jobs: []evidence.Job{job("job_aaaaaaaaaaaaaaaa"), job("job_bbbbbbbbbbbbbbbb"), job("job_cccccccccccccccc")},
		Events: []evidence.Event{
			{Timestamp: from.Add(10 * time.Second), Type: github.EventJobAssigned, Runner: runner, Job: "job_aaaaaaaaaaaaaaaa"},
			{Timestamp: from.Add(-24 * time.Hour), Type: github.EventJobAssigned, Runner: runner, Job: "job_cccccccccccccccc"},
		},
		Workers: []evidence.Worker{
			{Ref: "wkr_bbbbbbbbbbbbbbbb", Runner: runner, Job: "job_bbbbbbbbbbbbbbbb", Started: from.Add(-time.Hour)},
			{Ref: "wkr_cccccccccccccccc", Runner: runner, Job: "job_cccccccccccccccc", Started: from.Add(-24 * time.Hour), Exited: from.Add(-23 * time.Hour)},
		},
	}
	got := jobsForSectionWindow(section, from, to)
	var refs []evidence.Ref
	for _, j := range got {
		refs = append(refs, j.Ref)
	}
	if len(refs) != 2 || refs[0] != "job_bbbbbbbbbbbbbbbb" || refs[1] != "job_aaaaaaaaaaaaaaaa" {
		t.Fatalf("jobs in window = %v, want [job_b (running), job_a (assigned in window)]", refs)
	}
}
