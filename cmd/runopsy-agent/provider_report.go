package main

import (
	"fmt"
	"io"
	"sort"
	"time"

	"runopsy/internal/causal"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github"
)

// renderGitHubSummary adds the provider context that makes a systems report
// actionable, while keeping generic diagnoses distinct from provider effects.
// the window is the reported capture's [start, end]: a section also carries
// the runner's earlier job records, and those would otherwise put another
// job's outcome beside this incident's evidence.
func renderGitHubSummary(w io.Writer, sections []evidence.Section, from, to time.Time) error {
	for _, section := range sections {
		if section.Provider != github.Name {
			continue
		}
		if _, err := fmt.Fprintln(w, "\nGitHub Actions"); err != nil {
			return err
		}
		for _, runner := range section.Runners {
			if _, err := fmt.Fprintf(w, "Runner        %s source=%s\nVersion       %s source=%s\n", providerText(runner.Name), providerSource(runner.Name.Source), providerText(runner.Version), providerSource(runner.Version.Source)); err != nil {
				return err
			}
		}
		for _, job := range jobsForSectionWindow(section, from, to) {
			if _, err := fmt.Fprintf(w, "Repository    %s source=%s\nWorkflow      %s source=%s\nJob           %s source=%s ref=%s\nRun           %s source=%s\nAttempt       %s source=%s\nJob outcome   %s source=%s\n", providerText(job.Repository), providerSource(job.Repository.Source), providerText(job.Workflow), providerSource(job.Workflow.Source), providerText(job.Name), providerSource(job.Name.Source), job.Ref, providerInt(job.RunID), providerSource(job.RunID.Source), providerInt(job.Attempt), providerSource(job.Attempt.Source), job.Outcome, providerSource(job.OutcomeSource)); err != nil {
				return err
			}
			if !job.StartedAt.IsZero() {
				if _, err := fmt.Fprintf(w, "Job started   %s (%s)\n", job.StartedAt.UTC().Format(time.RFC3339), job.StartedAtSource); err != nil {
					return err
				}
			}
			if !job.CompletedAt.IsZero() {
				if _, err := fmt.Fprintf(w, "Job completed %s (%s)\n", job.CompletedAt.UTC().Format(time.RFC3339), job.CompletedAtSource); err != nil {
					return err
				}
			}
			if !job.RunStartedAt.IsZero() {
				if _, err := fmt.Fprintf(w, "Run started   %s (%s)\n", job.RunStartedAt.UTC().Format(time.RFC3339), job.RunStartedAtSource); err != nil {
					return err
				}
			}
			if !job.RunCompletedAt.IsZero() {
				if _, err := fmt.Fprintf(w, "Run completed %s (%s)\n", job.RunCompletedAt.UTC().Format(time.RFC3339), job.RunCompletedAtSource); err != nil {
					return err
				}
			}
		}
		for _, conflict := range section.Conflicts {
			if _, err := fmt.Fprintf(w, "PROVIDER_STATE_CONFLICT topic=%s claims=%d\n", conflict.Question, len(conflict.Claims)); err != nil {
				return err
			}
		}
	}
	return nil
}

// jobsForWindow returns the job records that describe the reported capture,
// oldest first. the section keeps a running job history (it survives a runner
// restart and is reused by later captures), so rendering all of it would
// present a previous job's outcome as this incident's. a runner self-update
// captured on 2026-11-02 would have shown the previous day's FAILED job as its
// own. A record is shown when any of its observed times falls inside the
// window, or when it started before the window and never completed. A capture
// with no job of its own shows no job block; the history stays in the section
// for JSON consumers.
func jobsForWindow(jobs []evidence.Job, from, to time.Time) []evidence.Job {
	if from.IsZero() || to.IsZero() {
		return jobs
	}
	inside := make([]evidence.Job, 0, len(jobs))
	for _, job := range jobs {
		if jobInWindow(job, from, to) {
			inside = append(inside, job)
		}
	}
	sort.SliceStable(inside, func(i, j int) bool {
		return jobFirstSeen(inside[i]).Before(jobFirstSeen(inside[j]))
	})
	return inside
}

func jobInWindow(job evidence.Job, from, to time.Time) bool {
	for _, at := range []time.Time{job.StartedAt, job.CompletedAt, job.OutcomeObservedAt, job.RunStartedAt, job.RunCompletedAt} {
		if !at.IsZero() && !at.Before(from) && !at.After(to) {
			return true
		}
	}
	// A job that began before the capture and never reported a completion was
	// still the runner's job while the capture ran.
	return !job.StartedAt.IsZero() && job.StartedAt.Before(from) && job.CompletedAt.IsZero()
}

// jobsForSectionWindow is jobsForWindow with the section's own local
// evidence: a job known only from the runner log and the process table has
// none of the API timestamps, so its events and its worker's lifetime decide
// (principal review of L6: without this, every job of an unenriched capture
// vanished from the header, including the job the incident is about).
func jobsForSectionWindow(section evidence.Section, from, to time.Time) []evidence.Job {
	if from.IsZero() || to.IsZero() {
		return section.Jobs
	}
	local := map[evidence.Ref][]time.Time{}
	running := map[evidence.Ref]bool{}
	for _, ev := range section.Events {
		if ev.Job != "" && !ev.Timestamp.IsZero() {
			local[ev.Job] = append(local[ev.Job], ev.Timestamp)
		}
	}
	for _, w := range section.Workers {
		if w.Job == "" {
			continue
		}
		for _, at := range []time.Time{w.Started, w.Exited} {
			if !at.IsZero() {
				local[w.Job] = append(local[w.Job], at)
			}
		}
		// A worker that started before the window and had not exited by its
		// start was still running this job during the capture.
		if !w.Started.IsZero() && w.Started.Before(from) && (w.Exited.IsZero() || !w.Exited.Before(from)) {
			running[w.Job] = true
		}
	}
	inwindow := func(times []time.Time) bool {
		for _, at := range times {
			if !at.Before(from) && !at.After(to) {
				return true
			}
		}
		return false
	}
	first := func(job evidence.Job) time.Time {
		earliest := jobFirstSeen(job)
		for _, at := range local[job.Ref] {
			if earliest.IsZero() || at.Before(earliest) {
				earliest = at
			}
		}
		return earliest
	}
	inside := make([]evidence.Job, 0, len(section.Jobs))
	for _, job := range section.Jobs {
		if jobInWindow(job, from, to) || inwindow(local[job.Ref]) || running[job.Ref] {
			inside = append(inside, job)
		}
	}
	sort.SliceStable(inside, func(i, j int) bool { return first(inside[i]).Before(first(inside[j])) })
	return inside
}

// jobFirstSeen is the earliest timestamp the record carries; it orders the
// blocks without inventing a time the provider never stated.
func jobFirstSeen(job evidence.Job) time.Time {
	var first time.Time
	for _, at := range []time.Time{job.StartedAt, job.RunStartedAt, job.OutcomeObservedAt, job.CompletedAt, job.RunCompletedAt} {
		if at.IsZero() {
			continue
		}
		if first.IsZero() || at.Before(first) {
			first = at
		}
	}
	return first
}

// renderGitHubTimeline renders provider-specific events chronologically.
// times remain absolute UTC; no causal edge is implied.
func renderGitHubTimeline(w io.Writer, sections []evidence.Section) error {
	type entry struct {
		at      time.Time
		detail  string
		tieType string
	}
	var entries []entry
	for _, section := range sections {
		if section.Provider != github.Name {
			continue
		}
		for _, event := range section.Events {
			entries = append(entries, entry{at: event.Timestamp, detail: githubEventDescription(event), tieType: event.Type})
		}
		for _, job := range section.Jobs {
			if !job.StartedAt.IsZero() {
				entries = append(entries, entry{at: job.StartedAt, detail: fmt.Sprintf("GITHUB_JOB_STARTED job=%s source=%s", job.Ref, job.StartedAtSource), tieType: "GITHUB_JOB_STARTED"})
			}
			if !job.CompletedAt.IsZero() {
				entries = append(entries, entry{at: job.CompletedAt, detail: fmt.Sprintf("GITHUB_JOB_COMPLETED job=%s outcome=%s source=%s", job.Ref, job.Outcome, job.CompletedAtSource), tieType: "GITHUB_JOB_COMPLETED"})
			}
			if !job.RunStartedAt.IsZero() {
				entries = append(entries, entry{at: job.RunStartedAt, detail: fmt.Sprintf("GITHUB_RUN_STARTED source=%s", job.RunStartedAtSource), tieType: "GITHUB_RUN_STARTED"})
			}
			if !job.RunCompletedAt.IsZero() {
				entries = append(entries, entry{at: job.RunCompletedAt, detail: fmt.Sprintf("GITHUB_RUN_COMPLETED source=%s", job.RunCompletedAtSource), tieType: "GITHUB_RUN_COMPLETED"})
			}
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if !entries[i].at.Equal(entries[j].at) {
			return entries[i].at.Before(entries[j].at)
		}
		return entries[i].tieType < entries[j].tieType
	})
	if len(entries) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "GITHUB ACTIONS TIMELINE (UTC)"); err != nil {
		return err
	}
	for _, item := range entries {
		if _, err := fmt.Fprintf(w, "%s  %s\n", item.at.UTC().Format("15:04:05.000"), item.detail); err != nil {
			return err
		}
	}
	return nil
}

func providerSource(source evidence.Source) string {
	if source == "" {
		return "UNKNOWN"
	}
	return string(source)
}

func githubEventDescription(event evidence.Event) string {
	detail := event.Type + " source=" + string(event.Source)
	if event.Runner != "" {
		detail += " runner=" + string(event.Runner)
	}
	if event.Job != "" {
		detail += " job=" + string(event.Job)
	}
	if event.Worker != "" {
		detail += " worker=" + string(event.Worker)
	}
	if event.Process != nil {
		detail += fmt.Sprintf(" process=%d@%d", event.Process.PID, event.Process.StartTicks)
	}
	if event.Outcome != "" {
		detail += " outcome=" + string(event.Outcome)
	}
	if event.Provenance.File > 0 {
		detail += fmt.Sprintf(" provenance=file:%d@%d", event.Provenance.File, event.Provenance.Offset)
	} else if event.Provenance.Sample > 0 {
		detail += fmt.Sprintf(" provenance=sample:%d", event.Provenance.Sample)
	}
	return detail
}

type combinedTimelineEntry struct {
	at      time.Time
	detail  string
	tieType string
}

// renderCombinedTimeline merges core and provider events into one UTC stream.
// the label explicitly avoids implying causal edges across event families.
func renderCombinedTimeline(w io.Writer, timeline *causal.Timeline, sections []evidence.Section) error {
	entries := make([]combinedTimelineEntry, 0, len(timeline.Events))
	for _, event := range timeline.Events {
		entries = append(entries, combinedTimelineEntry{
			at:      event.Timestamp,
			detail:  fmt.Sprintf("%s subject=%s:%s", event.Type, event.Subject.Kind, event.Subject.ID),
			tieType: string(event.Type),
		})
	}
	for _, section := range sections {
		if section.Provider != github.Name {
			continue
		}
		for _, event := range section.Events {
			entries = append(entries, combinedTimelineEntry{at: event.Timestamp, detail: githubEventDescription(event), tieType: event.Type})
		}
		for _, job := range section.Jobs {
			if !job.StartedAt.IsZero() {
				entries = append(entries, combinedTimelineEntry{at: job.StartedAt, detail: fmt.Sprintf("GITHUB_JOB_STARTED job=%s source=%s", job.Ref, job.StartedAtSource), tieType: "GITHUB_JOB_STARTED"})
			}
			if !job.CompletedAt.IsZero() {
				entries = append(entries, combinedTimelineEntry{at: job.CompletedAt, detail: fmt.Sprintf("GITHUB_JOB_COMPLETED job=%s outcome=%s source=%s", job.Ref, job.Outcome, job.CompletedAtSource), tieType: "GITHUB_JOB_COMPLETED"})
			}
			if !job.RunStartedAt.IsZero() {
				entries = append(entries, combinedTimelineEntry{at: job.RunStartedAt, detail: fmt.Sprintf("GITHUB_RUN_STARTED source=%s", job.RunStartedAtSource), tieType: "GITHUB_RUN_STARTED"})
			}
			if !job.RunCompletedAt.IsZero() {
				entries = append(entries, combinedTimelineEntry{at: job.RunCompletedAt, detail: fmt.Sprintf("GITHUB_RUN_COMPLETED source=%s", job.RunCompletedAtSource), tieType: "GITHUB_RUN_COMPLETED"})
			}
		}
	}
	if len(entries) == 0 {
		return nil
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if !entries[i].at.Equal(entries[j].at) {
			return entries[i].at.Before(entries[j].at)
		}
		if entries[i].tieType != entries[j].tieType {
			return entries[i].tieType < entries[j].tieType
		}
		return entries[i].detail < entries[j].detail
	})
	if _, err := fmt.Fprintln(w, "TIMELINE (UTC; order only, no cross-provider causal edges)"); err != nil {
		return err
	}
	for _, item := range entries {
		if _, err := fmt.Fprintf(w, "%s  %s\n", item.at.UTC().Format("15:04:05.000"), item.detail); err != nil {
			return err
		}
	}
	return nil
}
