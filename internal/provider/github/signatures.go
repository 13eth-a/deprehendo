package github

// offline GitHub provider signatures (phase 5 items 5.20 and 5.22; binding
// rules in docs/providers/architecture.md §10A). each signature is a pure
// function over the stored evidence section and the observation window end,
// so a bundle can be analyzed without the live runner or the network.
//
// every signature here is log-derived (RUNNER_LOG), so per §10A.2 (S2) it is
// capped at MEDIUM. signatures never copy log text, command lines or
// repository strings into their output; they carry only refs, times and
// registered evidence codes.

import (
	"time"

	"runopsy/internal/provider/evidence"
)

// signature labels (§10A.2).
const (
	SignatureJobAssignmentStall       = "GITHUB_JOB_ASSIGNMENT_STALL"
	SignatureJobFinalizationStall     = "GITHUB_JOB_FINALIZATION_STALL"
	SignatureRunnerCommunicationStall = "GITHUB_RUNNER_COMMUNICATION_STALL"
	SignatureRunnerSelfTermination    = "GITHUB_RUNNER_SELF_TERMINATION"
	SignatureOrphanedJobProcess       = "GITHUB_ORPHANED_JOB_PROCESS"
)

// intent windows (T2): a supervisor exit counts as intended only when a stated
// intent for its runner lands within [exit-60s, exit+1s]: the exit may follow
// the intent record by the shutdown grace, and may precede it by the log lag.
const (
	intentLeadWindow  = time.Second
	intentGraceWindow = 60 * time.Second
)

// selfTerminationIntents are the stated intents that can cover a supervisor
// exit (T1). CANCELLED and TIMED_OUT cover workers and job trees, not the
// supervisor, so they are not listed here.
var selfTerminationIntents = map[string]bool{
	EventShutdownStop:            true,
	EventRunnerUpdate:            true,
	EventRunnerEphemeralComplete: true,
}

// thresholds (§10A.2): assignment unbound for at least 30 s; worker alive at
// least 60 s after its job stated a result.
const (
	assignmentStallThreshold   = 30 * time.Second
	finalizationStallThreshold = 60 * time.Second
)

// finding is one provider signature instance. it holds refs and registered
// evidence codes only.
type Finding struct {
	Label      string
	Confidence evidence.Confidence
	Runner     evidence.Ref
	Job        evidence.Ref
	Onset      time.Time
	Evidence   []string
}

// intentEvents end a job or runner's normal lifecycle; once one is observed
// for a runner, a stall or unbound assignment is not an unexplained stall.
// GITHUB_RUNNER_DISCONNECTED is deliberately absent: a dropped connection
// during ASSIGNED or FINALIZING is supporting evidence for that phase's label
// (§10A.2 S1), not a reason to stay silent (principal B1 review).
var intentEvents = map[string]bool{
	EventJobCancellation:         true,
	EventJobTimeout:              true,
	EventJobCompleted:            true,
	EventRunnerStopped:           true,
	EventShutdownStop:            true,
	EventRunnerUpdate:            true,
	EventRunnerEphemeralComplete: true,
}

// finalizationIntentEvents is intentEvents without GITHUB_JOB_COMPLETED. the
// job's own stated result is the phase boundary, so it cannot also cover the
// stall that starts at that boundary.
var finalizationIntentEvents = func() map[string]bool {
	m := make(map[string]bool, len(intentEvents))
	for k, v := range intentEvents {
		if k != EventJobCompleted {
			m[k] = v
		}
	}
	return m
}()

// AssignmentStall reports GITHUB_JOB_ASSIGNMENT_STALL (5.20): a job was
// assigned to a runner whose supervisor stayed alive, no worker was bound to
// the assignment through windowEnd, and no intent or disconnect was recorded
// for the runner since the assignment. A degraded or unavailable section is
// never judged, because missing records would look like absence.
func AssignmentStall(section evidence.Section, windowEnd time.Time) []Finding {
	if section.Health.State != evidence.HealthAvailable {
		return nil
	}
	var out []Finding
	for _, runner := range section.Runners {
		if len(runner.Supervisors) == 0 {
			continue
		}
		assigned, ok := latestEvent(section.Events, runner.Ref, EventJobAssigned, time.Time{})
		if !ok || windowEnd.Sub(assigned.Timestamp) < assignmentStallThreshold {
			continue
		}
		if workerBound(section, runner.Ref, assigned.Timestamp, assignmentStallThreshold) {
			continue
		}
		if _, ended := afterWith(section.Events, runner.Ref, assigned.Timestamp, intentEvents); ended {
			continue
		}
		out = append(out, Finding{
			Label:      SignatureJobAssignmentStall,
			Confidence: evidence.ConfidenceMedium,
			Runner:     runner.Ref,
			Job:        assigned.Job,
			Onset:      assigned.Timestamp,
			Evidence:   []string{EvidenceLogDerived},
		})
	}
	return out
}

// FinalizationStall reports GITHUB_JOB_FINALIZATION_STALL (5.22): a job stated
// its result, its worker is still alive at least 60 s later with no recorded
// exit, and no intent or disconnect covers the runner. the job's own result
// is the phase boundary, so this never overlaps the assignment label.
func FinalizationStall(section evidence.Section, windowEnd time.Time) []Finding {
	if section.Health.State != evidence.HealthAvailable {
		return nil
	}
	var out []Finding
	out = append(out, treeEmptiedFindings(section, windowEnd)...)
	for _, job := range section.Jobs {
		if job.Outcome != evidence.OutcomeSucceeded && job.Outcome != evidence.OutcomeFailed {
			continue
		}
		if job.OutcomeObservedAt.IsZero() || windowEnd.Sub(job.OutcomeObservedAt) < finalizationStallThreshold {
			continue
		}
		worker, ok := workerFor(section, job.Ref)
		if !ok || !worker.Exited.IsZero() {
			continue
		}
		if workerExitedAfter(section.Events, worker.Runner, job.OutcomeObservedAt) {
			continue
		}
		if _, ended := afterWith(section.Events, job.Runner, job.OutcomeObservedAt, finalizationIntentEvents); ended {
			continue
		}
		out = append(out, Finding{
			Label:      SignatureJobFinalizationStall,
			Confidence: evidence.ConfidenceMedium,
			Runner:     job.Runner,
			Job:        job.Ref,
			Onset:      job.OutcomeObservedAt,
			Evidence:   []string{EvidenceLogDerived},
		})
	}
	return out
}

// treeEmptiedFindings is the 5.22 onset for a job whose process tree emptied
// while its worker stayed alive: the same 60 s, no-exit and no-intent checks
// apply, measured from the tree-empty event. A job with a stated result is
// handled by its outcome onset instead, so each episode gets one label.
func treeEmptiedFindings(section evidence.Section, windowEnd time.Time) []Finding {
	var out []Finding
	for _, ev := range section.Events {
		if ev.Type != EventJobTreeEmptied {
			continue
		}
		if windowEnd.Sub(ev.Timestamp) < finalizationStallThreshold {
			continue
		}
		if hasStatedOutcome(section, ev.Job) {
			continue
		}
		worker, ok := workerFor(section, ev.Job)
		if !ok || !worker.Exited.IsZero() || workerExitedAfter(section.Events, worker.Runner, ev.Timestamp) {
			continue
		}
		if _, ended := afterWith(section.Events, ev.Runner, ev.Timestamp, finalizationIntentEvents); ended {
			continue
		}
		out = append(out, Finding{
			Label:      SignatureJobFinalizationStall,
			Confidence: evidence.ConfidenceMedium,
			Runner:     ev.Runner,
			Job:        ev.Job,
			Onset:      ev.Timestamp,
			Evidence:   []string{EvidenceLogDerived},
		})
	}
	return out
}

// hasStatedOutcome reports whether the job for ref has a stated result.
func hasStatedOutcome(section evidence.Section, ref evidence.Ref) bool {
	for _, job := range section.Jobs {
		if job.Ref == ref && (job.Outcome == evidence.OutcomeSucceeded || job.Outcome == evidence.OutcomeFailed) {
			return true
		}
	}
	return false
}

// latestEvent returns the newest event of typ for runner, not older than since.
func latestEvent(events []evidence.Event, runner evidence.Ref, typ string, since time.Time) (evidence.Event, bool) {
	var best evidence.Event
	found := false
	for _, e := range events {
		if e.Type != typ || e.Runner != runner || e.Timestamp.Before(since) {
			continue
		}
		if !found || e.Timestamp.After(best.Timestamp) {
			best, found = e, true
		}
	}
	return best, found
}

// afterWith reports the first event of any type in set for runner observed at
// or after t.
func afterWith(events []evidence.Event, runner evidence.Ref, t time.Time, set map[string]bool) (evidence.Event, bool) {
	for _, e := range events {
		if set[e.Type] && e.Runner == runner && !e.Timestamp.Before(t) {
			return e, true
		}
	}
	return evidence.Event{}, false
}

// workerBound reports whether a worker started for runner within the stall
// threshold after the assignment. A worker that starts later does not bind
// the assignment in time, so the stall must still be reported (§10A.2).
func workerBound(section evidence.Section, runner evidence.Ref, assigned time.Time, within time.Duration) bool {
	deadline := assigned.Add(within)
	for _, w := range section.Workers {
		if w.Runner == runner && !w.Started.IsZero() && !w.Started.Before(assigned) && w.Started.Before(deadline) {
			return true
		}
	}
	for _, e := range section.Events {
		if e.Type == EventWorkerStarted && e.Runner == runner && !e.Timestamp.Before(assigned) && e.Timestamp.Before(deadline) {
			return true
		}
	}
	return false
}

// workerFor returns the worker bound to job, if the section recorded one.
func workerFor(section evidence.Section, job evidence.Ref) (evidence.Worker, bool) {
	for _, w := range section.Workers {
		if w.Job == job {
			return w, true
		}
	}
	return evidence.Worker{}, false
}

// workerExitedAfter reports whether a WORKER_EXITED event for runner happened
// at or after t.
func workerExitedAfter(events []evidence.Event, runner evidence.Ref, t time.Time) bool {
	_, ok := afterWith(events, runner, t, map[string]bool{EventWorkerExited: true})
	return ok
}

// SelfTermination reports GITHUB_RUNNER_SELF_TERMINATION (5.23): a runner
// supervisor exited (LOCAL_PROCESS) and no stated intent covers the exit. the
// label means "runner terminated without a stated reason": process evidence
// cannot tell a self-exit from an external kill. Log-derived intent is required
// before the exit is treated as intended, so a missing log record never
// produces a silent pass; the label is still MEDIUM (S2) because the exit
// is not known to fall inside one sample interval.
func SelfTermination(section evidence.Section) []Finding {
	if section.Health.State != evidence.HealthAvailable {
		return nil
	}
	var out []Finding
	for _, ev := range section.Events {
		if ev.Type != EventRunnerStopped || ev.Runner == "" {
			continue
		}
		if intentCovers(section.Events, ev.Runner, ev.Timestamp, selfTerminationIntents) {
			continue
		}
		out = append(out, Finding{
			Label:      SignatureRunnerSelfTermination,
			Confidence: evidence.ConfidenceMedium,
			Runner:     ev.Runner,
			Onset:      ev.Timestamp,
			Evidence:   []string{EvidenceSupervisorExitObserved},
		})
	}
	return out
}

// intentCovers reports whether a stated intent for runner covers the exit at
// exitAt (T2): the exit may precede the intent record by at most
// intentLeadWindow (a log may lag the signal) and may follow it by at most
// intentGraceWindow.
func intentCovers(events []evidence.Event, runner evidence.Ref, exitAt time.Time, set map[string]bool) bool {
	for _, e := range events {
		if !set[e.Type] || e.Runner != runner {
			continue
		}
		if e.Timestamp.Before(exitAt.Add(-intentGraceWindow)) || e.Timestamp.After(exitAt.Add(intentLeadWindow)) {
			continue
		}
		return true
	}
	return false
}

// OrphanedJob reports GITHUB_ORPHANED_JOB_PROCESS (5.24): a job-tree member
// outlived its worker's observed exit by at least orphanGrace. A job
// cancellation explains the worker's exit, not a survivor, so intent is not
// checked here (§10A.4). both facts are LOCAL_PROCESS observations, so HIGH.
// the report names the survivor by ref only.
func OrphanedJob(section evidence.Section) []Finding {
	if section.Health.State != evidence.HealthAvailable {
		return nil
	}
	var out []Finding
	for _, ev := range section.Events {
		if ev.Type != EventJobOrphaned {
			continue
		}
		out = append(out, Finding{
			Label:      SignatureOrphanedJobProcess,
			Confidence: evidence.ConfidenceHigh,
			Runner:     ev.Runner,
			Job:        ev.Job,
			Onset:      ev.Timestamp,
			Evidence:   []string{EvidenceDescendantAtFirstSeen, EvidenceStickyAfterExit},
		})
	}
	return out
}

// CommunicationStall reports GITHUB_RUNNER_COMMUNICATION_STALL (5.21). it is
// the IDLE-onset label of §10A.2: a GITHUB_COMMUNICATION_STALLED episode whose
// onset finds the runner idle (no live worker, supervisor alive). A stall
// during RUNNING or FINALIZING is supporting evidence for that phase's label,
// never this one (S1). derived from the control channel, so MEDIUM (S2).
func CommunicationStall(section evidence.Section, windowEnd time.Time) []Finding {
	if section.Health.State != evidence.HealthAvailable {
		return nil
	}
	var out []Finding
	for _, ev := range section.Events {
		if ev.Type != EventCommunicationStalled || ev.Runner == "" {
			continue
		}
		if !supervisorAliveAt(section, ev.Runner, ev.Timestamp, windowEnd) {
			continue
		}
		if workerLiveAt(section, ev.Runner, ev.Timestamp) {
			continue
		}
		// the phase table (§10A.1) ranks STOPPING and ASSIGNED above IDLE.
		// A stated shutdown, update or ephemeral completion means the drop is
		// the runner going away; an assignment still waiting for its worker
		// means the episode belongs to the assignment label.
		if stoppingAt(section.Events, ev.Runner, ev.Timestamp) {
			continue
		}
		if assignmentPendingAt(section, ev.Runner, ev.Timestamp) {
			continue
		}
		out = append(out, Finding{
			Label:      SignatureRunnerCommunicationStall,
			Confidence: evidence.ConfidenceMedium,
			Runner:     ev.Runner,
			Onset:      ev.Timestamp,
			Evidence:   []string{EvidenceLogDerived},
		})
	}
	return out
}

// supervisorAliveAt reports whether no RUNNER_STOPPED for runner was recorded
// at or before t, so the supervisor was alive when the channel dropped.
func supervisorAliveAt(section evidence.Section, runner evidence.Ref, t, windowEnd time.Time) bool {
	if windowEnd.Before(t) {
		return false
	}
	for _, e := range section.Events {
		if e.Type == EventRunnerStopped && e.Runner == runner && !e.Timestamp.After(t) {
			return false
		}
	}
	return true
}

// stoppingAt reports whether the runner was in the STOPPING phase at t: a
// stated shutdown, update or ephemeral completion lies in [t-grace, t+lead].
// the window looks back because the intent precedes the stop it announces.
func stoppingAt(events []evidence.Event, runner evidence.Ref, t time.Time) bool {
	for _, e := range events {
		if !selfTerminationIntents[e.Type] || e.Runner != runner {
			continue
		}
		if e.Timestamp.Before(t.Add(-intentGraceWindow)) || e.Timestamp.After(t.Add(intentLeadWindow)) {
			continue
		}
		return true
	}
	return false
}

// assignmentPendingAt reports whether the runner was in the ASSIGNED phase at
// t: its newest assignment at or before t has no worker started since and no
// lifecycle-ending event recorded between the assignment and t.
func assignmentPendingAt(section evidence.Section, runner evidence.Ref, t time.Time) bool {
	assigned, ok := latestEventAtOrBefore(section.Events, runner, EventJobAssigned, t)
	if !ok {
		return false
	}
	for _, w := range section.Workers {
		if w.Runner == runner && !w.Started.IsZero() && !w.Started.Before(assigned.Timestamp) && !w.Started.After(t) {
			return false
		}
	}
	for _, e := range section.Events {
		if e.Runner != runner || e.Timestamp.Before(assigned.Timestamp) || e.Timestamp.After(t) {
			continue
		}
		if e.Type == EventWorkerStarted || intentEvents[e.Type] {
			return false
		}
	}
	return true
}

// latestEventAtOrBefore returns the newest event of typ for runner at or
// before t.
func latestEventAtOrBefore(events []evidence.Event, runner evidence.Ref, typ string, t time.Time) (evidence.Event, bool) {
	var best evidence.Event
	found := false
	for _, e := range events {
		if e.Type != typ || e.Runner != runner || e.Timestamp.After(t) {
			continue
		}
		if !found || e.Timestamp.After(best.Timestamp) {
			best, found = e, true
		}
	}
	return best, found
}

// workerLiveAt reports whether a worker of runner was started at or before t
// and had not exited before t. an unobserved worker start is not live.
func workerLiveAt(section evidence.Section, runner evidence.Ref, t time.Time) bool {
	for _, w := range section.Workers {
		if w.Runner != runner || w.Started.IsZero() || w.Started.After(t) {
			continue
		}
		if w.Exited.IsZero() || w.Exited.After(t) {
			return true
		}
	}
	return false
}
