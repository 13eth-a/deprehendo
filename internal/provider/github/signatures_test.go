package github

import (
	"testing"
	"time"

	"deprehendo/internal/provider/evidence"
)

var sigT0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const (
	sigRunner = evidence.Ref("runner-a")
	sigJob    = evidence.Ref("job-1")
	sigWorker = evidence.Ref("worker-1")
)

// sigSection builds an available section with one supervisor-backed runner.
func sigSection(events []evidence.Event, workers []evidence.Worker, jobs []evidence.Job) evidence.Section {
	return evidence.Section{
		Provider: "github-actions",
		Health:   evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref:         sigRunner,
			Supervisors: []evidence.ProcessRef{{PID: 5218, StartTicks: 10}},
		}},
		Workers: workers,
		Jobs:    jobs,
		Events:  events,
	}
}

func sigEvent(at time.Duration, typ string) evidence.Event {
	return evidence.Event{Timestamp: sigT0.Add(at), Type: typ, Runner: sigRunner, Job: sigJob}
}

// healthy negatives (S3): none of these may yield a stall label.

func TestSignaturesHealthyIdleIsSilent(t *testing.T) {
	s := sigSection(nil, nil, nil)
	if got := AssignmentStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("idle runner produced assignment stall: %+v", got)
	}
	if got := FinalizationStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("idle runner produced finalization stall: %+v", got)
	}
}

func TestSignaturesHealthyJobIsSilent(t *testing.T) {
	// assignment bound by a worker one second later; job still running.
	s := sigSection(
		[]evidence.Event{sigEvent(0, EventJobAssigned), sigEvent(time.Second, EventWorkerStarted)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeRunning}},
	)
	if got := AssignmentStall(s, sigT0.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("bound assignment produced stall: %+v", got)
	}
	if got := FinalizationStall(s, sigT0.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("running job produced finalization stall: %+v", got)
	}
}

func TestSignaturesEphemeralExitIsSilent(t *testing.T) {
	// job succeeded, worker exited, runner stopped: a normal lifecycle.
	s := sigSection(
		[]evidence.Event{
			sigEvent(0, EventJobAssigned),
			sigEvent(time.Second, EventWorkerStarted),
			sigEvent(6*time.Second, EventJobCompleted),
			sigEvent(6*time.Second, EventWorkerExited),
			sigEvent(8*time.Second, EventRunnerStopped),
		},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second), Exited: sigT0.Add(6 * time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeSucceeded, OutcomeObservedAt: sigT0.Add(6 * time.Second)}},
	)
	if got := AssignmentStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("ephemeral exit produced assignment stall: %+v", got)
	}
	if got := FinalizationStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("ephemeral exit produced finalization stall: %+v", got)
	}
}

// 5.21 communication stall (IDLE onset). healthy negatives first.

func TestCommunicationStallHealthyLongPollIsSilent(t *testing.T) {
	// A reconnect inside the window was never a stall: no stalled event.
	s := sigSection(nil, nil, nil)
	if got := CommunicationStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("healthy idle runner produced communication stall: %+v", got)
	}
}

func TestCommunicationStallDuringRunningJobIsNotIdleLabel(t *testing.T) {
	// channel drops while a worker is live: that is the RUNNING label's job.
	s := sigSection(
		[]evidence.Event{
			sigEvent(0, EventWorkerStarted),
			{Timestamp: sigT0.Add(20 * time.Second), Type: EventCommunicationStalled, Runner: sigRunner, Source: evidence.SourceDerived},
		},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0}},
		nil,
	)
	if got := CommunicationStall(s, sigT0.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("running-job stall took the IDLE label: %+v", got)
	}
}

func TestCommunicationStallAfterSupervisorExitIsSilent(t *testing.T) {
	// dead runner is a lifecycle fact, not a communication stall (audit R7).
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
			{Timestamp: sigT0.Add(20 * time.Second), Type: EventCommunicationStalled, Runner: sigRunner, Source: evidence.SourceDerived},
		},
		nil, nil,
	)
	if got := CommunicationStall(s, sigT0.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("stopped supervisor produced communication stall: %+v", got)
	}
}

func TestCommunicationStallIdleFires(t *testing.T) {
	s := sigSection(
		[]evidence.Event{{Timestamp: sigT0.Add(20 * time.Second), Type: EventCommunicationStalled, Runner: sigRunner, Source: evidence.SourceDerived}},
		nil, nil,
	)
	got := CommunicationStall(s, sigT0.Add(5*time.Minute))
	if len(got) != 1 {
		t.Fatalf("want one communication stall, got %+v", got)
	}
	if got[0].Label != SignatureRunnerCommunicationStall || got[0].Confidence != evidence.ConfidenceMedium {
		t.Fatalf("label/confidence = %s/%s", got[0].Label, got[0].Confidence)
	}
}

// positive and boundary cases (§10A.2).

func TestAssignmentStallFiresWhenNoWorkerBinds(t *testing.T) {
	s := sigSection([]evidence.Event{sigEvent(0, EventJobAssigned)}, nil, nil)
	got := AssignmentStall(s, sigT0.Add(31*time.Second))
	if len(got) != 1 {
		t.Fatalf("want one assignment stall, got %+v", got)
	}
	f := got[0]
	if f.Label != SignatureJobAssignmentStall || f.Confidence != evidence.ConfidenceMedium {
		t.Fatalf("label/confidence = %s/%s, want assignment stall at MEDIUM", f.Label, f.Confidence)
	}
	if f.Runner != sigRunner || f.Job != sigJob || !f.Onset.Equal(sigT0) {
		t.Fatalf("refs/onset wrong: %+v", f)
	}
}

func TestAssignmentStallBoundaryAt29And31Seconds(t *testing.T) {
	// worker at +29 s binds the assignment: no stall.
	bound := sigSection(
		[]evidence.Event{sigEvent(0, EventJobAssigned), sigEvent(29*time.Second, EventWorkerStarted)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(29 * time.Second)}},
		nil,
	)
	if got := AssignmentStall(bound, sigT0.Add(31*time.Second)); len(got) != 0 {
		t.Fatalf("worker at +29s bound the assignment, but stall fired: %+v", got)
	}
	// worker at +31 s is too late to bind: the stall must still fire.
	late := sigSection(
		[]evidence.Event{sigEvent(0, EventJobAssigned), sigEvent(31*time.Second, EventWorkerStarted)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(31 * time.Second)}},
		nil,
	)
	if got := AssignmentStall(late, sigT0.Add(31*time.Second)); len(got) != 1 {
		t.Fatalf("worker at +31s must not hide the stall, got %+v", got)
	}
}

func TestAssignmentStallNotFiredBeforeThreshold(t *testing.T) {
	s := sigSection([]evidence.Event{sigEvent(0, EventJobAssigned)}, nil, nil)
	if got := AssignmentStall(s, sigT0.Add(29*time.Second)); len(got) != 0 {
		t.Fatalf("fired before 30s: %+v", got)
	}
}

func TestAssignmentStallSuppressedByCancellation(t *testing.T) {
	s := sigSection(
		[]evidence.Event{sigEvent(0, EventJobAssigned), sigEvent(5*time.Second, EventJobCancellation)},
		nil, nil,
	)
	if got := AssignmentStall(s, sigT0.Add(31*time.Second)); len(got) != 0 {
		t.Fatalf("stated cancellation must cover the assignment: %+v", got)
	}
}

func TestFinalizationStallFiresWhenWorkerLivesOnAfterResult(t *testing.T) {
	s := sigSection(
		[]evidence.Event{sigEvent(0, EventJobAssigned), sigEvent(time.Second, EventWorkerStarted), sigEvent(4*time.Second, EventJobCompleted)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeSucceeded, OutcomeObservedAt: sigT0.Add(4 * time.Second)}},
	)
	if got := FinalizationStall(s, sigT0.Add(65*time.Second)); len(got) != 1 {
		t.Fatalf("want one finalization stall, got %+v", got)
	} else if got[0].Label != SignatureJobFinalizationStall || got[0].Confidence != evidence.ConfidenceMedium {
		t.Fatalf("wrong label/confidence: %+v", got[0])
	}
	// 59 s after the result is below the 60 s threshold.
	if got := FinalizationStall(s, sigT0.Add(63*time.Second)); len(got) != 0 {
		t.Fatalf("fired before 60s after the result: %+v", got)
	}
}

func TestFinalizationStallNotFiredWhenWorkerExited(t *testing.T) {
	s := sigSection(
		[]evidence.Event{sigEvent(4*time.Second, EventJobCompleted), sigEvent(5*time.Second, EventWorkerExited)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second), Exited: sigT0.Add(5 * time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeSucceeded, OutcomeObservedAt: sigT0.Add(4 * time.Second)}},
	)
	if got := FinalizationStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("exited worker produced finalization stall: %+v", got)
	}
}

func TestFinalizationStallFiresWhenTreeEmptiedAndWorkerLivesOn(t *testing.T) {
	s := sigSection(
		[]evidence.Event{sigEvent(0, EventJobAssigned), sigEvent(2*time.Second, EventJobTreeEmptied)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second)}},
		nil,
	)
	if got := FinalizationStall(s, sigT0.Add(65*time.Second)); len(got) != 1 {
		t.Fatalf("want one tree-empty finalization stall, got %+v", got)
	} else if got[0].Label != SignatureJobFinalizationStall || !got[0].Onset.Equal(sigT0.Add(2*time.Second)) {
		t.Fatalf("wrong label/onset: %+v", got[0])
	}
	// 59 s after the tree emptied is below the 60 s threshold.
	if got := FinalizationStall(s, sigT0.Add(61*time.Second)); len(got) != 0 {
		t.Fatalf("fired before 60s after tree-empty: %+v", got)
	}
}

func TestFinalizationStallTreeEmptiedCoveredByStatedOutcome(t *testing.T) {
	s := sigSection(
		[]evidence.Event{sigEvent(2*time.Second, EventJobTreeEmptied), sigEvent(3*time.Second, EventJobCompleted)},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeSucceeded, OutcomeObservedAt: sigT0.Add(3 * time.Second)}},
	)
	for _, f := range FinalizationStall(s, sigT0.Add(10*time.Minute)) {
		if f.Onset.Equal(sigT0.Add(2 * time.Second)) {
			t.Fatalf("tree-empty onset labelled alongside a stated result: %+v", f)
		}
	}
}

// 5.23 self-termination. healthy negatives first.

func TestSelfTerminationCoveredByShutdownIsSilent(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventShutdownStop, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(11 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
		},
		nil, nil,
	)
	if got := SelfTermination(s); len(got) != 0 {
		t.Fatalf("shutdown-covered exit produced self-termination: %+v", got)
	}
}

func TestSelfTerminationAfterEphemeralCompleteIsSilent(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerEphemeralComplete, Runner: sigRunner, Source: evidence.SourceDerived},
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
		},
		nil, nil,
	)
	if got := SelfTermination(s); len(got) != 0 {
		t.Fatalf("ephemeral completion produced self-termination: %+v", got)
	}
}

func TestSelfTerminationUpdateWithinWindowIsSilent(t *testing.T) {
	// A self-update intent 0.5 s before the exit is inside the 1 s lead window.
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(9500 * time.Millisecond), Type: EventRunnerUpdate, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
		},
		nil, nil,
	)
	if got := SelfTermination(s); len(got) != 0 {
		t.Fatalf("covered update produced self-termination: %+v", got)
	}
}

// shutdown logged 1.5 s before the listener exit (the S6 real-runner lag) is
// covered: the log record may trail the signal by up to the 1 s lead window.
func TestSelfTerminationShutdownLogLagIsSilent(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(8500 * time.Millisecond), Type: EventShutdownStop, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
		},
		nil, nil,
	)
	if got := SelfTermination(s); len(got) != 0 {
		t.Fatalf("shutdown logged just before the exit produced self-termination: %+v", got)
	}
}

// A shutdown record 20 s before the exit is inside the 60 s grace window.
func TestSelfTerminationShutdownInGraceIsSilent(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(-10 * time.Second), Type: EventShutdownStop, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
		},
		nil, nil,
	)
	if got := SelfTermination(s); len(got) != 0 {
		t.Fatalf("shutdown inside the grace window produced self-termination: %+v", got)
	}
}

func TestSelfTerminationUncoveredExitFires(t *testing.T) {
	s := sigSection(
		[]evidence.Event{{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess}},
		nil, nil,
	)
	got := SelfTermination(s)
	if len(got) != 1 || got[0].Label != SignatureRunnerSelfTermination || got[0].Confidence != evidence.ConfidenceMedium {
		t.Fatalf("uncovered exit: %+v", got)
	}
}

func TestSelfTerminationIntentOutsideWindowDoesNotCover(t *testing.T) {
	// shutdown recorded 90 s after the exit is outside the 60 s grace window.
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0.Add(10 * time.Second), Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
			{Timestamp: sigT0.Add(100 * time.Second), Type: EventShutdownStop, Runner: sigRunner, Source: evidence.SourceRunnerLog},
		},
		nil, nil,
	)
	if got := SelfTermination(s); len(got) != 1 {
		t.Fatalf("late intent covered the exit: %+v", got)
	}
}

// 5.24 orphaned job process.

func TestOrphanedJobFires(t *testing.T) {
	s := sigSection(
		[]evidence.Event{{Timestamp: sigT0.Add(15 * time.Second), Type: EventJobOrphaned, Runner: sigRunner, Worker: sigWorker, Job: sigJob, Source: evidence.SourceLocalProcess}},
		nil, nil,
	)
	got := OrphanedJob(s)
	if len(got) != 1 || got[0].Label != SignatureOrphanedJobProcess || got[0].Confidence != evidence.ConfidenceHigh {
		t.Fatalf("orphan job: %+v", got)
	}
}

func TestOrphanedJobHealthyCleanExitIsSilent(t *testing.T) {
	// worker exited and its tree left with it: no orphan event.
	s := sigSection(
		[]evidence.Event{{Timestamp: sigT0.Add(6 * time.Second), Type: EventWorkerExited, Runner: sigRunner, Worker: sigWorker, Source: evidence.SourceLocalProcess}},
		nil, nil,
	)
	if got := OrphanedJob(s); len(got) != 0 {
		t.Fatalf("clean exit produced orphan: %+v", got)
	}
}

func TestSignaturesDegradedSectionIsNotJudged(t *testing.T) {
	s := sigSection([]evidence.Event{sigEvent(0, EventJobAssigned)}, nil, nil)
	s.Health = evidence.Health{State: evidence.HealthDegraded}
	if got := AssignmentStall(s, sigT0.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("degraded section was judged: %+v", got)
	}
}
