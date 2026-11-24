package github

import (
	"testing"
	"time"

	"deprehendo/internal/provider/evidence"
)

// principal B1 review (§10A.2 S1): one stall label per episode, chosen by the
// runner's phase when progress stopped. A communication drop during ASSIGNED
// or FINALIZING is supporting evidence for that phase's label. it must not
// suppress the label, and it must not be relabelled as the IDLE
// communication stall.

func allStallLabels(s evidence.Section, end time.Time) []string {
	var labels []string
	for _, f := range AssignmentStall(s, end) {
		labels = append(labels, f.Label)
	}
	for _, f := range FinalizationStall(s, end) {
		labels = append(labels, f.Label)
	}
	for _, f := range CommunicationStall(s, end) {
		labels = append(labels, f.Label)
	}
	return labels
}

func TestB1ReviewAssignedThenChannelDropIsAssignmentStall(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			sigEvent(0, EventJobAssigned),
			{Timestamp: sigT0.Add(5 * time.Second), Type: EventRunnerDisconnected, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(5 * time.Second), Type: EventCommunicationStalled, Runner: sigRunner, Source: evidence.SourceDerived},
		},
		nil, nil,
	)
	got := allStallLabels(s, sigT0.Add(2*time.Minute))
	if len(got) != 1 || got[0] != SignatureJobAssignmentStall {
		t.Fatalf("assigned runner whose channel dropped: labels %v, want exactly [%s]", got, SignatureJobAssignmentStall)
	}
}

func TestB1ReviewFinalizingThenChannelDropIsFinalizationStall(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			sigEvent(0, EventJobAssigned),
			sigEvent(time.Second, EventWorkerStarted),
			sigEvent(10*time.Second, EventJobCompleted),
			{Timestamp: sigT0.Add(15 * time.Second), Type: EventRunnerDisconnected, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(15 * time.Second), Type: EventCommunicationStalled, Runner: sigRunner, Source: evidence.SourceDerived},
		},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeSucceeded, OutcomeObservedAt: sigT0.Add(10 * time.Second)}},
	)
	got := allStallLabels(s, sigT0.Add(3*time.Minute))
	if len(got) != 1 || got[0] != SignatureJobFinalizationStall {
		t.Fatalf("finalizing worker whose channel dropped: labels %v, want exactly [%s]", got, SignatureJobFinalizationStall)
	}
}

// A normal reconnect while idle is still silent (S3), and a later assignment
// that is bound in time keeps the runner out of every stall label.
func TestB1ReviewIdleReconnectThenBoundJobIsSilent(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0, Type: EventRunnerDisconnected, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(3 * time.Second), Type: EventRunnerReconnected, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			sigEvent(30*time.Second, EventJobAssigned),
			sigEvent(31*time.Second, EventWorkerStarted),
		},
		[]evidence.Worker{{Ref: sigWorker, Runner: sigRunner, Job: sigJob, Started: sigT0.Add(31 * time.Second)}},
		[]evidence.Job{{Ref: sigJob, Runner: sigRunner, Outcome: evidence.OutcomeRunning}},
	)
	if got := allStallLabels(s, sigT0.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("healthy reconnect then bound job produced %v", got)
	}
}

// STOPPING outranks IDLE (§10A.1 row 2): a channel drop after a stated
// shutdown is the runner going away, not a communication stall.
func TestB1ReviewChannelDropDuringShutdownIsNotCommunicationStall(t *testing.T) {
	s := sigSection(
		[]evidence.Event{
			{Timestamp: sigT0, Type: EventShutdownStop, Runner: sigRunner, Source: evidence.SourceRunnerLog},
			{Timestamp: sigT0.Add(2 * time.Second), Type: EventCommunicationStalled, Runner: sigRunner, Source: evidence.SourceDerived},
		},
		nil, nil,
	)
	if got := allStallLabels(s, sigT0.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("shutdown channel drop produced %v", got)
	}
}
