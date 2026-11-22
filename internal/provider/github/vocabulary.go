// package github implements the github-actions CI provider (phase 5,
// docs/providers/architecture.md §11 items 3–6). its live half classifies
// GitHub actions runner processes, tails the runner's diagnostic logs, and
// binds workers, job trees and the control channel to typed evidence while
// the bundle can still hold it. its offline half (interpret) translates the
// stored section into the neutral vocabulary for the causal engine.
package github

import "runopsy/internal/provider/evidence"

// name of the provider in registries and bundle sections.
const Name = "github-actions"

// EventPrefix guards every stored event token, so no parser or log line can
// introduce a bare word into the vocabulary.
const EventPrefix = "GITHUB_"

// event types (5.8). the set is closed; interpret maps each type to the
// neutral GenericKind where one exists.
const (
	EventRunnerStarted        = "GITHUB_RUNNER_STARTED"
	EventRunnerStopped        = "GITHUB_RUNNER_STOPPED"
	EventRunnerDisconnected   = "GITHUB_RUNNER_DISCONNECTED"
	EventRunnerReconnected    = "GITHUB_RUNNER_RECONNECTED"
	EventRunnerUpdate         = "GITHUB_RUNNER_UPDATE"
	EventShutdownStop         = "GITHUB_RUNNER_SHUTDOWN"
	EventJobAssigned          = "GITHUB_JOB_ASSIGNED"
	EventJobAccepted          = "GITHUB_JOB_ACCEPTED"
	EventWorkerStarted        = "GITHUB_WORKER_STARTED"
	EventWorkerExited         = "GITHUB_WORKER_EXITED"
	EventJobCompleted         = "GITHUB_JOB_COMPLETED"
	EventJobCancellation      = "GITHUB_JOB_CANCELLATION_OBSERVED"
	EventJobTimeout           = "GITHUB_JOB_TIMEOUT_OBSERVED"
	EventJobProgressStopped   = "GITHUB_JOB_PROGRESS_STOPPED"
	EventCommunicationStalled = "GITHUB_COMMUNICATION_STALLED"
	// EventRunnerEphemeralComplete: the runner stopped with its configured
	// lifecycle EPHEMERAL and a job completed first, an intended stop
	// (5.44), distinct from an unexplained runner death.
	EventRunnerEphemeralComplete = "GITHUB_RUNNER_EPHEMERAL_COMPLETE"
)

// EventJobTreeEmptied is derived from process samples: the last live member of
// a worker's job tree disappeared while the worker itself stayed alive. it is
// the onset that opens a finalization stall (5.22) when no result was stated.
const EventJobTreeEmptied = "GITHUB_JOB_TREE_EMPTIED"

// EventJobOrphaned (5.24): a sticky job-tree member outlived its worker's
// observed exit by at least orphanGrace. named by refs only.
const EventJobOrphaned = "GITHUB_JOB_ORPHANED"

var eventTypes = []string{
	EventRunnerStarted, EventRunnerStopped, EventRunnerDisconnected,
	EventRunnerReconnected, EventRunnerUpdate, EventShutdownStop,
	EventJobAssigned, EventJobAccepted, EventWorkerStarted, EventWorkerExited,
	EventJobCompleted, EventJobCancellation, EventJobTimeout,
	EventJobProgressStopped, EventCommunicationStalled,
	EventRunnerEphemeralComplete, EventJobTreeEmptied, EventJobOrphaned,
}

// socket roles (5.15). CONTROL_CHANNEL is the runner's long-poll connection
// to GitHub; only evidence-checked sockets receive it. CONTROL_CHANNEL_
// CANDIDATE is a supporting-evidence-only classification.
const (
	SocketRoleControlChannel          = "CONTROL_CHANNEL"
	SocketRoleControlChannelCandidate = "CONTROL_CHANNEL_CANDIDATE"
)

var socketRoles = []string{SocketRoleControlChannel, SocketRoleControlChannelCandidate}

// evidence codes name the facts a correlation relied on. registered tokens
// only; validate rejects anything else.
const (
	EvidenceExeBaseNameMatch      = "EXE_BASENAME_MATCH"
	EvidenceInstallLayoutMatch    = "INSTALL_LAYOUT_MATCH"
	EvidenceParentIsSupervisor    = "PARENT_IS_SUPERVISOR"
	EvidenceParentGone            = "PARENT_GONE_REPARENTED"
	EvidenceUserOverride          = "USER_OVERRIDE"
	EvidenceOnlyControlCandidate  = "ONLY_CONTROL_CANDIDATE"
	EvidenceLogTimingMatch        = "LOG_TIMING_MATCH"
	EvidenceConnectionLongLived   = "CONNECTION_LONG_LIVED"
	EvidenceReestablishedQuickly  = "REESTABLISHED_QUICKLY"
	EvidenceDescendantAtFirstSeen = "DESCENDANT_AT_FIRST_SEEN"
	EvidenceStickyAfterExit       = "STICKY_AFTER_WORKER_EXIT"
	EvidenceRunnerRefConflict     = "RUNNER_INSTANCE_CONFLICT_UNTAGGED"
	EvidenceJobBindingAmbiguous   = "JOB_BINDING_WINDOW_AMBIGUOUS"
	EvidenceLayoutUnknown         = "INSTALL_LAYOUT_UNVERIFIABLE"
	EvidenceLogDerived            = "RUNNER_LOG_RECORD"
	EvidenceEphemeralConfigured   = "EPHEMERAL_CONFIGURED"
	// EvidenceSupervisorExitObserved: the supervisor incarnation's exit was
	// observed locally (LOCAL_PROCESS), the fact 5.23 rests on (audit F5).
	EvidenceSupervisorExitObserved = "SUPERVISOR_EXIT_OBSERVED"
	// C5/5.33 container membership: a container-step process is tagged
	// through cgroup linkage when a docker client ran inside the
	// worker's job tree and created the container cgroup. UNAVAILABLE is
	// the honest marker that the job's process list may be incomplete
	// because container membership could not be verified.
	EvidenceContainerCgroupLinkage      = "CONTAINER_CGROUP_LINKAGE"
	EvidenceContainerLinkageUnavailable = "CONTAINER_LINKAGE_UNAVAILABLE"
)

var evidenceCodes = []string{
	EvidenceExeBaseNameMatch, EvidenceInstallLayoutMatch, EvidenceParentIsSupervisor,
	EvidenceParentGone, EvidenceUserOverride, EvidenceOnlyControlCandidate,
	EvidenceLogTimingMatch, EvidenceConnectionLongLived, EvidenceReestablishedQuickly,
	EvidenceDescendantAtFirstSeen, EvidenceStickyAfterExit, EvidenceRunnerRefConflict,
	EvidenceJobBindingAmbiguous, EvidenceLayoutUnknown, EvidenceLogDerived,
	EvidenceEphemeralConfigured, EvidenceSupervisorExitObserved,
	EvidenceContainerCgroupLinkage, EvidenceContainerLinkageUnavailable,
}

// conflict topics (5.48) and the claim values valid within them.
const (
	ConflictTopicJobState    = "JOB_STATE"
	ConflictTopicJobBinding  = "JOB_BINDING"
	ConflictTopicRunnerBind  = "RUNNER_BINDING"
	ConflictTopicTermination = "TERMINATION_INTENT"
)

var conflictTopics = []string{ConflictTopicJobState, ConflictTopicJobBinding, ConflictTopicRunnerBind, ConflictTopicTermination}

var claimValues = []string{
	"QUEUED", "ASSIGNED", "RUNNING", "COMPLETED", "CANCELLED", "TIMED_OUT",
	"CONNECTED", "DISCONNECTED", "UPDATE_PENDING",
	// EXITED: a LOCAL_PROCESS claim that the worker was gone (T4).
	"EXITED",
}

// vocabulary returns the provider's registered closed set.
func Vocabulary() evidence.Vocabulary {
	return evidence.Vocabulary{
		Provider:       Name,
		EventPrefix:    EventPrefix,
		EventTypes:     eventTypes,
		SocketRoles:    socketRoles,
		EvidenceCodes:  evidenceCodes,
		ConflictTopics: conflictTopics,
		ClaimValues:    claimValues,
	}
}
