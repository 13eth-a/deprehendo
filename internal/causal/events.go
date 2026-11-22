// package causal converts phase 1-3 evidence into a deterministic, explainable
// event timeline and causal graph (phase 4). it is offline analysis: a decoded
// incident bundle becomes a normalized event stream, and a versioned rule set
// proposes causal edges that a validating engine accepts or rejects. nothing
// here infers causation merely from temporal proximity: PRECEDES is factual
// order only, and CAUSES is granted only by a rule whose required evidence the
// bundle actually provides. events that v1 bundles cannot observe (kernel OOM
// events, socket byte progress, job assignments) are declared but never
// fabricated.
//
// all output is deterministic for a given bundle: identical input produces
// byte-identical events, edges, and chains.
package causal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EventID is the stable, content-addressed identifier of one normalized
// event. it depends only on extraction content, never on rule versions, so a
// stored graph keeps pointing at the same events when rules change.
type EventID string

// EventType is the canonical event vocabulary (4.1). names are stable.
type EventType string

// observability (v1): event types below are declared for forward
// compatibility but are NOT emitted and NEVER inferred where v1 bundles
// cannot observe them: OOM_EVENT (no kernel event stream),
// NETWORK_PROGRESS_STOPPED / NETWORK_PROGRESS_RESUMED (no RX/TX byte
// counters), RUNNER_STARTED / WORKER_STARTED / WORKER_EXITED (no job or
// runner role telemetry). PROCESS_EXITED is emitted only from recorded
// bundle events, never inferred from sampling gaps.
const (
	EventProcessStarted         EventType = "PROCESS_STARTED"
	EventProcessExited          EventType = "PROCESS_EXITED"
	EventProcessStopped         EventType = "PROCESS_STOPPED"
	EventProcessResumed         EventType = "PROCESS_RESUMED"
	EventProcessReparented      EventType = "PROCESS_REPARENTED"
	EventProcessGroupTerminated EventType = "PROCESS_GROUP_TERMINATED"
	EventCPUSaturationActive    EventType = "CPU_SATURATION_ACTIVE"
	EventCPUSaturationStarted   EventType = "CPU_SATURATION_STARTED"
	EventCPUSaturationEnded     EventType = "CPU_SATURATION_ENDED"
	EventMemoryPressureActive   EventType = "MEMORY_PRESSURE_ACTIVE"
	EventMemoryPressureStarted  EventType = "MEMORY_PRESSURE_STARTED"
	EventMemoryLimitReached     EventType = "MEMORY_LIMIT_REACHED"
	EventMemoryRecovered        EventType = "MEMORY_RECOVERED"
	EventCgroupLimitReached     EventType = "CGROUP_LIMIT_REACHED"
	// EventCgroupLimitCleared closes a cgroup-limit episode: memory.current
	// fell below the hysteresis boundary (re-audit R11; it previously ended
	// silently, so a recovered cgroup stayed an unrecovered failure anchor).
	EventCgroupLimitCleared  EventType = "CGROUP_LIMIT_CLEARED"
	EventDiskLowActive       EventType = "DISK_LOW_ACTIVE"
	EventDiskPressureStarted EventType = "DISK_PRESSURE_STARTED"
	EventDiskPressureEnded   EventType = "DISK_PRESSURE_ENDED"
	EventDiskExhausted       EventType = "DISK_EXHAUSTED"
	EventDiskRecovered       EventType = "DISK_RECOVERED"
	EventConnectionOpened    EventType = "CONNECTION_OPENED"
	EventConnectionClosed    EventType = "CONNECTION_CLOSED"
	// EventSignalSent is the kernel's send observation (fact SIGNAL_SENT):
	// who asked for which signal against which process or group. it is a
	// fact about the send, never a claim that the signal was delivered.
	EventSignalSent             EventType = "SIGNAL_SENT"
	EventNetworkProgressStopped EventType = "NETWORK_PROGRESS_STOPPED"
	EventNetworkProgressResumed EventType = "NETWORK_PROGRESS_RESUMED"
	EventOOM                    EventType = "OOM_EVENT"
	EventRunnerStarted          EventType = "RUNNER_STARTED"
	EventWorkerStarted          EventType = "WORKER_STARTED"
	EventWorkerExited           EventType = "WORKER_EXITED"
	EventClockDiscontinuity     EventType = "CLOCK_DISCONTINUITY"
	EventTimelineGap            EventType = "TIMELINE_GAP"
	EventIncidentTriggered      EventType = "INCIDENT_TRIGGERED"

	// IO PSI (§3.3): host-level severe IO stall time is its own quantity, not
	// disk free space. v1 keeps DISK_* for the free-space machine only.
	EventIOPressureStarted EventType = "IO_PRESSURE_STARTED"
	EventIOPressureEnded   EventType = "IO_PRESSURE_ENDED"
)

// RootKind is what a root candidate is in the §5 root taxonomy: a supported
// initiating condition (ROOT_CAUSE), a failure heading a known chain whose own
// cause is unknown (UNEXPLAINED_HEAD), or a cofactor that reaches the anchor
// only through non-causal paths (CONTRIBUTING_FACTOR).
type RootKind string

const (
	KindRootCause          RootKind = "ROOT_CAUSE"
	KindUnexplainedHead    RootKind = "UNEXPLAINED_HEAD"
	KindContributingFactor RootKind = "CONTRIBUTING_FACTOR"
)

// RootRole labels a candidate's position among competitors for one anchor
// (§5.4). PRIMARY is the sole best-supported candidate; COMPETING candidates
// tie on band and none is promoted (audit A6); SECONDARY are weaker.
type RootRole string

const (
	RolePrimary   RootRole = "PRIMARY"
	RoleCompeting RootRole = "COMPETING"
	RoleSecondary RootRole = "SECONDARY"
)

// FailureStatus is a failure anchor's analysis outcome (§5).
type FailureStatus string

const (
	StatusExplained FailureStatus = "EXPLAINED"
	StatusAmbiguous FailureStatus = "AMBIGUOUS"
	StatusUnknown   FailureStatus = "UNKNOWN"
)

// FailureAnalysis is the per-anchor causal analysis (§5.2): every failure
// anchor gets one, with no exceptions, so an unknown cause is always
// reported instead of suppressed when some other anchor has a candidate.
type FailureAnalysis struct {
	Anchor          EventID         `json:"anchor"`
	AnchorType      EventType       `json:"anchor_type"`
	Status          FailureStatus   `json:"status"`
	Candidates      []RootCandidate `json:"candidates,omitempty"`
	KnownChain      []EventID       `json:"known_chain,omitempty"`
	MissingEvidence []string        `json:"missing_evidence,omitempty"`
	Alternatives    []string        `json:"alternatives"` // always present: [] is "checked, empty" (I2)
}

// CheckResultStatus is the tri-state answer of one evidence check (§1.1 /
// §2.3): PRESENT shows, ABSENT was evaluated and is clean, UNKNOWN is
// telemetry the bundle never captured. an UNKNOWN is never read as ABSENT.
type CheckResultStatus string

const (
	CheckPresent CheckResultStatus = "PRESENT"
	CheckAbsent  CheckResultStatus = "ABSENT"
	CheckUnknown CheckResultStatus = "UNKNOWN"
)

// CheckFunc evaluates one declared check against a source/target pair. it
// reads bundle facts only and never proposes state change.
type CheckFunc func(g *Graph, src, tgt *Event) CheckResult

// check is one named evidence requirement inside a rule contract (§3.1).
type Check struct {
	Code     string
	Evaluate CheckFunc
}

// CheckResult is one evaluator's answer: status, human detail, and whether
// the observation is sampled state (D6) rather than a recorded event.
type CheckResult struct {
	Status  CheckResultStatus
	Detail  string
	Sampled bool
}

// CheckRecord is one evaluated check stored on an edge (§4.2): every
// required, supporting and contradicting check with its final status, so
// explain-edge can show what was checked, what was missing, and what was
// not checkable (I2).
type CheckRecord struct {
	Kind    string            `json:"kind"` // "required" | "contradicting" | "supporting"
	Code    string            `json:"code"`
	Status  CheckResultStatus `json:"status"`
	Detail  string            `json:"detail,omitempty"`
	Sampled bool              `json:"sampled,omitempty"`
}

// EpisodeBinding is the P3 binding contract every non-temporal edge must
// satisfy (§1.1): causal, contributing, escalation and recovery edges connect
// events of one episode instance, or require the source episode to still be
// active and unrecovered at the target's timestamp.
type EpisodeBinding string

const (
	BindingNone                 EpisodeBinding = "NONE"
	BindingSameEpisode          EpisodeBinding = "SAME_EPISODE"
	BindingSourceActiveAtTarget EpisodeBinding = "SOURCE_ACTIVE_AT_TARGET"
	BindingNearestOnly          EpisodeBinding = "NEAREST_ONLY"
)

// IdentityStrength grades the subject identity a rule binds on (§2.2 D2):
// exact = PID + start ticks / inode / path; PIDOnly = PID without
// incarnation; scope = same resource scope (host, filesystem).
type IdentityStrength string

const (
	IdentityExact   IdentityStrength = "EXACT"
	IdentityPIDOnly IdentityStrength = "PID_ONLY"
	IdentityScope   IdentityStrength = "SCOPE"
)

// SubjectRef identifies what an event happened to (4.2). IDs are built from
// bundle facts only: rotating or redacted bundle content yields redacted
// subjects, which still compare equal to themselves.
type SubjectKind string

const (
	SubjectProcess    SubjectKind = "process"
	SubjectSocket     SubjectKind = "socket"
	SubjectFilesystem SubjectKind = "filesystem"
	SubjectCgroup     SubjectKind = "cgroup"
	SubjectHost       SubjectKind = "host"
	SubjectGroup      SubjectKind = "process_group"
)

type ProcessIdentity struct {
	PID        int   `json:"pid"`
	StartTicks int64 `json:"start_ticks"`
}

type SubjectRef struct {
	Kind SubjectKind
	ID   string
}

// stable subject ID formats:
//
//	process:    "<PID>@<StartTicks>"
//	process_group: "pgid:<PGID>"
//	socket:     "inode-<inode>" or "port:<local>:<remote>"
//	filesystem: the bundle's (possibly redacted) filesystem label
//	cgroup:     the bundle's (possibly redacted) cgroup path
//	host:       "local" (no host identifiers under conservative privacy)

func processSubject(pid int, startTicks int64) SubjectRef {
	return SubjectRef{SubjectProcess, strconv.Itoa(pid) + "@" + strconv.FormatInt(startTicks, 10)}
}

func groupSubject(pgid int) SubjectRef {
	return SubjectRef{SubjectGroup, "pgid:" + strconv.Itoa(pgid)}
}

// event is one normalized, ordered factual occurrence (4.1). timestamp is the
// wall-clock value recorded by the bundle; relative is its offset from the
// timeline origin. sequence is the canonical index after deterministic sorting
// (review 4.1 change 3). capture order travels in provenance references, not
// here. identity lives in the typed fields below, never in data: data is
// display-only and every number in it degrades to float64 across a JSON
// round-trip (audit A18).
type Event struct {
	ID         EventID         `json:"id"`
	Type       EventType       `json:"type"`
	Timestamp  time.Time       `json:"timestamp"`
	Sequence   uint64          `json:"sequence"`
	Subject    SubjectRef      `json:"subject"`
	Data       map[string]any  `json:"data,omitempty"`
	Provenance EventProvenance `json:"provenance"`

	// class is the type's role in explanation (§5.1); episode groups the
	// state-machine events of one resource episode so rules can bind to it
	// (§1.2 P3, "memory:host:local#2").
	Class   EventClass `json:"class"`
	Episode string     `json:"episode,omitempty"`

	// duration is the observed span for paired start/end events
	// (transient-vs-persistent, 4.27). OK is false when the episode did not
	// visibly end inside the capture.
	Duration   time.Duration `json:"duration,omitempty"`
	DurationOK bool          `json:"duration_ok,omitempty"`

	// OnsetUnknown marks a condition that was already in effect at its first
	// available observation (4.28): the event states that the condition held,
	// never when it began. OnsetWindow carries the observed crossing window
	// (last-known-below, observed-at] when the onset WAS observed.
	OnsetUnknown bool    `json:"onset_unknown,omitempty"`
	OnsetWindow  *Window `json:"onset_window,omitempty"`

	// typed identity (§4.2): rules bind on these, never on data assertions.
	PID            int   `json:"pid,omitempty"`
	StartTicks     int64 `json:"start_ticks,omitempty"`
	PPID           int   `json:"ppid,omitempty"`
	PPIDStartTicks int64 `json:"ppid_start_ticks,omitempty"`
	PGID           int   `json:"pgid,omitempty"`

	// ProcessIDs lists exact identities aggregated into a derived group event.
	ProcessIDs []ProcessIdentity `json:"process_ids,omitempty"`
}

// EventProvenance says where a derived event came from (4.17): the snapshots
// or recorded events it was extracted from, plus the versioned rule that
// derived it when applicable.
type EventProvenance struct {
	RuleID  string             `json:"rule_id,omitempty"`
	Sources []ProvenanceSource `json:"sources"`
}

type ProvenanceSource struct {
	Kind string `json:"kind"` // "snapshot" | "event" | "trigger"
	Ref  string `json:"ref"`
}

func provenance(kind, ref string) ProvenanceSource {
	return ProvenanceSource{Kind: kind, Ref: ref}
}

// RuleID constants are versioned now (4.18): changing semantics requires a
// new suffix so stored historical explanations never silently change.
const (
	RuleMemoryCrossing     = "MEMORY_CROSSING@1"
	RuleDiskCrossing       = "DISK_CROSSING@1"
	RuleCPUSaturation      = "CPU_SATURATION@1"
	RuleCgroupLimit        = "CGROUP_LIMIT@1"
	RuleIOPressure         = "IO_PRESSURE@1"
	RuleGroupTermination   = "GROUP_TERMINATION@1"
	RuleClockDiscontinuity = "CLOCK_DISCONTINUITY@1"
	RuleTimelineGap        = "TIMELINE_GAP@1"
	RuleNetworkProgress    = "NETWORK_PROGRESS@1"
	RuleTimelineBuild      = "TIMELINE_BUILD@1"
	RuleOOMKillCounter     = "OOM_KILL_COUNTER@1"
)

// EventClass groups every event type by its role in explanation (spec §5.1).
// A CONDITION can initiate a failure, a FAILURE needs an explanation and can
// head a known chain, and CONTEXT is fact or consequence only.
type EventClass string

const (
	ClassCondition EventClass = "CONDITION"
	ClassFailure   EventClass = "FAILURE"
	ClassContext   EventClass = "CONTEXT"
)

// classOf assigns the fixed class of every event type (§5.1). classes are a
// property of the vocabulary, not of the instance.
func classOf(t EventType) EventClass {
	switch t {
	case EventMemoryPressureActive, EventMemoryPressureStarted, EventMemoryLimitReached,
		EventCgroupLimitReached, EventDiskLowActive, EventDiskPressureStarted,
		EventDiskExhausted, EventIOPressureStarted, EventOOM, EventNetworkProgressStopped,
		EventSignalSent:
		return ClassCondition
	case EventProcessExited, EventProcessStopped, EventProcessGroupTerminated,
		EventWorkerExited, EventConnectionClosed:
		return ClassFailure
	default:
		// PROCESS_STARTED/RESUMED/REPARENTED, recoveries and endings, CPU
		// saturation (process-scoped symptom), clock/timeline facts, and the
		// incident trigger are context (§5.1).
		return ClassContext
	}
}

// window is the uncertainty interval of an observed crossing (§10 item 3):
// the condition was below its boundary at NotBefore (the last sample that
// showed it below) and observed at ObservedAt. A nil window on a
// STARTED/ACTION event says the onset was not captured (4.28).
type Window struct {
	NotBefore  time.Time `json:"not_before"`
	ObservedAt time.Time `json:"observed_at"`
}

// RelationType is the edge vocabulary (4.6). the distinctions are the phase 4
// foundation contract (spec §1):
//
//	PRECEDES         factual order; no causal claim; always drawable.
//	CORRELATED_WITH  temporal clustering without established order.
//	CAUSES           a declared mechanism whose required evidence the bundle
//	                 actually shows. never granted by adjacency alone.
//	CONTRIBUTES_TO   a cofactor that raised the likelihood of the consequent;
//	                 weaker than CAUSES, stronger than PRECEDES.
//	RECOVERY_OF      the episode resolution for a failure event.
//	CONTRADICTS      evidence against an earlier conclusion.
type RelationType string

const (
	RelationCauses      RelationType = "CAUSES"
	RelationContributes RelationType = "CONTRIBUTES_TO"
	RelationPrecedes    RelationType = "PRECEDES"
	RelationCorrelates  RelationType = "CORRELATED_WITH"
	RelationRecoveryOf  RelationType = "RECOVERY_OF"
	RelationContradicts RelationType = "CONTRADICTS"
	// ESCALATES_TO (spec §1.3): the same measured quantity on the same
	// subject crossed a higher severity threshold in the same episode. both
	// thresholds answer to the episode's (possibly unobserved) cause, so the
	// first crossing did not cause the second. traversable, never causal.
	RelationEscalates RelationType = "ESCALATES_TO"
)

// causalRelations participate in the causal DAG and in root/chain analysis.
// PRECEDES and CORRELATED_WITH are temporal context and never compute into
// root-cause eligibility.
func isCausal(r RelationType) bool {
	return r == RelationCauses || r == RelationContributes
}

// isDAGRelation covers the edges the cycle check (4.14) treats as ordered
// structure: causal ∪ episode (spec §4.1). PRECEDES/CORRELATED_WITH are
// retraceable temporal facts and may form patterns; CONTRADICTS attaches to
// claims, never chains them.
func isDAGRelation(r RelationType) bool {
	return isCausal(r) || r == RelationEscalates || r == RelationRecoveryOf
}

// recoveryTypes are the episode-closing event types. A recovery event for an
// episode marks that episode resolved at its timestamp: P3 refuses to run a
// source episode's effects through a resolution point (§1.1, P3).
var recoveryTypes = map[EventType]bool{
	EventMemoryRecovered:        true,
	EventCgroupLimitCleared:     true,
	EventDiskRecovered:          true,
	EventDiskPressureEnded:      true,
	EventIOPressureEnded:        true,
	EventCPUSaturationEnded:     true,
	EventProcessResumed:         true,
	EventNetworkProgressResumed: true,
}

// isRecoveryType reports whether t closes a resource episode.
func isRecoveryType(t EventType) bool { return recoveryTypes[t] }

// chainRelations traverse from a root toward its effects (§2.4): the causal
// layer plus ESCALATES_TO, which carries the episode onset to the episode's
// peak but contributes no confidence. PRECEDES/CORRELATED_WITH never appear
// in a chain.
func isChainRelation(r RelationType) bool {
	return isCausal(r) || r == RelationEscalates
}

func isTemporal(r RelationType) bool {
	return r == RelationPrecedes || r == RelationCorrelates
}

// CausalConfidence is the banded edge confidence (4.10). numeric internals
// are allowed, but rendering and comparability use the bands: causal
// confidence is a declared basis score, not a probability.
type CausalConfidence string

const (
	ConfidenceLow    CausalConfidence = "LOW"
	ConfidenceMedium CausalConfidence = "MEDIUM"
	ConfidenceHigh   CausalConfidence = "HIGH"
)

// numeric bases for internal ranking; bands are the external contract.
const (
	weightLow    = 0.35
	weightMedium = 0.65
	weightHigh   = 0.90
)

func confidenceFor(weight float64) CausalConfidence {
	switch {
	case weight >= weightHigh-0.001:
		return ConfidenceHigh
	case weight >= weightMedium-0.001:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func (c CausalConfidence) weight() float64 {
	switch c {
	case ConfidenceHigh:
		return weightHigh
	case ConfidenceMedium:
		return weightMedium
	default:
		return weightLow
	}
}

// canonicalEventKey is the deterministic, content-derived basis of the event
// ID. the dup index disambiguates otherwise identical facts, and it is
// assigned after deterministic normalization, so IDs are stable per bundle.
func canonicalEventKey(e Event, dup int) string {
	keys := make([]string, 0, len(e.Data))
	for k, v := range e.Data {
		keys = append(keys, k+"="+fmt.Sprintf("%v", v))
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(string(e.Type))
	b.WriteByte(0)
	b.WriteString(string(e.Subject.Kind))
	b.WriteByte(0)
	b.WriteString(e.Subject.ID)
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(e.Timestamp.UnixNano(), 10))
	b.WriteByte(0)
	b.WriteString(strconv.FormatBool(e.OnsetUnknown))
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
	}
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(dup))
	sum := sha256.Sum256([]byte(b.String()))
	return "EV_" + hex.EncodeToString(sum[:6])
}

// assignIDs finalizes event IDs after the timeline is normalized.
func assignIDs(events []Event) {
	seen := map[string]int{}
	for i := range events {
		dup := seen[canonicalEventKey(events[i], 0)]
		seen[canonicalEventKey(events[i], 0)]++
		events[i].ID = EventID(canonicalEventKey(events[i], dup))
	}
}

// sortEvents is the deterministic canonical event order: timestamp, type
// precedence, subject, then content (4.4).
func sortEvents(events []Event) {
	sort.SliceStable(events, func(i, j int) bool {
		return lessEvent(events[i], events[j])
	})
}

func lessEvent(a, b Event) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return a.Timestamp.Before(b.Timestamp)
	}
	if ra, rb := typeRank(a.Type), typeRank(b.Type); ra != rb {
		return ra < rb
	}
	if a.Subject.Kind != b.Subject.Kind {
		return a.Subject.Kind < b.Subject.Kind
	}
	if a.Subject.ID != b.Subject.ID {
		return a.Subject.ID < b.Subject.ID
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.OnsetUnknown != b.OnsetUnknown {
		return !a.OnsetUnknown
	}
	return a.ID < b.ID
}

// typeRank breaks equal-timestamp ties by evidence precedence: kernel/recorded
// facts first, then process state, then resource sensors, then derived
// summaries, then the incident trigger.
func typeRank(t EventType) int {
	switch t {
	case EventProcessExited, EventProcessStarted, EventOOM, EventSignalSent:
		return 0
	case EventProcessStopped, EventProcessResumed, EventProcessReparented:
		return 1
	case EventConnectionOpened, EventConnectionClosed:
		return 2
	case EventCgroupLimitReached, EventMemoryLimitReached, EventDiskExhausted:
		return 3
	case EventMemoryPressureActive, EventMemoryPressureStarted, EventMemoryRecovered, EventCgroupLimitCleared,
		EventCPUSaturationActive, EventCPUSaturationStarted, EventCPUSaturationEnded,
		EventDiskLowActive, EventDiskPressureStarted, EventDiskPressureEnded, EventDiskRecovered,
		EventIOPressureStarted, EventIOPressureEnded,
		EventNetworkProgressStopped, EventNetworkProgressResumed:
		return 4
	case EventProcessGroupTerminated, EventClockDiscontinuity, EventTimelineGap:
		return 5
	case EventIncidentTriggered:
		return 6
	case EventRunnerStarted, EventWorkerStarted, EventWorkerExited:
		return 1
	default:
		return 5
	}
}
