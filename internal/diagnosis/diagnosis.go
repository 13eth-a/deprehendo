// package diagnosis classifies phase 2 incident bundles into deterministic,
// evidence-backed failure signatures. it is offline analysis: given a decoded
// incident it computes normalized features once and evaluates registered
// signatures. A diagnosis is always explainable: missing telemetry is
// reported as UNKNOWN, never as FALSE, and every match carries the evidence
// that supports and contradicts it. confidence values are internal scores on
// a fixed declared-weight basis, not probabilities.
package diagnosis

import "time"

const (
	// AnalyzerVersion is bumped whenever matching behavior changes in a way
	// that can change results for the same bundle. 0.4.0: the analysis document
	// (internal/analysis) records the engine identity, so any future matching
	// change must bump this again. the golden fingerprint test pins it.
	AnalyzerVersion = "0.4.0"
	// SignatureSetVersion identifies the bundled rule set.
	SignatureSetVersion = 2
	// DefaultMinConfidence is the score below which a signature is reported
	// only as a rejection reason, never as a diagnosis.
	DefaultMinConfidence = 0.55
)

// SignatureID is the stable identifier reported by matches and rejections.
type SignatureID string

const (
	SignatureOOMKill        SignatureID = "OOM_KILL"
	SignatureFrozenProcess  SignatureID = "FROZEN_PROCESS"
	SignatureCPUSpin        SignatureID = "CPU_SPIN"
	SignatureDiskExhaustion SignatureID = "DISK_EXHAUSTION"
	SignatureOrphanProcess  SignatureID = "ORPHAN_PROCESS_TREE"
	SignatureGroupKill      SignatureID = "PROCESS_GROUP_TERMINATION"
	SignatureBrokerStall    SignatureID = "BROKER_SOCKET_STALL"
	SignatureNetworkFailure SignatureID = "NETWORK_PATH_FAILURE"
	SignatureStarvation     SignatureID = "RESOURCE_STARVATION"
) // SignatureVersion is bumped when any bundled rule's semantics change. A
// stored diagnosis can later name the precise rule version that produced it.
//
// 4: OOM_KILL reads an oom_kill counter rise in the victim's final sample
// (S11), and PROCESS_GROUP_TERMINATION requires the group not to survive
// (S2).
// 5: OOM_KILL accepts the phase 6 tracer's victim-naming oom:mark_victim
// record, which lifts the v1 cap without the sampled cgroup counter.
const SignatureVersion = 5

// ObservationState is the tri-state evidence model. FALSE means the evidence
// was actually observed and contradicts a hypothesis; UNKNOWN means the
// recording cannot answer, which supports nothing and contradicts nothing.
// treating missing telemetry as FALSE would silently convert absence of data
// into evidence of absence and invalidate nearly every signature.
type ObservationState int

const (
	Unknown ObservationState = iota
	False
	True
)

func (s ObservationState) String() string {
	switch s {
	case True:
		return "TRUE"
	case False:
		return "FALSE"
	default:
		return "UNKNOWN"
	}
}

// observation is a tri-state answer with the witness timestamp for TRUE and
// an optional value.
type Observation[T any] struct {
	State      ObservationState
	ObservedAt time.Time
	Value      T
}

func observationTrue[T any](at time.Time, value T) Observation[T] {
	return Observation[T]{State: True, ObservedAt: at, Value: value}
}

func observationFalse[T any]() Observation[T] {
	return Observation[T]{State: False}
}

func observationUnknown[T any]() Observation[T] {
	return Observation[T]{State: Unknown}
}

// evidence records one factual observation used by a signature. value and
// threshold are machine-readable so later tooling can render or re-diff them.
type Evidence struct {
	Code      EvidenceCode   `json:"code"`
	Source    EvidenceSource `json:"source"`
	At        time.Time      `json:"at"`
	Weight    float64        `json:"weight"`
	Observed  any            `json:"observed,omitempty"`
	Threshold any            `json:"threshold,omitempty"`
}

// EvidenceCode values used by the bundled signatures. codes are stable and
// are the rendering contract of --explain and --json output.
type EvidenceCode string

const (
	CodeHostMemoryNearLimit      EvidenceCode = "HOST_MEMORY_NEAR_LIMIT"
	CodeCgroupMemoryNearLimit    EvidenceCode = "CGROUP_MEMORY_NEAR_LIMIT"
	CodeMemoryPressureSpike      EvidenceCode = "MEMORY_PRESSURE_SPIKE"
	CodeProcessDisappeared       EvidenceCode = "PROCESS_DISAPPEARED"
	CodeProcessDepartureNearPeak EvidenceCode = "PROCESS_DEPARTURE_NEAR_MEMORY_PEAK"
	CodeCandidateRSSLarge        EvidenceCode = "CANDIDATE_RSS_LARGE"
	CodeKernelOOMCounter         EvidenceCode = "KERNEL_OOM_COUNTER_ROSE"
	// CodeKernelOOMVictim is the phase 6 tracer's oom:mark_victim record for
	// this exact process identity: the kernel itself named the victim.
	CodeKernelOOMVictim EvidenceCode = "KERNEL_OOM_VICTIM_OBSERVED"

	CodeProcessStopped         EvidenceCode = "PROCESS_STOPPED"
	CodeProcessRemainedStopped EvidenceCode = "PROCESS_REMAINED_STOPPED"
	CodeProcessResumed         EvidenceCode = "PROCESS_RESUMED"
	CodeWatchedIdentity        EvidenceCode = "WATCHED_IDENTITY"

	CodeCPUSustained      EvidenceCode = "CPU_SUSTAINED"
	CodeCPUNoChildChanges EvidenceCode = "CPU_NO_CHILD_CHANGES"
	CodeCPUNoProgress     EvidenceCode = "CPU_NO_PROGRESS"
	CodeCPUHealthy        EvidenceCode = "CPU_HEALTHY"
	CodeMemoryHealthy     EvidenceCode = "MEMORY_HEALTHY"
	CodePeakMemoryHealthy EvidenceCode = "PEAK_MEMORY_HEALTHY"
	CodePressureHealthy   EvidenceCode = "PRESSURE_HEALTHY"

	CodeDiskSustainedLowFree       EvidenceCode = "DISK_SUSTAINED_LOW_FREE"
	CodeDiskPressure               EvidenceCode = "DISK_PRESSURE"
	CodeInodeExhaustion            EvidenceCode = "INODE_EXHAUSTION"
	CodeDiskPersistedToAnalysisEnd EvidenceCode = "DISK_PERSISTED_TO_ANALYSIS_END"
	CodeDiskRecoveredMidIncident   EvidenceCode = "DISK_RECOVERED_MID_INCIDENT"

	CodeParentDisappeared     EvidenceCode = "PARENT_DISAPPEARED"
	CodeChildReparented       EvidenceCode = "CHILD_REPARENTED"
	CodeChildReparentedToInit EvidenceCode = "CHILD_REPARENTED_TO_INIT"
	CodeChildPersisted        EvidenceCode = "CHILD_PERSISTED"
	CodeTriggerConsistent     EvidenceCode = "TRIGGER_CONSISTENT"

	CodeSharedProcessGroup     EvidenceCode = "SHARED_PROCESS_GROUP"
	CodeCoordinatedTermination EvidenceCode = "COORDINATED_TERMINATION"
	CodeProcessesDidNotReturn  EvidenceCode = "PROCESSES_DID_NOT_RETURN"
	CodeTriggerInGroup         EvidenceCode = "TRIGGER_IN_GROUP"
	CodeNoSharedProcessGroup   EvidenceCode = "NO_SHARED_PROCESS_GROUP"
	CodeProcessExited          EvidenceCode = "PROCESS_EXITED"

	CodeStableConnection         EvidenceCode = "STABLE_CONNECTION"
	CodeOwnerStaysAlive          EvidenceCode = "OWNER_STAYS_ALIVE"
	CodeNoReconnectChurn         EvidenceCode = "NO_RECONNECT_CHURN"
	CodeDisconnectedSockets      EvidenceCode = "DISCONNECTED_SOCKETS"
	CodeSynChurn                 EvidenceCode = "SYN_CHURN"
	CodeMultipleConnectionsHit   EvidenceCode = "MULTIPLE_CONNECTIONS_AFFECTED"
	CodeSocketBoundToDiedProcess EvidenceCode = "SOCKET_BOUND_TO_DIED_PROCESS"
	CodeCollectorHeavyLoss       EvidenceCode = "COLLECTOR_HEAVY_LOSS"

	CodePsiSomeExhausted EvidenceCode = "PSI_SOME_EXHAUSTED"
	CodePsiFullStalled   EvidenceCode = "PSI_FULL_STALLED"
	CodePsiSustained     EvidenceCode = "PSI_SUSTAINED"
)

// EvidenceSource is the provenance of one evidence item: which recorder
// section or analyzer input the observation came from.
type EvidenceSource string

const (
	SourceEvent                EvidenceSource = "event"
	SourceProcess              EvidenceSource = "process_table"
	SourceNetwork              EvidenceSource = "network_collector"
	SourceCgroup               EvidenceSource = "cgroup_collector"
	SourceHost                 EvidenceSource = "host_sensor"
	SourcePressure             EvidenceSource = "pressure_collector"
	SourceTrigger              EvidenceSource = "incident_trigger"
	SourceCollectorReliability EvidenceSource = "collector_reliability"
)

// ConfidenceBand turns a score into shareable words without pretending the
// score is a probability.
type ConfidenceBand string

const (
	BandNone     ConfidenceBand = "NONE"
	BandModerate ConfidenceBand = "MODERATE"
	BandHigh     ConfidenceBand = "HIGH"
	BandVeryHigh ConfidenceBand = "VERY_HIGH"
)

// BandFor labels a score using fixed boundaries aligned with
// DefaultMinConfidence.
func BandFor(c float64) ConfidenceBand {
	switch {
	case c >= 0.90:
		return BandVeryHigh
	case c >= 0.75:
		return BandHigh
	case c >= 0.55:
		return BandModerate
	default:
		return BandNone
	}
}

// severity is the incident-level impact label attached by the engine, not a
// per-signature severity model.
type Severity string

const (
	SeverityInformational Severity = "INFORMATIONAL"
	SeverityWarning       Severity = "WARNING"
	SeverityCritical      Severity = "CRITICAL"
)

// ProcessIdentity is the PID incarnation a process-scoped diagnosis is about.
// StartTicks distinguishes a reused PID from the process actually observed.
type ProcessIdentity struct {
	PID        int   `json:"pid"`
	StartTicks int64 `json:"start_ticks"`
}

// SignatureMatch is one signature's evaluation result for an incident. A
// match with rejected == "" is a diagnosis; non-empty rejected means the
// signature was evaluated but is not reported as one.
type SignatureMatch struct {
	SignatureID SignatureID    `json:"signature"`
	Version     int            `json:"signature_version"`
	Confidence  float64        `json:"confidence"`
	Band        ConfidenceBand `json:"confidence_band"`
	Severity    Severity       `json:"severity"`
	Summary     string         `json:"summary"`

	Supporting    []Evidence `json:"supporting,omitempty"`
	Contradicting []Evidence `json:"contradicting,omitempty"`

	// rejected explains why the signature is not a diagnosis. empty when the
	// signature is reported as a match.
	Rejected string `json:"rejected,omitempty"`

	// MissingEvidence codes the tri-state checks that were UNKNOWN for this
	// rule: evidence the recording could not provide, not evidence of absence.
	MissingEvidence []string          `json:"missing_evidence,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`

	// RelatedEvents (phase 4, 4.16) lists causal-package event IDs on the
	// normalized timeline that this signature's evidence overlaps. it is
	// populated by the caller that owns both the report and the timeline;
	// the engine itself fills nothing here.
	RelatedEvents []string `json:"related_events,omitempty"`

	// ProcessIdentities scopes process-related evidence to the exact PID
	// incarnations the signature evaluated. ProcessGroupID is set for a
	// process-group diagnosis, whose subject is the group rather than one PID.
	ProcessIdentities []ProcessIdentity `json:"process_identities,omitempty"`
	ProcessGroupID    int               `json:"process_group_id,omitempty"`
}

// report is the deterministic engine result for one incident.
type Report struct {
	IncidentID    string           `json:"incident_id"`
	Trigger       string           `json:"trigger"`
	TriggeredAt   time.Time        `json:"triggered_at"`
	Analyzer      string           `json:"analyzer_version"`
	SignatureSet  int              `json:"signature_set_version"`
	MinConfidence float64          `json:"min_confidence"`
	Matches       []SignatureMatch `json:"matches"`
	Rejections    []SignatureMatch `json:"rejections"`
	// ambiguous lists signature pairs the engine could not rank.
	Ambiguous          []string   `json:"ambiguous,omitempty"`
	Unknown            bool       `json:"unknown"`
	StrongObservations []Evidence `json:"strong_observations,omitempty"`
}
