// package evidence is the provider section of a .runopsy bundle (phase 5,
// docs/providers/architecture.md §3). it is a leaf package: it imports only
// the standard library, so internal/incident can embed it without depending
// on any provider implementation.
//
// everything here is designed for the conservative privacy policy:
//
//   - roles, states, event types and reasons are bounded enumerations;
//   - every free-text value is a text with a privacy class and a tri-state
//     (KNOWN / UNKNOWN / WITHHELD). WITHHELD means "the agent knew it and the
//     privacy policy kept it out of the bundle", which is different from
//     UNKNOWN ("the agent never learned it");
//   - identities of runners and jobs are opaque refs (salted hashes), never
//     names, paths or PIDs;
//   - there is no field that can carry a log line, URL, command line,
//     environment variable, header or token.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// SchemaVersion of the provider section. readers must reject a section whose
// version they do not know rather than guess at its meaning.
const SchemaVersion = 1

// bounds keep a hostile or runaway provider from growing a bundle.
const (
	MaxRunners      = 64
	MaxWorkers      = 4096
	MaxJobs         = 4096
	MaxProcessRoles = 65536
	MaxSocketRoles  = 4096
	MaxEvents       = 50000
	MaxConflicts    = 1024
	MaxTextBytes    = 256
	MaxReasons      = 16
)

// ---------------------------------------------------------------------------
// Tri-state values
// ---------------------------------------------------------------------------

// state says what the agent knows about a value.
type State string

const (
	Known    State = "KNOWN"
	Unknown  State = "UNKNOWN"  // never learned
	Withheld State = "WITHHELD" // learned, kept out by the privacy policy
)

// source is where a fact came from (5.47). sources are not equally
// authoritative; the authority table lives in architecture.md §8.
type Source string

const (
	SourceLocalProcess Source = "LOCAL_PROCESS" // kernel / procfs observation
	SourceLocalSocket  Source = "LOCAL_SOCKET"  // socket table / sock_diag
	SourceRunnerLog    Source = "RUNNER_LOG"    // provider diagnostic log
	SourceRunnerConfig Source = "RUNNER_CONFIG" // provider installation metadata
	SourceProviderAPI  Source = "PROVIDER_API"  // remote API (enrichment only)
	SourceDerived      Source = "DERIVED"       // correlation over other facts
	SourceUserOverride Source = "USER_OVERRIDE" // explicit CLI flag
)

var validSources = map[Source]bool{
	SourceLocalProcess: true, SourceLocalSocket: true, SourceRunnerLog: true,
	SourceRunnerConfig: true, SourceProviderAPI: true, SourceDerived: true,
	SourceUserOverride: true,
}

// class is the privacy class of a free-text value. the policy table decides
// which classes may be KNOWN in an exported bundle.
type Class string

const (
	ClassVersion    Class = "VERSION"     // runner software version
	ClassRunnerName Class = "RUNNER_NAME" // often equals the hostname
	ClassLabels     Class = "LABELS"
	ClassRepository Class = "REPOSITORY"
	ClassWorkflow   Class = "WORKFLOW"
	ClassJobName    Class = "JOB_NAME"
)

var validClasses = map[Class]bool{
	ClassVersion: true, ClassRunnerName: true, ClassLabels: true,
	ClassRepository: true, ClassWorkflow: true, ClassJobName: true,
}

// text is a tri-state string with a privacy class.
type Text struct {
	State  State  `json:"state"`
	Class  Class  `json:"class"`
	Value  string `json:"value,omitempty"`
	Source Source `json:"source,omitempty"`
}

// KnownText builds a KNOWN value.
func KnownText(class Class, value string, source Source) Text {
	return Text{State: Known, Class: class, Value: value, Source: source}
}

// UnknownText builds an UNKNOWN value of a class.
func UnknownText(class Class) Text { return Text{State: Unknown, Class: class} }

// Int64 is a tri-state number (run IDs, job IDs, attempt numbers). numbers are
// identifiers too, so they follow the same policy through their Class.
type Int64 struct {
	State  State  `json:"state"`
	Class  Class  `json:"class"`
	Value  int64  `json:"value,omitempty"`
	Source Source `json:"source,omitempty"`
}

// number classes reuse the text classes they identify.
const (
	ClassRunID   Class = "RUN_ID"
	ClassJobID   Class = "JOB_ID"
	ClassAttempt Class = "ATTEMPT"
)

func init() {
	validClasses[ClassRunID] = true
	validClasses[ClassJobID] = true
	validClasses[ClassAttempt] = true
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

// ref is an opaque, stable identity: "rnr_" (runner), "wkr_" (worker
// incarnation) or "job_" (job) plus 16 hex digits. it is a salted hash of the
// provider-native identity, so two incidents from the same runner share a ref
// without the bundle naming the runner (5.4).
type Ref string

var refPattern = regexp.MustCompile(`^(rnr|wkr|job)_[0-9a-f]{16}$`)

// NewRef derives a ref from identity parts. salt is per-installation (the
// agent's host salt), so refs are stable on one host and not linkable across
// hosts by a reader who lacks the salt.
func NewRef(kind string, salt []byte, parts ...string) (Ref, error) {
	switch kind {
	case "rnr", "wkr", "job":
	default:
		return "", fmt.Errorf("evidence: unknown ref kind %q", kind)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("evidence: a ref needs at least one identity part")
	}
	h := sha256.New()
	h.Write(salt)
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return Ref(kind + "_" + hex.EncodeToString(sum[:8])), nil
}

// valid reports whether r is a well-formed Ref.
func (r Ref) Valid() bool { return refPattern.MatchString(string(r)) }

// ProcessRef is the PID + start-time identity used everywhere else in
// Runopsy. PID alone is never an identity.
type ProcessRef struct {
	PID        int   `json:"pid"`
	StartTicks int64 `json:"start_ticks"`
}

// ---------------------------------------------------------------------------
// section
// ---------------------------------------------------------------------------

// HealthState is the provider's own state during the capture (5.1, 5.37).
type HealthState string

const (
	HealthAvailable   HealthState = "AVAILABLE"
	HealthDegraded    HealthState = "DEGRADED"    // partial evidence
	HealthUnavailable HealthState = "UNAVAILABLE" // no provider evidence
	HealthDisabled    HealthState = "DISABLED"    // turned off by the user
)

// reason codes explain degraded / unavailable health and other states.
type Reason string

const (
	ReasonNotDetected      Reason = "NOT_DETECTED"
	ReasonPermissionDenied Reason = "PERMISSION_DENIED"
	ReasonPanic            Reason = "PROVIDER_PANIC"
	ReasonTimeout          Reason = "PROVIDER_TIMEOUT"
	ReasonBackpressure     Reason = "OBSERVATIONS_DROPPED"
	ReasonLogUnreadable    Reason = "LOG_UNREADABLE"
	ReasonLogRotated       Reason = "LOG_ROTATED"
	ReasonLogTruncated     Reason = "LOG_TRUNCATED"
	ReasonAPIUnavailable   Reason = "API_UNAVAILABLE"
	ReasonAPIUnauthorized  Reason = "API_UNAUTHORIZED"
	ReasonAPIRateLimited   Reason = "API_RATE_LIMITED"
	ReasonInternalError    Reason = "PROVIDER_ERROR"
	ReasonUnsupportedOS    Reason = "UNSUPPORTED_PLATFORM"
)

var validReasons = map[Reason]bool{
	ReasonNotDetected: true, ReasonPermissionDenied: true, ReasonPanic: true,
	ReasonTimeout: true, ReasonBackpressure: true, ReasonLogUnreadable: true,
	ReasonLogRotated: true, ReasonLogTruncated: true, ReasonAPIUnavailable: true,
	ReasonAPIUnauthorized: true, ReasonAPIRateLimited: true,
	ReasonInternalError: true, ReasonUnsupportedOS: true,
}

// health is recorded in every section, including failed ones: "provider
// evidence unavailable because X" is itself evidence.
type Health struct {
	State   HealthState `json:"state"`
	Reasons []Reason    `json:"reasons,omitempty"`
	// dropped counts live observations the supervisor discarded because the
	// provider fell behind. A non-zero count makes the section DEGRADED.
	Dropped int `json:"dropped,omitempty"`
}

// lifecycle of a runner (5.32).
type Lifecycle string

const (
	LifecyclePersistent Lifecycle = "PERSISTENT"
	LifecycleEphemeral  Lifecycle = "EPHEMERAL"
	LifecycleUnknown    Lifecycle = "UNKNOWN"
)

// runner is one runner identity seen during the capture.
type Runner struct {
	Ref       Ref       `json:"ref"`
	Name      Text      `json:"name"`    // ClassRunnerName
	Version   Text      `json:"version"` // ClassVersion
	Labels    Text      `json:"labels"`  // ClassLabels
	Lifecycle Lifecycle `json:"lifecycle"`
	// containerized is tri-state: nil means unknown (5.33).
	Containerized *bool `json:"containerized,omitempty"`
	// supervisors are the supervisor (listener) incarnations observed for
	// this runner, oldest first. more than one means a restart (5.34).
	Supervisors []ProcessRef `json:"supervisors"`
}

// worker is one worker incarnation (5.5): a worker is identified by its
// process incarnation, never by PID alone.
type Worker struct {
	Ref     Ref        `json:"ref"`
	Runner  Ref        `json:"runner"`
	Process ProcessRef `json:"process"`
	Job     Ref        `json:"job,omitempty"` // empty: not correlated
	// Started/Exited are observation times; zero means not observed in the
	// capture (onset or end outside the window).
	Started time.Time `json:"started,omitempty"`
	Exited  time.Time `json:"exited,omitempty"`
}

// job is one job execution (5.9). every field may be UNKNOWN.
type Job struct {
	Ref        Ref   `json:"ref"`
	Runner     Ref   `json:"runner"`
	Repository Text  `json:"repository"` // ClassRepository
	Workflow   Text  `json:"workflow"`   // ClassWorkflow
	Name       Text  `json:"name"`       // ClassJobName
	RunID      Int64 `json:"run_id"`     // ClassRunID
	JobID      Int64 `json:"job_id"`     // ClassJobID
	Attempt    Int64 `json:"attempt"`    // ClassAttempt
	// evidence are enumerated reason codes registered by the provider
	// ("CONTAINER_LINKAGE_UNAVAILABLE", ...). container membership is not
	// fully verifiable on every platform (C5/5.33); a job states honestly
	// when its process list may be incomplete.
	Evidence []string `json:"evidence,omitempty"`
	// outcome is the provider's own verdict when known (5.44-5.46).
	Outcome           Outcome   `json:"outcome"`
	OutcomeSource     Source    `json:"outcome_source,omitempty"`
	OutcomeObservedAt time.Time `json:"outcome_observed_at,omitempty"`
	// StartedAt and CompletedAt are optional provider timestamps. their source
	// is paired explicitly so API-derived times remain distinguishable offline.
	StartedAt            time.Time `json:"started_at,omitempty"`
	StartedAtSource      Source    `json:"started_at_source,omitempty"`
	CompletedAt          time.Time `json:"completed_at,omitempty"`
	CompletedAtSource    Source    `json:"completed_at_source,omitempty"`
	RunStartedAt         time.Time `json:"run_started_at,omitempty"`
	RunStartedAtSource   Source    `json:"run_started_at_source,omitempty"`
	RunCompletedAt       time.Time `json:"run_completed_at,omitempty"`
	RunCompletedAtSource Source    `json:"run_completed_at_source,omitempty"`
}

// outcome is an enumerated job/runner outcome. intentional outcomes suppress
// "unexplained failure" conclusions (architecture.md §7).
type Outcome string

const (
	OutcomeUnknown   Outcome = "UNKNOWN"
	OutcomeRunning   Outcome = "RUNNING"
	OutcomeSucceeded Outcome = "SUCCEEDED"
	OutcomeFailed    Outcome = "FAILED"
	OutcomeCancelled Outcome = "CANCELLED"
	OutcomeTimedOut  Outcome = "TIMED_OUT"
)

var validOutcomes = map[Outcome]bool{
	OutcomeUnknown: true, OutcomeRunning: true, OutcomeSucceeded: true,
	OutcomeFailed: true, OutcomeCancelled: true, OutcomeTimedOut: true,
}

// role is what a process is to the provider.
type Role string

const (
	RoleSupervisor Role = "RUNNER_SUPERVISOR" // e.g. Runner.Listener
	RoleWorker     Role = "RUNNER_WORKER"     // e.g. Runner.Worker
	RoleJobRoot    Role = "JOB_ROOT"          // first job process under the worker
	RoleJobProcess Role = "JOB_PROCESS"       // any other job descendant
	RoleHelper     Role = "RUNNER_HELPER"     // updater, service wrapper
)

var validRoles = map[Role]bool{
	RoleSupervisor: true, RoleWorker: true, RoleJobRoot: true,
	RoleJobProcess: true, RoleHelper: true,
}

// confidence of a correlation. same meaning as causal bands: how surprised a
// reader should be if it is wrong (causal-semantics.md §2.1).
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

var validConfidence = map[Confidence]bool{ConfidenceHigh: true, ConfidenceMedium: true, ConfidenceLow: true}

// ProcessRole tags one process incarnation with its provider role.
type ProcessRole struct {
	Process    ProcessRef `json:"process"`
	Role       Role       `json:"role"`
	Runner     Ref        `json:"runner"`
	Worker     Ref        `json:"worker,omitempty"`
	Job        Ref        `json:"job,omitempty"`
	Confidence Confidence `json:"confidence"`
	Sources    []Source   `json:"sources"`
	// evidence are enumerated reason codes registered by the provider
	// ("EXE_BASENAME_MATCH", "PARENT_IS_SUPERVISOR", ...).
	Evidence []string `json:"evidence"`
}

// SocketRole tags one socket with its provider role (5.15).
type SocketRole struct {
	Inode      uint64     `json:"inode"`
	Owner      ProcessRef `json:"owner"`
	Role       string     `json:"role"` // provider vocabulary, e.g. "CONTROL_CHANNEL"
	Runner     Ref        `json:"runner"`
	Confidence Confidence `json:"confidence"`
	Sources    []Source   `json:"sources"`
	Evidence   []string   `json:"evidence"`
}

// event is one provider event (5.8). type is a provider-registered,
// namespaced enumeration (GITHUB_JOB_ASSIGNED). there is no message field.
type Event struct {
	Timestamp time.Time   `json:"timestamp"`
	Type      string      `json:"type"`
	Runner    Ref         `json:"runner,omitempty"`
	Job       Ref         `json:"job,omitempty"`
	Worker    Ref         `json:"worker,omitempty"`
	Process   *ProcessRef `json:"process,omitempty"`
	Outcome   Outcome     `json:"outcome,omitempty"`
	Source    Source      `json:"source"`
	// provenance points at where the fact came from without copying it:
	// which collected file (by index into the provider's own file list,
	// never a path) and which byte offset.
	Provenance Provenance `json:"provenance"`
}

// provenance of a provider fact (5.47).
type Provenance struct {
	File   int   `json:"file,omitempty"`   // 1-based provider-local file index; 0 = none
	Offset int64 `json:"offset,omitempty"` // byte offset of the source record
	// sample is the 1-based core snapshot index the fact was derived from;
	// 0 = none. (1-based so the zero value cannot alias snapshot 0.)
	Sample int `json:"sample,omitempty"`
}

// conflict records disagreeing sources about one question (5.48). conflicts
// are never resolved silently; see architecture.md §8.
type Conflict struct {
	Question string  `json:"question"` // e.g. "JOB_STATE"
	Job      Ref     `json:"job,omitempty"`
	Runner   Ref     `json:"runner,omitempty"`
	Claims   []Claim `json:"claims"`
}

// claim is one source's answer to a conflict question.
type Claim struct {
	Source     Source    `json:"source"`
	Value      string    `json:"value"` // provider vocabulary enum
	ObservedAt time.Time `json:"observed_at"`
}

// PrivacyLevel of the section.
type PrivacyLevel string

const (
	// PrivacyConservative: only VERSION text is KNOWN; every other class is
	// WITHHELD. the default, matching the core conservative-v1 policy.
	PrivacyConservative PrivacyLevel = "conservative"
	// PrivacyIdentifiers: the user opted in to runner, repository, workflow
	// and job identifiers so reports can name them.
	PrivacyIdentifiers PrivacyLevel = "identifiers"
)

// section is the provider section embedded in an incident bundle.
type Section struct {
	Provider      string        `json:"provider"`
	SchemaVersion int           `json:"schema_version"`
	Privacy       PrivacyLevel  `json:"privacy"`
	Health        Health        `json:"health"`
	Runners       []Runner      `json:"runners"`
	Workers       []Worker      `json:"workers"`
	Jobs          []Job         `json:"jobs"`
	ProcessRoles  []ProcessRole `json:"process_roles"`
	SocketRoles   []SocketRole  `json:"socket_roles"`
	Events        []Event       `json:"events"`
	Conflicts     []Conflict    `json:"conflicts"`
	// StallWindowSeconds is the job-progress stall window the provider used
	// (audit F4). zero means not recorded (older bundles, or a provider
	// without such a window).
	StallWindowSeconds int64 `json:"stall_window_seconds,omitempty"`
}

// bounds for StallWindowSeconds when recorded.
const (
	MinStallWindowSeconds = 10
	MaxStallWindowSeconds = 24 * 60 * 60
)

// unavailable builds the section recorded when the provider produced no
// evidence. it is still written: the absence must be explainable.
func Unavailable(provider string, reasons ...Reason) Section {
	return Section{
		Provider: provider, SchemaVersion: SchemaVersion, Privacy: PrivacyConservative,
		Health: Health{State: HealthUnavailable, Reasons: reasons},
	}
}

// ---------------------------------------------------------------------------
// vocabulary registry
// ---------------------------------------------------------------------------

// vocabulary is the closed set of provider-specific enumerations. A provider
// registers it at init; validate rejects anything outside it, so a parser bug
// or a hostile log line cannot invent tokens that end up in a bundle.
type Vocabulary struct {
	Provider       string
	EventPrefix    string // e.g. "GITHUB_"; every event type must start with it
	EventTypes     []string
	SocketRoles    []string
	EvidenceCodes  []string
	ConflictTopics []string
	ClaimValues    []string
}

var (
	vocabMu sync.RWMutex
	vocabs  = map[string]vocabSets{}
)

type vocabSets struct {
	prefix                                    string
	events, sockets, evidence, topics, claims map[string]bool
	// structural: the provider is not compiled into this binary. its tokens
	// are checked for shape only (principal phase 5 audit R17): a reader must
	// accept a bundle from a newer or different agent, and InterpretAll then
	// reports the section UNAVAILABLE, so unknown evidence still never
	// strengthens a diagnosis. writers always validate against a registered
	// vocabulary, because the recording provider registered it.
	structural bool
}

func (v vocabSets) has(set map[string]bool, token string) bool {
	if v.structural {
		return tokenPattern.MatchString(token)
	}
	return set[token]
}

var (
	providerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	tokenPattern        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
)

// RegisterVocabulary installs a provider's vocabulary. it panics on malformed
// input: vocabularies are compiled-in constants, so this is a programmer error.
func RegisterVocabulary(v Vocabulary) {
	if !providerNamePattern.MatchString(v.Provider) {
		panic(fmt.Sprintf("evidence: invalid provider name %q", v.Provider))
	}
	if !tokenPattern.MatchString(strings.TrimSuffix(v.EventPrefix, "_")) || !strings.HasSuffix(v.EventPrefix, "_") {
		panic(fmt.Sprintf("evidence: invalid event prefix %q", v.EventPrefix))
	}
	set := func(list []string, needPrefix bool) map[string]bool {
		out := make(map[string]bool, len(list))
		for _, t := range list {
			if !tokenPattern.MatchString(t) || (needPrefix && !strings.HasPrefix(t, v.EventPrefix)) {
				panic(fmt.Sprintf("evidence: invalid vocabulary token %q for %s", t, v.Provider))
			}
			out[t] = true
		}
		return out
	}
	vocabMu.Lock()
	defer vocabMu.Unlock()
	if _, dup := vocabs[v.Provider]; dup {
		panic(fmt.Sprintf("evidence: vocabulary for %s registered twice", v.Provider))
	}
	vocabs[v.Provider] = vocabSets{
		prefix:   v.EventPrefix,
		events:   set(v.EventTypes, true),
		sockets:  set(v.SocketRoles, false),
		evidence: set(v.EvidenceCodes, false),
		topics:   set(v.ConflictTopics, false),
		claims:   set(v.ClaimValues, false),
	}
}

func vocabulary(provider string) (vocabSets, bool) {
	vocabMu.RLock()
	defer vocabMu.RUnlock()
	v, ok := vocabs[provider]
	return v, ok
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

// validate checks a section against the schema, bounds and the provider's
// registered vocabulary. it is called on write and on read.
func (s *Section) Validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("evidence: unsupported provider schema version %d", s.SchemaVersion)
	}
	if s.StallWindowSeconds != 0 && (s.StallWindowSeconds < MinStallWindowSeconds || s.StallWindowSeconds > MaxStallWindowSeconds) {
		return fmt.Errorf("evidence: stall window %ds outside [%d, %d]", s.StallWindowSeconds, MinStallWindowSeconds, MaxStallWindowSeconds)
	}
	vocab, ok := vocabulary(s.Provider)
	if !ok {
		if !providerNamePattern.MatchString(s.Provider) {
			return fmt.Errorf("evidence: invalid provider name %q", s.Provider)
		}
		vocab = vocabSets{structural: true}
	}
	switch s.Privacy {
	case PrivacyConservative, PrivacyIdentifiers:
	default:
		return fmt.Errorf("evidence: unknown privacy level %q", s.Privacy)
	}
	if err := s.Health.validate(); err != nil {
		return err
	}
	if len(s.Runners) > MaxRunners || len(s.Workers) > MaxWorkers || len(s.Jobs) > MaxJobs ||
		len(s.ProcessRoles) > MaxProcessRoles || len(s.SocketRoles) > MaxSocketRoles ||
		len(s.Events) > MaxEvents || len(s.Conflicts) > MaxConflicts {
		return fmt.Errorf("evidence: provider section exceeds its record bounds")
	}
	runners := map[Ref]bool{}
	for i, r := range s.Runners {
		if !r.Ref.Valid() || !strings.HasPrefix(string(r.Ref), "rnr_") {
			return fmt.Errorf("evidence: runner %d has an invalid ref", i)
		}
		if runners[r.Ref] {
			return fmt.Errorf("evidence: duplicate runner ref %s", r.Ref)
		}
		runners[r.Ref] = true
		for _, t := range []struct {
			text  Text
			class Class
		}{{r.Name, ClassRunnerName}, {r.Version, ClassVersion}, {r.Labels, ClassLabels}} {
			if err := t.text.validate(t.class, s.Privacy); err != nil {
				return fmt.Errorf("evidence: runner %s: %w", r.Ref, err)
			}
		}
		switch r.Lifecycle {
		case LifecyclePersistent, LifecycleEphemeral, LifecycleUnknown:
		default:
			return fmt.Errorf("evidence: runner %s: invalid lifecycle %q", r.Ref, r.Lifecycle)
		}
		for _, p := range r.Supervisors {
			if err := p.validate(); err != nil {
				return fmt.Errorf("evidence: runner %s supervisor: %w", r.Ref, err)
			}
		}
	}
	refok := func(ref Ref, kind string, optional bool) bool {
		if ref == "" {
			return optional
		}
		return ref.Valid() && strings.HasPrefix(string(ref), kind+"_")
	}
	runnerok := func(ref Ref, optional bool) bool {
		if ref == "" {
			return optional
		}
		return refok(ref, "rnr", false) && runners[ref]
	}
	jobs := map[Ref]bool{}
	for i, j := range s.Jobs {
		if !refok(j.Ref, "job", false) || jobs[j.Ref] {
			return fmt.Errorf("evidence: job %d has an invalid or duplicate ref", i)
		}
		jobs[j.Ref] = true
		if !runnerok(j.Runner, false) {
			return fmt.Errorf("evidence: job %s names an unknown runner", j.Ref)
		}
		if err := validateJobEvidence(j.Evidence, vocab); err != nil {
			return fmt.Errorf("evidence: job %s: %w", j.Ref, err)
		}
		for _, t := range []struct {
			text  Text
			class Class
		}{{j.Repository, ClassRepository}, {j.Workflow, ClassWorkflow}, {j.Name, ClassJobName}} {
			if err := t.text.validate(t.class, s.Privacy); err != nil {
				return fmt.Errorf("evidence: job %s: %w", j.Ref, err)
			}
		}
		for _, n := range []struct {
			v     Int64
			class Class
		}{{j.RunID, ClassRunID}, {j.JobID, ClassJobID}, {j.Attempt, ClassAttempt}} {
			if err := n.v.validate(n.class, s.Privacy); err != nil {
				return fmt.Errorf("evidence: job %s: %w", j.Ref, err)
			}
		}
		if !validOutcomes[j.Outcome] {
			return fmt.Errorf("evidence: job %s: invalid outcome %q", j.Ref, j.Outcome)
		}
		if j.OutcomeSource != "" && !validSources[j.OutcomeSource] {
			return fmt.Errorf("evidence: job %s: invalid outcome source", j.Ref)
		}
		if (j.OutcomeSource == "") != j.OutcomeObservedAt.IsZero() {
			return fmt.Errorf("evidence: job %s: outcome provenance must include both source and time", j.Ref)
		}
		for _, timestamp := range []struct {
			value  time.Time
			source Source
		}{{j.StartedAt, j.StartedAtSource}, {j.CompletedAt, j.CompletedAtSource}, {j.RunStartedAt, j.RunStartedAtSource}, {j.RunCompletedAt, j.RunCompletedAtSource}} {
			if timestamp.source == "" && !timestamp.value.IsZero() || timestamp.source != "" && timestamp.value.IsZero() {
				return fmt.Errorf("evidence: job %s: timestamp provenance must include both source and time", j.Ref)
			}
			if timestamp.source != "" && !validSources[timestamp.source] {
				return fmt.Errorf("evidence: job %s: invalid timestamp source", j.Ref)
			}
		}
		if !j.StartedAt.IsZero() && !j.CompletedAt.IsZero() && j.CompletedAt.Before(j.StartedAt) {
			return fmt.Errorf("evidence: job %s: completion precedes start", j.Ref)
		}
		if !j.RunStartedAt.IsZero() && !j.RunCompletedAt.IsZero() && j.RunCompletedAt.Before(j.RunStartedAt) {
			return fmt.Errorf("evidence: job %s: run completion precedes start", j.Ref)
		}
	}
	jobok := func(ref Ref) bool { return ref == "" || (refok(ref, "job", false) && jobs[ref]) }
	workers := map[Ref]bool{}
	for i, w := range s.Workers {
		if !refok(w.Ref, "wkr", false) || workers[w.Ref] {
			return fmt.Errorf("evidence: worker %d has an invalid or duplicate ref", i)
		}
		workers[w.Ref] = true
		if !runnerok(w.Runner, false) || !jobok(w.Job) {
			return fmt.Errorf("evidence: worker %s names an unknown runner or job", w.Ref)
		}
		if err := w.Process.validate(); err != nil {
			return fmt.Errorf("evidence: worker %s: %w", w.Ref, err)
		}
		if !w.Started.IsZero() && !w.Exited.IsZero() && w.Exited.Before(w.Started) {
			return fmt.Errorf("evidence: worker %s exits before it starts", w.Ref)
		}
	}
	workerok := func(ref Ref) bool { return ref == "" || (refok(ref, "wkr", false) && workers[ref]) }
	for i, pr := range s.ProcessRoles {
		if err := pr.Process.validate(); err != nil {
			return fmt.Errorf("evidence: process role %d: %w", i, err)
		}
		if !validRoles[pr.Role] || !validConfidence[pr.Confidence] {
			return fmt.Errorf("evidence: process role %d: invalid role or confidence", i)
		}
		if !runnerok(pr.Runner, false) || !workerok(pr.Worker) || !jobok(pr.Job) {
			return fmt.Errorf("evidence: process role %d names an unknown runner, worker or job", i)
		}
		if err := validateProvenanceLists(pr.Sources, pr.Evidence, vocab); err != nil {
			return fmt.Errorf("evidence: process role %d: %w", i, err)
		}
	}
	for i, sr := range s.SocketRoles {
		if sr.Inode == 0 {
			return fmt.Errorf("evidence: socket role %d has no inode", i)
		}
		if err := sr.Owner.validate(); err != nil {
			return fmt.Errorf("evidence: socket role %d: %w", i, err)
		}
		if !vocab.has(vocab.sockets, sr.Role) || !validConfidence[sr.Confidence] || !runnerok(sr.Runner, false) {
			return fmt.Errorf("evidence: socket role %d: invalid role, confidence or runner", i)
		}
		if err := validateProvenanceLists(sr.Sources, sr.Evidence, vocab); err != nil {
			return fmt.Errorf("evidence: socket role %d: %w", i, err)
		}
	}
	for i, e := range s.Events {
		if e.Timestamp.IsZero() || !vocab.has(vocab.events, e.Type) || !validSources[e.Source] {
			return fmt.Errorf("evidence: event %d: invalid timestamp, type or source", i)
		}
		if !runnerok(e.Runner, true) || !jobok(e.Job) || !workerok(e.Worker) {
			return fmt.Errorf("evidence: event %d names an unknown runner, worker or job", i)
		}
		if e.Outcome != "" && !validOutcomes[e.Outcome] {
			return fmt.Errorf("evidence: event %d: invalid outcome", i)
		}
		if e.Process != nil {
			if err := e.Process.validate(); err != nil {
				return fmt.Errorf("evidence: event %d: %w", i, err)
			}
		}
		if e.Provenance.File < 0 || e.Provenance.Offset < 0 || e.Provenance.Sample < 0 {
			return fmt.Errorf("evidence: event %d: invalid provenance", i)
		}
	}
	for i, c := range s.Conflicts {
		if !vocab.has(vocab.topics, c.Question) || len(c.Claims) < 2 {
			return fmt.Errorf("evidence: conflict %d: unknown topic or fewer than two claims", i)
		}
		if !jobok(c.Job) || !runnerok(c.Runner, true) {
			return fmt.Errorf("evidence: conflict %d names an unknown runner or job", i)
		}
		for _, cl := range c.Claims {
			if !validSources[cl.Source] || !vocab.has(vocab.claims, cl.Value) || cl.ObservedAt.IsZero() {
				return fmt.Errorf("evidence: conflict %d: invalid claim", i)
			}
		}
	}
	return nil
}

func (h Health) validate() error {
	switch h.State {
	case HealthAvailable, HealthDegraded, HealthUnavailable, HealthDisabled:
	default:
		return fmt.Errorf("evidence: invalid health state %q", h.State)
	}
	if len(h.Reasons) > MaxReasons || h.Dropped < 0 {
		return fmt.Errorf("evidence: invalid health detail")
	}
	for _, r := range h.Reasons {
		if !validReasons[r] {
			return fmt.Errorf("evidence: invalid health reason %q", r)
		}
	}
	if h.Dropped > 0 && h.State == HealthAvailable {
		return fmt.Errorf("evidence: dropped observations require DEGRADED health")
	}
	return nil
}

func (p ProcessRef) validate() error {
	if p.PID <= 0 || p.StartTicks < 0 {
		return fmt.Errorf("invalid process identity %d@%d", p.PID, p.StartTicks)
	}
	return nil
}

// validateJobEvidence checks a job's marker codes: each must be a registered
// provider evidence code and appear once. unlike the process and socket role
// lists, job markers carry no provenance pair (job has no sources field);
// they state the job's own capture conditions (C5/5.33).
func validateJobEvidence(codes []string, vocab vocabSets) error {
	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if !vocab.has(vocab.evidence, c) {
			return fmt.Errorf("unregistered evidence code %q", c)
		}
		if seen[c] {
			return fmt.Errorf("duplicate evidence code %q", c)
		}
		seen[c] = true
	}
	return nil
}

func validateProvenanceLists(sources []Source, codes []string, vocab vocabSets) error {
	if len(sources) == 0 || len(codes) == 0 {
		return fmt.Errorf("a correlation needs at least one source and one evidence code")
	}
	for _, s := range sources {
		if !validSources[s] {
			return fmt.Errorf("invalid source %q", s)
		}
	}
	for _, c := range codes {
		if !vocab.has(vocab.evidence, c) {
			return fmt.Errorf("unregistered evidence code %q", c)
		}
	}
	return nil
}

// textAllowed is the privacy policy table (architecture.md §9.2).
func textAllowed(class Class, level PrivacyLevel) bool {
	if class == ClassVersion {
		return true
	}
	return level == PrivacyIdentifiers
}

// safeText bounds the characters a KNOWN value may contain: printable,
// no control or format characters, no URL schemes, no credential markers.
var credentialMarkers = []string{"://", "token", "bearer", "authorization", "ghp_", "gho_", "ghs_", "ghr_", "github_pat_", "x-access", "sig=", "signature=", "password", "secret"}

func safeText(v string) error {
	if len(v) == 0 || len(v) > MaxTextBytes || !utf8.ValidString(v) {
		return fmt.Errorf("value is empty, too long or not UTF-8")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return fmt.Errorf("value contains control characters")
		}
		switch r {
		case 0x200b, 0x200c, 0x200d, 0x2028, 0x2029, 0x202e, 0xfeff:
			return fmt.Errorf("value contains invisible or format characters")
		}
	}
	// Percent-encoded forms (https%3A%2F%2F, ghs%5F) must hit the same markers
	// as their decoded text, so decode a few rounds before matching.
	decoded := v
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	lower := strings.ToLower(v)
	lowerdecoded := strings.ToLower(decoded)
	for _, m := range credentialMarkers {
		if strings.Contains(lower, m) || strings.Contains(lowerdecoded, m) {
			return fmt.Errorf("value looks like a URL or credential")
		}
	}
	if jwtShape.MatchString(decoded) || looksOpaque(decoded) {
		return fmt.Errorf("value looks like a token")
	}
	return nil
}

// jwtShape matches a JSON web token: base64url JSON header ("eyJ"), then two
// more base64url segments.
var jwtShape = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}`)

// opaqueRun matches a run with no separators that could be an encoded token.
var opaqueRun = regexp.MustCompile(`[A-Za-z0-9+/=_]{20,}`)

// looksOpaque reports whether a long separator-free run mixes letters and
// digits, the shape of hex digests and random tokens. hyphenated names split
// into short runs and pass.
func looksOpaque(s string) bool {
	for _, run := range opaqueRun.FindAllString(s, -1) {
		hasdigit, hasletter := false, false
		for _, r := range run {
			switch {
			case r >= '0' && r <= '9':
				hasdigit = true
			case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
				hasletter = true
			}
		}
		if hasdigit && hasletter {
			return true
		}
	}
	return false
}

func (t Text) validate(class Class, level PrivacyLevel) error {
	if t.Class != class {
		return fmt.Errorf("text has class %q, want %q", t.Class, class)
	}
	switch t.State {
	case Unknown, Withheld:
		if t.Value != "" {
			return fmt.Errorf("%s %s value must be empty", t.State, class)
		}
		return nil
	case Known:
		if !textAllowed(class, level) {
			return fmt.Errorf("%s may not be KNOWN under privacy %q", class, level)
		}
		if !validSources[t.Source] {
			return fmt.Errorf("%s has an invalid source", class)
		}
		return safeText(t.Value)
	}
	return fmt.Errorf("text %s has invalid state %q", class, t.State)
}

func (n Int64) validate(class Class, level PrivacyLevel) error {
	if n.Class != class {
		return fmt.Errorf("number has class %q, want %q", n.Class, class)
	}
	switch n.State {
	case Unknown, Withheld:
		if n.Value != 0 {
			return fmt.Errorf("%s %s value must be zero", n.State, class)
		}
		return nil
	case Known:
		if !textAllowed(class, level) {
			return fmt.Errorf("%s may not be KNOWN under privacy %q", class, level)
		}
		if n.Value <= 0 || !validSources[n.Source] {
			return fmt.Errorf("%s needs a positive value and a valid source", class)
		}
		return nil
	}
	return fmt.Errorf("number %s has invalid state %q", class, n.State)
}

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

// redact applies the privacy level in place: every KNOWN value whose class
// the level does not allow becomes WITHHELD (value and source cleared), and
// every KNOWN value that fails the safe-text check becomes WITHHELD too, so a
// value that slipped past the provider never reaches the bundle. order of
// slices is normalised for deterministic output.
func (s *Section) Redact(level PrivacyLevel) {
	s.Privacy = level
	withhold := func(t *Text) {
		if t.State == Known && (!textAllowed(t.Class, level) || safeText(t.Value) != nil) {
			*t = Text{State: Withheld, Class: t.Class}
		}
	}
	withholdn := func(n *Int64) {
		if n.State == Known && !textAllowed(n.Class, level) {
			*n = Int64{State: Withheld, Class: n.Class}
		}
	}
	for i := range s.Runners {
		withhold(&s.Runners[i].Name)
		withhold(&s.Runners[i].Version)
		withhold(&s.Runners[i].Labels)
	}
	for i := range s.Jobs {
		withhold(&s.Jobs[i].Repository)
		withhold(&s.Jobs[i].Workflow)
		withhold(&s.Jobs[i].Name)
		withholdn(&s.Jobs[i].RunID)
		withholdn(&s.Jobs[i].JobID)
		withholdn(&s.Jobs[i].Attempt)
	}
	sort.SliceStable(s.Events, func(i, j int) bool { return s.Events[i].Timestamp.Before(s.Events[j].Timestamp) })
}
