// package provider is the CI-provider abstraction (phase 5 item 5.1,
// docs/providers/architecture.md). it is provider-neutral: it names no CI
// system. concrete providers live in subpackages (internal/provider/github)
// and are wired in only by cmd/ binaries, so the recorder, the bundle format,
// the diagnosis engine and the causal engine never depend on GitHub.
//
// A provider has two halves with different rules:
//
//   - the LIVE half (detect, discover, Attach/Session) runs on the host while
//     recording. it may read procfs, the runner's diagnostic logs and its
//     installation metadata. it converts what it sees into typed, enumerated,
//     redactable evidence (package evidence) at capture time, because the
//     bundle keeps no names, paths, command lines or addresses: a fact that is
//     not turned into evidence while the host is live is lost.
//   - the OFFLINE half (interpret) runs on a bundle. it is pure: no file,
//     process, network or clock access. everything a diagnosis needs must be
//     in the bundle (5.38).
//
// remote API enrichment (enricher) is optional and never required for
// recording or diagnosis (5.11, 5.37).
package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
	"runopsy/internal/provider/evidence"
)

// HostView is the provider's read-only window onto the live host. the agent
// implements it; tests implement it with fixtures.
type HostView interface {
	// processes returns a full process table (not the recorder's filtered
	// view). implementations may cache; providers must not call it more than
	// once per discovery pass.
	Processes(ctx context.Context) ([]platform.Process, error)
	// inspect reads live-only details of one process incarnation. it fails
	// if the PID now belongs to a different incarnation.
	Inspect(ctx context.Context, p evidence.ProcessRef) (ProcessDetail, error)
	// now is the host clock.
	Now() time.Time
	// salt is the per-installation salt for evidence.NewRef.
	Salt() []byte
}

// ProcessDetail is live-only process information used for classification.
// it is never serialized (every field is json:"-") and has deliberately no
// environment field: providers must not read process environments (5.12).
type ProcessDetail struct {
	Process    platform.Process `json:"-"`
	Executable string           `json:"-"` // resolved executable path
	WorkingDir string           `json:"-"`
	Argv       []string         `json:"-"`
}

// detection is the cheap "is this provider plausibly present?" answer.
type Detection struct {
	Present    bool
	Candidates int // supervisor candidates seen
	Reasons    []evidence.Reason
}

// RunnerInstance is one discovered runner (5.2-5.4). identity is ref, never a
// PID; supervisor is the current supervisor incarnation.
type RunnerInstance struct {
	Provider      string
	Ref           evidence.Ref
	Supervisor    evidence.ProcessRef
	Name          evidence.Text
	Version       evidence.Text
	Lifecycle     evidence.Lifecycle
	Containerized *bool
	// private is provider-owned live state (installation root, diagnostic
	// directory, ...). it is never serialized and never leaves the provider.
	Private any `json:"-"`
}

// budget bounds a session's resource use (5.49).
type Budget struct {
	MaxLogBytesPerSecond int64 // log tailing read rate
	MaxRetainedLogBytes  int64 // parsed-event backlog kept in memory
	MaxTrackedProcesses  int   // role-tagged process incarnations retained
}

// DefaultBudget is conservative for a recorder that must stay light.
func DefaultBudget() Budget {
	return Budget{MaxLogBytesPerSecond: 1 << 20, MaxRetainedLogBytes: 8 << 20, MaxTrackedProcesses: 20000}
}

// AttachOptions configures a live session.
type AttachOptions struct {
	Privacy evidence.PrivacyLevel
	// runners pins the session to discovered runners; empty means the
	// session discovers (and re-discovers) on its own.
	Runners []RunnerInstance
	// SupervisorPIDs is the manual override (5.2); facts derived from it
	// carry evidence.SourceUserOverride.
	SupervisorPIDs []int
	Budget         Budget
}

// session is one live observation session. the supervisor calls every
// method from a single goroutine, so implementations need no locking of their
// own against these calls.
type Session interface {
	// observe receives each completed recorder snapshot. the snapshot is a
	// detached copy and must not be retained beyond the provider's own
	// bounded state.
	Observe(ctx context.Context, s collector.Snapshot)
	// freeze returns the provider evidence for [from, to] (the incident
	// capture window). the section must validate; the supervisor redacts it
	// to the configured privacy level afterwards.
	Freeze(ctx context.Context, from, to time.Time) (evidence.Section, error)
	// close releases resources (log handles, goroutines).
	Close() error
}

// GenericKind is a provider-neutral event the causal engine understands.
// providers translate their own events into these where a generic concept
// exists (5.8); everything provider-specific stays in the provider section.
type GenericKind string

const (
	GenericRunnerStarted         GenericKind = "RUNNER_STARTED"
	GenericRunnerStopped         GenericKind = "RUNNER_STOPPED"
	GenericWorkAssigned          GenericKind = "WORK_ASSIGNED"
	GenericWorkerStarted         GenericKind = "WORKER_STARTED"
	GenericWorkerExited          GenericKind = "WORKER_EXITED"
	GenericWorkerProgressStopped GenericKind = "WORKER_PROGRESS_STOPPED"
	GenericTerminationIntended   GenericKind = "TERMINATION_INTENDED"
)

// intent qualifies TERMINATION_INTENDED (5.44-5.46). an intended termination
// is a fact that suppresses "unexplained failure" conclusions for the
// processes it covers; it is never inferred from the termination itself.
type Intent string

const (
	IntentCancelled         Intent = "CANCELLED"
	IntentTimedOut          Intent = "TIMED_OUT"
	IntentServiceShutdown   Intent = "SERVICE_SHUTDOWN"
	IntentEphemeralComplete Intent = "EPHEMERAL_COMPLETE"
	IntentUpdate            Intent = "RUNNER_UPDATE"
	// IntentJobSucceeded: the job's stated result was SUCCEEDED, so its
	// worker's and job tree's exits are the normal end of a job, not a kill.
	IntentJobSucceeded Intent = "JOB_SUCCEEDED"
)

// GenericEvent is one translated event.
type GenericEvent struct {
	Timestamp    time.Time
	Kind         GenericKind
	Intent       Intent // only for TERMINATION_INTENDED
	Process      *evidence.ProcessRef
	Runner       evidence.Ref
	Worker       evidence.Ref
	Job          evidence.Ref
	Source       evidence.Source
	Confidence   evidence.Confidence
	ProviderType string // the provider event it came from, for rendering
}

// interpretation is the offline result for one provider section.
type Interpretation struct {
	Provider   string
	Section    evidence.Section // validated, as stored
	Generic    []GenericEvent   // sorted by timestamp, deterministic
	Signatures []Signature      // provider-specific findings, reported beside generic
}

// signature is a provider-specific finding in neutral form. it carries refs,
// times and registered evidence codes only, never log text.
type Signature struct {
	Label      string
	Confidence evidence.Confidence
	Runner     evidence.Ref
	Job        evidence.Ref
	Onset      time.Time
	Evidence   []string
}

// provider is one CI system integration.
type Provider interface {
	// name is the registry key, e.g. "github-actions".
	Name() string
	// vocabulary is the provider's closed set of evidence tokens.
	Vocabulary() evidence.Vocabulary
	// detect is cheap and local: no network, bounded procfs reads.
	Detect(ctx context.Context, host HostView) (Detection, error)
	// discover enumerates runner instances (5.2-5.4). local only.
	Discover(ctx context.Context, host HostView) ([]RunnerInstance, error)
	// attach starts a live session.
	Attach(ctx context.Context, host HostView, opts AttachOptions) (Session, error)
	// interpret is offline and pure (no I/O, no clock): the same section and
	// incident always give the same Interpretation.
	Interpret(section evidence.Section, inc *incident.Incident) (Interpretation, error)
}

// credentials supplies an API secret at the moment of use. providers must not
// store, log, wrap into errors or serialize the returned value (5.12).
type Credentials interface {
	Token(ctx context.Context) (string, error)
}

// enricher is the optional remote-API half (5.11). it adds facts with
// evidence.SourceProviderAPI to a section and records disagreements as
// conflicts; it never removes or overrides local facts (architecture.md §8).
// A failure returns a health describing why enrichment is unavailable.
type Enricher interface {
	Enrich(ctx context.Context, section *evidence.Section, creds Credentials) evidence.Health
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// registry holds the providers compiled into a binary.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{providers: map[string]Provider{}} }

// default is the registry cmd/ binaries populate.
var Default = NewRegistry()

// register adds a provider and installs its vocabulary.
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return fmt.Errorf("provider: nil provider")
	}
	name := p.Name()
	if !namePattern.MatchString(name) {
		return fmt.Errorf("provider: invalid name %q", name)
	}
	vocab := p.Vocabulary()
	if vocab.Provider != name {
		return fmt.Errorf("provider: %s vocabulary is registered under %q", name, vocab.Provider)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.providers[name]; dup {
		return fmt.Errorf("provider: %s registered twice", name)
	}
	if err := registerVocabularyOnce(vocab); err != nil {
		return err
	}
	r.providers[name] = p
	return nil
}

var (
	vocabOnceMu sync.Mutex
	vocabDone   = map[string]bool{}
)

// registerVocabularyOnce lets several registries (tests) share one global
// vocabulary table without double registration.
func registerVocabularyOnce(v evidence.Vocabulary) (err error) {
	vocabOnceMu.Lock()
	defer vocabOnceMu.Unlock()
	if vocabDone[v.Provider] {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("provider: %v", r)
		}
	}()
	evidence.RegisterVocabulary(v)
	vocabDone[v.Provider] = true
	return nil
}

// get returns a provider by name.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// all returns providers sorted by name (deterministic).
func (r *Registry) All() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// InterpretAll interprets every provider section of an incident. A section
// whose provider is not compiled in, or that fails validation, yields an
// interpretation with UNAVAILABLE health and no generic events: unknown
// provider evidence can never strengthen a diagnosis.
func (r *Registry) InterpretAll(sections []evidence.Section, inc *incident.Incident) []Interpretation {
	out := make([]Interpretation, 0, len(sections))
	for _, section := range sections {
		p, ok := r.Get(section.Provider)
		if !ok {
			out = append(out, unavailableInterpretation(section.Provider, evidence.ReasonNotDetected))
			continue
		}
		if err := section.Validate(); err != nil {
			out = append(out, unavailableInterpretation(section.Provider, evidence.ReasonInternalError))
			continue
		}
		interp, err := safeInterpret(p, section, inc)
		if err != nil {
			out = append(out, unavailableInterpretation(section.Provider, evidence.ReasonInternalError))
			continue
		}
		out = append(out, interp)
	}
	return out
}

func safeInterpret(p Provider, section evidence.Section, inc *incident.Incident) (interp Interpretation, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("provider %s: interpret panicked", p.Name())
		}
	}()
	interp, err = p.Interpret(section, inc)
	if err == nil {
		sort.SliceStable(interp.Generic, func(i, j int) bool {
			return interp.Generic[i].Timestamp.Before(interp.Generic[j].Timestamp)
		})
	}
	return interp, err
}

func unavailableInterpretation(name string, reason evidence.Reason) Interpretation {
	return Interpretation{Provider: name, Section: evidence.Unavailable(name, reason)}
}
