// package incident preserves observations, not diagnoses. its v1 bundles are
// bounded ZIP archives with versioned JSON and SHA-256 component checksums.
package incident

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"time"
	"unicode/utf8"

	"deprehendo/internal/collector"
	"deprehendo/internal/platform"
	"deprehendo/internal/provider/evidence"
)

const SchemaVersion = 1
const AgentVersion = "0.3.4"
const MaxPayloadBytes = 64 << 20
const MaxSnapshots = 10000
const MaxEvents = 100000

// MaxEvidenceRecords bounds decoded record amplification independently of bytes.
const MaxEvidenceRecords = 250000

// MaxProviders bounds how many provider sections one bundle may embed
// (docs/providers/architecture.md §1 item 8: multi-provider from day one).
const MaxProviders = 8

var validID = regexp.MustCompile(`^inc_[a-f0-9]{32}$`)

type Trigger struct {
	Type       string `json:"type"`
	PID        int    `json:"pid,omitempty"`
	StartTicks int64  `json:"start_ticks,omitempty"`
	Note       string `json:"note,omitempty"`
}
type CaptureWindow struct {
	PreTrigger  time.Duration `json:"pre_trigger"`
	PostTrigger time.Duration `json:"post_trigger"`
}

func DefaultWindow() CaptureWindow { return CaptureWindow{90 * time.Second, 30 * time.Second} }

type HostMetadata struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	CPUCount     int    `json:"cpu_count"`
	MemoryTotal  uint64 `json:"memory_total"`
}

// LocalHost captures descriptive host identity for offline interpretation.
// MemoryTotal is best effort: zero means the platform did not expose a total,
// never an assumed value. hostnames and other global identifiers are omitted
// by the conservative privacy policy.
func LocalHost() HostMetadata {
	return HostMetadata{OS: runtime.GOOS, Architecture: runtime.GOARCH, CPUCount: runtime.NumCPU(), MemoryTotal: platform.TotalMemoryBytes()}
}

// ProcessMetadata is deliberately identity-only. Executable/command line and
// UID are not collected: paths/arguments/user identities are private by default.
type ProcessMetadata struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	PGID       int    `json:"pgid"`
	SID        int    `json:"sid"`
	StartTicks int64  `json:"start_ticks"`
	Name       string `json:"name"`
}
type Metadata struct {
	AgentVersion string            `json:"agent_version"`
	Host         HostMetadata      `json:"host"`
	Processes    []ProcessMetadata `json:"processes"`
}

// event uses typed factual fields rather than arbitrary metadata maps, which
// could become an unreviewed secret-exfiltration path.
type Event struct {
	Timestamp  time.Time                     `json:"timestamp"`
	Type       string                        `json:"type"`
	PID        int                           `json:"pid,omitempty"`
	StartTicks int64                         `json:"start_ticks,omitempty"`
	From       string                        `json:"from,omitempty"`
	To         string                        `json:"to,omitempty"`
	Connection *collector.ConnectionSnapshot `json:"connection,omitempty"`
	Collector  string                        `json:"collector,omitempty"`
	// ExitStatus is the terminal state of a PROCESS_EXITED event when the
	// platform exposed one: "exit:<code>", "signal:<number>", or empty when
	// it was not captured (the ordinary reaped-exit case; see
	// platform.Process). additive: older readers ignore it.
	ExitStatus string `json:"exit_status,omitempty"`
	// provenance records the evidence source for phase 6 merged events
	// (6.29): "rust_trace" for kernel-tracer evidence, empty for the
	// legacy snapshot-derived differ events. see tracemerge.go.
	Provenance string `json:"provenance,omitempty"`
	// CorroboratedBy lists additional, weaker evidence sources that observed
	// the same underlying lifecycle event (6.30/6.31): the stronger source
	// owns the normalized timeline entry, the weaker one is never deleted.
	CorroboratedBy []string `json:"corroborated_by,omitempty"`
	// MonotonicNs carries the tracer's CLOCK_MONOTONIC reading for ordering
	// trace events whose wall-clock millisecond granularity ties (6.28).
	MonotonicNs int64 `json:"monotonic_ns,omitempty"`
	// signal / SignalFact carry tracer signal observations (6.13/6.14):
	// signal is the signal number and SignalFact what the kernel mechanism
	// actually established (SIGNAL_SENT / EXITED_BY_SIGNAL / OBSERVED_STOP).
	// Polling-derived events never set these.
	Signal     int    `json:"signal,omitempty"`
	SignalFact string `json:"signal_fact,omitempty"`
	// SenderPID and TargetPGID carry a SIGNAL_SENT's addressing (contract
	// §3.3): the process that asked for the signal, and the process group it
	// addressed when it named a group instead of one process (PID is then
	// 0). both are 0 when unknown; PID and TargetPGID both 0 on a
	// SIGNAL_SENT means kill(-1) or an unresolved target. additive: older
	// readers ignore them. without them a bundle could not say who sent a
	// signal, which is the fact SIGNAL_SENT exists for (§3.4 "Y sent S").
	SenderPID  int `json:"sender_pid,omitempty"`
	TargetPGID int `json:"target_pgid,omitempty"`
	// conflicts records why the merge kept this fact as its own entry despite
	// a same-PID, same-kind claim inside the dedup window (contract §9.1:
	// "otherwise both are kept and the disagreement is recorded as a
	// conflict"). the values are a closed vocabulary; see tracemerge.go.
	Conflicts []string `json:"conflicts,omitempty"`
}

const (
	ProcessStarted      = "PROCESS_STARTED"
	ProcessExited       = "PROCESS_EXITED"
	ProcessStateChanged = "PROCESS_STATE_CHANGED"
	ConnectionOpened    = "CONNECTION_OPENED"
	ConnectionClosed    = "CONNECTION_CLOSED"
	CollectorError      = "COLLECTOR_ERROR"
	IncidentTriggered   = "INCIDENT_TRIGGERED"
	MemoryThreshold     = "MEMORY_THRESHOLD"
	DiskThreshold       = "DISK_THRESHOLD"
)

// Tracer-derived event types (phase 6, tracemerge.go). additive: existing
// readers treat them as opaque extra timeline entries.
const (
	TraceProcessExec = "TRACE_PROCESS_EXEC"
	TraceProcessExit = "TRACE_PROCESS_EXIT"
	// the remaining tracer-derived types use the tracer's own normalized
	// vocabulary (tracemerge.FromTrace). they stay in one closed whitelist so
	// a merged incident carrying stop/resume/signal/OOM evidence validates,
	// while no arbitrary string can enter Event.Type through the merge path.
	TraceSignalSent     = "SIGNAL_SENT"
	TraceProcessStopped = "PROCESS_STOPPED"
	TraceProcessResumed = "PROCESS_RESUMED"
	TraceOomKill        = "OOM_KILL"
)

type PrivacyReport struct {
	Policy           string `json:"policy"`
	Hostname         bool   `json:"hostname"`
	CommandLines     bool   `json:"command_lines"`
	Environment      bool   `json:"environment"`
	RepositoryName   bool   `json:"repository_name"`
	NetworkAddresses bool   `json:"network_addresses"`
	FilesystemPaths  bool   `json:"filesystem_paths"`
	ProcessNames     bool   `json:"process_names"`
	UserNote         bool   `json:"user_note"`
	// ProviderIdentifiers records that a provider section exported runner,
	// repository or job identifiers, which requires --provider-identifiers.
	ProviderIdentifiers bool `json:"provider_identifiers,omitempty"`
}
type Incident struct {
	SchemaVersion int           `json:"schema_version"`
	ID            string        `json:"id"`
	CreatedAt     time.Time     `json:"created_at"`
	TriggeredAt   time.Time     `json:"triggered_at"`
	CaptureStart  time.Time     `json:"capture_start"`
	CaptureEnd    time.Time     `json:"capture_end"`
	Window        CaptureWindow `json:"window"`
	Trigger       Trigger       `json:"trigger"`
	Metadata      Metadata      `json:"metadata"`
	Truncated     bool          `json:"truncated"`
	Privacy       PrivacyReport `json:"privacy"`
	// providers holds one CI-provider evidence section per provider compiled
	// into the recording agent (phase 5, docs/providers/architecture.md §3.3).
	// additive: older readers ignore this field.
	Providers []evidence.Section `json:"providers,omitempty"`
	// tracing records the tracer component's reliability self-report, stamped
	// at finalize time (6.48). additive: nil means the agent had no tracer.
	Tracing   *TraceReliability    `json:"tracing,omitempty"`
	Snapshots []collector.Snapshot `json:"snapshots"`
	Events    []Event              `json:"events"`
}

type IncidentWriter interface {
	Write(context.Context, *Incident) (string, error)
}
type Redactor interface{ RedactIncident(*Incident) error }

func newID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return "inc_" + hex.EncodeToString(id[:]), nil
}
func clone(i *Incident) (*Incident, error) {
	if i == nil {
		return nil, fmt.Errorf("incident: nil incident")
	}
	if err := validateRecordBudget(i); err != nil {
		return nil, err
	}
	if len(i.Trigger.Note) > 1024 || !utf8.ValidString(i.Trigger.Note) {
		return nil, fmt.Errorf("incident: invalid user note")
	}
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPayloadBytes {
		return nil, fmt.Errorf("incident: payload exceeds budget")
	}
	var out Incident
	err = json.Unmarshal(data, &out)
	return &out, err
}
func validTrigger(t string) bool {
	switch t {
	case "manual", "process_exit", "process_stopped", "memory_threshold", "disk_threshold", "collector_unavailable":
		return true
	}
	return false
}
func validEvent(t string) bool {
	switch t {
	case ProcessStarted, ProcessExited, ProcessStateChanged, ConnectionOpened, ConnectionClosed, CollectorError, IncidentTriggered, MemoryThreshold, DiskThreshold,
		// Tracer-derived entries (phase 6): normalized tracer vocabulary is
		// whitelisted so a merged incident validates end to end. the
		// TRACE_EVENT_* forward-compatible labels (and any parent-supplied
		// string) arrive only via tracemerge, which whitelists them below.
		TraceProcessExec, TraceProcessExit,
		TraceSignalSent, TraceProcessStopped, TraceProcessResumed, TraceOomKill:
		return true
	}
	return validTraceEvent(t)
}

func validateRecordBudget(i *Incident) error {
	if len(i.Snapshots) > MaxSnapshots || len(i.Events) > MaxEvents || len(i.Metadata.Processes) > MaxEvents {
		return fmt.Errorf("incident: record limit exceeded")
	}
	total := len(i.Snapshots) + len(i.Events) + len(i.Metadata.Processes)
	for _, s := range i.Snapshots {
		// compare lengths before adding, avoiding integer overflow.
		for _, n := range []int{len(s.Processes), len(s.Connections), len(s.Errors), len(s.Metrics)} {
			if n > MaxEvidenceRecords-total {
				return fmt.Errorf("incident: evidence record budget exceeded")
			}
			total += n
		}
	}
	if total > MaxEvidenceRecords {
		return fmt.Errorf("incident: evidence record budget exceeded")
	}
	return nil
}

// validate checks semantic invariants in addition to the archive checksums.
func Validate(i *Incident) error {
	if i == nil {
		return fmt.Errorf("incident: nil incident")
	}
	if i.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported Deprehendo bundle schema: %d", i.SchemaVersion)
	}
	if !validID.MatchString(i.ID) || !validTrigger(i.Trigger.Type) || i.Trigger.PID < 0 || i.Trigger.StartTicks < 0 || len(i.Trigger.Note) > 1024 || !utf8.ValidString(i.Trigger.Note) {
		return fmt.Errorf("incident: invalid identity or trigger")
	}
	if i.CreatedAt.IsZero() || i.TriggeredAt.IsZero() || i.CreatedAt.Before(i.TriggeredAt) || i.CaptureStart.IsZero() || i.CaptureEnd.IsZero() || i.CaptureStart.After(i.TriggeredAt) || i.CaptureEnd.Before(i.TriggeredAt) || i.CaptureEnd.After(i.CreatedAt) {
		return fmt.Errorf("incident: invalid capture timestamps")
	}
	if i.Window.PreTrigger < 0 || i.Window.PostTrigger < 0 || i.Window.PreTrigger > 24*time.Hour || i.Window.PostTrigger > time.Hour || i.CaptureStart.Before(i.TriggeredAt.Add(-i.Window.PreTrigger)) || i.CaptureEnd.After(i.TriggeredAt.Add(i.Window.PostTrigger)) {
		return fmt.Errorf("incident: invalid capture window")
	}
	if len(i.Metadata.AgentVersion) == 0 || len(i.Metadata.AgentVersion) > 64 || len(i.Metadata.Host.OS) == 0 || len(i.Metadata.Host.OS) > 32 || len(i.Metadata.Host.Architecture) == 0 || len(i.Metadata.Host.Architecture) > 32 || i.Metadata.Host.CPUCount < 1 {
		return fmt.Errorf("incident: invalid agent/host metadata")
	}
	if err := validateRecordBudget(i); err != nil {
		return err
	}
	var prev time.Time
	for _, s := range i.Snapshots {
		if s.Timestamp.IsZero() || s.Timestamp.Before(i.CaptureStart) || s.Timestamp.After(i.CaptureEnd) || (!prev.IsZero() && !s.Timestamp.After(prev)) {
			return fmt.Errorf("incident: snapshots not strictly ordered within capture")
		}
		prev = s.Timestamp
	}
	prev = time.Time{}
	for _, e := range i.Events {
		if !validEvent(e.Type) || e.Timestamp.IsZero() || e.Timestamp.Before(i.CaptureStart) || e.Timestamp.After(i.CaptureEnd) || e.Timestamp.Before(prev) || e.PID < 0 || e.StartTicks < 0 {
			return fmt.Errorf("incident: invalid event timeline")
		}
		for _, c := range e.Conflicts {
			if !validMergeConflict(c) {
				return fmt.Errorf("incident: invalid merge conflict %q", c)
			}
		}
		prev = e.Timestamp
	}
	if i.Tracing != nil {
		if err := i.Tracing.validate(); err != nil {
			return err
		}
	}
	return validateProviders(i)
}

// validateProviders checks every embedded provider evidence section (phase 5).
// each section carries its own schema version, bounds and vocabulary, so the
// incident validation only adds uniqueness and count discipline; an invalid
// section fails the whole bundle, because the capture pipeline never writes
// one and a hand-built one is a corrupted artifact.
func validateProviders(i *Incident) error {
	if len(i.Providers) > MaxProviders {
		return fmt.Errorf("incident: too many provider sections")
	}
	seen := map[string]bool{}
	for _, s := range i.Providers {
		if s.Provider == "" || seen[s.Provider] {
			return fmt.Errorf("incident: duplicate or empty provider section name")
		}
		seen[s.Provider] = true
		if err := s.Validate(); err != nil {
			return fmt.Errorf("incident: provider section %q invalid: %w", s.Provider, err)
		}
	}
	return nil
}
