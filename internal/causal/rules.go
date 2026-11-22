package causal

import (
	"fmt"
	"sort"
	"time"
)

// rule is one causal hypothesis with a declared evidence contract (§3.1).
//
// every check code in required, supporting, contradicting and discriminator
// MUST resolve to an evaluator in checkRegistry (invariant 4); the engine
// evaluates them tri-state (PRESENT/ABSENT/UNKNOWN) and treats an UNKNOWN as
// missing telemetry, never as a clean absence (§2.3).
//
// semantics:
//
//   - required: every check must come back PRESENT; any ABSENT vetoes the
//     edge, any UNKNOWN vetoes it with the reason "unobservable in this
//     bundle", which feeds the unknown-cause report's missing evidence.
//   - discriminator: codes within required that satisfy E4, the observation
//     that THIS mechanism operated. edge == CAUSES requires at least one
//     (invariant 1).
//   - supporting: context; never raises a band. ABSENT/UNKNOWN land on the
//     edge's missing list.
//   - contradicting: PRESENT vetoes the edge; UNKNOWN demotes to at most
//     MEDIUM (D1); ABSENT is recorded as "checked, absent".
//
// ceiling caps the computed band (§2.2); edge.Band = min(ceiling, grade).
type Rule struct {
	ID        string // NAME@VERSION; any semantic change → new version
	Source    EventType
	Target    EventType
	Edge      RelationType
	Ceiling   CausalConfidence
	Mechanism string // E3: the declared mechanism, rendered by explain-edge

	Required      []string
	Discriminator []string
	Supporting    []string
	Contradicting []string

	MinGap, MaxGap time.Duration

	// SameInstant allows E1′ (co-occurrence in one sampling instant) to
	// satisfy order for this rule. it caps the band at MEDIUM (D5/P6).
	SameInstant bool

	// binding enforces P3 episode discipline (§4.4 V2). BindingNone requires
	// BindingNote: a documented reason episode binding is impossible.
	Binding     EpisodeBinding
	BindingNote string

	// NearestOnly accepts at most one edge per source, to the first
	// validated target: each recovery belongs to the nearest preceding
	// failure episode (§3.3). kept separate from binding because a rule can
	// bind by episode AND still pair to the nearest instance only.
	NearestOnly bool

	// identity drives D2: anything weaker than exact caps the band at
	// MEDIUM.
	Identity IdentityStrength
}

// checks resolves every code the rule declares to its evaluator.
func (r *Rule) Checks() ([]Check, error) {
	out := make([]Check, 0, len(r.Required)+len(r.Contradicting)+len(r.Supporting))
	for _, code := range r.Required {
		c, err := lookupCheck(code)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// lookupCheck resolves one declared code to its evaluator; an unresolvable
// code is an error, not a silent placeholder (invariant 4).
func lookupCheck(code string) (Check, error) {
	fn, ok := checkRegistry[code]
	if !ok {
		return Check{}, &unknownCheckCodeError{code: code}
	}
	return Check{Code: code, Evaluate: fn}, nil
}

type unknownCheckCodeError struct{ code string }

func (e *unknownCheckCodeError) Error() string {
	return "declared check code has no evaluator: " + e.code
}

// rev is the version suffix of the v1 registry rewrite (spec §3.3). none of
// the retired/re-versioned IDs were released, but the version is bumped where
// semantics changed so stored explanations stay interpretable (4.18).
const rev = "@2"

// rules is the shipped v1 registry implementing spec §3.3. rules whose
// required evidence is unobservable in v1 bundles (kernel OOM records, socket
// progress, runner roles) stay registered but can never fire: their
// evaluators answer UNKNOWN, the engine rejects the pair with
// "unobservable in this bundle", and the unknown-cause report names exactly
// that telemetry (conservative by construction, §3.2).
func Rules() []*Rule {
	rules := []*Rule{
		{
			// §3.2: the constitutive condition (E4) is a kernel OOM record
			// that identifies the victim; a SIGKILL exit status only
			// supports. dormant in v1: no OOM records, so also no OOM_EVENT
			// source instances.
			ID:     "OOM_CAUSES_PROCESS_EXIT" + rev,
			Source: EventOOM, Target: EventProcessExited,
			Edge: RelationCauses, Ceiling: ConfidenceHigh,
			Mechanism:     "the kernel out-of-memory killer selected the victim process and terminated it",
			Required:      []string{"OOM_RECORD_IDENTIFIES_VICTIM", "SAME_SUBJECT_AS_VICTIM", "EXIT_NOT_NORMAL"},
			Discriminator: []string{"OOM_RECORD_IDENTIFIES_VICTIM"},
			Contradicting: []string{"NORMAL_EXIT_BEFORE_OOM"},
			MinGap:        0, MaxGap: 2 * time.Second,
			Binding:     BindingNone,
			BindingNote: "identity binding: the discriminator check is the same-subject binding; there is no episode instance for a one-shot kill",
			Identity:    IdentityExact,
		},
		{
			// §3.4 "Y sent S": the kernel observed the signal being sent to
			// this exact process (or to a group the exit belongs to), and the
			// target then exited BY that same signal. the send is the
			// mechanism; the exit's wait status (FACT_EXITED_BY_SIGNAL) is a
			// fact about the target, never a claim that the signal was
			// delivered by the sender. both halves are kernel observations,
			// so the ceiling is HIGH with no inference on either side.
			ID:     "SIGNAL_TERMINATES_PROCESS@1",
			Source: EventSignalSent, Target: EventProcessExited,
			Edge: RelationCauses, Ceiling: ConfidenceHigh,
			Mechanism:     "the recorded signal send to this process identity preceded its exit by that same signal",
			Required:      []string{"SIGNAL_SEND_OBSERVED", "SIGNAL_TARGETS_VICTIM", "EXIT_MATCHES_SIGNAL"},
			Discriminator: []string{"SIGNAL_TARGETS_VICTIM"},
			MinGap:        0, MaxGap: 2 * time.Second,
			Binding:     BindingNone,
			BindingNote: "identity binding: the exact-subject or group-PGID match is the binding; a one-shot send has no episode instance",
			Identity:    IdentityExact,
		},
		{
			// §3.3: host memory limit → host (global) OOM only; a host-side
			// 98% reading is not proof the killer fired for that process.
			// dormant in v1 (no OOM_EVENT).
			ID:     "MEMORY_LIMIT_CAUSES_OOM" + rev,
			Source: EventMemoryLimitReached, Target: EventOOM,
			Edge: RelationCauses, Ceiling: ConfidenceMedium,
			Mechanism:     "host memory exhaustion forced the kernel global out-of-memory killer to act",
			Required:      []string{"HOST_OOM_OBSERVED", "MEMORY_AT_LIMIT"},
			Discriminator: []string{"HOST_OOM_OBSERVED"},
			MaxGap:        30 * time.Second,
			Binding:       BindingSourceActiveAtTarget,
			Identity:      IdentityScope,
		},
		{
			// §3.3: replaces CGROUP_LIMIT_PRECEDES_OOM@1 (strength was
			// inverted). the canonical cgroup-OOM mechanism: the cgroup at
			// memory.max with an OOM record for that cgroup. dormant in v1.
			ID:     "CGROUP_LIMIT_CAUSES_OOM@1",
			Source: EventCgroupLimitReached, Target: EventOOM,
			Edge: RelationCauses, Ceiling: ConfidenceHigh,
			Mechanism:     "the cgroup hit memory.max and the kernel killed one of its members to honour the limit",
			Required:      []string{"OOM_RECORD_NAMES_CGROUP", "SAME_CGROUP_SUBJECT"},
			Discriminator: []string{"OOM_RECORD_NAMES_CGROUP"},
			Binding:       BindingSourceActiveAtTarget,
			Identity:      IdentityExact,
		},
		{
			// §3.2 counter path: the first OOM edge that fires on v1
			// telemetry. the capture-order rise of the cgroup's sampled
			// oom_kill counter proves the kernel killed a member inside the
			// window the event names; the victim is identified by its own
			// exit record's cgroup stamp, evidence the bundle already
			// carries (§3.2 extraction), not a graph-side inference.
			// Member-level certainty (a coincident abnormal exit of a
			// different member of the same cgroup in the same window is not
			// excluded) caps the ceiling at MEDIUM; kernel victim records
			// upgrade through OOM_CAUSES_PROCESS_EXIT@2.
			ID:     "CGROUP_OOM_KILLS_MEMBER@1",
			Source: EventOOM, Target: EventProcessExited,
			Edge: RelationCauses, Ceiling: ConfidenceMedium,
			Mechanism:     "the kernel out-of-memory killer terminated a member of the cgroup inside the recorded kill window, and the victim's last recorded cgroup is that one",
			Required:      []string{"OOM_COUNTER_OBSERVED", "VICTIM_EXITED_IN_CGROUP", "EXIT_NOT_NORMAL"},
			Discriminator: []string{"OOM_COUNTER_OBSERVED"},
			Contradicting: []string{"NORMAL_EXIT_BEFORE_OOM"},
			MaxGap:        5 * time.Second,
			Binding:       BindingNone,
			BindingNote:   "identity binding: the cgroup-path and window checks are the identity binding; a one-shot kill has no episode instance",
			Identity:      IdentityExact,
		},
		{
			// §1.3: one measured quantity crossing two thresholds. crossing
			// 90% did not cause crossing 98%; the escalation relation keeps
			// the episode onset traversable without a fake mechanism (A3).
			ID:     "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1",
			Source: EventMemoryPressureStarted, Target: EventMemoryLimitReached,
			Edge: RelationEscalates, Ceiling: ConfidenceHigh,
			Mechanism:   "the same host memory measurement crossed the higher severity boundary of one worsening episode",
			Required:    []string{"SAME_QUANTITY_SAME_EPISODE"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityScope,
			SameInstant: true, // one sample can jump straight past both boundaries (A10)
		},
		{
			// Active-onset variant: the episode began before recording, so
			// the escalation pairs ACTIVE → limit.
			ID:     "MEMORY_ACTIVE_ESCALATES_TO_LIMIT@1",
			Source: EventMemoryPressureActive, Target: EventMemoryLimitReached,
			Edge: RelationEscalates, Ceiling: ConfidenceHigh,
			Mechanism:   "the same host memory measurement crossed the higher severity boundary of one worsening episode",
			Required:    []string{"SAME_QUANTITY_SAME_EPISODE"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityScope,
			SameInstant: true,
		},
		{
			// §3.3 (fixes A2): the recovery closes the whole episode, so the
			// source is the episode onset, not the limit crossing.
			ID:     "MEMORY_RECOVERY_FOLLOWS_ONSET" + rev,
			Source: EventMemoryPressureStarted, Target: EventMemoryRecovered,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "the observed memory decline below the hysteresis boundary is the same episode ending",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityScope,
			NearestOnly: true,
		},
		{
			ID:     "MEMORY_ACTIVE_RECOVERY_FOLLOWS_ONSET" + rev,
			Source: EventMemoryPressureActive, Target: EventMemoryRecovered,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "the observed memory decline below the hysteresis boundary is the same episode ending",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityScope,
			NearestOnly: true,
		},
		{
			// §3.3 (A22/A18): E4 is the recorded parent identity the child
			// was detached from, bound through typed identity fields. the
			// discriminator is the binding, so episode binding is impossible
			// by design (process events carry no resource episode).
			ID:     "PROCESS_EXIT_CAUSES_REPARENT" + rev,
			Source: EventProcessExited, Target: EventProcessReparented,
			Edge: RelationCauses, Ceiling: ConfidenceMedium,
			Mechanism:     "the kernel reparents a child process when its parent process exits",
			Required:      []string{"REPARENTED_FROM_EXITED_PID", "EXIT_IS_LAST_EXIT_OF_PARENT"},
			Discriminator: []string{"REPARENTED_FROM_EXITED_PID"},
			Contradicting: []string{"CHILD_REPARENTED_BEFORE_EXIT"},
			// the reparent is observed in the first sample after the exit, so
			// 5 s is five default 1 s samples of slack. A later observation does
			// not show when the adoption happened, so it must not link.
			MinGap:      0,
			MaxGap:      5 * time.Second,
			Binding:     BindingNone,
			BindingNote: "identity binding: the typed PPID lineage is the binding; process lifecycle has no resource episode",
			Identity:    IdentityPIDOnly, // D2 ⇒ MEDIUM cap (§3.3)
		},
		{
			// §2.2 (A5): a stopped task is not scheduled, so its thread stops
			// consuming CPU. required: same identity, and the saturation end
			// is the first such end at or after the stop. this rule explains
			// the end of an anomaly and can never make a root.
			ID:     "PROCESS_STOP_ENDS_CPU_SATURATION" + rev,
			Source: EventProcessStopped, Target: EventCPUSaturationEnded,
			Edge: RelationCauses, Ceiling: ConfidenceMedium,
			Mechanism:     "a stopped task is never scheduled, so its measured CPU saturation ends",
			Required:      []string{"SATURATION_END_AT_OR_AFTER_STOP"},
			Discriminator: []string{"SATURATION_END_AT_OR_AFTER_STOP"},
			Contradicting: []string{"CPU_SATURATION_HALTED_WITHOUT_STOP"},
			// as for the reparent rule: five default 1 s samples of slack. an
			// end observed long after the stop does not show the stop ended it.
			MinGap:      0,
			MaxGap:      5 * time.Second,
			Binding:     BindingNone,
			BindingNote: "process identity binding: the saturation episode ends, it is not a joined instance",
			Identity:    IdentityExact,
		},
		{
			// §3.3: kept, episode-bound.
			ID:     "CPU_SATURATION_RESOLVES@1",
			Source: EventCPUSaturationStarted, Target: EventCPUSaturationEnded,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "the same process's measured saturation fell below the hysteresis boundary",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityExact,
			NearestOnly: true,
		},
		{
			// §3.3 (A4): retired PROCESS_GROUP_TERM_CAUSES_GROUP_EXIT@1:
			// the group event is an aggregate failure clustered FROM member
			// exits (P2 forbids it from causing them). no fewer rules may
			// re-introduce the violation.
			//
			// §7.4 (N1, live: verified on a real SIGSTOP'd socket reader): a stopped local process is the mechanism when
			// the stall shape is LOCAL_NOT_READING.
			ID:     "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1",
			Source: EventProcessStopped, Target: EventNetworkProgressStopped,
			Edge: RelationCauses, Ceiling: ConfidenceHigh,
			Mechanism:     "a stopped process is not reading its socket, so outstanding receive data accumulates and progress stops",
			Required:      []string{"SOCKET_OWNED_BY_STOPPED_IDENTITY", "STALL_SHAPE_LOCAL_NOT_READING"},
			Discriminator: []string{"STALL_SHAPE_LOCAL_NOT_READING"},
			Binding:       BindingNone,
			BindingNote:   "identity binding: typed socket owner, no resource episode",
			Identity:      IdentityExact,
		},
		{
			ID:     "NETWORK_RECOVERY_FOLLOWS_STALL" + rev,
			Source: EventNetworkProgressStopped, Target: EventNetworkProgressResumed,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "traffic resumed on the same socket inode: the stall episode ended",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityExact,
			NearestOnly: true,
		},
		{
			// §3.3: same-quantity escalation on one filesystem subject
			// (free-space machine only). Same-instant allowed for the jump
			// past both boundaries (A10).
			ID:     "DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1",
			Source: EventDiskPressureStarted, Target: EventDiskExhausted,
			Edge: RelationEscalates, Ceiling: ConfidenceHigh,
			Mechanism:   "the same filesystem free-space measurement crossed the lower severity boundary of one worsening episode",
			Required:    []string{"SAME_QUANTITY_SAME_EPISODE"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityExact,
			SameInstant: true,
		},
		{
			ID:     "DISK_LOW_ACTIVE_ESCALATES_TO_EXHAUSTION@1",
			Source: EventDiskLowActive, Target: EventDiskExhausted,
			Edge: RelationEscalates, Ceiling: ConfidenceHigh,
			Mechanism:   "the same filesystem free-space measurement crossed the lower severity boundary of one worsening episode",
			Required:    []string{"SAME_QUANTITY_SAME_EPISODE"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityExact,
			SameInstant: true,
		},
		{
			// §3.3 (fixes A2 for disk): source = episode onset.
			ID:     "DISK_RECOVERY_FOLLOWS_ONSET" + rev,
			Source: EventDiskPressureStarted, Target: EventDiskRecovered,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "the observed free-space recovery above the hysteresis boundary is the same episode ending",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityExact,
			NearestOnly: true,
		},
		{
			ID:     "DISK_LOW_ACTIVE_RECOVERY_FOLLOWS_ONSET" + rev,
			Source: EventDiskLowActive, Target: EventDiskRecovered,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "the observed free-space recovery above the hysteresis boundary is the same episode ending",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityExact,
			NearestOnly: true,
		},
		{
			ID:     "IO_PRESSURE_RESOLVES@1",
			Source: EventIOPressureStarted, Target: EventIOPressureEnded,
			Edge: RelationRecoveryOf, Ceiling: ConfidenceHigh,
			Mechanism:   "severe IO stall time fell back below its boundary: the sustained-stall episode ended",
			Required:    []string{"EPISODE_RECOVERY_OBSERVED"},
			Binding:     BindingSameEpisode,
			Identity:    IdentityScope,
			NearestOnly: true,
		},
		{
			// kept dormant (§3.3): runner/job role telemetry is phase 5.
			ID:     "WORKER_EXIT_CAUSES_INCIDENT@1",
			Source: EventWorkerExited, Target: EventIncidentTriggered,
			Edge: RelationCauses, Ceiling: ConfidenceMedium,
			Mechanism:     "losing the job process makes the runner mark the job failed and trigger the incident",
			Required:      []string{"WORKER_EXIT_MATCHES_TRIGGER"},
			Discriminator: []string{"WORKER_EXIT_MATCHES_TRIGGER"},
			Binding:       BindingNone,
			BindingNote:   "role binding: the trigger references the runner's job handle, which v1 does not record",
			Identity:      IdentityScope,
		},
	}
	// resolve evaluators once at registry build: an unresolvable code fails
	// here, at rule construction, rather than silently weakening a rule later
	// (invariant 4).
	for _, rule := range rules {
		if err := resolveRuleCodes(rule); err != nil {
			panic(err)
		}
	}
	sortRules(rules)
	return rules
}

// checkRegistry maps every declared check code to its evaluator (invariant 4:
// every code in every rule list resolves; no placeholders wearing real names).
// evaluators read bundle facts off the graph and answer tri-state; an UNKNOWN
// is telemetry the bundle never captured and is never read as ABSENT (§2.3).
var checkRegistry = map[string]CheckFunc{
	// --- E4 discriminators: v1 unobservable, so their rules stay dormant ---

	// OOM_RECORD_IDENTIFIES_VICTIM: the kernel OOM record names the victim
	// process identity. v1 bundles have no kernel event stream (§3.2).
	"OOM_RECORD_IDENTIFIES_VICTIM": func(g *Graph, src, tgt *Event) CheckResult {
		// phase 6 bundles can carry the tracer's oom:mark_victim record,
		// which names the victim identity. that is the E4 observation; the
		// sampled cgroup counter cannot answer it (it names a cgroup, not a
		// victim) and stays UNKNOWN so CGROUP_OOM_KILLS_MEMBER owns that
		// path instead of double-claiming it here.
		if src.Type == EventOOM {
			if record, _ := src.Data["record"].(string); record == "oom_mark_victim" && src.PID > 0 && src.StartTicks > 0 {
				return CheckResult{
					Status: CheckPresent,
					Detail: fmt.Sprintf("the kernel OOM record names victim %d@%d", src.PID, src.StartTicks),
				}
			}
		}
		return CheckResult{
			Status: CheckUnknown,
			Detail: "no kernel OOM record naming this victim is captured in the bundle",
		}
	},
	"OOM_RECORD_NAMES_CGROUP": func(g *Graph, src, tgt *Event) CheckResult {
		return CheckResult{
			Status: CheckUnknown,
			Detail: "kernel OOM record telemetry is not captured in v1 bundles",
		}
	},
	"HOST_OOM_OBSERVED": func(g *Graph, src, tgt *Event) CheckResult {
		return CheckResult{
			Status: CheckUnknown,
			Detail: "kernel OOM record telemetry is not captured in v1 bundles",
		}
	},

	// --- identity / linkage (E2) ---

	// SAME_SUBJECT_AS_VICTIM: exact subject equality is bundle-observed.
	"SAME_SUBJECT_AS_VICTIM": func(g *Graph, src, tgt *Event) CheckResult {
		if src.Subject == tgt.Subject {
			return CheckResult{Status: CheckPresent, Detail: "source and target name the same subject identity"}
		}
		return CheckResult{Status: CheckAbsent, Detail: "subjects differ"}
	},

	// --- phase 6 signal evidence (§3.4 "Y sent S") ---

	// SIGNAL_SEND_OBSERVED: the source is the kernel's send observation.
	// A FACT level below SIGNAL_SENT would be a stronger fact (delivery /
	// exited-by-signal) that this rule must not re-read as a send.
	"SIGNAL_SEND_OBSERVED": func(g *Graph, src, tgt *Event) CheckResult {
		if src.Type != EventSignalSent {
			return CheckResult{Status: CheckAbsent, Detail: "source is not a recorded signal send"}
		}
		fact, _ := src.Data["signal_fact"].(string)
		switch fact {
		case "SIGNAL_SENT":
			return CheckResult{Status: CheckPresent, Detail: "the kernel observed the signal being sent"}
		case "":
			return CheckResult{Status: CheckUnknown, Detail: "the recorded send carries no signal fact"}
		default:
			return CheckResult{Status: CheckAbsent, Detail: "recorded signal fact is " + fact}
		}
	},

	// SIGNAL_TARGETS_VICTIM: a single-target send must name the exact
	// incarnation; a group send binds to a member through its PGID. A PID
	// match alone is never identity (6.11).
	"SIGNAL_TARGETS_VICTIM": func(g *Graph, src, tgt *Event) CheckResult {
		switch src.Subject.Kind {
		case SubjectProcess:
			if src.Subject == tgt.Subject {
				return CheckResult{Status: CheckPresent, Detail: "the send addressed this exact process identity"}
			}
			return CheckResult{Status: CheckAbsent, Detail: "the send addressed another process identity"}
		case SubjectGroup:
			pgid, ok := intField(src, "target_pgid")
			if !ok || pgid <= 0 {
				return CheckResult{Status: CheckUnknown, Detail: "the group send does not record which group it addressed"}
			}
			if tgt.PGID == pgid {
				return CheckResult{Status: CheckPresent, Detail: fmt.Sprintf("the exit belongs to the addressed process group %d", pgid)}
			}
			return CheckResult{Status: CheckAbsent, Detail: "the exit belongs to another process group"}
		default:
			return CheckResult{Status: CheckUnknown, Detail: "the send has no resolvable target identity"}
		}
	},

	// EXIT_MATCHES_SIGNAL: the target's own wait status says it exited by a
	// signal, and that signal is the one that was sent. an exit with no
	// captured signal fact is UNKNOWN, not a mismatch.
	"EXIT_MATCHES_SIGNAL": func(g *Graph, src, tgt *Event) CheckResult {
		if tgt.Type != EventProcessExited {
			return CheckResult{Status: CheckAbsent, Detail: "target is not a process exit"}
		}
		fact, _ := tgt.Data["signal_fact"].(string)
		switch fact {
		case "":
			return CheckResult{Status: CheckUnknown, Detail: "the exit carries no captured signal fact"}
		case "EXITED_BY_SIGNAL":
		default:
			return CheckResult{Status: CheckAbsent, Detail: "the exit fact is " + fact}
		}
		sent, sentok := intField(src, "signal")
		got, gotok := intField(tgt, "signal")
		if !sentok || !gotok || sent <= 0 || got <= 0 {
			return CheckResult{Status: CheckUnknown, Detail: "the signal number is not recorded on both sides"}
		}
		if sent == got {
			return CheckResult{Status: CheckPresent, Detail: fmt.Sprintf("the exit's signal %d is the signal that was sent", got)}
		}
		return CheckResult{Status: CheckAbsent, Detail: fmt.Sprintf("the exit's signal %d is not the sent signal %d", got, sent)}
	},
	"SAME_QUANTITY_SAME_EPISODE": func(g *Graph, src, tgt *Event) CheckResult {
		if src.Episode != "" && src.Episode == tgt.Episode && src.Subject == tgt.Subject {
			return CheckResult{Status: CheckPresent, Detail: "both events belong to episode " + src.Episode}
		}
		if src.Episode == "" || tgt.Episode != src.Episode {
			return CheckResult{Status: CheckAbsent, Detail: fmt.Sprintf("episodes %q vs %q", src.Episode, tgt.Episode)}
		}
		return CheckResult{Status: CheckAbsent, Detail: "subjects differ"}
	},
	"SAME_CGROUP_SUBJECT": func(g *Graph, src, tgt *Event) CheckResult {
		if src.Subject == tgt.Subject && src.Subject.Kind == SubjectCgroup {
			return CheckResult{Status: CheckPresent, Detail: "both events name the same cgroup path"}
		}
		return CheckResult{Status: CheckAbsent, Detail: "cgroup paths differ"}
	},

	// --- state conditions (evaluated from sampled state; D6) ---

	// MEMORY_AT_LIMIT: the target sample recorded memory at the limit
	// boundary. sampled state, not a recorded event (D6 applies).
	"MEMORY_AT_LIMIT": func(g *Graph, src, tgt *Event) CheckResult {
		// the limit reading lives on the SOURCE (the limit event), not on the
		// OOM target (re-audit R4; dormant until OOM records exist).
		v, ok := src.Data["memory_percent"]
		if !ok {
			return CheckResult{Status: CheckUnknown, Detail: "memory percentage was not recorded on this event"}
		}
		percent, ok := asFloat(v)
		if !ok {
			return CheckResult{Status: CheckUnknown, Detail: "memory percentage was not numeric"}
		}
		if percent >= 98 {
			return CheckResult{
				Status: CheckPresent, Sampled: true,
				Detail: fmt.Sprintf("recorded memory %.1f%% at the 98%% limit boundary", percent),
			}
		}
		return CheckResult{Status: CheckAbsent, Detail: fmt.Sprintf("recorded memory %.1f%% below the limit boundary", percent)}
	},

	// --- exit status (unobservable in v1: no signal/status stream) ---

	"EXIT_NOT_NORMAL": func(g *Graph, src, tgt *Event) CheckResult {
		switch state := exitStatus(tgt); state {
		case "":
			return CheckResult{Status: CheckUnknown, Detail: "exit status is not captured in v1 bundles"}
		case "normal":
			return CheckResult{Status: CheckAbsent, Detail: "the exit was recorded as normal"}
		default:
			return CheckResult{Status: CheckPresent, Detail: "recorded exit state " + state}
		}
	},
	"NORMAL_EXIT_BEFORE_OOM": func(g *Graph, src, tgt *Event) CheckResult {
		if state := exitStatus(tgt); state == "normal" && src.Timestamp.Before(tgt.Timestamp) {
			return CheckResult{Status: CheckPresent, Detail: "target exited normally"}
		}
		return CheckResult{Status: CheckAbsent, Detail: "no recorded normal exit of the target before the source"}
	},

	// --- sampled OOM counters (§3.2 counter path; live in v1 from the
	// --- extractor's memory.events observations, never read as
	// --- kernel-record evidence) ---

	// OOM_COUNTER_OBSERVED: the source OOM event is an observation of the
	// capture-order rise of a cgroup's cumulative oom_kill counter. the
	// extractor stamps those events with the counter provenance, so a
	// different provenance is structural absence (kernel-record evidence
	// belongs to the OOM_RECORD_ checks), never UNKNOWN.
	"OOM_COUNTER_OBSERVED": func(g *Graph, src, tgt *Event) CheckResult {
		if src.Type != EventOOM {
			return CheckResult{Status: CheckAbsent, Detail: "source is not an OOM observation"}
		}
		if src.Provenance.RuleID != RuleOOMKillCounter {
			return CheckResult{Status: CheckAbsent, Detail: "the OOM observation came from another provenance (kernel records use the OOM_RECORD_ checks)"}
		}
		if _, ok := src.Data["oom_kill_delta"]; !ok {
			return CheckResult{Status: CheckUnknown, Detail: "the OOM observation records no counter delta"}
		}
		return CheckResult{Status: CheckPresent, Detail: "the OOM observation is a capture-order rise of the sampled oom_kill counter"}
	},

	// VICTIM_EXITED_IN_CGROUP: the victim's exit record carries its own
	// cgroup stamp (§3.2 extraction); it must name the killing cgroup, and
	// the exit must fall inside the recorded kill window: a rise observed
	// after the window closed cannot be that exit's kill.
	"VICTIM_EXITED_IN_CGROUP": func(g *Graph, src, tgt *Event) CheckResult {
		stamp, ok := tgt.Data["cgroup"]
		if !ok {
			return CheckResult{Status: CheckUnknown, Detail: "the exit record carries no cgroup stamp"}
		}
		path, ok := stamp.(string)
		if !ok || path == "" {
			return CheckResult{Status: CheckUnknown, Detail: "the exit record's cgroup stamp is not a path"}
		}
		if src.Subject.Kind != SubjectCgroup || src.Subject.ID != path {
			return CheckResult{Status: CheckAbsent, Detail: fmt.Sprintf("the victim's recorded cgroup %q is not the killing cgroup %q", path, src.Subject.ID)}
		}
		end, ok := src.Data["interval_end"].(string)
		if !ok || end == "" {
			return CheckResult{Status: CheckUnknown, Detail: "the OOM observation records no kill window"}
		}
		intervalend, err := time.Parse(time.RFC3339Nano, end)
		if err != nil {
			return CheckResult{Status: CheckUnknown, Detail: "the recorded kill window end is not parseable"}
		}
		if tgt.Timestamp.After(intervalend) {
			return CheckResult{Status: CheckAbsent, Detail: "the exit is recorded after the kill window closed"}
		}
		return CheckResult{Status: CheckPresent, Detail: fmt.Sprintf("the victim's last recorded cgroup is %q and its exit falls inside the recorded kill window", path)}
	},

	// --- reparent lineage (E4 via recorded PPID change; A22/A18) ---

	"REPARENTED_FROM_EXITED_PID": func(g *Graph, src, tgt *Event) CheckResult {
		if tgt.PPID != 0 && tgt.PPID == src.PID && src.PID != 0 {
			return CheckResult{
				Status: CheckPresent,
				Detail: fmt.Sprintf("the child's recorded pre-change parent was PID %d, the exited process", src.PID),
			}
		}
		return CheckResult{Status: CheckAbsent, Detail: "the child's recorded parent lineage does not name the exited PID"}
	},
	"EXIT_IS_LAST_EXIT_OF_PARENT": func(g *Graph, src, tgt *Event) CheckResult {
		for _, e := range g.EventIDs() {
			other := g.Get(e)
			if other == nil || other.Timestamp.Before(src.Timestamp) || other.Timestamp.After(tgt.Timestamp) {
				continue
			}
			// A22 incarnation binding (re-audit R2): a later exit of the same
			// PID by a different incarnation, before the reparent was
			// observed, means the PID was reused and that later process was
			// the parent the child lost. without this the stale incarnation
			// linked whenever both exits fell inside MaxGap.
			if other.Type == EventProcessExited && other != src && other.PID == src.PID &&
				other.Subject != src.Subject && other.Timestamp.After(src.Timestamp) {
				return CheckResult{Status: CheckAbsent, Detail: fmt.Sprintf("PID %d exited again (a later incarnation) before the reparent was observed", src.PID)}
			}
			if other.Type != EventProcessReparented || other.Subject != tgt.Subject || other == tgt {
				continue
			}
			if other.PPID == src.PID {
				return CheckResult{Status: CheckAbsent, Detail: "another reparenting of the same child from that parent marks this one non-terminal"}
			}
		}
		return CheckResult{Status: CheckPresent, Detail: "the last recorded detachment of this child from that parent"}
	},
	"CHILD_REPARENTED_BEFORE_EXIT": func(g *Graph, src, tgt *Event) CheckResult {
		for _, e := range g.EventIDs() {
			other := g.Get(e)
			if other.Type != EventProcessReparented || other.Subject != tgt.Subject || !other.Timestamp.Before(src.Timestamp) {
				continue
			}
			if other.PPID == src.PID {
				return CheckResult{Status: CheckPresent, Detail: "the child was already reparented away from that parent before the exit"}
			}
		}
		return CheckResult{Status: CheckAbsent, Detail: "checked: no earlier detachment of this child from that parent"}
	},

	// --- CPU saturation end ---

	"SATURATION_END_AT_OR_AFTER_STOP": func(g *Graph, src, tgt *Event) CheckResult {
		if tgt.Subject != src.Subject || tgt.Type != EventCPUSaturationEnded {
			return CheckResult{Status: CheckAbsent, Detail: "the saturation end does not belong to the stopped process"}
		}
		for _, e := range g.EventIDs() {
			other := g.Get(e)
			if other.Type != EventCPUSaturationEnded || other.Subject != src.Subject || other == tgt {
				continue
			}
			if other.Timestamp.After(src.Timestamp) && other.Timestamp.Before(tgt.Timestamp) {
				return CheckResult{Status: CheckAbsent, Detail: "an earlier saturation end already follows the stop"}
			}
		}
		return CheckResult{Status: CheckPresent, Detail: "the saturation ended at the first sample at or after the stop"}
	},
	"CPU_SATURATION_HALTED_WITHOUT_STOP": func(g *Graph, src, tgt *Event) CheckResult {
		for _, e := range g.EventIDs() {
			other := g.Get(e)
			if other.Type != EventCPUSaturationEnded || other.Subject != src.Subject || other == tgt {
				continue
			}
			if other.Timestamp.After(src.Timestamp) && other.Timestamp.Before(tgt.Timestamp) {
				return CheckResult{Status: CheckPresent, Detail: "a saturation episode of the same process ended without a recorded stop between them"}
			}
		}
		return CheckResult{Status: CheckAbsent, Detail: "checked: the only saturation end follows the stop directly"}
	},

	// --- episode recovery ---

	"EPISODE_RECOVERY_OBSERVED": func(g *Graph, src, tgt *Event) CheckResult {
		if src.Episode != "" && src.Episode == tgt.Episode && isRecoveryType(tgt.Type) {
			return CheckResult{Status: CheckPresent, Detail: "the observed end of episode " + src.Episode}
		}
		return CheckResult{Status: CheckAbsent, Detail: "the end event does not close the source episode"}
	},

	// --- network (dormant until socket telemetry lands, §7) ---

	// SOCKET_OWNED_BY_STOPPED_IDENTITY (§7.2): the stall's recorded owner is
	// the stopped process incarnation. source is the stop, target the stall.
	"SOCKET_OWNED_BY_STOPPED_IDENTITY": func(g *Graph, src, tgt *Event) CheckResult {
		if tgt.PID == 0 || tgt.StartTicks == 0 {
			return CheckResult{Status: CheckUnknown, Detail: "the socket owner was not resolved on the stall event"}
		}
		if src.PID == 0 || src.StartTicks == 0 {
			return CheckResult{Status: CheckUnknown, Detail: "the stopped process identity is incomplete"}
		}
		if tgt.PID != src.PID || tgt.StartTicks != src.StartTicks {
			return CheckResult{Status: CheckAbsent, Detail: fmt.Sprintf("socket owner %d@%d is not the stopped process %d@%d", tgt.PID, tgt.StartTicks, src.PID, src.StartTicks)}
		}
		return CheckResult{Status: CheckPresent, Sampled: true, Detail: fmt.Sprintf("socket owner %d@%d is the stopped process", tgt.PID, tgt.StartTicks)}
	},
	// STALL_SHAPE_LOCAL_NOT_READING (§7.2): unread data sits in our receive
	// queue. read from the stall event (the target) that recorded the queues.
	"STALL_SHAPE_LOCAL_NOT_READING": func(g *Graph, src, tgt *Event) CheckResult {
		recvq, ok := tgt.Data["recv_q"]
		if !ok {
			return CheckResult{Status: CheckUnknown, Detail: "receive queue was not recorded on the stall event"}
		}
		q, ok := asFloat(recvq)
		if !ok {
			return CheckResult{Status: CheckUnknown, Detail: "receive queue was not numeric"}
		}
		if q > 0 {
			return CheckResult{Status: CheckPresent, Sampled: true, Detail: fmt.Sprintf("%.0f bytes unread in our receive queue during the stall", q)}
		}
		return CheckResult{Status: CheckAbsent, Detail: "receive queue empty: we were reading"}
	},
	"NETWORK_PROGRESS_RESUMED_BEFORE_TRIGGER": func(g *Graph, src, tgt *Event) CheckResult {
		return CheckResult{Status: CheckUnknown, Detail: "socket byte counters are not captured in v1 bundles"}
	},
	"WORKER_EXIT_MATCHES_TRIGGER": func(g *Graph, src, tgt *Event) CheckResult {
		return CheckResult{Status: CheckUnknown, Detail: "runner/job role telemetry is not captured in v1 bundles"}
	},
}

// asFloat reads a numeric bundle fact without type assertion on data: the
// JSON round-trip makes every number float64, so accept both ints and floats
// (A18).
func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// exitStatus reads the recorded exit state of an exit event; empty string is
// "not captured", the honest v1 answer.
func exitStatus(e *Event) string {
	s, _ := e.Data["exit_state"].(string)
	return s
}

// intField reads one numeric fact off an event. A stored graph has been
// through JSON, so the same value can arrive as int, int64 or float64;
// identity never depends on data (audit A18), but non-identity numbers such
// as a signal number do.
func intField(e *Event, key string) (int, bool) {
	switch v := e.Data[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case uint64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// resolveRuleCodes verifies every declared check code resolves to an
// evaluator (invariant 4: no code is a placeholder wearing a real name).
func resolveRuleCodes(rule *Rule) error {
	for _, rulecodes := range [][]string{rule.Required, rule.Contradicting, rule.Supporting, rule.Discriminator} {
		for _, code := range rulecodes {
			if _, err := lookupCheck(code); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortRules(rules []*Rule) {
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
}
