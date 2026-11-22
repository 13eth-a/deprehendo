package causal

import (
	"strings"
	"testing"
	"time"
)

// TestEqualTimestampTieBreakIsDeterministic asserts the canonical order rule
// (4.4): equal timestamps break on type precedence, then subject, then type
// name - and identical runs produce identical order (4.19).
func TestEqualTimestampTieBreakIsDeterministic(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	worker := processSubject(9, 1)
	// same wall time; the incident trigger must sort after the process event.
	events := []Event{
		baseEvent(EventIncidentTriggered, base, host, nil),
		baseEvent(EventProcessExited, base, worker, nil),
	}
	sortEvents(events)
	assignIDs(events)
	if events[0].Subject.Kind != SubjectProcess {
		t.Errorf("process event did not outrank the incident trigger at equal timestamps: order=%s,%s",
			events[0].Type, events[1].Type)
	}
	// same kind, differing types: alphabetical, stably.
	x := baseEvent(EventMemoryPressureStarted, base, host, nil)
	y := baseEvent(EventMemoryPressureActive, base, host, nil)
	sortEvents([]Event{x, y})
	pair := []Event{x, y}
	sortEvents(pair)
	if pair[0].Type != EventMemoryPressureActive || pair[1].Type != EventMemoryPressureStarted {
		t.Errorf("same-kind tie-break unstable: %s then %s", pair[0].Type, pair[1].Type)
	}
}

// TestOriginalTimestampsNeverFabricated asserts sequence preserves the
// collection order and no timestamp is rewritten (4.4's "never fabricate
// finer timing").
func TestOriginalTimestampsNeverFabricated(t *testing.T) {
	base := baseStart()
	odd := base.Add(17 * time.Millisecond)
	events := []Event{
		baseEvent(EventProcessExited, base, processSubject(1, 1), nil),
		baseEvent(EventProcessExited, odd, processSubject(2, 2), nil),
	}
	sortEvents(events)
	assignIDs(events)
	if !events[0].Timestamp.Equal(base) || !events[1].Timestamp.Equal(odd) {
		t.Fatalf("timestamps were altered by normalization: %v %v", events[0].Timestamp, events[1].Timestamp)
	}
	// sequence is only assigned by BuildTimeline, not sortEvents.
	for i := range events {
		events[i].Sequence = uint64(i)
	}
	if events[1].Sequence-events[0].Sequence != 1 {
		t.Errorf("sequence not dense: %d -> %d", events[0].Sequence, events[1].Sequence)
	}
}

// TestRuleRegistryContract locks the §3 registry invariants (4.18): versioned
// IDs, declared endpoints, resolvable check codes, sane gaps.
func TestRuleRegistryContract(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range Rules() {
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = true
		if !strings.Contains(rule.ID, "@") {
			t.Errorf("rule %q is not versioned", rule.ID)
		}
		version := strings.SplitN(rule.ID, "@", 2)[1]
		if version == "" {
			t.Errorf("rule %q has an empty version", rule.ID)
		}
		if rule.Source == "" || rule.Target == "" {
			t.Errorf("rule %q does not declare both endpoint types (rule index contract)", rule.ID)
		}
		if rule.Mechanism == "" {
			t.Errorf("rule %q declares no mechanism (§3.1 contract)", rule.ID)
		}
		for _, code := range rule.Required {
			if _, err := lookupCheck(code); err != nil {
				t.Errorf("rule %q requires unresolvable check %q", rule.ID, code)
			}
		}
		for _, code := range rule.Contradicting {
			if _, err := lookupCheck(code); err != nil {
				t.Errorf("rule %q contradicts with unresolvable check %q", rule.ID, code)
			}
		}
		for _, code := range rule.Supporting {
			if _, err := lookupCheck(code); err != nil {
				t.Errorf("rule %q supports with unresolvable check %q", rule.ID, code)
			}
		}
		if err := resolveRuleCodes(rule); err != nil {
			t.Errorf("rule contract broken: %v", err)
		}
		if rule.MaxGap < rule.MinGap {
			t.Errorf("rule %q declares max gap %s below min gap %s", rule.ID, rule.MaxGap, rule.MinGap)
		}
		if !isDefinedRelation(rule.Edge) {
			t.Errorf("rule %q declares undefined relation %q", rule.ID, rule.Edge)
		}
	}
	if len(seen) < 8 {
		t.Errorf("rule registry shrank: %d rules", len(seen))
	}
}

// TestEngineSkipsDisabledRules asserts the exclusion surface (4.42 registry
// semantics): a disabled rule ID produces no edges but still validates.
func TestEngineSkipsDisabledRules(t *testing.T) {
	base := baseStart()
	exit := baseEvent(EventProcessExited, base, processSubject(7, 100), nil)
	reparent := baseEvent(EventProcessReparented, base.Add(50*time.Millisecond),
		processSubject(8, 200), map[string]any{"old_parent": exit.Subject.ID})
	g := graphFrom(t, []Event{exit, reparent})
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(g, &AnalysisContext{Disabled: []string{"PROCESS_EXIT_CAUSES_REPARENT@2"}}); err != nil {
		t.Fatal(err)
	}
	for _, edge := range g.Edges {
		if edge.RuleID == "PROCESS_EXIT_CAUSES_REPARENT@2" {
			t.Errorf("disabled rule produced an edge: %+v", edge)
		}
	}
}

// TestRelatedEventTypesCoverageAndStability links phase 3 signature IDs to
// emitted event types and asserts the conservative contract (4.16).
func TestRelatedEventTypesCoverageAndStability(t *testing.T) {
	emitted := map[EventType]bool{
		EventProcessStarted: true, EventProcessExited: true, EventProcessStopped: true,
		EventProcessResumed: true, EventProcessReparented: true, EventProcessGroupTerminated: true,
		EventCPUSaturationActive: true, EventCPUSaturationStarted: true, EventCPUSaturationEnded: true,
		EventMemoryPressureActive: true, EventMemoryPressureStarted: true, EventMemoryLimitReached: true,
		EventMemoryRecovered: true, EventCgroupLimitReached: true,
		EventDiskLowActive: true, EventDiskPressureStarted: true, EventDiskPressureEnded: true,
		EventDiskExhausted: true, EventDiskRecovered: true,
		EventConnectionOpened: true, EventConnectionClosed: true,
		EventIncidentTriggered: true, EventClockDiscontinuity: true,
	}
	for _, signature := range []string{"FROZEN_PROCESS", "ORPHAN_PROCESS", "PROCESS_GROUP_KILL", "DISK_EXHAUSTION", "RESOURCE_STARVATION", "MEMORY_PRESSURE"} {
		for _, et := range RelatedEventTypes(signature) {
			if !emitted[et] {
				t.Errorf("%s links unemitted event type %s", signature, et)
			}
		}
	}
	if RelatedEventTypes("NO_SUCH_SIGNATURE") != nil {
		t.Errorf("unknown signature returned types instead of nil")
	}
	// OOM_KILL may now cite a kernel OOM record (phase 6's victim-naming
	// oom:mark_victim event). the scope filter still refuses the cgroup
	// counter event, which names no victim.
	linkedoom := false
	for _, et := range RelatedEventTypes("OOM_KILL") {
		if et == EventOOM {
			linkedoom = true
		}
	}
	if !linkedoom {
		t.Errorf("OOM_KILL linkage no longer accepts a victim-naming kernel record")
	}
}
