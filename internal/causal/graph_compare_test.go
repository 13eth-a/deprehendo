package causal

import (
	"strings"
	"testing"
	"time"
)

func addRuleEdge(t *testing.T, g *Graph, ruleID string, from, to EventType) {
	t.Helper()
	for _, rule := range Rules() {
		if rule.ID != ruleID {
			continue
		}
		var fromID, toID EventID
		for _, id := range g.EventIDs() {
			switch g.Get(id).Type {
			case from:
				fromID = id
			case to:
				toID = id
			}
		}
		if fromID == "" || toID == "" {
			t.Fatalf("fixture lacks %s or %s", from, to)
		}
		// V3: a non-temporal edge carries its declared check records and
		// mechanism; the band equals the recomputed cap without demotions.
		checks := []CheckRecord{}
		discriminator := map[string]bool{}
		for _, code := range rule.Discriminator {
			discriminator[code] = true
		}
		for _, code := range rule.Required {
			kind := "required"
			if discriminator[code] {
				kind = "required"
			}
			checks = append(checks, CheckRecord{Kind: kind, Code: code, Status: CheckPresent, Detail: "test fixture evidence"})
		}
		for _, code := range rule.Contradicting {
			checks = append(checks, CheckRecord{Kind: "contradicting", Code: code, Status: CheckAbsent, Detail: "checked, absent in fixture"})
		}
		p := EdgeProposal{From: fromID, To: toID, Relation: rule.Edge, Confidence: capBand(rule.Ceiling, nil),
			Evidence: []EvidenceNote{{Code: "TEST_EVIDENCE", Detail: "known fixture fact"}},
			Checks:   checks, Mechanism: rule.Mechanism}
		p.ruleID = rule.ID
		if err := g.addEdge(p); err != nil {
			t.Fatalf("add %s: %v", rule.ID, err)
		}
		return
	}
	t.Fatalf("unknown test rule %q", ruleID)
}

// withEpisode stamps the episode instance a state-machine event belongs to,
// so test-built events can satisfy the SAME_EPISODE binding contract (P3).
func withEpisode(e Event, episode string) Event {
	e.Episode = episode
	return e
}

// TestGraphComparisonChecksStructureRatherThanRendering satisfies 4.40:
// fixture assertions compare nodes, edges, relations, roots, and rules.
func TestGraphComparisonChecksStructureRatherThanRendering(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	incident := baseEvent(EventIncidentTriggered, base.Add(2*time.Second), host, nil)
	pressure := withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1")
	limit := withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, nil), "memory:host:local#1")
	g := graphFrom(t, []Event{pressure, limit, incident})
	addRuleEdge(t, g, "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1", EventMemoryPressureStarted, EventMemoryLimitReached)
	if err := g.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}

	wantnodes := map[EventType]bool{EventMemoryPressureStarted: false, EventMemoryLimitReached: false, EventIncidentTriggered: false}
	for _, id := range g.EventIDs() {
		if _, ok := wantnodes[g.Get(id).Type]; ok {
			wantnodes[g.Get(id).Type] = true
		}
	}
	for typ, found := range wantnodes {
		if !found {
			t.Errorf("expected node %s absent", typ)
		}
	}
	if len(g.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(g.Edges))
	}
	edge := g.Edges[0]
	if g.Get(edge.From).Type != EventMemoryPressureStarted || g.Get(edge.To).Type != EventMemoryLimitReached {
		t.Errorf("wrong endpoints: %s -> %s", g.Get(edge.From).Type, g.Get(edge.To).Type)
	}
	if edge.Relation != RelationEscalates || edge.RuleID != "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1" || edge.ID == "" {
		t.Errorf("wrong edge contract: %+v", edge)
	}
	// the escalation makes the limit a severe anchor whose candidate
	// resolves up the episode to the onset (§5.2 criterion 3).
	var limitAnalysis *FailureAnalysis
	for i := range g.FailureAnalyses() {
		if g.FailureAnalyses()[i].AnchorType == EventMemoryLimitReached {
			limitAnalysis = &g.FailureAnalyses()[i]
		}
	}
	if limitAnalysis == nil {
		t.Fatal("no analysis for the limit anchor")
	}
	if limitAnalysis.Status != StatusUnknown {
		t.Errorf("limit anchor status = %s, want UNKNOWN", limitAnalysis.Status)
	}
	// Re-audit R6 (§5.2 clarified): an escalation-only path is the anchor's
	// own episode, not a contributing factor. no candidate; the onset is the
	// first step of the known chain.
	if len(limitAnalysis.Candidates) != 0 {
		t.Errorf("escalation-only onset listed as a candidate: %+v", limitAnalysis.Candidates)
	}
	var knownChain []EventType
	for _, id := range limitAnalysis.KnownChain {
		knownChain = append(knownChain, g.Get(id).Type)
	}
	if len(knownChain) != 2 || knownChain[0] != EventMemoryPressureStarted || knownChain[1] != EventMemoryLimitReached {
		t.Errorf("wrong known chain: %v", knownChain)
	}
	if chains := g.Chains(); len(chains) != 0 {
		t.Errorf("escalation-only reach produced rendered chains: %+v", chains)
	}
}

// TestValidateRejectsUnknownRuleAndWrongRuleEndpoints enforces 4.34 rule
// validity instead of accepting arbitrary version-shaped strings.
func TestValidateRejectsUnknownRuleAndWrongRuleEndpoints(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	p := baseEvent(EventMemoryPressureStarted, base, host, nil)
	l := baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, nil)
	g := graphFrom(t, []Event{p, l})
	proposal := EdgeProposal{From: g.order[0], To: g.order[1], Relation: RelationCauses, Confidence: ConfidenceMedium,
		Evidence: []EvidenceNote{{Code: "TEST"}},
		Checks:   []CheckRecord{{Kind: "required", Code: "SAME_SUBJECT_AS_VICTIM", Status: CheckPresent}}, Mechanism: "test"}
	proposal.ruleID = "MADE_UP@1"
	if err := g.addEdge(proposal); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "unknown or unversioned rule") {
		t.Fatalf("Validate() = %v, want unknown rule", err)
	}

	g = graphFrom(t, []Event{p, l})
	proposal = EdgeProposal{From: g.order[0], To: g.order[1], Relation: RelationPrecedes, Confidence: ConfidenceLow, Evidence: []EvidenceNote{{Code: "TEST"}}}
	proposal.ruleID = "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1"
	if err := g.addEdge(proposal); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "declared endpoints/relation") {
		t.Fatalf("Validate() = %v, want rule relation mismatch", err)
	}
}

// TestValidateRejectsDerivedEventWithoutProvenance tests provenance required
// by the graph validator (4.34).
func TestValidateRejectsDerivedEventWithoutProvenance(t *testing.T) {
	base := baseStart()
	e := baseEvent(EventMemoryPressureStarted, base, SubjectRef{SubjectHost, "local"}, nil)
	e.Provenance.Sources = nil
	g := graphFrom(t, []Event{e})
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("Validate() = %v, want missing provenance", err)
	}
}

// TestValidateAcceptsNetworkProgressDerivedRule guards the live socket path:
// stall events are stamped with RuleNetworkProgress, which must be a known
// derived rule or every real socket stall fails graph validation.
func TestValidateAcceptsNetworkProgressDerivedRule(t *testing.T) {
	base := baseStart()
	e := baseEvent(EventNetworkProgressStopped, base, SubjectRef{SubjectSocket, "inode-7"}, nil)
	e.Provenance.RuleID = RuleNetworkProgress
	g := graphFrom(t, []Event{e})
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want network progress event accepted", err)
	}
}

// TestValidateRejectsDuplicateEventIDs checks duplicate map/order identity
// defects cannot silently escape graph construction.
func TestValidateRejectsDuplicateEventIDs(t *testing.T) {
	base := baseStart()
	a := baseEvent(EventProcessStarted, base, processSubject(1, 1), nil)
	b := baseEvent(EventProcessExited, base.Add(time.Second), processSubject(1, 1), nil)
	a.ID, b.ID = "EV_DUP", "EV_DUP"
	g := NewGraph(&Timeline{Events: []Event{a, b}, Origin: base})
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "sizes") {
		t.Fatalf("Validate() = %v, want duplicate ID", err)
	}
}

// TestPrecedesRequiresObservedStrictOrder checks equal timestamp ordering may
// not be presented as an observed PRECEDES relation (4.7).
func TestPrecedesRequiresObservedStrictOrder(t *testing.T) {
	base := baseStart()
	a := baseEvent(EventProcessStopped, base, processSubject(1, 1), nil)
	b := baseEvent(EventIncidentTriggered, base, SubjectRef{SubjectHost, "local"}, nil)
	g := graphFrom(t, []Event{a, b})
	var from, to EventID
	for _, id := range g.EventIDs() {
		if g.Get(id).Type == EventProcessStopped {
			from = id
		} else {
			to = id
		}
	}
	p := EdgeProposal{From: from, To: to, Relation: RelationPrecedes, Confidence: ConfidenceLow}
	p.ruleID = "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1"
	if err := g.addEdge(p); err == nil || !strings.Contains(err.Error(), "equal wall timestamps") {
		t.Fatalf("equal-timestamp PRECEDES = %v, want no-order rejection", err)
	}
}

// TestEngineRuleContractsPositiveNegativeAndMissingEvidence gives each
// executable high-impact rule a positive fixture plus a negative or missing
// contract fixture; dormant signal rules are explicitly tested as missing.
func TestEngineRuleContractsPositiveNegativeAndMissingEvidence(t *testing.T) {
	base := baseStart()

	t.Run("memory threshold positive", func(t *testing.T) {
		host := SubjectRef{SubjectHost, "local"}
		g := graphFrom(t, []Event{
			withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1"),
			withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, map[string]any{"memory_percent": 99.0}), "memory:host:local#1"),
		})
		engine := NewEngine(Rules(), base)
		if _, err := engine.Apply(g, nil); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range g.Edges {
			if e.RuleID == "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected rule edge; rejections=%+v", g.Rejected)
		}
	})

	t.Run("unrelated memory subjects negative", func(t *testing.T) {
		g := graphFrom(t, []Event{
			withEpisode(baseEvent(EventMemoryPressureStarted, base, SubjectRef{SubjectHost, "host-A"}, nil), "memory:host:a#1"),
			withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), SubjectRef{SubjectHost, "host-B"}, nil), "memory:host:b#1"),
		})
		engine := NewEngine(Rules(), base)
		_, _ = engine.Apply(g, nil)
		for _, edge := range g.Edges {
			if edge.RuleID == "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1" {
				t.Fatal("unrelated subject memory events were causally linked")
			}
		}
	})

	t.Run("reparent lineage positive", func(t *testing.T) {
		parent := processSubject(10, 100)
		exit := baseEvent(EventProcessExited, base, parent, nil)
		exit.PID = 10 // the typed identity of the exiting parent
		child := baseEvent(EventProcessReparented, base.Add(50*time.Millisecond), processSubject(11, 101), nil)
		child.PPID = 10 // the typed identity the kernel reparent fact records
		g := graphFrom(t, []Event{
			exit,
			child,
		})
		engine := NewEngine(Rules(), base)
		_, _ = engine.Apply(g, nil)
		found := false
		for _, edge := range g.Edges {
			if edge.RuleID == "PROCESS_EXIT_CAUSES_REPARENT@2" {
				found = true
			}
		}
		if !found {
			t.Fatalf("recorded parent PID lineage failed to match; rejects=%+v", g.Rejected)
		}
	})

	t.Run("unrelated parent lineage negative", func(t *testing.T) {
		child := baseEvent(EventProcessReparented, base.Add(50*time.Millisecond), processSubject(11, 101), nil)
		child.PPID = 99
		g := graphFrom(t, []Event{
			baseEvent(EventProcessExited, base, processSubject(10, 100), nil),
			child,
		})
		engine := NewEngine(Rules(), base)
		_, _ = engine.Apply(g, nil)
		for _, edge := range g.Edges {
			if edge.RuleID == "PROCESS_EXIT_CAUSES_REPARENT@2" {
				t.Fatal("unrelated PPID linked as causal")
			}
		}
	})

	t.Run("OOM signal missing", func(t *testing.T) {
		g := graphFrom(t, []Event{
			baseEvent(EventOOM, base, SubjectRef{SubjectHost, "local"}, nil),
			baseEvent(EventProcessExited, base.Add(100*time.Millisecond), SubjectRef{SubjectHost, "local"}, nil),
		})
		engine := NewEngine(Rules(), base)
		_, _ = engine.Apply(g, nil)
		matched := false
		for _, edge := range g.Edges {
			if edge.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" {
				matched = true
			}
		}
		if matched {
			t.Fatal("OOM edge created without required kernel signal evidence")
		}
		foundmissing := false
		for _, rejected := range g.Rejected {
			if rejected.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" && strings.Contains(rejected.Reason, "unobservable in this bundle") {
				foundmissing = true
			}
		}
		if !foundmissing {
			t.Errorf("missing required signal evidence not reported: %+v", g.Rejected)
		}
	})

	t.Run("max gap boundary", func(t *testing.T) {
		g := graphFrom(t, []Event{
			baseEvent(EventOOM, base, SubjectRef{SubjectHost, "local"}, nil),
			baseEvent(EventProcessExited, base.Add(2*time.Second), SubjectRef{SubjectHost, "local"}, nil),
		})
		engine := NewEngine(Rules(), base)
		_, _ = engine.Apply(g, nil)
		foundmissingsignal := false
		for _, rejected := range g.Rejected {
			if rejected.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" && strings.Contains(rejected.Reason, "unobservable in this bundle") {
				foundmissingsignal = true
			}
		}
		if !foundmissingsignal {
			t.Fatalf("at-boundary pair did not reach evidence check: %+v", g.Rejected)
		}
		g = graphFrom(t, []Event{
			baseEvent(EventOOM, base, SubjectRef{SubjectHost, "local"}, nil),
			baseEvent(EventProcessExited, base.Add(2*time.Second+time.Nanosecond), SubjectRef{SubjectHost, "local"}, nil),
		})
		_, _ = engine.Apply(g, nil)
		for _, rejected := range g.Rejected {
			if rejected.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" {
				t.Fatal("out-of-bound pair should be skipped before evidence matching")
			}
		}
	})
}
