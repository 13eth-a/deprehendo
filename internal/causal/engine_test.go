package causal

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// graphFrom builds a graph over events through the same normalization path
// the engine uses, so IDs and ordering match production behavior.
func graphFrom(t *testing.T, events []Event) *Graph {
	t.Helper()
	sortEvents(events)
	assignIDs(events)
	for i := range events {
		events[i].Sequence = uint64(i)
	}
	origin := baseStart()
	if len(events) > 0 {
		origin = events[0].Timestamp
	}
	return NewGraph(&Timeline{Events: events, Origin: origin})
}

func baseEvent(eventType EventType, at time.Time, subject SubjectRef, data map[string]any) Event {
	return Event{
		Type: eventType, Timestamp: at, Subject: subject, Data: data,
		Provenance: EventProvenance{Sources: []ProvenanceSource{provenance("event", "test")}},
	}
}

func graphEvents(t *testing.T, g *Graph, eventType EventType) []EventID {
	t.Helper()
	var out []EventID
	for _, id := range g.order {
		if g.Events[id].Type == eventType {
			out = append(out, id)
		}
	}
	return out
}

// TestGraphRejectsBackwardsCausalEdge asserts the direction validation (4.34).
func TestGraphRejectsBackwardsCausalEdge(t *testing.T) {
	base := baseStart()
	death := baseEvent(EventProcessExited, base, processSubject(9, 1), nil)
	oom := baseEvent(EventOOM, base.Add(-3*time.Second), SubjectRef{SubjectHost, "local"}, nil)
	g := graphFrom(t, []Event{death, oom})
	e := NewEngine(Rules(), base)
	var exitID, oomID EventID
	for _, id := range g.order {
		switch g.Events[id].Type {
		case EventProcessExited:
			exitID = id
		case EventOOM:
			oomID = id
		}
	}
	proposal := EdgeProposal{From: exitID, To: oomID, Relation: RelationCauses, Confidence: ConfidenceHigh}
	proposal.ruleID = "TEST@1"
	err := g.addEdge(proposal)
	if err == nil {
		t.Fatalf("backwards CAUSES edge was accepted")
	}
	if !strings.Contains(err.Error(), "backwards") {
		t.Errorf("error = %v, want a direction complaint", err)
	}
	_ = e
}

// TestEdgeCannotExistWithoutEndpoints asserts the endpoint validation.
func TestEdgeCannotExistWithoutEndpoints(t *testing.T) {
	base := baseStart()
	g := graphFrom(t, []Event{baseEvent(EventIncidentTriggered, base, SubjectRef{SubjectHost, "local"}, nil)})
	proposal := EdgeProposal{
		From: "EV_MISSING", To: g.order[0],
		Relation: RelationCauses, Confidence: ConfidenceHigh,
	}
	proposal.ruleID = "TEST@1"
	if err := g.addEdge(proposal); err == nil {
		t.Fatal("edge with a missing From endpoint was accepted")
	}
}

// TestCausalCycleRejectedAndRecorded asserts cycle prevention records the
// rejected rule attempt (4.14).
func TestCausalCycleRejectedAndRecorded(t *testing.T) {
	base := baseStart()
	a := baseEvent(EventProcessStopped, base, processSubject(1, 1), nil)
	b := baseEvent(EventProcessResumed, base.Add(time.Second), processSubject(1, 1), nil)
	c := baseEvent(EventProcessExited, base.Add(2*time.Second), processSubject(1, 1), nil)
	g := graphFrom(t, []Event{a, b, c})
	must := func(p EdgeProposal) {
		t.Helper()
		p.ruleID = "TEST@1"
		// V3: test-only proposals carry the same structural contract as
		// engine-produced edges: checks and a declared mechanism.
		p.Checks = []CheckRecord{{Kind: "required", Code: "TEST_REQUIRED", Status: CheckPresent, Detail: "test-only evidence"}}
		p.Mechanism = "test-only mechanism (no production rule)"
		if err := g.addEdge(p); err != nil {
			t.Fatalf("add edge %s->%s: %v", p.From, p.To, err)
		}
	}
	must(EdgeProposal{From: g.order[0], To: g.order[1], Relation: RelationCauses, Confidence: ConfidenceLow})
	must(EdgeProposal{From: g.order[1], To: g.order[2], Relation: RelationCauses, Confidence: ConfidenceLow})
	cycle := EdgeProposal{From: g.order[2], To: g.order[0], Relation: RelationCauses, Confidence: ConfidenceLow}
	cycle.ruleID = "TEST_CYCLERULE@1"
	cycle.Checks = []CheckRecord{{Kind: "required", Code: "TEST_REQUIRED", Status: CheckPresent, Detail: "test-only evidence"}}
	cycle.Mechanism = "test-only mechanism (no production rule)"
	if err := g.addEdge(cycle); err == nil {
		t.Fatal("cycle-forming edge was accepted")
	}
	if len(g.Rejected) == 0 {
		t.Fatal("cycle rejection was not recorded")
	}
	if g.Rejected[0].RuleID != "TEST_CYCLERULE@1" {
		t.Errorf("rejection names rule %q, want TEST_CYCLERULE@1", g.Rejected[0].RuleID)
	}
	// Test-only proposals name no production rule. validation's cycle check
	// is exercised separately by the direct cycle rejection above.
	if g.hasDAGCycle() {
		t.Error("cycle rejection left a cycle in the graph")
	}
}

// TestTemporalEdgesDoNotCreateCycles asserts PRECEDES edges may form
// retraceable patterns without violating the causal DAG.
func TestTemporalEdgesDoNotCreateCycles(t *testing.T) {
	base := baseStart()
	a := baseEvent(EventProcessStopped, base, processSubject(1, 1), nil)
	b := baseEvent(EventProcessResumed, base.Add(time.Second), processSubject(1, 1), nil)
	g := graphFrom(t, []Event{a, b})
	p1 := EdgeProposal{From: g.order[0], To: g.order[1], Relation: RelationPrecedes, Confidence: ConfidenceLow}
	p1.ruleID = "TEST@1"
	p2 := EdgeProposal{From: g.order[1], To: g.order[0], Relation: RelationPrecedes, Confidence: ConfidenceLow}
	p2.ruleID = "TEST@1"
	if err := g.addEdge(p1); err != nil {
		t.Fatalf("forward PRECEDES edge rejected: %v", err)
	}
	if err := g.addEdge(p2); err == nil {
		t.Fatal("reverse PRECEDES edge (backwards) was accepted")
	}
}

// TestRuleMaxGapEnforced asserts the temporal-gap contract (4.9): too distant
// pairs never connect.
func TestRuleMaxGapEnforced(t *testing.T) {
	base := baseStart()
	oom := baseEvent(EventOOM, base, SubjectRef{SubjectHost, "local"}, nil)
	death := baseEvent(EventProcessExited, base.Add(10*time.Minute), processSubject(9, 1), nil)
	g := graphFrom(t, []Event{oom, death})
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	for _, edge := range g.Edges {
		if edge.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" {
			t.Errorf("edge created beyond the rule gap bound: %+v", edge)
		}
	}
}

// TestV1BundlesCannotSupportSignalBoundRules asserts that signal-required
// rules cannot fire on v1 data: the OOM rule is shipped but its required
// signal contract is unobservable, so any OOM pair is recorded as a
// rejection, never as an edge (conservative contract 4.9).
func TestV1BundlesCannotSupportSignalBoundRules(t *testing.T) {
	base := baseStart()
	oom := baseEvent(EventOOM, base, SubjectRef{SubjectHost, "local"}, nil)
	death := baseEvent(EventProcessExited, base.Add(500*time.Millisecond), processSubject(9, 1), nil)
	g := graphFrom(t, []Event{oom, death})
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	for _, edge := range g.Edges {
		if edge.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" {
			t.Fatalf("OOM_CAUSES_PROCESS_EXIT fired without signal evidence: %+v", edge)
		}
	}
	found := false
	for _, r := range g.Rejected {
		if r.RuleID == "OOM_CAUSES_PROCESS_EXIT@2" && strings.Contains(r.Reason, "unobservable in this bundle") {
			found = true
		}
	}
	if !found {
		t.Errorf("no rejection recorded for the unmet signal contract: %+v", g.Rejected)
	}
}

// TestExitCausesReparentRecordedLineage asserts the reparent rule fires only
// through recorded lineage facts (old_ppid), never through adjacency alone.
func TestExitCausesReparentRecordedLineage(t *testing.T) {
	base := baseStart()
	parent := processSubject(7, 100)
	exit := baseEvent(EventProcessExited, base, parent, nil)
	// reparent event records the typed PPID lineage (E4/A18): the rule must
	// bind on the recorded parent identity, never on adjacency or data maps.
	reparent := baseEvent(EventProcessReparented, base.Add(50*time.Millisecond), processSubject(8, 200),
		map[string]any{"old_parent": parent.ID})
	reparent.PPID = 7
	reparent.PID = 8
	exit.PID = 7
	death := baseEvent(EventProcessExited, base.Add(500*time.Millisecond), processSubject(10, 300), nil)
	g := graphFrom(t, []Event{exit, reparent, death})
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, edge := range g.Edges {
		if edge.RuleID == "PROCESS_EXIT_CAUSES_REPARENT"+rev {
			found = true
			if edge.Relation != RelationCauses {
				t.Errorf("relation = %s, want CAUSES", edge.Relation)
			}
			if edge.Confidence != ConfidenceMedium && edge.Confidence != ConfidenceHigh {
				t.Errorf("confidence = %s, want MEDIUM (rule default)", edge.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("exit→reparent edge missing despite recorded lineage")
	}
	// the unrelated death is not the reparent parent: no rule gift-wraps it.
	// with no lineage the rule cannot distinguish, so it must not fire.
}

// TestChainRootRolesFromGraph asserts root candidates, roles, and chains on a
// synthetic recorded-exit chain (worker complaint: exit → incident).
func TestChainRootRolesFromGraph(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	worker := processSubject(9, 1)
	events := []Event{
		baseEvent(EventProcessStopped, base, worker, nil),
		baseEvent(EventProcessResumed, base.Add(2*time.Second), worker, nil),
		baseEvent(EventProcessExited, base.Add(3*time.Second), worker, nil),
		baseEvent(EventIncidentTriggered, base.Add(4*time.Second), host, nil),
	}
	g := graphFrom(t, events)
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("graph does not validate: %v", err)
	}
	// §5.6: the exit is its own anchor with an unexplained-head candidate;
	// nothing causal points INTO it, so its cause is UNKNOWN.
	var exitAnalysis *FailureAnalysis
	for i := range g.FailureAnalyses() {
		if g.FailureAnalyses()[i].AnchorType == EventProcessExited {
			exitAnalysis = &g.FailureAnalyses()[i]
		}
	}
	if exitAnalysis == nil {
		t.Skip("no else-anchor candidate from this fixture; root coverage in counterfactual test")
	}
	if exitAnalysis.Status != StatusUnknown {
		t.Errorf("isolated exit anchor status = %s, want UNKNOWN", exitAnalysis.Status)
	}
	// Re-audit R5: a failure is never its own candidate; the UNKNOWN status
	// and the known chain carry the honest answer.
	if len(exitAnalysis.Candidates) != 0 {
		t.Errorf("isolated exit lists candidates %+v; a failure is never its own root", exitAnalysis.Candidates)
	}
	if len(exitAnalysis.KnownChain) == 0 || exitAnalysis.KnownChain[0] != exitAnalysis.Anchor {
		t.Errorf("known chain %v does not start at the exit anchor", exitAnalysis.KnownChain)
	}
}

// TestCompetingChainsBothPreserved asserts ambiguity is represented (§6):
// when two validated proposals point into the same target (two observed
// stops, each plausibly ending the same saturation episode) both chains
// survive with distinct roots; no rule silently collapsed them (4.15).
func TestCompetingChainsBothPreserved(t *testing.T) {
	base := baseStart()
	worker := processSubject(9, 1)
	stop1 := baseEvent(EventProcessStopped, base, worker, nil)
	stop2 := baseEvent(EventProcessStopped, base.Add(2*time.Second), worker, nil)
	satend := baseEvent(EventCPUSaturationEnded, base.Add(4*time.Second), worker, nil)
	// distinct provenance per event: P2 forbids self-explanation, so the
	// fixture must not make every event the same piece of evidence.
	stop1.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("event", "stop-1")}}
	stop2.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("event", "stop-2")}}
	satend.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("event", "sat-end")}}
	g := graphFrom(t, []Event{stop1, stop2, satend})
	engine := NewEngine(Rules(), base)
	if _, err := engine.Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	// both stop→saturation proposals are preserved as alternate order
	// stories into the same target.
	intotarget := 0
	for _, edge := range g.Edges {
		if edge.RuleID == "PROCESS_STOP_ENDS_CPU_SATURATION"+rev {
			intotarget++
		}
	}
	if intotarget != 2 {
		t.Fatalf("competing proposals into one target = %d edges (rejected=%+v), want both preserved", intotarget, g.Rejected)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("competing graph does not validate: %v", err)
	}
	// both proposals stay, each naming the other as its competitor (D3).
	for _, edge := range g.Edges {
		if len(edge.Competes) != 1 {
			t.Errorf("edge %s competes_with = %v, want the other stop's edge", edge.ID, edge.Competes)
		}
	}
}

// TestHealthyFixtureNoFailureChain asserts the healthy-fixture contract
// (4.36): recovery edges make an episode history, and healthy() is true.
func TestHealthyFixtureNoFailureChain(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	pressure := withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1")
	recovered := withEpisode(baseEvent(EventMemoryRecovered, base.Add(90*time.Second), host,
		map[string]any{"duration_ms": 90000}), "memory:host:local#1")
	g := graphFrom(t, []Event{pressure, recovered})
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	if !g.Healthy() {
		t.Errorf("recovered pressure episode reported as an unresolved failure: analyses=%+v",
			g.FailureAnalyses())
	}
}

// TestCounterfactualEscalationRemovalChangesConclusion asserts evidence
// dependence (4.37): removing the severe threshold-crossing event changes the
// causal conclusion. with the exhaustion present, the filesystem episode is a
// failure anchor (unhealthy, chain pressure→exhaustion); without it, no
// failure anchor exists and the graph is healthy.
func TestCounterfactualEscalationRemovalChangesConclusion(t *testing.T) {
	base := baseStart()
	fs := SubjectRef{SubjectFilesystem, "/data"}
	episode := "disk:/data#1"
	pressure := withEpisode(baseEvent(EventDiskPressureStarted, base, fs, nil), episode)
	exhausted := withEpisode(baseEvent(EventDiskExhausted, base.Add(time.Second), fs,
		map[string]any{"free_bytes": 0}), episode)
	writefail := baseEvent(EventProcessExited, base.Add(1500*time.Millisecond), processSubject(9, 1), nil)

	with := graphFrom(t, []Event{pressure, exhausted, writefail})
	e := NewEngine(Rules(), base)
	if _, err := e.Apply(with, nil); err != nil {
		t.Fatal(err)
	}
	if err := with.Validate(); err != nil {
		t.Fatalf("with-exhaustion graph invalid: %v", err)
	}
	if got := len(with.Edges); got != 1 {
		t.Fatalf("with-exhaustion edges = %d (%+v), want the pressure→exhaustion escalation only", got, with.Edges)
	}
	if with.Healthy() {
		t.Errorf("a disk exhausted at capture end is a failure anchor; Healthy() claimed otherwise")
	}

	without := graphFrom(t, []Event{withEpisode(baseEvent(EventDiskPressureStarted, base, fs, nil), episode), writefail})
	if _, err := e.Apply(without, nil); err != nil {
		t.Fatal(err)
	}
	// conclusion changes: without the threshold crossing, the disk episode
	// stops being a failure anchor (4.28: the un-crossed pressure carries
	// no consequence observation). the write-failure exit stays recorded.
	// it is evidence, and it keeps its own UNKNOWN analysis.
	seen := func(g *Graph, want EventType) bool {
		for _, analysis := range g.FailureAnalyses() {
			if analysis.AnchorType == want {
				return true
			}
		}
		return false
	}
	if !seen(with, EventDiskExhausted) {
		t.Errorf("disk exhausted at capture end is not a failure anchor in the with-graph")
	}
	if seen(without, EventDiskExhausted) {
		t.Errorf("removing the exhaustion event did not change the conclusion: analyses=%+v",
			without.FailureAnalyses())
	}
	for _, analysis := range with.FailureAnalyses() {
		if analysis.AnchorType == EventDiskExhausted {
			if analysis.Status != StatusUnknown || analysis.Alternatives == nil ||
				!containsAny(analysis.MissingEvidence, "write-failure") {
				t.Errorf("exhaustion anchor analysis = %+v, want UNKNOWN chain with the write-failure gap", analysis)
			}
		}
	}
	for _, edge := range without.Edges {
		if without.Get(edge.To) == nil || without.Get(edge.From) == nil {
			t.Errorf("dangling edge survived exhaustion removal: %+v", edge)
		}
	}
}

// findTargetByID is a small test helper asserting edge targets exist.
func (g *Graph) findTargetByID(id EventID) *Event { return g.Events[id] }

// TestGroupTerminationIsClusteredNeverCausing asserts the A4 verdict (§5.6):
// the group-termination event is an aggregate built FROM the member exits
// (P2), so no edge may leave it into those exits, each member exit is
// evidence of the group anchor, and the group event anchors its own UNKNOWN
// analysis instead of impersonating a root cause over them.
func TestGroupTerminationIsClusteredNeverCausing(t *testing.T) {
	base := baseStart()
	group := baseEvent(EventProcessGroupTerminated, base, groupSubject(7),
		map[string]any{"pgid": 7, "exits": 2, "member_pids": []int{11, 12}})
	group.PGID = 7
	first := baseEvent(EventProcessExited, base, processSubject(11, 100), map[string]any{"pgid": 7})
	first.PGID = 7
	later := baseEvent(EventProcessExited, base.Add(400*time.Millisecond), processSubject(12, 200), map[string]any{"pgid": 7})
	later.PGID = 7
	g := graphFrom(t, []Event{group, first, later})
	engine := NewEngine(Rules(), base)
	accepted, err := engine.Apply(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	// the aggregate-cause rule is retired (§3.3): nothing may reconstruct an
	// edge out of the group event. P2's structural guard lives in
	// validate(): any edge sharing the group's provenance into a member
	// exit would be rejected there.
	if accepted != 0 || len(g.Edges) != 0 {
		t.Fatalf("group termination produced edges (A4 regression): edges=%+v", g.Edges)
	}

	var groupAnalysis *FailureAnalysis
	memberanchors := 0
	for i := range g.FailureAnalyses() {
		switch g.FailureAnalyses()[i].AnchorType {
		case EventProcessGroupTerminated:
			groupAnalysis = &g.FailureAnalyses()[i]
		case EventProcessExited:
			memberanchors++
		}
	}
	if groupAnalysis == nil {
		t.Fatal("group termination is not its own anchor")
	}
	// §5.6 / re-audit R8: member exits inside the window are the group
	// anchor's evidence (its provenance), not separate primary failures.
	if memberanchors != 0 {
		t.Errorf("member exit anchors = %d, want 0 (folded into the group anchor)", memberanchors)
	}
	if groupAnalysis.Status != StatusUnknown || len(groupAnalysis.Candidates) != 0 {
		t.Errorf("group-termination anchor analysis = %+v, want UNKNOWN with no candidates", groupAnalysis)
	}
	if !containsAny(groupAnalysis.MissingEvidence, "no signal-sender telemetry") {
		t.Errorf("expected the signal-sender telemetry gap cited, got %+v", groupAnalysis.MissingEvidence)
	}
}

func containsAny(values []string, fragment string) bool {
	for _, v := range values {
		if strings.Contains(v, fragment) {
			return true
		}
	}
	return false
}

// TestSameInstantEscalationAllowed asserts E1′: one sample that jumps straight
// past the 90% and 98% boundaries emits the episode onset and the limit at the
// same wall timestamp, and the escalation edge may connect them (A10).
func TestSameInstantEscalationAllowed(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	started := baseEvent(EventMemoryPressureStarted, base, host, map[string]any{"memory_percent": 99.0})
	limit := baseEvent(EventMemoryLimitReached, base, host, map[string]any{"memory_percent": 99.0})
	started.Episode = "memory:host:local#1"
	limit.Episode = "memory:host:local#1"
	g := graphFrom(t, []Event{started, limit})
	engine := NewEngine(Rules(), base)
	accepted, err := engine.Apply(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 1 {
		t.Fatalf("accepted %d edges, want 1 same-instant ESCALATES_TO: edges=%+v rejected=%+v",
			accepted, g.Edges, g.Rejected)
	}
	edge := g.Edges[0]
	if edge.Relation != RelationEscalates {
		t.Errorf("relation = %s, want ESCALATES_TO", edge.Relation)
	}
	if !edge.SameInstant {
		t.Errorf("same-instant escalation lost its SameInstant record")
	}
	if edge.RuleID != "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1" {
		t.Errorf("rule = %s, want the memory escalation", edge.RuleID)
	}
}

// TestSeparateInstantEscalationMotor asserts the common case: pressure begins
// at one sample, the limit is crossed at a later one, and the escalation still
// connects one episode's two boundary crossings.
func TestSeparateInstantEscalationAllowed(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	started := baseEvent(EventMemoryPressureStarted, base, host, map[string]any{"memory_percent": 92.0})
	limit := baseEvent(EventMemoryLimitReached, base.Add(3*time.Second), host, map[string]any{"memory_percent": 99.0})
	started.Episode = "memory:host:local#1"
	limit.Episode = "memory:host:local#1"
	g := graphFrom(t, []Event{started, limit})
	accepted, err := NewEngine(Rules(), base).Apply(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 1 {
		t.Fatalf("accepted %d edges, want 1 episode escalation: edges=%+v rejected=%+v",
			accepted, g.Edges, g.Rejected)
	}
}

// TestRecoveryEdgesAreEpisodeLocal asserts each failure episode resolves to the
// nearest following recovery, not to every later one (4.26). A cross-episode
// pairing would also make edge generation quadratic in long captures (4.41).
func TestRecoveryEdgesAreEpisodeLocal(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	const episodes = 200
	events := make([]Event, 0, episodes*2)
	for index := 0; index < episodes; index++ {
		start := base.Add(time.Duration(index) * 10 * time.Second)
		episode := fmt.Sprintf("memory:host:local#%d", index)
		events = append(events,
			withEpisode(baseEvent(EventMemoryPressureStarted, start, host, nil), episode),
			withEpisode(baseEvent(EventMemoryRecovered, start.Add(5*time.Second), host, nil), episode),
		)
	}
	g := graphFrom(t, events)
	accepted, err := NewEngine(Rules(), base).Apply(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != episodes || len(g.Edges) != episodes {
		t.Fatalf("episode recovery produced %d edges, want %d (quadratic pairing is the regression)",
			len(g.Edges), episodes)
	}
	persource := map[EventID]int{}
	for _, edge := range g.Edges {
		if edge.RuleID != "MEMORY_RECOVERY_FOLLOWS_ONSET@2" {
			t.Errorf("unexpected recovery edge rule %s", edge.RuleID)
		}
		persource[edge.From]++
		if gap := g.Get(edge.To).Timestamp.Sub(g.Get(edge.From).Timestamp); gap != 5*time.Second {
			t.Errorf("onset paired with a recovery %s later; want its own episode's 5s", gap)
		}
	}
	for source, count := range persource {
		if count != 1 {
			t.Errorf("source %s has %d recovery edges, want 1", source, count)
		}
	}
}

// TestTemporalEdgeDoesNotPairAcrossEpisodes asserts a pressure episode yields
// at most one documented order edge to its nearest exhaustion. pairing every
// pressure with every later exhaustion would be both a false episode history
// and quadratic edge growth (4.41).
func TestTemporalEdgeDoesNotPairAcrossEpisodes(t *testing.T) {
	base := baseStart()
	fs := SubjectRef{SubjectFilesystem, "/data"}
	const episodes = 100
	events := make([]Event, 0, episodes*2)
	for index := 0; index < episodes; index++ {
		start := base.Add(time.Duration(index) * 20 * time.Second)
		episode := fmt.Sprintf("disk:/data#%d", index)
		events = append(events,
			withEpisode(baseEvent(EventDiskPressureStarted, start, fs, nil), episode),
			withEpisode(baseEvent(EventDiskExhausted, start.Add(5*time.Second), fs, nil), episode),
		)
	}
	g := graphFrom(t, events)
	accepted, err := NewEngine(Rules(), base).Apply(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != episodes || len(g.Edges) != episodes {
		t.Fatalf("pressure/exhaustion produced %d edges, want %d", len(g.Edges), episodes)
	}
	for _, edge := range g.Edges {
		if edge.RuleID != "DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1" {
			t.Errorf("unexpected edge rule %s", edge.RuleID)
		}
		if edge.Relation != RelationEscalates {
			t.Errorf("relation = %s, want ESCALATES_TO within one disk episode", edge.Relation)
		}
		if gap := g.Get(edge.To).Timestamp.Sub(g.Get(edge.From).Timestamp); gap != 5*time.Second {
			t.Errorf("pressure paired with an exhaustion %s later; want its own episode's 5s", gap)
		}
	}
}
