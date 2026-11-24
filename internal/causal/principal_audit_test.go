package causal

// phase 4 principal audit counterexamples (2026-10-27).
//
// each test encodes one finding from docs/reviews/phase4-principal-audit.md as the
// behavior the binding spec (docs/causal-semantics.md) requires. they FAIL on
// the code as audited, so they are gated: by default each one skips with its
// finding ID. run them with
//
//	DEPREHENDO_REVIEW_AUDIT=1 go test ./internal/causal -run PrincipalAudit -v
//
// when a fix lands, delete that test's principalPending call so the test becomes
// a permanent regression guard. do not weaken an assertion to make it pass;
// if the spec is wrong, change the spec first and record why.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

func principalPending(t *testing.T, finding string) {
	t.Helper()
	if os.Getenv("DEPREHENDO_REVIEW_AUDIT") == "" {
		t.Skipf("principal-AUDIT %s pending engineering implementation (set DEPREHENDO_REVIEW_AUDIT=1 to run)", finding)
	}
}

// explainSection returns the text of one numbered explanation section (e.g.
// "contradictions:") up to the next numbered heading, or "" when the section
// is absent. section headings render as "N title:" on their own line.
func explainSection(text, title string) string {
	start := strings.Index(text, title)
	if start < 0 {
		return ""
	}
	linestart := strings.LastIndex(text[:start], "\n") + 1
	rest := text[linestart:]
	for i := 1; i < len(rest); i++ {
		if rest[i] != '\n' {
			continue
		}
		if j := i + 1; j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			return rest[:i]
		}
	}
	return rest
}

func analyzeIncident(t *testing.T, inc *incident.Incident) (*Timeline, *Graph) {
	t.Helper()
	tl := BuildTimeline(inc)
	g := NewGraph(tl)
	if _, err := NewEngine(Rules(), tl.Origin).Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	return tl, g
}

// rootsJSON reads root candidates through the public JSON contract (4.33), so
// the assertions survive the RootCandidate field additions the spec requires.
func rootsJSON(t *testing.T, g *Graph) []map[string]any {
	t.Helper()
	var candidates []RootCandidate
	for _, analysis := range g.FailureAnalyses() {
		candidates = append(candidates, analysis.Candidates...)
	}
	data, err := json.Marshal(candidates)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A1/A2: a healthy build that briefly touches the 98% boundary and recovers
// has no failure anchor, so it has no root cause and the graph is healthy.
// audited behavior: PRIMARY root MEMORY_PRESSURE_STARTED, healthy() == false.
func TestPrincipalAuditA1RecoveredConditionWithoutFailureIsNotARoot(t *testing.T) {

	b := baseStart()
	inc := &incident.Incident{CaptureStart: b, TriggeredAt: b.Add(10 * time.Second), Snapshots: []collector.Snapshot{
		snapAt(b, 0, memSys(500, 1000)),
		snapAt(b, 1*time.Second, memSys(920, 1000)),
		snapAt(b, 2*time.Second, memSys(985, 1000)),
		snapAt(b, 3*time.Second, memSys(600, 1000)),
		snapAt(b, 9*time.Second, memSys(600, 1000)),
	}}
	_, g := analyzeIncident(t, inc)
	var candidates []RootCandidate
	for _, analysis := range g.FailureAnalyses() {
		candidates = append(candidates, analysis.Candidates...)
	}
	if len(candidates) != 0 {
		t.Errorf("recovered condition with no failure produced root candidates: %+v", candidates)
	}
	if !g.Healthy() {
		t.Errorf("recovered memory episode reported unhealthy")
	}
}

// A1: in the oom-chain fixture the only failure (the worker exit) is not
// reached by any validated chain, so no root cause may be reported; the
// condition chain is context and the exit's cause is UNKNOWN.
func TestPrincipalAuditA1ConditionChainNotReachingFailureIsNotARootCause(t *testing.T) {

	_, g := analyzeIncident(t, loadCausalFixture(t, "oom-chain"))
	for _, root := range rootsJSON(t, g) {
		if root["kind"] == "ROOT_CAUSE" || root["kind"] == nil {
			t.Errorf("root-cause candidate reported although no chain reaches the PROCESS_EXITED failure: %v", root)
		}
	}
}

// A3: a causal edge never crosses an episode boundary. the first pressure
// episode recovered before the second episode reached the limit.
// audited behavior: both pressure-start events CAUSE the later limit event.
func TestPrincipalAuditA3NoCausalEdgeAcrossRecoveredEpisode(t *testing.T) {
	b := baseStart()
	inc := &incident.Incident{CaptureStart: b, Snapshots: []collector.Snapshot{
		snapAt(b, 0, memSys(500, 1000)),
		snapAt(b, 1*time.Second, memSys(920, 1000)),
		snapAt(b, 2*time.Second, memSys(500, 1000)),
		snapAt(b, 20*time.Second, memSys(500, 1000)),
		snapAt(b, 21*time.Second, memSys(920, 1000)),
		snapAt(b, 22*time.Second, memSys(990, 1000)),
	}}
	_, g := analyzeIncident(t, inc)
	for _, edge := range g.Edges {
		if !isCausal(edge.Relation) && edge.Relation != "ESCALATES_TO" {
			continue
		}
		from, to := g.Get(edge.From), g.Get(edge.To)
		if from.Timestamp.Before(b.Add(20*time.Second)) && to.Timestamp.After(b.Add(20*time.Second)) {
			t.Errorf("%s edge %s crosses the recovered episode boundary: %s@%s -> %s@%s",
				edge.Relation, edge.RuleID, from.Type, from.Timestamp.Sub(b), to.Type, to.Timestamp.Sub(b))
		}
	}
}

// A4: a derived summary event may not be a cause of the very events it was
// derived from. PROCESS_GROUP_TERMINATED is clustered from member exits.
func TestPrincipalAuditA4DerivedSummaryCannotCauseItsOwnSources(t *testing.T) {

	_, g := analyzeIncident(t, loadCausalFixture(t, "process-group-kill"))
	for _, edge := range g.Edges {
		if !isCausal(edge.Relation) {
			continue
		}
		from, to := g.Get(edge.From), g.Get(edge.To)
		for _, fromsource := range from.Provenance.Sources {
			for _, tosource := range to.Provenance.Sources {
				if fromsource == tosource {
					t.Errorf("%s: %s CAUSES %s but the source event was derived from the target's own evidence %v",
						edge.RuleID, from.Type, to.Type, tosource)
				}
			}
		}
	}
}

// A5: the edge explanation must report each declared contradiction check
// with its evaluation status; "none recorded" is not acceptable when the
// checks were never evaluated.
func TestPrincipalAuditA5ExplainReportsContradictionCheckStatus(t *testing.T) {
	b := baseStart()
	parent := baseEvent(EventProcessExited, b, processSubject(800, 10), nil)
	parent.PID = 800
	// A18/A22 (the fix): lineage binds on typed identity fields, never on a
	// data map, so the child records its pre-change parent as PPID.
	child := baseEvent(EventProcessReparented, b.Add(2*time.Second), processSubject(900, 20), nil)
	child.PID = 900
	child.PPID = 800
	g := graphFrom(t, []Event{parent, child})
	if _, err := NewEngine(Rules(), b).Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want the reparent edge, got %+v rejected=%+v", g.Edges, g.Rejected)
	}
	text, err := g.Explain(0)
	if err != nil {
		t.Fatal(err)
	}
	// the whole-text "none recorded" scan is gone: the fixed explainer's
	// honest alternatives line ("none recorded by the engine (checked, empty)")
	// contains that phrase on every edge. the A5 regression is pinned by the
	// contradictions section reporting the declared check's status.
	contradictions := explainSection(text, "Contradictions:")
	if contradictions == "" || strings.Contains(contradictions, "none recorded") ||
		!strings.Contains(contradictions, "CHILD_REPARENTED_BEFORE_EXIT") {
		t.Errorf("explanation omits the declared contradiction check or its evaluated status;\ncontradictions section: %q\nfull text:\n%s", contradictions, text)
	}
	if !strings.Contains(text, "CHILD_REPARENTED_BEFORE_EXIT") {
		t.Errorf("explanation omits the rule's declared contradiction check:\n%s", text)
	}
}

// A6: two independent candidates with equal support for the same failure are
// AMBIGUOUS. canonical order is a determinism device, not evidence, so it may
// not promote one of them to PRIMARY.
func TestPrincipalAuditA6TiedCompetingRootsAreNotSilentlyRanked(t *testing.T) {

	b := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	limita := baseEvent(EventMemoryLimitReached, b, host, map[string]any{"memory_percent": 99.0})
	limitb := baseEvent(EventCgroupLimitReached, b, SubjectRef{SubjectCgroup, "/runner"}, map[string]any{"memory_percent": 99.0})
	exit := baseEvent(EventProcessExited, b.Add(time.Second), processSubject(42, 7), nil)
	g := graphFrom(t, []Event{limita, limitb, exit})
	ids := g.EventIDs()
	bytype := map[EventType]EventID{}
	for _, id := range ids {
		bytype[g.Get(id).Type] = id
	}
	for _, src := range []EventType{EventMemoryLimitReached, EventCgroupLimitReached} {
		p := EdgeProposal{From: bytype[src], To: bytype[EventProcessExited], Relation: RelationCauses,
			Confidence: ConfidenceMedium, Evidence: []EvidenceNote{{Code: "TEST"}}}
		// V3: engine- and test-produced edges share the structural contract:
		// evaluated check records and a declared mechanism.
		p.Checks = []CheckRecord{{Kind: "required", Code: "TEST_REQUIRED", Status: CheckPresent, Detail: "test-only tie evidence"}}
		p.Mechanism = "test-only mechanism (no production rule)"
		p.ruleID = "TEST_RULE@1"
		if err := g.addEdge(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range rootsJSON(t, g) {
		if root["role"] == string(RolePrimary) {
			t.Errorf("tied, independent candidates for one failure: %v was promoted to PRIMARY by canonical order", root)
		}
	}
}

// A7: a small backward wall-clock step must be detected and must not be
// "repaired" by re-sorting samples, which fabricates a pre-capture episode
// and a recovery that never happened in capture order.
func TestPrincipalAuditA7BackwardClockStepIsDetectedNotReordered(t *testing.T) {

	b := baseStart()
	inc := &incident.Incident{CaptureStart: b, Snapshots: []collector.Snapshot{
		snapAt(b, 0, memSys(500, 1000)),
		snapAt(b, 2*time.Second, memSys(950, 1000)),
		snapAt(b, -3*time.Second, memSys(995, 1000)), // NTP step back by 5s
		snapAt(b, 4*time.Second, memSys(995, 1000)),
	}}
	tl, _ := analyzeIncident(t, inc)
	if countType(tl, EventClockDiscontinuity) == 0 {
		t.Errorf("5s backward clock step not reported: %v", eventTypesOf(tl))
	}
	if countType(tl, EventMemoryRecovered) != 0 {
		t.Errorf("re-sorting the stepped sample fabricated a memory recovery: %v", eventTypesOf(tl))
	}
	for _, e := range tl.Events {
		if e.Timestamp.Before(b) && e.Type != EventClockDiscontinuity {
			t.Errorf("%s placed before capture start by a clock step", e.Type)
		}
	}
}

// A8: a chain is only as strong as its weakest link. root confidence for a
// failure is the weakest edge on the best path to it, not the strongest
// edge leaving the root.
func TestPrincipalAuditA8RootConfidenceIsWeakestLink(t *testing.T) {
	b := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	limit := baseEvent(EventMemoryLimitReached, b, host, map[string]any{"memory_percent": 99.0})
	oom := baseEvent(EventOOM, b.Add(200*time.Millisecond), host, nil)
	exit := baseEvent(EventProcessExited, b.Add(400*time.Millisecond), processSubject(42, 7), nil)
	g := graphFrom(t, []Event{limit, oom, exit})
	// V3-lawful edges: each band equals its rule's recomputed cap, so the
	// chain's weakest link is the first edge's MEDIUM, not the head's HIGH.
	addRuleEdge(t, g, "MEMORY_LIMIT_CAUSES_OOM@2", EventMemoryLimitReached, EventOOM)
	addRuleEdge(t, g, "OOM_CAUSES_PROCESS_EXIT@2", EventOOM, EventProcessExited)
	var candidates []RootCandidate
	for _, analysis := range g.FailureAnalyses() {
		if analysis.AnchorType != EventProcessExited {
			continue
		}
		candidates = analysis.Candidates
	}
	if len(candidates) == 0 {
		t.Fatal("no root candidate for the exit anchor")
	}
	if candidates[0].Confidence != ConfidenceMedium {
		t.Errorf("root confidence %s reported for a chain whose weakest link is MEDIUM",
			candidates[0].Confidence)
	}
}

// A9: an effect whose own cause is unobserved (a parent PROCESS_EXITED) heads
// a known chain but is not a root cause; the report says root cause UNKNOWN.
func TestPrincipalAuditA9FailureEventHeadsChainButIsNotRootCause(t *testing.T) {
	// revised 2026-10-28 (re-audit R5): the parent exit is the anchor, and a
	// failure is never its own candidate. the honest report is status
	// UNKNOWN with the known chain exit -> reparent and no ROOT_CAUSE.
	_, g := analyzeIncident(t, loadCausalFixture(t, "orphan-process"))
	for _, root := range rootsJSON(t, g) {
		if root["kind"] == "ROOT_CAUSE" {
			t.Errorf("the parent exit's chain produced a ROOT_CAUSE: %v", root)
		}
	}
	var exitAnalysis *FailureAnalysis
	for i, analysis := range g.FailureAnalyses() {
		if analysis.AnchorType == EventProcessExited {
			exitAnalysis = &g.FailureAnalyses()[i]
		}
	}
	if exitAnalysis == nil || exitAnalysis.Status != StatusUnknown {
		t.Fatalf("parent exit analysis = %+v, want status UNKNOWN", exitAnalysis)
	}
	var chain []EventType
	for _, id := range exitAnalysis.KnownChain {
		chain = append(chain, g.Get(id).Type)
	}
	if len(chain) != 2 || chain[0] != EventProcessExited || chain[1] != EventProcessReparented {
		t.Errorf("known chain = %v, want [PROCESS_EXITED PROCESS_REPARENTED]", chain)
	}
}

// A10: a jump straight from healthy to the limit/exhaustion boundary between
// two samples must keep the boundary fact. audited behavior: only the
// pressure-start event is emitted and the limit is lost for the episode.
func TestPrincipalAuditA10JumpStraightToBoundaryKeepsBoundaryFact(t *testing.T) {

	b := baseStart()
	meminc := &incident.Incident{CaptureStart: b, Snapshots: []collector.Snapshot{
		snapAt(b, 0, memSys(500, 1000)),
		snapAt(b, time.Second, memSys(995, 1000)),
		snapAt(b, 2*time.Second, memSys(995, 1000)),
	}}
	memtl := BuildTimeline(meminc)
	if got := countType(memtl, EventMemoryLimitReached); got != 1 {
		t.Errorf("MEMORY_LIMIT_REACHED = %d after a 50%%->99.5%% jump, want 1: %v", got, eventTypesOf(memtl))
	}
	disk := func(off time.Duration, free uint64) collector.Snapshot {
		return snapAt(b, off, &collector.SystemSnapshot{DiskStatsAvailable: true, DiskTotal: 100, DiskFree: free, DiskFilesystem: "/data"})
	}
	disktl := BuildTimeline(&incident.Incident{CaptureStart: b, Snapshots: []collector.Snapshot{
		disk(0, 60), disk(time.Second, 3), disk(2*time.Second, 3),
	}})
	if got := countType(disktl, EventDiskExhausted); got != 1 {
		t.Errorf("DISK_EXHAUSTED = %d after a 60%%->3%% free jump, want 1: %v", got, eventTypesOf(disktl))
	}
}

// A11: FROZEN_PROCESS evidence is a stopped process with no CPU progress;
// CPU saturation events are the opposite observation and may not be listed
// as that diagnosis's related evidence.
func TestPrincipalAuditA11FrozenProcessDoesNotLinkCPUSaturation(t *testing.T) {
	for _, eventType := range RelatedEventTypes("FROZEN_PROCESS") {
		if eventType == EventCPUSaturationStarted || eventType == EventCPUSaturationEnded {
			t.Errorf("FROZEN_PROCESS links %s as related evidence", eventType)
		}
	}
}

// A17: a condition already in effect at the first usable observation keeps
// onset_unknown for IO pressure and cgroup limits too (4.28).
func TestPrincipalAuditA17OnsetUnknownForIOAndCgroupConditions(t *testing.T) {

	b := baseStart()
	io := func(off time.Duration) collector.Snapshot {
		s := snapAt(b, off, &collector.SystemSnapshot{})
		s.Pressure = map[platform.Resource]platform.PressureSnapshot{
			platform.PressureIO: {HasSome: true, Some: platform.Pressure{Avg10: 50}},
		}
		return s
	}
	tl := BuildTimeline(&incident.Incident{CaptureStart: b, Snapshots: []collector.Snapshot{
		io(0), io(5 * time.Second), io(11 * time.Second),
	}})
	for _, e := range tl.Events {
		if e.Type == EventDiskPressureStarted && e.Subject.Kind == SubjectHost && !e.OnsetUnknown {
			t.Errorf("IO pressure present from the first sample claims an observed onset at t+%s", e.Timestamp.Sub(b))
		}
	}
	cg := func(off time.Duration, current uint64) collector.Snapshot {
		s := snapAt(b, off, nil)
		s.Processes = []collector.ProcessSnapshot{{
			Process: platform.Process{PID: 42, StartTicks: 7, State: "R"},
			Cgroup:  &platform.CgroupSnapshot{Path: "/runner", MemoryCurrentAvailable: true, MemoryMaxAvailable: true, MemoryCurrent: current, MemoryMax: 100},
		}}
		return s
	}
	cgtl := BuildTimeline(&incident.Incident{CaptureStart: b, Snapshots: []collector.Snapshot{cg(0, 99), cg(time.Second, 99)}})
	for _, e := range cgtl.Events {
		if e.Type == EventCgroupLimitReached && !e.OnsetUnknown {
			t.Errorf("cgroup at its limit in the first sample claims an observed crossing at t+%s", e.Timestamp.Sub(b))
		}
	}
}

// A22: the reparent edge binds to the parent incarnation the child actually
// had. PID 800 exits, is reused, the child is observed under the new PID-800
// process, which then exits: only the second exit caused the reparent.
func TestPrincipalAuditA22ReparentBindsToParentIncarnation(t *testing.T) {

	b := baseStart()
	stale := baseEvent(EventProcessExited, b, processSubject(800, 10), nil)
	actual := baseEvent(EventProcessExited, b.Add(10*time.Second), processSubject(800, 99), nil)
	child := baseEvent(EventProcessReparented, b.Add(12*time.Second), processSubject(900, 120),
		map[string]any{"from_ppid": 800, "to_ppid": 1, "capture_start": b.Add(5 * time.Second)})
	g := graphFrom(t, []Event{stale, actual, child})
	if _, err := NewEngine(Rules(), b).Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	for _, edge := range g.Edges {
		if g.Get(edge.From).Subject.ID == "800@10" {
			t.Errorf("stale PID-800 incarnation (exited before the child was ever observed under PID 800) CAUSES the reparent")
		}
	}
}

// A23: cgroup limit crossings need hysteresis like the host machine. A cgroup
// hovering at the 98% boundary must not emit a new limit event per wobble.
func TestPrincipalAuditA23CgroupLimitHasHysteresis(t *testing.T) {

	b := baseStart()
	cg := func(off time.Duration, current uint64) collector.Snapshot {
		s := snapAt(b, off, nil)
		s.Processes = []collector.ProcessSnapshot{{
			Process: platform.Process{PID: 42, StartTicks: 7, State: "R"},
			Cgroup: &platform.CgroupSnapshot{Path: "/runner", MemoryCurrentAvailable: true, MemoryMaxAvailable: true,
				MemoryCurrent: current, MemoryMax: 1000},
		}}
		return s
	}
	var snaps []collector.Snapshot
	for i, current := range []uint64{500, 981, 979, 981, 979, 981} {
		snaps = append(snaps, cg(time.Duration(i)*time.Second, current))
	}
	tl := BuildTimeline(&incident.Incident{CaptureStart: b, Snapshots: snaps})
	if got := countType(tl, EventCgroupLimitReached); got != 1 {
		t.Errorf("CGROUP_LIMIT_REACHED = %d for one episode wobbling across 98%%, want 1", got)
	}
}

// A8b (re-audit, 2026-10-28): the adapted A8 test and the a8 fixture both put
// the weaker edge FIRST, which the original bug (root band = strongest edge
// leaving the root) also reports correctly. this variant puts a HIGH edge at
// the head and a demoted MEDIUM edge downstream, so only a true weakest-link
// computation passes.
func TestPrincipalAuditA8bWeakLinkDownstreamOfStrongHead(t *testing.T) {
	b := baseStart()
	cg := SubjectRef{SubjectCgroup, "/runner"}
	limit := baseEvent(EventCgroupLimitReached, b, cg, map[string]any{"memory_percent": 99.0})
	oom := baseEvent(EventOOM, b.Add(200*time.Millisecond), cg, nil)
	exit := baseEvent(EventProcessExited, b.Add(400*time.Millisecond), processSubject(42, 7), nil)
	g := graphFrom(t, []Event{limit, oom, exit})
	addRuleEdge(t, g, "CGROUP_LIMIT_CAUSES_OOM@1", EventCgroupLimitReached, EventOOM)

	var rule *Rule
	for _, r := range Rules() {
		if r.ID == "OOM_CAUSES_PROCESS_EXIT@2" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("OOM_CAUSES_PROCESS_EXIT@2 not registered")
	}
	ids := map[EventType]EventID{}
	for _, id := range g.EventIDs() {
		ids[g.Get(id).Type] = id
	}
	var checks []CheckRecord
	for _, code := range rule.Required {
		checks = append(checks, CheckRecord{Kind: "required", Code: code, Status: CheckPresent, Detail: "test fixture evidence"})
	}
	for _, code := range rule.Contradicting {
		checks = append(checks, CheckRecord{Kind: "contradicting", Code: code, Status: CheckAbsent, Detail: "checked, absent"})
	}
	demotions := []string{"D2: victim identity is PID-only"}
	p := EdgeProposal{From: ids[EventOOM], To: ids[EventProcessExited], Relation: rule.Edge,
		Confidence: capBand(rule.Ceiling, demotions), Demotions: demotions,
		Evidence: []EvidenceNote{{Code: "TEST_EVIDENCE"}}, Checks: checks, Mechanism: rule.Mechanism}
	p.ruleID = rule.ID
	if err := g.addEdge(p); err != nil {
		t.Fatal(err)
	}
	head := g.Edges[0].Confidence
	if head != ConfidenceHigh || p.Confidence != ConfidenceMedium {
		t.Fatalf("setup: want head HIGH and downstream MEDIUM, got %s / %s", head, p.Confidence)
	}
	for _, analysis := range g.FailureAnalyses() {
		if analysis.AnchorType != EventProcessExited {
			continue
		}
		if len(analysis.Candidates) == 0 {
			t.Fatal("no candidate for the exit anchor")
		}
		if got := analysis.Candidates[0].Confidence; got != ConfidenceMedium {
			t.Errorf("root band %s for a chain HIGH -> MEDIUM; weakest link is MEDIUM", got)
		}
		return
	}
	t.Fatal("no analysis for the exit anchor")
}

// Re-audit findings (2026-10-28), found after the remediation pass landed.

func withProvenance(e Event, ref string) Event {
	e.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("event", ref)}}
	return e
}

// R1: D3 must stack with the edge's other demotion families. A bare MEDIUM
// cap left a PID-only (D2) edge at MEDIUM after D3, validate (V3) then
// re-graded it LOW and rejected the graph, so `timeline` failed outright.
func TestPrincipalReauditR1CompetitionStacksWithOtherDemotions(t *testing.T) {
	b := baseStart()
	exita := withProvenance(baseEvent(EventProcessExited, b, processSubject(800, 10), nil), "a")
	exita.PID = 800
	exitb := withProvenance(baseEvent(EventProcessExited, b.Add(time.Second), processSubject(801, 11), nil), "b")
	exitb.PID = 801
	child := withProvenance(baseEvent(EventProcessReparented, b.Add(2*time.Second), processSubject(900, 20), nil), "c")
	child.PID, child.PPID = 900, 800
	g := graphFrom(t, []Event{exita, exitb, child})
	var rule *Rule
	for _, r := range Rules() {
		if r.ID == "PROCESS_EXIT_CAUSES_REPARENT@2" {
			rule = r
		}
	}
	for _, id := range g.EventIDs() {
		if g.Get(id).Type != EventProcessExited {
			continue
		}
		var checks []CheckRecord
		for _, code := range rule.Required {
			checks = append(checks, CheckRecord{Kind: "required", Code: code, Status: CheckPresent})
		}
		for _, code := range rule.Contradicting {
			checks = append(checks, CheckRecord{Kind: "contradicting", Code: code, Status: CheckAbsent})
		}
		demotions := []string{"D2:identity PID_ONLY"}
		p := EdgeProposal{From: id, To: graphEvents(t, g, EventProcessReparented)[0], Relation: rule.Edge,
			Confidence: capBand(rule.Ceiling, demotions), Demotions: demotions, Checks: checks,
			Mechanism: rule.Mechanism, Evidence: []EvidenceNote{{Code: "TEST"}}}
		p.ruleID = rule.ID
		if err := g.addEdge(p); err != nil {
			t.Fatal(err)
		}
	}
	markCompetingEdges(g)
	for _, edge := range g.Edges {
		if edge.Confidence != ConfidenceLow {
			t.Errorf("edge with D2 + D3 graded %s, want LOW (two stacking families)", edge.Confidence)
		}
	}
	if err := g.Validate(); err != nil && strings.Contains(err.Error(), "demotions grade") {
		t.Errorf("competition left an edge band Validate rejects: %v", err)
	}
}

// R2: the reparent rule binds to the parent incarnation even when the reused
// PID's two exits both fall inside MaxGap (A22 passed only via MaxGap).
func TestPrincipalReauditR2ReparentIncarnationInsideMaxGap(t *testing.T) {
	b := baseStart()
	stale := withProvenance(baseEvent(EventProcessExited, b.Add(8*time.Second), processSubject(800, 10), nil), "a")
	stale.PID = 800
	actual := withProvenance(baseEvent(EventProcessExited, b.Add(10*time.Second), processSubject(800, 99), nil), "b")
	actual.PID = 800
	child := withProvenance(baseEvent(EventProcessReparented, b.Add(12*time.Second), processSubject(900, 120), nil), "c")
	child.PID, child.PPID = 900, 800
	g := graphFrom(t, []Event{stale, actual, child})
	if _, err := NewEngine(Rules(), b).Apply(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(g.Edges) != 1 || g.Get(g.Edges[0].From).Subject.ID != "800@99" {
		for _, e := range g.Edges {
			t.Logf("edge from %s", g.Get(e.From).Subject.ID)
		}
		t.Errorf("want exactly one reparent edge, from the later PID-800 incarnation")
	}
}

// R3: an edge whose endpoints straddle a backward clock step is demoted D4,
// although the discontinuity event carries the stepped-back wall time.
func TestPrincipalReauditR3BackwardStepDemotesSpanningEdge(t *testing.T) {
	b := baseStart()
	proc := func(pid, ppid int) collector.ProcessSnapshot {
		return collector.ProcessSnapshot{Process: platform.Process{PID: pid, PPID: ppid, StartTicks: int64(pid), State: "S"}}
	}
	snap := func(off time.Duration, ps ...collector.ProcessSnapshot) collector.Snapshot {
		s := snapAt(b, off, nil)
		s.Processes = ps
		return s
	}
	inc := &incident.Incident{CaptureStart: b,
		Snapshots: []collector.Snapshot{
			snap(0, proc(800, 1), proc(900, 800)),
			snap(time.Second, proc(800, 1), proc(900, 800)),
			snap(-2*time.Second, proc(900, 800)), // clock stepped back 3 s
			snap(3*time.Second, proc(900, 1)),
		},
		Events: []incident.Event{{Type: incident.ProcessExited, Timestamp: b.Add(1500 * time.Millisecond), PID: 800, StartTicks: 800}},
	}
	_, g := analyzeIncident(t, inc)
	if len(g.Edges) == 0 {
		t.Fatal("expected the reparent edge")
	}
	for _, edge := range g.Edges {
		found := false
		for _, d := range edge.Demotions {
			if strings.HasPrefix(d, "D4:") {
				found = true
			}
		}
		if !found || edge.Confidence != ConfidenceLow {
			t.Errorf("edge across a backward clock step: band %s, demotions %v; want LOW with D4", edge.Confidence, edge.Demotions)
		}
	}
}

// R9: the group event carries every member exit inside its window, and a
// later, separate coordinated kill of the same PGID derives its own event.
func TestPrincipalReauditR9GroupTerminationMembership(t *testing.T) {
	b := baseStart()
	exit := func(pid int, off time.Duration) incident.Event {
		return incident.Event{Type: incident.ProcessExited, Timestamp: b.Add(off), PID: pid, StartTicks: int64(pid)}
	}
	inc := &incident.Incident{CaptureStart: b,
		Events: []incident.Event{
			exit(21, 0), exit(22, 400*time.Millisecond), exit(23, 800*time.Millisecond),
			exit(24, 60*time.Second), exit(25, 61*time.Second),
		},
		Metadata: incident.Metadata{Processes: []incident.ProcessMetadata{
			{PID: 21, PGID: 55}, {PID: 22, PGID: 55}, {PID: 23, PGID: 55}, {PID: 24, PGID: 55}, {PID: 25, PGID: 55},
		}},
	}
	tl := BuildTimeline(inc)
	var groups []Event
	for _, e := range tl.Events {
		if e.Type == EventProcessGroupTerminated {
			groups = append(groups, e)
		}
	}
	if len(groups) != 2 {
		t.Fatalf("group events = %d, want 2 (two separate coordinated kills)", len(groups))
	}
	if exits, _ := asFloat(groups[0].Data["exits"]); exits != 3 || len(groups[0].Provenance.Sources) != 3 {
		t.Errorf("first group: exits=%v sources=%d, want 3 members", groups[0].Data["exits"], len(groups[0].Provenance.Sources))
	}
	if exits, _ := asFloat(groups[1].Data["exits"]); exits != 2 {
		t.Errorf("second group: exits=%v, want 2", groups[1].Data["exits"])
	}
}

func cgroupSnap(b time.Time, off time.Duration, current uint64) collector.Snapshot {
	s := snapAt(b, off, nil)
	s.Processes = []collector.ProcessSnapshot{
		{Process: platform.Process{PID: 42, StartTicks: 7, State: "R"},
			Cgroup: &platform.CgroupSnapshot{Path: "/runner", MemoryCurrentAvailable: true, MemoryMaxAvailable: true, MemoryCurrent: current, MemoryMax: 1000}},
		{Process: platform.Process{PID: 43, StartTicks: 8, State: "R"},
			Cgroup: &platform.CgroupSnapshot{Path: "/runner", MemoryCurrentAvailable: true, MemoryMaxAvailable: true, MemoryCurrent: current, MemoryMax: 1000}},
	}
	return s
}

// R11: a cgroup that hit its limit and fell back is a closed episode, not an
// unrecovered failure (the cgroup analogue of A2).
func TestPrincipalReauditR11CgroupLimitRecoveryClosesEpisode(t *testing.T) {
	b := baseStart()
	var snaps []collector.Snapshot
	for i, c := range []uint64{500, 990, 990, 500, 500} {
		snaps = append(snaps, cgroupSnap(b, time.Duration(i)*time.Second, c))
	}
	tl, g := analyzeIncident(t, &incident.Incident{CaptureStart: b, Snapshots: snaps})
	if countType(tl, EventCgroupLimitCleared) != 1 {
		t.Errorf("CGROUP_LIMIT_CLEARED = %d, want 1: %v", countType(tl, EventCgroupLimitCleared), eventTypesOf(tl))
	}
	if !g.Healthy() {
		t.Errorf("recovered cgroup episode reported as a failure: %+v", g.FailureAnalyses())
	}
}

// R12: a severe reading in a single sample (healthy-disk-brief shape) is not
// a failure anchor; two or more samples are.
func TestPrincipalReauditR12SevereConditionNeedsPersistence(t *testing.T) {
	b := baseStart()
	single := []collector.Snapshot{cgroupSnap(b, 0, 500), cgroupSnap(b, time.Second, 500), cgroupSnap(b, 2*time.Second, 990)}
	_, g := analyzeIncident(t, &incident.Incident{CaptureStart: b, Snapshots: single})
	if !g.Healthy() || len(g.UnconfirmedSevere()) != 1 {
		t.Errorf("single severe sample: healthy=%v unconfirmed=%d, want healthy with 1 unconfirmed reading",
			g.Healthy(), len(g.UnconfirmedSevere()))
	}
	persisted := append(single, cgroupSnap(b, 3*time.Second, 990))
	_, g = analyzeIncident(t, &incident.Incident{CaptureStart: b, Snapshots: persisted})
	if g.Healthy() {
		t.Errorf("cgroup at its limit for two samples at capture end must be a failure anchor")
	}
}

// R13: with no exit status in v1, an exit is a failure only with context:
// the trigger names it, it has a causal cause/consequence, or it happened
// during an unresolved memory/cgroup limit. A helper process exiting during a
// healthy capture is context, not "failure PROCESS_EXITED".
func TestPrincipalReauditR13ExitsNeedFailureContext(t *testing.T) {
	b := baseStart()
	helper := incident.Event{Type: incident.ProcessExited, Timestamp: b.Add(2 * time.Second), PID: 300, StartTicks: 3}
	quiet := &incident.Incident{CaptureStart: b, Events: []incident.Event{helper},
		Snapshots: []collector.Snapshot{snapAt(b, 0, memSys(500, 1000)), snapAt(b, 5*time.Second, memSys(500, 1000))}}
	_, g := analyzeIncident(t, quiet)
	if !g.Healthy() || g.OtherExits() != 1 {
		t.Errorf("helper exit: healthy=%v otherExits=%d, want healthy with 1 other exit", g.Healthy(), g.OtherExits())
	}

	triggered := *quiet
	triggered.TriggeredAt = b.Add(3 * time.Second)
	triggered.Trigger = incident.Trigger{Type: "process_exit", PID: 300, StartTicks: 3}
	_, g = analyzeIncident(t, &triggered)
	if g.Healthy() {
		t.Errorf("the exit the trigger names must be a failure anchor")
	}

	duringlimit := &incident.Incident{CaptureStart: b, Events: []incident.Event{helper},
		Snapshots: []collector.Snapshot{
			snapAt(b, 0, memSys(500, 1000)), snapAt(b, time.Second, memSys(990, 1000)),
			snapAt(b, 1500*time.Millisecond, memSys(990, 1000)), snapAt(b, 5*time.Second, memSys(990, 1000)),
		}}
	_, g = analyzeIncident(t, duringlimit)
	exitanchored := false
	for _, a := range g.FailureAnalyses() {
		if a.AnchorType == EventProcessExited {
			exitanchored = true
		}
	}
	if !exitanchored {
		t.Errorf("an exit during an unresolved memory limit must be a failure anchor (OOM suspected)")
	}
}

// A16 guard: docs/causal-rules/README.md lists every registered rule in its
// registry table, and no registered rule appears in the retired table.
func TestCausalRulesReadmeMatchesRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../docs/causal-rules/README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	retiredat := strings.Index(text, "## Retired rules")
	if retiredat < 0 {
		t.Fatal("README lacks the retired-rules section")
	}
	registry, retired := text[:retiredat], text[retiredat:]
	for _, rule := range Rules() {
		if !strings.Contains(registry, "`"+rule.ID+"`") {
			t.Errorf("registered rule %s missing from the README registry table", rule.ID)
		}
		for _, line := range strings.Split(retired, "\n") {
			cells := strings.Split(line, "|")
			if len(cells) > 2 && strings.Contains(cells[1], "`"+rule.ID+"`") {
				t.Errorf("registered rule %s is listed as retired", rule.ID)
			}
		}
	}
}
