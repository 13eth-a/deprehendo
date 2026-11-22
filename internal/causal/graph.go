package causal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CausalEdge is one validated relation between two events (4.6). RuleID is
// versioned (4.18); confidence uses the banded causal scale (4.10). every
// non-temporal edge carries its full check record, mechanism and demotion
// list so the explainability contract (§8) is data on the graph, not prose
// assembled at render time.
type CausalEdge struct {
	ID         string           `json:"id"`
	From       EventID          `json:"from"`
	To         EventID          `json:"to"`
	Relation   RelationType     `json:"relation"`
	Confidence CausalConfidence `json:"confidence"`
	RuleID     string           `json:"rule"`
	Evidence   []EvidenceNote   `json:"evidence,omitempty"`

	// §4.2 additions: every evaluated check, the supporting evidence that
	// was missing, why the band was demoted, and the declared mechanism.
	Checks      []CheckRecord `json:"checks"`
	Missing     []string      `json:"missing_supporting,omitempty"`
	Demotions   []string      `json:"demotions,omitempty"`
	SameInstant bool          `json:"same_instant,omitempty"`
	Mechanism   string        `json:"mechanism"`
	Competes    []string      `json:"competes_with,omitempty"` // alternative CAUSES edges into the same target (§6)
}

type EvidenceNote struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// EdgeProposal is the engine's validated request to add an edge. proposals
// are never trusted: the graph validates direction, cycles and endpoints
// before accepting.
type EdgeProposal struct {
	From        EventID
	To          EventID
	Relation    RelationType
	Confidence  CausalConfidence
	Evidence    []EvidenceNote
	Checks      []CheckRecord
	Missing     []string
	Demotions   []string
	SameInstant bool
	Mechanism   string
	// RuleID is captured from the proposing engine by the graph.
	ruleID string
}

// RejectedEdge preserves why a proposal was not added (4.43 explainability:
// every non-edge is as inspectable as an edge). reasons carry the failing
// check code so the unknown-cause report can name missing telemetry.
type RejectedEdge struct {
	From, To EventID
	Relation RelationType
	RuleID   string
	Reason   string
}

// CausalChain is one root-to-effect path (4.13). every step carries the edge,
// so every arrow is traceable to a versioned rule and its evidence.
type CausalChain struct {
	Root       EventID     `json:"root"`
	OnsetKnown bool        `json:"onset_known"`
	Role       RootRole    `json:"role"`
	Steps      []ChainStep `json:"steps"`
	// band is the weakest causal link on the path (§2.4); ESCALATES_TO and
	// RECOVERY_OF steps contribute nothing to it.
	Band CausalConfidence `json:"band"`
}

type ChainStep struct {
	Event EventID    `json:"event"`
	Edge  CausalEdge `json:"edge"`
}

// RootCandidate is one root-cause candidate (§5.2). every candidate names the
// failure it explains (I3); roots without a supported causal path into their
// anchor are contributing factors or unexplained heads, never root causes.
type RootCandidate struct {
	Event        EventID          `json:"event"`
	Kind         RootKind         `json:"kind"`
	Anchor       EventID          `json:"anchor"`
	Role         RootRole         `json:"role"`
	Confidence   CausalConfidence `json:"confidence"` // weakest-link band to anchor
	OnsetUnknown bool             `json:"onset_unknown"`
	Effects      int              `json:"downstream_effects"` // distinct events reached (A14: not path count)
} // severityAnchorTypes are the severe conditions whose unresolved instance is
// a failure anchor (§5.1): a disk still full at capture end needs explaining
// even with no observed write failure. A network stall is here even though it
// is never "severe" in the resource sense: it was only emitted after ≥
// stallThreshold of continuous non-progress (§7.2), so it is a serious,
// undertstood condition whose BROKER_SOCKET_STALL / NETWORK_PATH_FAILURE
// discrimination must be rendered (§7.3).
var severityAnchorTypes = map[EventType]bool{
	EventMemoryLimitReached:     true,
	EventCgroupLimitReached:     true,
	EventDiskExhausted:          true,
	EventOOM:                    true,
	EventNetworkProgressStopped: true,
}

// failureAnchorEventTypes are the FAILURE-class types that anchor analyses in
// v1. CONNECTION_CLOSED stays failure class but is anchored only when a phase
// 3 network signature claimed it (§5.1), which the causal package cannot see
// standalone. it is therefore not anchorable here (documented; revisit in
// 4.44).
var failureAnchorEventTypes = map[EventType]bool{
	EventProcessExited:          true,
	EventProcessStopped:         true,
	EventProcessGroupTerminated: true,
	EventWorkerExited:           true,
}

// graph is the causal event graph (4.6) over a normalized timeline.
// construction is append-only through addEdge; the graph is immutable once
// rules have run.
type Graph struct {
	Events    map[EventID]*Event `json:"events"`
	order     []EventID
	index     map[EventID]int
	Edges     []CausalEdge   `json:"edges"`
	Rejected  []RejectedEdge `json:"rejected_edges,omitempty"`
	causalOut map[EventID][]int
	Origin    time.Time `json:"origin"`

	// analyses is the per-anchor FailureAnalysis set (§5), computed once by
	// FailureAnalyses and cached.
	analyses []FailureAnalysis
	analyzed bool

	// covers are stated intents (provider §7, 5.25). exits of covered
	// processes inside a cover's window are CONTEXT, not failure anchors.
	covers []IntentCover

	// pgidOf maps each observed process incarnation to its process group,
	// so a runner-tree intent can cover the untagged members of the tree it
	// ended without covering unrelated groups in the same window.
	pgidOf map[ProcessIdentity]int
}

// IntentCover is a provider-neutral statement that the listed process
// incarnations were intentionally terminated between from and Until. the
// caller derives it from a provider's TERMINATION_INTENDED event; the causal
// package never sees provider types.
type IntentCover struct {
	Processes []ProcessIdentity
	From      time.Time
	Until     time.Time
	// RunnerTree marks an intent that ends the runner's whole tree: a service
	// stop, a self-update or an ephemeral completion. its named set can only
	// cover role-tagged members, so a whole-group collapse in the window is
	// attributed to the intent even when individual members were never tagged
	// (B3: a runner self-update left untagged job processes whose exit looked
	// like PROCESS_GROUP_TERMINATION).
	RunnerTree bool
	// JobTree marks an intent that states the outcome of one job
	// (cancellation, timeout or success). the diagnosis engine widens this
	// cover from the role-tagged processes to the job's observed descendants,
	// because the runner SIGKILLs leftover job processes at job end. it is not
	// a group cover here: coversGroup stays limited to RunnerTree.
	JobTree bool
}

// SetIntentCovers installs the intent covers used by failureAnchors. it must
// be called before FailureAnalyses.
func (g *Graph) SetIntentCovers(covers []IntentCover) {
	g.covers = covers
}

// covered reports whether a process exit at ts with identity pid is inside a
// cover's window and names that process, or belongs to the process group of a
// named process under a runner-tree intent.
func (g *Graph) covered(pid int, startTicks int64, pgid int, ts time.Time) bool {
	for _, c := range g.covers {
		if ts.Before(c.From) || ts.After(c.Until) {
			continue
		}
		if c.RunnerTree && pgid != 0 && g.coversGroup(c, pgid) {
			return true
		}
		for _, p := range c.Processes {
			if p.PID == pid && (p.StartTicks == 0 || startTicks == 0 || p.StartTicks == startTicks) {
				return true
			}
		}
	}
	return false
}

// coversGroup reports whether the cover names a process that ran in group
// pgid. A runner-tree intent (service stop, self-update, ephemeral completion)
// takes the runner's whole tree down, and the section can only name the
// role-tagged members; on a real runner the job processes left behind by a
// self-update share the listener's group but were never tagged (B3). tying the
// coverage to that observed group keeps an unrelated exit in the intent's
// window unexplained rather than silently intended.
func (g *Graph) coversGroup(c IntentCover, pgid int) bool {
	for _, p := range c.Processes {
		if got, ok := g.pgidOf[p]; ok && got == pgid {
			return true
		}
		// A cover may name only the PID (a log-scoped intent carries no start
		// time); compare incarnations loosely then, but never across PIDs.
		for key, got := range g.pgidOf {
			if got == pgid && key.PID == p.PID && (p.StartTicks == 0 || key.StartTicks == 0 || key.StartTicks == p.StartTicks) {
				return true
			}
		}
	}
	return false
}

// allCovered reports whether there is at least one member and every member is
// covered at ts. A partly covered group keeps its failure anchor.
func (g *Graph) allCovered(members []ProcessIdentity, pgid int, ts time.Time) bool {
	if len(members) == 0 {
		return false
	}
	for _, m := range members {
		if !g.covered(m.PID, m.StartTicks, pgid, ts) {
			return false
		}
	}
	return true
}

// NewGraph indexes a normalized timeline. events arrive sorted; the graph
// preserves that order for canonical before/after checks (4.4).
func NewGraph(tl *Timeline) *Graph {
	g := &Graph{
		Events: make(map[EventID]*Event, len(tl.Events)),
		index:  make(map[EventID]int, len(tl.Events)),
		pgidOf: make(map[ProcessIdentity]int, len(tl.Events)),
		Origin: tl.Origin,
	}
	for i := range tl.Events {
		e := tl.Events[i]
		clone := e
		g.Events[clone.ID] = &clone
		g.order = append(g.order, clone.ID)
		g.index[clone.ID] = i
		if clone.PID != 0 && clone.PGID != 0 {
			g.pgidOf[ProcessIdentity{PID: clone.PID, StartTicks: clone.StartTicks}] = clone.PGID
		}
	}
	return g
}

func (g *Graph) canonIndex(id EventID) int { return g.index[id] }

func (g *Graph) Has(id EventID) bool { _, ok := g.Events[id]; return ok }

func (g *Graph) Get(id EventID) *Event { return g.Events[id] }

func (g *Graph) Count() int { return len(g.order) }

// EventIDs returns event IDs in canonical timeline order.
func (g *Graph) EventIDs() []EventID {
	return append([]EventID(nil), g.order...)
}

// canonBefore reports whether a precedes or equals b in the canonical order.
// canonical order is determinism only, never evidence (P7).
func (g *Graph) canonBefore(a, b EventID) bool { return g.index[a] < g.index[b] }

// observedBefore reports whether a's wall timestamp is strictly before b's.
// this is E1, the only order relation edges and rules may rely on (P7).
func (g *Graph) observedBefore(a, b EventID) bool {
	return g.Events[a].Timestamp.Before(g.Events[b].Timestamp)
}

// relationDirectionOK validates the direction constraints an edge claims.
// Causal/escalation edges require observed order (E1) or, when SameInstant
// was declared, co-occurrence (E1′): the engine already enforced that, so the
// check here only refuses wall-clock inversions. PRECEDES/RECOVERY_OF demand
// strictly observed order.
func (g *Graph) relationDirectionOK(rel RelationType, from, to EventID) error {
	switch rel {
	case RelationCauses, RelationContributes, RelationEscalates:
		if g.Events[from].Timestamp.After(g.Events[to].Timestamp) {
			return fmt.Errorf("edge runs backwards in wall-clock order")
		}
	case RelationPrecedes, RelationRecoveryOf:
		if !g.observedBefore(from, to) {
			if g.Events[from].Timestamp.Equal(g.Events[to].Timestamp) && rel == RelationPrecedes {
				return fmt.Errorf("PRECEDES with equal wall timestamps carries no observed order; use CORRELATED_WITH")
			}
			return fmt.Errorf("edge runs backwards in time")
		}
	}
	return nil
}

// addEdge validates and appends one proposal. Cycle-producing DAG edges are
// rejected and recorded, naming the rule that attempted them (4.14). the DAG
// check covers causal ∪ episode relations (§4.1).
func (g *Graph) addEdge(p EdgeProposal) error {
	if !g.Has(p.From) {
		return fmt.Errorf("edge From %s does not exist", p.From)
	}
	if !g.Has(p.To) {
		return fmt.Errorf("edge To %s does not exist", p.To)
	}
	if p.From == p.To {
		return fmt.Errorf("self edges are meaningless")
	}
	if p.Relation == "" {
		return g.reject(p, fmt.Errorf("relation is required"))
	}
	if p.Confidence == "" {
		return g.reject(p, fmt.Errorf("confidence band is required"))
	}
	if !isDefinedRelation(p.Relation) {
		return g.reject(p, fmt.Errorf("relation %s is not a defined relation type", p.Relation))
	}
	if err := g.relationDirectionOK(p.Relation, p.From, p.To); err != nil {
		return g.reject(p, err)
	}
	if isChainRelation(p.Relation) {
		// V3 (§4.4): a non-temporal edge must carry its checks and mechanism.
		if len(p.Checks) == 0 {
			return g.reject(p, fmt.Errorf("non-temporal edge carries no check records"))
		}
		if p.Mechanism == "" {
			return g.reject(p, fmt.Errorf("non-temporal edge carries no mechanism"))
		}
	}
	index := len(g.Edges)
	if isChainRelation(p.Relation) {
		if g.causalOut == nil {
			g.rebuildIndexes()
		}
		if g.wouldCycle(p.From, p.To, index) {
			return g.reject(p, fmt.Errorf("edge would create a cycle in the causal/episode DAG"))
		}
	}
	edge := CausalEdge{
		From: p.From, To: p.To, Relation: p.Relation,
		Confidence: p.Confidence, RuleID: p.ruleID, Evidence: p.Evidence,
		Checks: p.Checks, Missing: p.Missing, Demotions: p.Demotions,
		SameInstant: p.SameInstant, Mechanism: p.Mechanism,
	}
	edge.ID = stableEdgeID(edge)
	g.Edges = append(g.Edges, edge)
	if isChainRelation(p.Relation) {
		// keep the traversal index current (4.41).
		g.causalOut[p.From] = append(g.causalOut[p.From], index)
	}
	return nil
}

// reject records an unaccepted proposal (4.43) before returning the error.
func stableEdgeID(edge CausalEdge) string {
	key := string(edge.From) + "\x00" + string(edge.To) + "\x00" + string(edge.Relation) + "\x00" + edge.RuleID
	h := sha256.Sum256([]byte(key))
	return "ED_" + hex.EncodeToString(h[:8])
}

func (g *Graph) reject(p EdgeProposal, err error) error {
	g.Rejected = append(g.Rejected, RejectedEdge{
		From: p.From, To: p.To, Relation: p.Relation,
		RuleID: p.ruleID, Reason: err.Error(),
	})
	return err
}

// wouldCycle reports whether adding edge from→to creates a cycle through
// existing DAG edges. the caller guarantees causalOut is current.
func (g *Graph) wouldCycle(from, to EventID, candidateIndex int) bool {
	visited := map[EventID]bool{from: true}
	stack := []EventID{to}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current == from {
			return true
		}
		if visited[current] {
			continue
		}
		visited[current] = true
		for _, edge := range g.causalOut[current] {
			if edge != candidateIndex && isDAGRelation(g.Edges[edge].Relation) {
				stack = append(stack, g.Edges[edge].To)
			}
		}
	}
	return false
}

// isDefinedRelation covers the full edge vocabulary (4.6).
func isDefinedRelation(r RelationType) bool {
	switch r {
	case RelationCauses, RelationContributes, RelationPrecedes,
		RelationCorrelates, RelationRecoveryOf, RelationContradicts,
		RelationEscalates:
		return true
	}
	return false
}

// validate checks the graph's structural invariants (4.34 + §4.4):
//   - every edge endpoint exists, no DAG cycles, rules are versioned,
//     derived events carry provenance, edges never point backwards;
//   - V1 (P2): a causal edge may not connect events sharing a provenance
//     source (no self-explanation through derived aggregates, audit A4);
//   - V2 (P3): SameEpisode edges connect one episode instance;
//   - V3: every non-temporal edge carries checks and mechanism, and its band
//     equals the band recomputed from its recorded demotions;
//   - V4 (§3.1): every CAUSES edge has at least one PRESENT discriminator.
func (g *Graph) Validate() error {
	if len(g.order) != len(g.Events) {
		return fmt.Errorf("event map and canonical order have different sizes")
	}
	g.rebuildIndexes()
	rules := Rules()
	rulebyid := make(map[string]*Rule, len(rules))
	for _, rule := range rules {
		rulebyid[rule.ID] = rule
	}
	derived := make(map[string]bool, len(derivedRuleIDs))
	for _, id := range derivedRuleIDs {
		derived[id] = true
	}
	ids := map[EventID]bool{}
	ordinals := make(map[string]int, len(g.order))
	for _, id := range g.order {
		e, exists := g.Events[id]
		if !exists {
			return fmt.Errorf("event order references missing event %s", id)
		}
		if ids[id] {
			return fmt.Errorf("duplicate event ID %s", id)
		}
		ids[id] = true
		if id == "" {
			return fmt.Errorf("event has an empty ID")
		}
		if e.Type == "" || e.Subject.Kind == "" {
			return fmt.Errorf("event %s is missing type or subject", id)
		}
		if e.Timestamp.IsZero() {
			return fmt.Errorf("event %s has no timestamp", id)
		}
		base := canonicalEventKey(*e, 0)
		ordinal := ordinals[base]
		ordinals[base] = ordinal + 1
		if e.ID != id || id != EventID(canonicalEventKey(*e, ordinal)) {
			return fmt.Errorf("event %s has an invalid stable event ID", id)
		}
		if e.Provenance.RuleID != "" && (!strings.Contains(e.Provenance.RuleID, "@") ||
			(rulebyid[e.Provenance.RuleID] == nil && !derived[e.Provenance.RuleID])) {
			return fmt.Errorf("derived event %s names an unknown or unversioned rule %q", id, e.Provenance.RuleID)
		}
		if len(e.Provenance.Sources) == 0 {
			return fmt.Errorf("event %s has no provenance", id)
		}
	}
	if len(ids) != len(g.Events) {
		return fmt.Errorf("event map contains IDs absent from canonical order")
	}
	for _, edge := range g.Edges {
		if !ids[edge.From] || !ids[edge.To] {
			return fmt.Errorf("edge %s->%s references missing endpoints", edge.From, edge.To)
		}
		rule, known := rulebyid[edge.RuleID]
		if edge.RuleID == "" || !strings.Contains(edge.RuleID, "@") || (!known && !derived[edge.RuleID]) {
			return fmt.Errorf("edge %s->%s names unknown or unversioned rule %q", edge.From, edge.To, edge.RuleID)
		}
		if known && (rule.Source != g.Events[edge.From].Type || rule.Target != g.Events[edge.To].Type ||
			rule.Edge != edge.Relation) {
			return fmt.Errorf("edge %s->%s (%s) does not honor its rule's declared endpoints/relation",
				edge.From, edge.To, edge.RuleID)
		}
		if isChainRelation(edge.Relation) {
			if len(edge.Checks) == 0 || edge.Mechanism == "" {
				return fmt.Errorf("edge %s->%s (%s) is non-temporal but carries no check records or mechanism",
					edge.From, edge.To, edge.RuleID)
			}
			if got := capBand(rule.Ceiling, edge.Demotions); got != edge.Confidence {
				return fmt.Errorf("edge %s->%s has band %s but its recorded demotions grade %s",
					edge.From, edge.To, edge.Confidence, got)
			}
			if edge.Relation == RelationCauses && !hasPresentDiscriminator(rule, edge) {
				return fmt.Errorf("edge %s->%s (%s) claims CAUSES with no present discriminator check",
					edge.From, edge.To, edge.RuleID)
			}
		}
		if edge.ID != stableEdgeID(edge) {
			return fmt.Errorf("edge %s->%s has invalid stable ID %q", edge.From, edge.To, edge.ID)
		}
		if err := g.relationDirectionOK(edge.Relation, edge.From, edge.To); err != nil {
			return fmt.Errorf("edge %s->%s (%s): %w", edge.From, edge.To, edge.Relation, err)
		}
		// V1 (P2): no shared provenance across a causal edge.
		if isCausal(edge.Relation) && sharesProvenance(g.Events[edge.From], g.Events[edge.To]) {
			return fmt.Errorf("edge %s->%s (%s) connects events derived from the same evidence (self-explanation, P2)",
				edge.From, edge.To, edge.RuleID)
		}
		// V2 (P3): episode-bound edges join one instance.
		if rule != nil && rule.Binding == BindingSameEpisode {
			src, tgt := g.Events[edge.From], g.Events[edge.To]
			if src.Episode == "" || src.Episode != tgt.Episode {
				return fmt.Errorf("edge %s->%s (%s) declares SAME_EPISODE but endpoints are not the same episode instance",
					edge.From, edge.To, edge.RuleID)
			}
		}
	}
	if g.hasDAGCycle() {
		return fmt.Errorf("causal/episode edges form a cycle")
	}
	return nil
}

// sharesProvenance reports whether two events' provenance lists name a common
// source (P2/audit A4).
func sharesProvenance(src, tgt *Event) bool {
	for _, from := range src.Provenance.Sources {
		for _, to := range tgt.Provenance.Sources {
			if from == to {
				return true
			}
		}
	}
	return false
}

// hasPresentDiscriminator reports whether any PRESENT check record is one of
// the rule's declared E4 discriminator codes (V4).
func hasPresentDiscriminator(rule *Rule, edge CausalEdge) bool {
	disc := map[string]bool{}
	for _, code := range rule.Discriminator {
		disc[code] = true
	}
	for _, record := range edge.Checks {
		if record.Status == CheckPresent && disc[record.Code] {
			return true
		}
	}
	return false
}

// hasDAGCycle is a DFS over the causal ∪ episode layer (§4.1).
func (g *Graph) hasDAGCycle() bool {
	state := map[EventID]int{} // 0 unseen, 1 visiting, 2 done
	var visit func(EventID) bool
	visit = func(id EventID) bool {
		switch state[id] {
		case 1:
			return true
		case 2:
			return false
		}
		state[id] = 1
		for _, edgeindex := range g.causalOut[id] {
			if isDAGRelation(g.Edges[edgeindex].Relation) && visit(g.Edges[edgeindex].To) {
				return true
			}
		}
		state[id] = 2
		return false
	}
	for _, id := range g.order {
		if visit(id) {
			return true
		}
	}
	return false
}

// derivedRuleIDs are the extraction rules that name themselves in provenance
// but do not propose graph edges.
var derivedRuleIDs = []string{RuleMemoryCrossing, RuleDiskCrossing, RuleCPUSaturation,
	RuleCgroupLimit, RuleIOPressure, RuleGroupTermination, RuleClockDiscontinuity,
	RuleTimelineGap, RuleTimelineBuild, RuleNetworkProgress, RuleOOMKillCounter}

// rebuildIndexes rebuilds the outgoing chain-edge index (used by the engine
// and by confirmation checks; 4.41 keeps it linear rebuild).
func (g *Graph) rebuildIndexes() {
	g.causalOut = make(map[EventID][]int, len(g.order))
	for i := range g.Edges {
		if isChainRelation(g.Edges[i].Relation) {
			g.causalOut[g.Edges[i].From] = append(g.causalOut[g.Edges[i].From], i)
		}
	}
}

// FailureAnalyses returns the per-anchor analyses (§5.2), computing once.
func (g *Graph) FailureAnalyses() []FailureAnalysis {
	if !g.analyzed {
		g.analyses = g.analyzeFailures()
		g.analyzed = true
	}
	return g.analyses
}

// analyze is the JSON-rendering alias of FailureAnalyses (§4.2 top-level
// "failures" array).
func (g *Graph) Analyze() []FailureAnalysis { return g.FailureAnalyses() }

// failureAnchors lists the graph's failure anchors (§5.1): recorded failure
// events, plus severe conditions with no observed episode resolution, plus
// unresolved PROCESS_STOPPED (a stop with an observed resume is a closed
// episode, 4.26).
func (g *Graph) failureAnchors() []EventID {
	resolvedepisodes := map[string]bool{}
	for _, id := range g.order {
		e := g.Events[id]
		if e.Episode != "" && isRecoveryType(e.Type) {
			resolvedepisodes[e.Episode] = true
		}
	}
	resumed := map[string]bool{}
	for _, id := range g.order {
		e := g.Events[id]
		if e.Type == EventProcessResumed {
			resumed[e.Subject.ID] = true
		}
	}
	// coordinated member exits (§5.6 process-group-kill) are evidence of the
	// derived group termination, not separate primary failures: the members
	// fall inside their group event's aggregation window.
	timeouts := []struct {
		at     time.Time
		pgid   int
		window time.Duration
	}{}
	for _, id := range g.order {
		e := g.Events[id]
		if e.Type == EventProcessGroupTerminated && e.PGID != 0 {
			timeouts = append(timeouts, struct {
				at     time.Time
				pgid   int
				window time.Duration
			}{e.Timestamp, e.PGID, groupCoordinatedWindow})
		}
	}
	var anchors []EventID
	for _, id := range g.order {
		e := g.Events[id]
		switch {
		case failureAnchorEventTypes[e.Type]:
			if e.Type == EventProcessStopped && resumed[e.Subject.ID] {
				continue
			}
			// §10A.5 / T3: a group whose every member is covered is context too.
			if e.Type == EventProcessGroupTerminated && g.allCovered(e.ProcessIDs, e.PGID, e.Timestamp) {
				continue
			}
			member := false
			if e.Type == EventProcessExited && e.PGID != 0 {
				for _, group := range timeouts {
					if group.pgid == e.PGID &&
						!e.Timestamp.Before(group.at) &&
						e.Timestamp.Before(group.at.Add(group.window)) {
						member = true
						break
					}
				}
			}
			if member {
				continue
			}
			// §10A.5 / T3: a covered exit is context, not a failure anchor.
			if e.Type == EventProcessExited && g.covered(e.PID, e.StartTicks, e.PGID, e.Timestamp) {
				continue
			}
			if e.Type == EventProcessExited && !g.exitIsFailure(e, resolvedepisodes) {
				continue
			}
			anchors = append(anchors, id)
		case severityAnchorTypes[e.Type] && e.Episode != "" && !resolvedepisodes[e.Episode] && persistedSevere(e):
			anchors = append(anchors, id)
		}
	}
	return anchors
}

// exitIsFailure decides whether a recorded process exit needs a causal
// explanation (spec §5.1 as refined 2026-10-28, re-audit R13). v1 records no
// exit status, and the recorder's default is to watch every process, so
// treating every exit as a failure turned each short-lived helper process
// into "failure PROCESS_EXITED, root cause UNKNOWN". since 2026-10-30 the
// recorder does carry an opportunistic exit status: a sampled zombie names
// its terminal wait status (exit_state), so "recorded as normal" is now a
// real outcome, not just absence. an exit is a failure
// when it is not recorded as normal AND at least one of these holds:
//
//   - its recorded exit status is non-normal;
//   - it is the process the incident trigger names;
//   - it has an established cause or consequence (a chain edge into or out
//     of it, e.g. an OOM kill, or the kernel reparenting its children);
//   - it happened while a memory or cgroup limit episode was unresolved
//     (the "OOM suspected" situation).
//
// member exits of a coordinated group are folded into the group anchor
// before this check. other exits are context, counted by OtherExits.
func (g *Graph) exitIsFailure(e *Event, resolvedEpisodes map[string]bool) bool {
	switch exitStatus(e) {
	case "normal":
		return false
	case "":
	default:
		return true
	}
	for _, id := range g.order {
		other := g.Events[id]
		if other.Type == EventIncidentTriggered && other.PID != 0 && other.PID == e.PID &&
			(other.StartTicks == 0 || other.StartTicks == e.StartTicks) {
			return true
		}
	}
	for _, edge := range g.Edges {
		// an established consequence (outgoing) or an established cause
		// (incoming, e.g. an OOM kill) both make the exit a failure.
		if isChainRelation(edge.Relation) && (edge.From == e.ID || edge.To == e.ID) {
			return true
		}
	}
	for _, id := range g.order {
		cond := g.Events[id]
		if cond.Type != EventMemoryLimitReached && cond.Type != EventCgroupLimitReached {
			continue
		}
		if cond.Timestamp.After(e.Timestamp) || cond.Episode == "" {
			continue
		}
		if !episodeResolvedBefore(g, cond.Episode, e.Timestamp) {
			return true
		}
	}
	return false
}

func episodeResolvedBefore(g *Graph, episode string, ts time.Time) bool {
	for _, id := range g.order {
		e := g.Events[id]
		if e.Episode == episode && isRecoveryType(e.Type) && !e.Timestamp.After(ts) {
			return true
		}
	}
	return false
}

// OtherExits counts recorded process exits that are not failure anchors
// (status not captured, no trigger, consequence or limit context): the
// report states the count instead of listing each as a failure.
func (g *Graph) OtherExits() int {
	anchors := map[EventID]bool{}
	for _, id := range g.failureAnchors() {
		anchors[id] = true
	}
	n := 0
	for _, id := range g.order {
		if g.Events[id].Type == EventProcessExited && !anchors[id] {
			n++
		}
	}
	return n
}

// persistedSevere reports whether a severe condition was observed for more
// than one sample (4.27, re-audit R12). one reading at the severe level
// cannot tell a transient dip from a full disk or an exhausted cgroup, so it
// is reported as an unconfirmed severe reading, not a failure. events built
// without the extraction count (tests, injected hypotheses) keep the
// pre-R12 behaviour.
func persistedSevere(e *Event) bool {
	v, ok := e.Data["severe_samples"]
	if !ok {
		return true
	}
	n, ok := asFloat(v)
	return !ok || n >= 2
}

// UnconfirmedSevere lists severe readings that are unresolved at capture end
// but were seen in a single sample only: noteworthy, not a failure.
func (g *Graph) UnconfirmedSevere() []EventID {
	resolved := map[string]bool{}
	for _, id := range g.order {
		if e := g.Events[id]; e.Episode != "" && isRecoveryType(e.Type) {
			resolved[e.Episode] = true
		}
	}
	var out []EventID
	for _, id := range g.order {
		e := g.Events[id]
		if severityAnchorTypes[e.Type] && e.Episode != "" && !resolved[e.Episode] && !persistedSevere(e) {
			out = append(out, id)
		}
	}
	return out
}

type rootInfo struct {
	event   EventID
	effects int
}

// rootContext caches, per candidate event, the resolved episode onset and
// the count of distinct events its chain reaches (A14).
func (g *Graph) rootContext(id EventID) rootInfo {
	resolved := id
	// walk episode escalations back to the onset: an incoming
	// ESCALATES_TO means this event is not the episode's beginning (§5.2).
	for {
		previous := EventID("")
		for _, edge := range g.Edges {
			if edge.Relation == RelationEscalates && edge.To == resolved {
				previous = edge.From
				break
			}
		}
		if previous == "" {
			break
		}
		resolved = previous
	}
	reached := map[EventID]bool{resolved: true}
	stack := []EventID{resolved}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, edgeindex := range g.causalOut[current] {
			if !isChainRelation(g.Edges[edgeindex].Relation) {
				continue
			}
			next := g.Edges[edgeindex].To
			if !reached[next] {
				reached[next] = true
				stack = append(stack, next)
			}
		}
	}
	return rootInfo{event: resolved, effects: len(reached) - 1}
}

// reaches reports whether from can reach to through causal ∪ ESCALATES_TO
// edges (§5.2 criterion 2). preference goes to a path containing at least one
// CAUSES edge; among equal-content paths the highest weakest-link band.
// only causal edges contribute band; escalation edges carry the chain but
// no confidence (§2.4).
func (g *Graph) reaches(from, to EventID) (found, hasCauses bool, band CausalConfidence) {
	g.rebuildIndexes()
	bestfound, bestcauses := false, false
	bestband := ConfidenceLow
	var walk func(EventID, CausalConfidence, bool)
	walk = func(id EventID, band CausalConfidence, causes bool) {
		if id == to {
			consider := false
			switch {
			case !bestfound:
				consider = true
			case bestcauses && !causes:
				// a causal path was already found; escalation-only paths
				// never supersede it
			case !bestcauses && causes:
				consider = true
			case bestcauses == causes:
				consider = band.weight() > bestband.weight()
			}
			if consider {
				bestfound, bestcauses, bestband = true, causes, band
			}
			// keep walking: shorter/other paths may also reach to
		}
		for _, edgeindex := range g.causalOut[id] {
			edge := g.Edges[edgeindex]
			if !isChainRelation(edge.Relation) {
				continue
			}
			nextband, nextcauses := band, causes
			if isCausal(edge.Relation) {
				if edge.Confidence.weight() < nextband.weight() {
					nextband = edge.Confidence
				}
				if edge.Relation == RelationCauses {
					nextcauses = true
				}
			}
			walk(edge.To, nextband, nextcauses)
		}
	}
	walk(from, ConfidenceHigh, false)
	return bestfound, bestcauses, bestband
}

// reachesThroughCausal reports whether some path from → to through chain
// edges contains at least one Causal-layer edge (CAUSES or CONTRIBUTES_TO).
func (g *Graph) reachesThroughCausal(from, to EventID) bool {
	type state struct {
		id     EventID
		causal bool
	}
	seen := map[state]bool{}
	stack := []state{{from, false}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.id == to && current.causal {
			return true
		}
		if seen[current] {
			continue
		}
		seen[current] = true
		for _, edgeindex := range g.causalOut[current.id] {
			edge := g.Edges[edgeindex]
			if !isChainRelation(edge.Relation) {
				continue
			}
			stack = append(stack, state{edge.To, current.causal || isCausal(edge.Relation)})
		}
	}
	return false
}

// analyzeFailures builds one FailureAnalysis per anchor (§5.2/§5.4).
func (g *Graph) analyzeFailures() []FailureAnalysis {
	g.rebuildIndexes()
	var out []FailureAnalysis
	for _, anchor := range g.failureAnchors() {
		anchorevent := g.Events[anchor]
		analysis := FailureAnalysis{
			Anchor:     anchor,
			AnchorType: anchorevent.Type,
		}
		type candidate struct {
			event    EventID
			kind     RootKind
			band     CausalConfidence
			onsetUnk bool
			effects  int
		}
		var candidates []candidate
		for _, id := range g.order {
			e := g.Events[id]
			class := classOf(e.Type)
			iscondition := class == ClassCondition
			isfailurehead := class == ClassFailure && failureAnchorEventTypes[e.Type]
			if !iscondition && !isfailurehead {
				continue
			}
			found, hascauses, band := g.reaches(id, anchor)
			if id != anchor && !found {
				continue // the candidate chain never reaches this anchor
			}
			if id == anchor {
				// A failure is never its own candidate (re-audit R5, spec
				// §5.2 as clarified 2026-10-28): "the exit caused the exit"
				// carries no information and rendered as "root cause: X".
				// an anchor with no upstream link is reported as status
				// UNKNOWN with its known chain.
				continue
			}
			if iscondition && !hascauses && !g.reachesThroughCausal(id, anchor) {
				// Escalation-only reach (re-audit R6, §5.2 clarified): the
				// 90% crossing does not contribute to the 98% crossing of the
				// same episode, both share the episode's cause. the path is
				// the anchor's own known chain, not a contributing factor.
				continue
			}
			if id != anchor && iscondition && !g.rootEligible(id) {
				// A8 (§5.2 criterion 3): root candidacy is not granted to a
				// condition that is itself a later chain step. it has an
				// incoming causal edge, or an incoming escalation that ties it
				// to its episode onset (the onset is the candidate).
				continue
			}
			isself := id == anchor
			kind := KindContributingFactor
			if iscondition && hascauses {
				kind = KindRootCause
			} else if isfailurehead && (hascauses || isself) {
				kind = KindUnexplainedHead
			}
			confidence := band
			if isself {
				// A self-candidate's path into its own anchor is empty: no
				// upstream evidence exists, so the band is LOW by definition
				// (reaches(self,self) rewinds to HIGH; that number would
				// fabricate confidence for an unexplained head).
				confidence = ConfidenceLow
			}
			if kind == KindContributingFactor {
				// Escalation-only reach: contributing factor, band ≤ MEDIUM
				// (§5.2). candidates resolve to the episode onset.
				confidence = capTo(confidence, ConfidenceMedium)
			}
			info := g.rootContext(id)
			candidates = append(candidates, candidate{
				event:    info.event,
				kind:     kind,
				band:     confidence,
				onsetUnk: e.OnsetUnknown,
				effects:  info.effects,
			})
		}
		// deduplicate candidates resolved to the same onset event.
		seenkinds := map[EventID]candidate{}
		var unique []candidate
		for _, c := range candidates {
			if previous, ok := seenkinds[c.event]; ok {
				// keep the strongest representation of the same root event.
				if previous.kind == KindContributingFactor && c.kind != KindContributingFactor {
					seenkinds[c.event] = c
					continue
				}
				continue
			}
			seenkinds[c.event] = c
			unique = append(unique, c)
		}
		candidates = unique
		// rank: band first, then effects, then canonical order (display
		// order only; roles are never tied off canonical order, P7/A6).
		tieorder := func(list []candidate) {
			sort.SliceStable(list, func(i, j int) bool {
				if list[i].band.weight() != list[j].band.weight() {
					return list[i].band.weight() > list[j].band.weight()
				}
				if list[i].effects != list[j].effects {
					return list[i].effects > list[j].effects
				}
				return g.index[list[i].event] < g.index[list[j].event]
			})
		}
		tieorder(candidates)
		// the top band group consists of non-contributing candidates.
		var top []candidate
		var contributors []candidate
		topband := ConfidenceLow
		sawtop := false
		for _, c := range candidates {
			if c.kind == KindContributingFactor {
				contributors = append(contributors, c)
				continue
			}
			if !sawtop {
				topband, sawtop = c.band, true
			}
			if c.band == topband {
				top = append(top, c)
			}
		}
		// independence within the top group (§6.1): candidates that reach
		// each other are ordered, not competing.
		competing := false
		if len(top) > 1 {
			independent := 0
			for i := range top {
				for j := range top {
					if i >= j {
						continue
					}
					areachb, _, _ := g.reaches(top[i].event, top[j].event)
					breacha, _, _ := g.reaches(top[j].event, top[i].event)
					if !areachb && !breacha {
						independent++
					}
				}
			}
			competing = independent > 0
		}
		for _, c := range candidates {
			role := RoleSecondary
			switch {
			case c.kind == KindContributingFactor:
				role = RoleSecondary // a cofactor never leads the report (§5.2)
			case competing && c.band == topband:
				role = RoleCompeting
			case !competing && c.band == topband && sawtop:
				role = RolePrimary
			}
			analysis.Candidates = append(analysis.Candidates, RootCandidate{
				Event:        c.event,
				Kind:         c.kind,
				Anchor:       anchor,
				Role:         role,
				Confidence:   c.band,
				OnsetUnknown: c.onsetUnk,
				Effects:      c.effects,
			})
		}
		// status (§5.4/§5.6): a ROOT_CAUSE candidate explains; ties that
		// cannot be discriminated are AMBIGUOUS; unexplained heads and
		// contributing factors leave the cause UNKNOWN (conservative
		// fallback, §9).
		hasrootcause := false
		for _, c := range candidates {
			if c.kind == KindRootCause {
				hasrootcause = true
				break
			}
		}
		switch {
		case !hasrootcause:
			analysis.Status = StatusUnknown
		case competing:
			analysis.Status = StatusAmbiguous
		default:
			analysis.Status = StatusExplained
		}
		analysis.KnownChain = g.knownChain(anchor)
		analysis.MissingEvidence = g.missingEvidence(anchor)
		analysis.Alternatives = g.alternatives(anchor)
		out = append(out, analysis)
	}
	return out
}

// rootEligible reports whether an event can head a chain (§5.2 criterion 3):
// no incoming causal edge from a CONDITION or FAILURE event, and no incoming
// ESCALATES_TO (the episode onset is the candidate, not a later step).
func (g *Graph) rootEligible(id EventID) bool {
	for _, edge := range g.Edges {
		if !isChainRelation(edge.Relation) {
			continue
		}
		if edge.To != id {
			continue
		}
		if isCausal(edge.Relation) {
			from := g.Events[edge.From]
			if classOf(from.Type) == ClassCondition || classOf(from.Type) == ClassFailure {
				return false
			}
		}
		if edge.Relation == RelationEscalates {
			return false
		}
	}
	return true
}

// knownChain renders the connected chain segment containing the anchor (§4.45
// "known chain" language, §5.6): upstream episode escalation into the anchor,
// then the anchor, then its downstream consequences.
func (g *Graph) knownChain(anchor EventID) []EventID {
	// walk upstream through escalations (recovery edges end episodes and
	// never carry a chain).
	upstream := []EventID{}
	current := anchor
	for {
		previous := EventID("")
		for _, edge := range g.Edges {
			if edge.Relation == RelationEscalates && edge.To == current {
				previous = edge.From
				break
			}
		}
		if previous == "" {
			break
		}
		upstream = append([]EventID{previous}, upstream...)
		current = previous
	}
	chain := append(upstream, anchor)
	// walk downstream through chain relations from the anchor.
	seen := map[EventID]bool{}
	for _, e := range chain {
		seen[e] = true
	}
	stack := []EventID{anchor}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, edgeindex := range g.causalOut[node] {
			edge := g.Edges[edgeindex]
			if !isChainRelation(edge.Relation) || seen[edge.To] {
				continue
			}
			seen[edge.To] = true
			chain = append(chain, edge.To)
			stack = append(stack, edge.To)
		}
	}
	// an isolated anchor is still its own known chain (4.45): the report
	// names the observed effect even with nothing connected to it.
	return chain
}

// missingEvidence names what the anchor's analysis could not use: rejection
// reasons that said a required check was unobservable, plus the standing v1
// telemetry gaps cited by §5.6.
func (g *Graph) missingEvidence(anchor EventID) []string {
	var out []string
	for _, rejected := range g.Rejected {
		if rejected.To != anchor {
			continue
		}
		if strings.Contains(rejected.Reason, "unobservable in this bundle") {
			code := strings.TrimPrefix(rejected.Reason, "required ")
			code = strings.TrimSuffix(code, " unobservable in this bundle")
			if cut := strings.Index(code, ":"); cut >= 0 {
				code = code[:cut]
			}
			entry := code + " is not checkable in v1 bundles"
			if !containsString(out, entry) {
				out = append(out, entry)
			}
		}
	}
	anchorType := g.Events[anchor].Type
	switch anchorType {
	case EventProcessGroupTerminated:
		out = append(out, "no signal-sender telemetry: who signalled the group is not captured in v1 bundles")
	case EventProcessExited:
		out = append(out, "exit status and signal lineage are not captured in v1 bundles")
	case EventProcessStopped:
		out = append(out, "stop-sender telemetry (who sent SIGSTOP/ptrace) is not captured in v1 bundles")
	case EventMemoryLimitReached, EventCgroupLimitReached, EventOOM:
		out = append(out, "the originating allocation growth (or a kernel OOM record) is not captured in v1 bundles")
	case EventDiskExhausted:
		out = append(out, "write-failure / ENOSPC telemetry is not captured in v1 bundles")
	case EventNetworkProgressStopped:
		// §7.4: worker progress and tier C blocked-in-read telemetry are what
		// would carry the stall into a job's failure.
		out = append(out, "job/application progress over the stalled socket is not observed in v1 (WORKER_PROGRESS_STOPPED), and Tier C blocked-in-read evidence is not captured")
	}
	return dedupeStrings(out)
}

// alternatives lists explanations the bundle suggested but could not confirm
// (§5.6, counterfactual 4.37 wording): an exit occurring while a severe,
// unresolved resource condition was in effect suspects the matching failure
// mode, but without the kernel record the suspicion stays an alternative.
func (g *Graph) alternatives(anchor EventID) []string {
	var out []string
	anchorevent := g.Events[anchor]
	// resolved episodes cannot suspect anything (their condition ended).
	resolvedepisodes := map[string]bool{}
	for _, id := range g.order {
		e := g.Events[id]
		if e.Episode != "" && isRecoveryType(e.Type) {
			resolvedepisodes[e.Episode] = true
		}
	}
	suspectoom, suspectwrite := false, false
	for _, id := range g.order {
		e := g.Events[id]
		if !severityAnchorTypes[e.Type] || e.Episode == "" || resolvedepisodes[e.Episode] {
			continue
		}
		if classOf(e.Type) != ClassCondition && !severityAnchorTypes[e.Type] {
			continue
		}
		if e.Timestamp.After(anchorevent.Timestamp) {
			continue
		}
		switch {
		case e.Type == EventMemoryLimitReached || e.Type == EventCgroupLimitReached || e.Type == EventOOM:
			suspectoom = true
		case e.Type == EventDiskExhausted:
			suspectwrite = true
		}
	}
	// A suspected kill explains an exit, not a condition: an OOM follows a
	// limit and cannot explain it, and a write failure is a consequence of a
	// full disk, not an alternative cause of it (re-audit R7).
	exitfailure := anchorevent.Type == EventProcessExited || anchorevent.Type == EventWorkerExited ||
		anchorevent.Type == EventProcessGroupTerminated
	if !exitfailure {
		suspectoom, suspectwrite = false, false
	}
	if suspectoom {
		out = append(out, "OOM suspected; kernel OOM record not captured")
	}
	if suspectwrite {
		out = append(out, "write failure / ENOSPC suspected; no write-failure evidence captured")
	}
	// §7.3: an open (never recovered) network stall reaching this anchor is
	// evaluated as competing explanations (BROKER_SOCKET_STALL vs
	// NETWORK_PATH_FAILURE) whose discrimination is the stamped stall
	// shape. neither hypothesis is promoted to a root cause: application-
	// level broker progress is not captured in v1, so both stay alternatives
	// with their discriminator status stated.
	out = append(out, g.networkStallAlternatives(anchor, resolvedepisodes)...)
	if len(out) == 0 {
		// checked, empty (I2): render "alternatives": [] rather than omit.
		return []string{}
	}
	return out
}

// networkStallAlternatives names, per network stall that reaches the anchor
// in capture order, what its stamped shape (§7.2) supports and contradicts:
// the BROKER_SOCKET_STALL / NETWORK_PATH_FAILURE pair of §7.3.
func (g *Graph) networkStallAlternatives(anchor EventID, resolvedEpisodes map[string]bool) []string {
	var out []string
	for _, id := range g.order {
		e := g.Events[id]
		if e.Type != EventNetworkProgressStopped || e.Episode == "" || resolvedEpisodes[e.Episode] {
			continue // the stall recovered; it explains nothing here
		}
		if e.Timestamp.After(g.Events[anchor].Timestamp) {
			continue // the stall opened after the failure
		}
		found, _, _ := g.reaches(id, anchor)
		if !found {
			continue // the stall never touches this failure's chain
		}
		shape, _ := e.Data["stall_shape"].(string)
		if shape == "" {
			// the 0.x stamping pre-dates the shape field; cite the
			// discrimination as what tier A would have shown.
			shape = StallShapeUnknown
		}
		switch shape {
		case StallShapePeerSilent:
			out = append(out, "network stall shape PEER_SILENT supports BROKER_SOCKET_STALL; NETWORK_PATH_FAILURE is contradicted (send queue empty, no retransmit timer)")
		case StallShapePathLoss:
			out = append(out, "network stall shape PATH_LOSS supports NETWORK_PATH_FAILURE; BROKER_SOCKET_STALL is contradicted (our data is queued and unacknowledged)")
		case StallShapeZeroWindow:
			out = append(out, "network stall shape ZERO_WINDOW points at the peer not reading (peer-side application stall); broker and path hypotheses stay unconfirmed")
		case StallShapeLocalNotReading:
			out = append(out, "network stall shape LOCAL_NOT_READING points at the local process not reading: the stall is an effect of a local stop, not a broker or path failure")
		default:
			out = append(out, "network stall shape UNKNOWN: BROKER_SOCKET_STALL and NETWORK_PATH_FAILURE cannot be discriminated without Tier A (send-queue state, retransmit timer)")
		}
	}
	return out
}

// chainTo walks the chain edges from root, depth-first, to every reachable
// leaf. visited prevents re-entry.
func (g *Graph) chainTo(root EventID) []CausalChain {
	g.rebuildIndexes()
	var out []CausalChain
	var walk func(EventID, []ChainStep, map[EventID]bool)
	walk = func(id EventID, steps []ChainStep, path map[EventID]bool) {
		children := make([]int, 0, len(g.causalOut[id]))
		for _, edgeindex := range g.causalOut[id] {
			if path[g.Edges[edgeindex].To] {
				continue
			}
			children = append(children, edgeindex)
		}
		if len(children) == 0 {
			if len(steps) == 0 {
				return
			}
			out = append(out, CausalChain{
				Root: root, OnsetKnown: !g.Events[root].OnsetUnknown,
				Steps: append([]ChainStep(nil), steps...),
				Band:  weakestBand(steps),
			})
			return
		}
		for _, edgeindex := range children {
			edge := g.Edges[edgeindex]
			nextpath := make(map[EventID]bool, len(path)+1)
			for seen := range path {
				nextpath[seen] = true
			}
			nextpath[edge.To] = true
			walk(edge.To, append(append([]ChainStep(nil), steps...), ChainStep{Event: edge.To, Edge: edge}), nextpath)
		}
	}
	walk(root, nil, map[EventID]bool{root: true})
	return out
}

// weakestBand is the weakest CAUSES/CONTRIBUTES link on a chain; escalation
// and recovery steps contribute nothing (§2.4). A chain with no causal link
// is LOW by definition.
func weakestBand(steps []ChainStep) CausalConfidence {
	band := ConfidenceLow
	sawcausal := false
	for _, step := range steps {
		if !isCausal(step.Edge.Relation) {
			continue
		}
		if !sawcausal || step.Edge.Confidence.weight() < band.weight() {
			band = step.Edge.Confidence
			sawcausal = true
		}
	}
	return band
}

// chains returns every chain of every contributing or explained root,
// stable and cycle-safe (4.13).
func (g *Graph) Chains() []CausalChain {
	var out []CausalChain
	for _, analysis := range g.FailureAnalyses() {
		for _, candidate := range analysis.Candidates {
			if candidate.Kind == KindContributingFactor {
				continue
			}
			chains := g.chainTo(candidate.Event)
			for i := range chains {
				chains[i].Role = candidate.Role
			}
			out = append(out, chains...)
		}
	}
	return out
}

// healthy reports whether no failure anchor exists (§5.5): condition episodes
// that recovered and reached no anchor are healthy-but-noteworthy, and a
// severe condition still in effect at capture end is NOT healthy even when
// nothing else failed.
func (g *Graph) Healthy() bool {
	return len(g.failureAnchors()) == 0
}

// explain returns the human-auditable eight-question record for one edge
// (§8.1/4.32). empty sections say whether they are checked-and-empty or not
// checkable (I2); nothing is asserted without its evidence record.
func (g *Graph) Explain(edgeIndex int) (string, error) {
	if edgeIndex < 0 || edgeIndex >= len(g.Edges) {
		return "", fmt.Errorf("edge %d does not exist", edgeIndex)
	}
	edge := g.Edges[edgeIndex]
	var b strings.Builder
	fmt.Fprintf(&b, "Edge: %s\n", edge.ID)
	fmt.Fprintf(&b, "1 Claim: %s -> %s\n", describeEvent(g, edge.From), describeEvent(g, edge.To))
	fmt.Fprintf(&b, "2 Evidence:\n")
	for _, record := range edge.Checks {
		fmt.Fprintf(&b, "- %s %s (%s)\n", record.Code, record.Status, record.Detail)
	}
	fmt.Fprintf(&b, "3 Rule: %s\n", edge.RuleID)
	fmt.Fprintf(&b, "3 Mechanism: %s\n", edge.Mechanism)
	from, to := g.Events[edge.From], g.Events[edge.To]
	if edge.SameInstant {
		fmt.Fprintf(&b, "4 Timing: both at %s (t+%s) — same sampling instant; order within the instant not observed\n",
			from.Timestamp.Format(time.RFC3339), from.Timestamp.Sub(g.Origin).Round(time.Millisecond))
	} else {
		fmt.Fprintf(&b, "4 Timing: %s at %s (t+%s) → %s at %s (t+%s); gap %s (sampling-resolution span, not measured cause latency)\n",
			describeEvent(g, edge.From), from.Timestamp.Format(time.RFC3339), from.Timestamp.Sub(g.Origin).Round(time.Millisecond),
			describeEvent(g, edge.To), to.Timestamp.Format(time.RFC3339), to.Timestamp.Sub(g.Origin).Round(time.Millisecond),
			to.Timestamp.Sub(from.Timestamp).Round(time.Millisecond))
	}
	fmt.Fprintf(&b, "5 Confidence: %s\n", edge.Confidence)
	if len(edge.Demotions) == 0 {
		b.WriteString("5 Why not higher: no demotion applied (checked, empty)\n")
	} else {
		fmt.Fprintf(&b, "5 Why not higher:\n")
		for _, d := range edge.Demotions {
			fmt.Fprintf(&b, "- %s\n", d)
		}
	}
	b.WriteString("6 Contradictions:\n")
	contradicting := filterChecks(edge, "contradicting")
	if len(contradicting) == 0 {
		b.WriteString("- none declared: the rule declares no contradicting checks\n")
	} else {
		for _, record := range contradicting {
			if record.Status == CheckAbsent {
				fmt.Fprintf(&b, "- checked, absent: %s (%s)\n", record.Code, record.Detail)
			}
		}
	}
	b.WriteString("7 Missing evidence:\n")
	if len(edge.Missing) == 0 {
		b.WriteString("- none: every supporting check the rule declares was observed\n")
	} else {
		for _, missing := range edge.Missing {
			fmt.Fprintf(&b, "- %s not observed\n", missing)
		}
	}
	for _, record := range edge.Checks {
		if record.Status == CheckUnknown {
			fmt.Fprintf(&b, "- %s not checkable in this bundle\n", record.Code)
		}
	}
	b.WriteString("8 Alternatives:\n")
	if len(edge.Competes) == 0 {
		b.WriteString("- none recorded by the engine (checked, empty)\n")
	} else {
		for _, id := range edge.Competes {
			fmt.Fprintf(&b, "- competing CAUSES edge %s\n", id)
		}
	}
	return b.String(), nil
}

func filterChecks(edge CausalEdge, kind string) []CheckRecord {
	var out []CheckRecord
	for _, record := range edge.Checks {
		if record.Kind == kind {
			out = append(out, record)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func describeEvent(g *Graph, id EventID) string {
	e := g.Get(id)
	if e == nil {
		return string(id)
	}
	description := string(e.Type)
	if e.Subject.Kind != "" {
		description += " on " + string(e.Subject.Kind) + ":" + e.Subject.ID
	}
	return description
}
