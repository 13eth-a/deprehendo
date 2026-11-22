package causal

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// AnalysisContext carries rule-exclusion state for one evaluation pass
// (4.15): a disabled signature's derived events never match rules.
type AnalysisContext struct {
	Disabled     []string
	relativeTime *Timeline
}

// engine validates and applies rule proposals. it never invents edges: a
// proposal that fails the proposing rule's declared contract is recorded as a
// rejection with the reason (4.43). checks are tri-state (§2.3): an UNKNOWN
// required check rejects the pair as "unobservable in this bundle" and feeds
// the unknown-cause report's missing evidence; an UNKNOWN contradicting
// check allows the edge with demotion D1.
type Engine struct {
	rules []compositeRule
	// clockOrigin ties edge gaps back to the normalized timeline (4.19).
	clockOrigin time.Time
}

// compositeRule pairs a rule with its resolved evaluators, built once per
// engine.
type compositeRule struct {
	*Rule
	required      []Check
	supporting    []Check
	contradicting []Check
}

func compile(rules []*Rule) []compositeRule {
	out := make([]compositeRule, 0, len(rules))
	for _, r := range rules {
		c := compositeRule{Rule: r}
		for _, code := range r.Required {
			if check, err := lookupCheck(code); err == nil {
				c.required = append(c.required, check)
			}
		}
		for _, code := range r.Supporting {
			if check, err := lookupCheck(code); err == nil {
				c.supporting = append(c.supporting, check)
			}
		}
		for _, code := range r.Contradicting {
			if check, err := lookupCheck(code); err == nil {
				c.contradicting = append(c.contradicting, check)
			}
		}
		out = append(out, c)
	}
	return out
}

func NewEngine(rules []*Rule, origin time.Time) *Engine {
	rulescopy := make([]*Rule, len(rules))
	copy(rulescopy, rules)
	sort.Slice(rulescopy, func(i, j int) bool { return rulescopy[i].ID < rulescopy[j].ID })
	return &Engine{rules: compile(rulescopy), clockOrigin: origin}
}

// RuleIDs returns the engine's rule IDs in evaluation order, disabled rules
// excluded (4.42: the registry is the index documentation).
func (e *Engine) RuleIDs() []string {
	return e.RuleIDsWithContext(nil)
}

// RuleIDsWithContext returns the rules active for one analysis without
// mutating shared engine state; this is safe for concurrent bundle analysis.
func (e *Engine) RuleIDsWithContext(ctx *AnalysisContext) []string {
	var disabled []string
	if ctx != nil {
		disabled = ctx.Disabled
	}
	var out []string
	for _, r := range e.rules {
		if rulesDisabled(r.Rule, disabled) {
			continue
		}
		out = append(out, r.ID)
	}
	return out
}

func rulesDisabled(r *Rule, disabled []string) bool {
	for _, d := range disabled {
		if d == r.ID {
			return true
		}
		base := strings.SplitN(r.ID, "@", 2)[0]
		if d == base {
			return true
		}
	}
	return false
}

// apply runs every rule against the indexed graph, accepting validated
// proposals and recording rejected ones, then applies the competition
// demotion D3 (§6.1). applied edge count is returned.
func (e *Engine) Apply(g *Graph, ctx *AnalysisContext) (int, error) {
	var disabled []string
	if ctx != nil {
		disabled = ctx.Disabled
	}
	g.rebuildIndexes()
	// index events by type once (4.42): every rule scans only its own types.
	bytype := map[EventType][]EventID{}
	for _, id := range g.order {
		bytype[g.Events[id].Type] = append(bytype[g.Events[id].Type], id)
	}
	idx := buildApplyIndex(g, bytype)
	accepted := 0
	for _, rule := range e.rules {
		if rulesDisabled(rule.Rule, disabled) {
			continue
		}
		accepted += e.applyRule(g, rule, idx)
	}
	markCompetingEdges(g)
	return accepted, nil
}

// applyIndex holds the per-Apply lookups that keep rule evaluation near
// O(n log n) (4.41). Re-audit R10: the remediation pass paired every source
// with every target and rescanned all events per pair for recoveries and
// discontinuities, which made a 10k-sample capture ~35x slower than the
// pre-remediation baseline and grew the rejection list per pair (A21).
type applyIndex struct {
	byType        map[EventType][]EventID // canonical order, so timestamps are non-decreasing
	byTypeEpisode map[EventType]map[string][]EventID
	firstRecovery map[string]time.Time // earliest recovery timestamp per episode
	windows       []discontinuityWindow
}

func buildApplyIndex(g *Graph, byType map[EventType][]EventID) *applyIndex {
	idx := &applyIndex{
		byType:        byType,
		byTypeEpisode: map[EventType]map[string][]EventID{},
		firstRecovery: map[string]time.Time{},
	}
	for _, id := range g.order {
		e := g.Events[id]
		if e.Episode != "" {
			if idx.byTypeEpisode[e.Type] == nil {
				idx.byTypeEpisode[e.Type] = map[string][]EventID{}
			}
			idx.byTypeEpisode[e.Type][e.Episode] = append(idx.byTypeEpisode[e.Type][e.Episode], id)
			if isRecoveryType(e.Type) {
				if first, ok := idx.firstRecovery[e.Episode]; !ok || e.Timestamp.Before(first) {
					idx.firstRecovery[e.Episode] = e.Timestamp
				}
			}
		}
	}
	idx.windows = discontinuityWindows(g)
	return idx
}

// candidateTargets narrows the rule's targets for one source without
// changing which pairs can edge: same-episode rules only ever accept targets
// of the source's episode, and gap-bounded rules only targets inside
// [src, src+MaxGap] (byType lists are timestamp-ordered).
func (idx *applyIndex) candidateTargets(rule *Rule, src *Event, g *Graph) []EventID {
	if rule.Binding == BindingSameEpisode {
		if src.Episode == "" {
			return nil
		}
		return idx.byTypeEpisode[rule.Target][src.Episode]
	}
	targets := idx.byType[rule.Target]
	if rule.MaxGap <= 0 {
		return targets
	}
	lo := sort.Search(len(targets), func(i int) bool {
		return !g.Events[targets[i]].Timestamp.Before(src.Timestamp)
	})
	limit := src.Timestamp.Add(rule.MaxGap)
	hi := sort.Search(len(targets), func(i int) bool {
		return g.Events[targets[i]].Timestamp.After(limit)
	})
	if hi < lo {
		return nil
	}
	return targets[lo:hi]
}

// applyRule evaluates one rule across its indexed source/target pairs.
func (e *Engine) applyRule(g *Graph, rule compositeRule, idx *applyIndex) int {
	accepted := 0
	for _, srcid := range idx.byType[rule.Source] {
		for _, tgtid := range idx.candidateTargets(rule.Rule, g.Events[srcid], g) {
			src := g.Events[srcid]
			tgt := g.Events[tgtid]
			if e.outsideOrderBounds(g, rule.Rule, srcid, tgtid) {
				continue
			}
			binding, ok := e.bindingOK(idx, rule.Rule, src, tgt)
			if !ok {
				g.Rejected = append(g.Rejected, RejectedEdge{
					From: srcid, To: tgtid, Relation: rule.Edge, RuleID: rule.ID,
					Reason: binding,
				})
				continue
			}
			checks, demotions, band, missing, rejectreason := e.evaluateChecks(g, rule, src, tgt)
			if rejectreason != "" {
				g.Rejected = append(g.Rejected, RejectedEdge{
					From: srcid, To: tgtid, Relation: rule.Edge, RuleID: rule.ID,
					Reason: rejectreason,
				})
				continue
			}
			sameInstant := src.Timestamp.Equal(tgt.Timestamp)
			demotions = append(demotions, e.orderDemotions(idx, rule.Rule, src, tgt, sameInstant)...)
			band = capBand(band, demotions)
			proposal := EdgeProposal{
				From: srcid, To: tgtid, Relation: rule.Edge,
				Confidence:  band,
				Checks:      checks,
				Missing:     missing,
				Demotions:   dedupeStrings(demotions),
				Mechanism:   rule.Mechanism,
				SameInstant: sameInstant,
				ruleID:      rule.ID,
			}
			if err := g.addEdge(proposal); err != nil {
				continue
			}
			accepted++
			if rule.NearestOnly || rule.Binding == BindingNearestOnly {
				// the first validated target resolves this source; later
				// targets belong to later episodes (4.26/4.41).
				break
			}
		}
	}
	return accepted
}

// outsideOrderBounds applies the observed-order bounds (P7: canonical order
// is never order evidence):
//
//   - every relation requires observed order, except rules declaring
//     SameInstant, which may pair events of one sampling instant (E1′;
//     caps the band at MEDIUM, D5/P6);
//   - gap ∈ [MinGap, MaxGap] when the rule declares bounds.
func (e *Engine) outsideOrderBounds(g *Graph, rule *Rule, srcID, tgtID EventID) bool {
	src, tgt := g.Events[srcID], g.Events[tgtID]
	if src.Timestamp.After(tgt.Timestamp) {
		return true
	}
	if src.Timestamp.Equal(tgt.Timestamp) && !rule.SameInstant {
		// equal wall timestamps carry no observed order (E1). only rules
		// that declare same-instant may use the pairing; relationDirectionOK
		// refuses PRECEDES/RECOVERY_OF at equal instants regardless.
		if isCausal(rule.Edge) || rule.Edge == RelationEscalates {
			return true
		}
	}
	gap := tgt.Timestamp.Sub(src.Timestamp)
	if gap < 0 {
		return true
	}
	if rule.MaxGap > 0 && gap > rule.MaxGap {
		return true
	}
	if rule.MinGap > 0 && gap < rule.MinGap {
		return true
	}
	return false
}

// bindingOK enforces the P3 episode binding (§4.4 V2). returns (rejection
// reason, false) or ("", true).
func (e *Engine) bindingOK(idx *applyIndex, rule *Rule, src, tgt *Event) (string, bool) {
	switch rule.Binding {
	case BindingNone:
		return "", true
	case BindingSameEpisode:
		if src.Episode == "" || src.Episode != tgt.Episode {
			return fmt.Sprintf("episode binding: source episode %q does not match target episode %q", src.Episode, tgt.Episode), false
		}
		return "", true
	case BindingSourceActiveAtTarget:
		if src.Episode == "" {
			return "episode binding: source carries no episode instance", false
		}
		if first, resolved := idx.firstRecovery[src.Episode]; resolved && first.Before(tgt.Timestamp) {
			return "episode binding: the source episode was already resolved at the target's timestamp (recovered episodes cannot cause, audit A3)", false
		}
		return "", true
	case BindingNearestOnly:
		return "", true
	}
	return "unknown episode binding " + string(rule.Binding), false
}

// episodeActiveAt reports whether the episode was still active (no observed
// resolution) strictly before ts. A recovery observed in the same sampling
// instant as the target keeps the pair usable but the same-instant rule caps
// the band.
func episodeActiveAt(g *Graph, episode string, ts time.Time) bool {
	for _, id := range g.order {
		e := g.Events[id]
		if e.Episode != episode || !e.Timestamp.Before(ts) {
			continue
		}
		if isRecoveryType(e.Type) {
			return false
		}
	}
	return true
}

// evaluateChecks runs the rule's tri-state checks (§2.2/§2.3). returns the
// check records, demotion entries, computed band, missing supporting/unknown
// codes, and a rejection reason when the pair must not edge.
func (e *Engine) evaluateChecks(g *Graph, rule compositeRule, src, tgt *Event) (checks []CheckRecord, demotions []string, band CausalConfidence, missing []string, rejection string) {
	for _, check := range rule.required {
		result := check.Evaluate(g, src, tgt)
		checks = append(checks, CheckRecord{Kind: "required", Code: check.Code, Status: result.Status, Detail: result.Detail, Sampled: result.Sampled})
		switch result.Status {
		case CheckAbsent:
			return checks, demotions, band, missing, "required " + check.Code + " absent: " + result.Detail
		case CheckUnknown:
			return checks, demotions, band, missing, "required " + check.Code + " unobservable in this bundle: " + result.Detail
		case CheckPresent:
			if result.Sampled {
				// D6: the requirement rests on sampled state.
				demotions = append(demotions, "D6:"+check.Code+" rests on sampled state")
			}
		}
	}
	for _, check := range rule.contradicting {
		result := check.Evaluate(g, src, tgt)
		checks = append(checks, CheckRecord{Kind: "contradicting", Code: check.Code, Status: result.Status, Detail: result.Detail})
		switch result.Status {
		case CheckPresent:
			return checks, demotions, band, missing, "contradicting evidence PRESENT: " + check.Code + " (" + result.Detail + ")"
		case CheckUnknown:
			// D1: the check could not be evaluated.
			demotions = append(demotions, "D1:"+check.Code+" unevaluable")
		case CheckAbsent:
			// checked and clean: recorded, no effect (I2).
		}
	}
	for _, check := range rule.supporting {
		result := check.Evaluate(g, src, tgt)
		checks = append(checks, CheckRecord{Kind: "supporting", Code: check.Code, Status: result.Status, Detail: result.Detail})
		if result.Status != CheckPresent {
			missing = append(missing, check.Code)
		}
	}
	// D2: identity weaker than exact.
	if rule.Identity != IdentityExact {
		demotions = append(demotions, "D2:identity "+string(rule.Identity))
	}
	band = capBand(rule.Ceiling, dedupeStrings(demotions))
	return checks, demotions, band, missing, ""
}

// orderDemotions records the order-derived demotions: D5 same-instant and
// D4 discontinuity between endpoints.
func (e *Engine) orderDemotions(idx *applyIndex, rule *Rule, src, tgt *Event, sameInstant bool) []string {
	var demotions []string
	if sameInstant {
		demotions = append(demotions, "D5:same sampling instant (order within the instant not observed)")
	}
	if straddlesDiscontinuity(idx.windows, src, tgt) {
		demotions = append(demotions, "D4:timeline discontinuity between endpoints")
	}
	return demotions
}

// discontinuityBetween reports whether an edge's endpoints straddle a
// CLOCK_DISCONTINUITY or TIMELINE_GAP (P4/D4). A forward hole covers the
// wall interval (previous_wall, wall). A backward step makes a wall range
// ambiguous: readings after the step re-cover times the pre-step clock had
// already used, so an endpoint in [stepped_wall, previous_wall + |step|] may
// lie on either side of it. timestamp ordering alone cannot see that (the
// discontinuity event carries the stepped-back wall time), so the test is an
// interval overlap, deliberately conservative (re-audit R3).
type discontinuityWindow struct {
	gap       bool // TIMELINE_GAP (forward hole) vs backward CLOCK_DISCONTINUITY
	point     bool // no recorded window: strict point test on at
	at        time.Time
	low, high time.Time
}

func discontinuityWindows(g *Graph) []discontinuityWindow {
	var out []discontinuityWindow
	for _, id := range g.order {
		e := g.Events[id]
		if e.Type != EventClockDiscontinuity && e.Type != EventTimelineGap {
			continue
		}
		previous, err := time.Parse(time.RFC3339Nano, fmt.Sprint(e.Data["previous_wall"]))
		if err != nil {
			out = append(out, discontinuityWindow{point: true, at: e.Timestamp})
			continue
		}
		if e.Type == EventTimelineGap {
			out = append(out, discontinuityWindow{gap: true, low: previous, high: e.Timestamp})
			continue
		}
		step := previous.Sub(e.Timestamp)
		if step < 0 {
			step = -step
		}
		out = append(out, discontinuityWindow{low: e.Timestamp, high: previous.Add(step)})
	}
	return out
}

func straddlesDiscontinuity(windows []discontinuityWindow, src, tgt *Event) bool {
	for _, w := range windows {
		switch {
		case w.point:
			if w.at.After(src.Timestamp) && w.at.Before(tgt.Timestamp) {
				return true
			}
		case w.gap:
			if src.Timestamp.Before(w.high) && tgt.Timestamp.After(w.low) {
				return true
			}
		default:
			if !src.Timestamp.After(w.high) && !tgt.Timestamp.Before(w.low) {
				return true
			}
		}
	}
	return false
}

// discontinuityBetween is the unindexed form, kept for callers outside Apply.
func discontinuityBetween(g *Graph, src, tgt *Event) bool {
	return straddlesDiscontinuity(discontinuityWindows(g), src, tgt)
}

// capBand applies the demotion-family caps (§2.2): D1/D2/D3/D5/D6 each cap
// at MEDIUM, two or more distinct stacking families cap at LOW, D4 (a
// timeline discontinuity between endpoints) caps at LOW on its own.
func capBand(start CausalConfidence, demotions []string) CausalConfidence {
	band := start
	stacking := map[string]bool{}
	stackingsawlow := false
	for _, d := range demotions {
		switch {
		case strings.HasPrefix(d, "D1:"), strings.HasPrefix(d, "D2:"),
			strings.HasPrefix(d, "D3:"), strings.HasPrefix(d, "D5:"),
			strings.HasPrefix(d, "D6:"):
			stacking[d[:2]] = true
			band = capTo(band, ConfidenceMedium)
		case strings.HasPrefix(d, "D4:"):
			stackingsawlow = true
			band = capTo(band, ConfidenceLow)
		}
	}
	if stackingsawlow || len(stacking) >= 2 {
		band = ConfidenceLow
	}
	return band
}

func capTo(band CausalConfidence, cap CausalConfidence) CausalConfidence {
	if band.weight() > cap.weight() {
		return cap
	}
	return band
}

// markCompetingEdges applies D3 (§6.1): two CAUSES edges into the same target
// from non-ancestral sources are alternative sufficiency claims; both cap at
// MEDIUM and reference each other in Competes. it is idempotent (re-marking a
// pair is a no-op), so later edge sets (test-only injection harnesses, any
// future post-Apply ingest pass) can safely re-run it over the final state.
func markCompetingEdges(g *Graph) {
	bytarget := map[EventID][]int{}
	for i, edge := range g.Edges {
		if edge.Relation == RelationCauses {
			bytarget[edge.To] = append(bytarget[edge.To], i)
		}
	}
	for _, indexes := range bytarget {
		if len(indexes) < 2 {
			continue
		}
		for a := 0; a < len(indexes); a++ {
			for b := a + 1; b < len(indexes); b++ {
				first, second := g.Edges[indexes[a]], g.Edges[indexes[b]]
				// A6 (§6.1): competition is judged between the two SOURCES.
				// judging source→shared-target is vacuous: both sources reach
				// their own common target through their own edges, which
				// would silently skip the demotion on every same-target pair.
				if isAncestor(g, first.From, second.From) || isAncestor(g, second.From, first.From) {
					continue // causally ordered, not competing
				}
				g.Edges[indexes[a]] = demoteCompetition(g.Edges[indexes[a]], second.ID)
				g.Edges[indexes[b]] = demoteCompetition(g.Edges[indexes[b]], first.ID)
			}
		}
	}
}

func demoteCompetition(edge CausalEdge, otherID string) CausalEdge {
	for _, id := range edge.Competes {
		if id == otherID {
			return edge
		}
	}
	edge.Competes = append(edge.Competes, otherID)
	edge.Demotions = append(edge.Demotions, "D3:competing CAUSES edge "+otherID)
	// Re-grade through capBand, not a bare MEDIUM cap: D3 stacks with the
	// edge's other demotion families (§2.2 "two or more → LOW"), and
	// validate (V3) recomputes the band that way. A bare cap left PID-only
	// reparent edges at MEDIUM with D2+D3 recorded, which validate then
	// rejected, failing the whole timeline (re-audit R1).
	edge.Confidence = capBand(edge.Confidence, edge.Demotions)
	return edge
}

// isAncestor reports whether ancestor reaches id through Causal-layer edges.
func isAncestor(g *Graph, ancestor, id EventID) bool {
	if ancestor == id {
		return true
	}
	visited := map[EventID]bool{ancestor: true}
	stack := []EventID{ancestor}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, edge := range g.causalOut[current] {
			next := g.Edges[edge].To
			if next == id {
				return true
			}
			if !visited[next] {
				visited[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := map[string]bool{}
	out := values[:0]
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
