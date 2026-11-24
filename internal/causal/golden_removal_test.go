package causal

import (
	"os"
	"testing"
	"time"
)

// goldenGraph builds and applies the rules over events with a fixed origin,
// mirroring the fixture path, so removals are compared on identical engine
// settings.
func goldenGraph(t *testing.T, events []Event, origin time.Time) *Graph {
	t.Helper()
	cp := append([]Event(nil), events...)
	sortEvents(cp)
	assignIDs(cp)
	for i := range cp {
		cp[i].Sequence = uint64(i)
	}
	g := NewGraph(&Timeline{Events: cp, Origin: origin})
	if _, err := NewEngine(Rules(), origin).Apply(g, nil); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("graph invalid: %v", err)
	}
	return g
}

// edgeBands maps rule|fromType|toType to the highest band of that edge.
func edgeBands(g *Graph) map[string]int {
	out := map[string]int{}
	for _, edge := range g.Edges {
		from, to := g.Get(edge.From), g.Get(edge.To)
		if from == nil || to == nil {
			continue
		}
		key := edge.RuleID + "|" + string(from.Type) + "|" + string(to.Type)
		if w := bandWeight(edge.Confidence); w > out[key] {
			out[key] = w
		}
	}
	return out
}

// chainBands maps each candidate cause type to its highest chain band.
func chainBands(g *Graph) map[EventType]int {
	out := map[EventType]int{}
	for _, analysis := range g.FailureAnalyses() {
		for _, cand := range analysis.Candidates {
			ev := g.Get(cand.Event)
			if ev == nil {
				continue
			}
			if w := bandWeight(cand.Confidence); w > out[ev.Type] {
				out[ev.Type] = w
			}
		}
	}
	return out
}

// TestGoldenFixtureRemovalNeverStrengthens is the 4.37 property test: removing
// any single event from a golden fixture must never raise an edge band, a
// chain band, or an anchor status. every event is tried, which covers every
// PRESENT evidence event. absent keys count as zero, so a newly created claim
// is also a strengthening.
func TestGoldenFixtureRemovalNeverStrengthens(t *testing.T) {
	for _, fixture := range causalFixtures() {
		if fixture.Class != "GOLDEN" {
			continue
		}
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			if fixture.Gate != "" && os.Getenv("DEPREHENDO_REVIEW_AUDIT") == "" {
				t.Skip("gated fixture (set DEPREHENDO_REVIEW_AUDIT=1 to run)")
			}
			if fixture.Mode == "events" {
				t.Skip("events-mode fixture: no bundle timeline to vary")
			}
			timeline := BuildTimeline(loadCausalFixture(t, fixture.Name))
			base := goldenGraph(t, timeline.Events, timeline.Origin)
			basebands := edgeBands(base)
			basechains := chainBands(base)
			baseanchors := map[EventType]FailureStatus{}
			for _, analysis := range base.FailureAnalyses() {
				baseanchors[analysis.AnchorType] = analysis.Status
			}
			// A golden fixture may legitimately conclude nothing (socket-stall and
			// network-failure expect no edges). that is not vacuous: a removal that
			// creates a claim is still flagged against the empty base.

			for i, removed := range timeline.Events {
				rest := append(append([]Event(nil), timeline.Events[:i]...), timeline.Events[i+1:]...)
				g := goldenGraph(t, rest, timeline.Origin)
				for key, w := range edgeBands(g) {
					if w > basebands[key] {
						t.Errorf("removing %s raised edge %s to weight %d", removed.Type, key, w)
					}
				}
				for cause, w := range chainBands(g) {
					if w > basechains[cause] {
						t.Errorf("removing %s raised chain band for %s to weight %d", removed.Type, cause, w)
					}
				}
				for _, analysis := range g.FailureAnalyses() {
					if statusRank(analysis.Status) > statusRank(baseanchors[analysis.AnchorType]) {
						t.Errorf("removing %s strengthened anchor %s to %s", removed.Type, analysis.AnchorType, analysis.Status)
					}
				}
			}
		})
	}
}
