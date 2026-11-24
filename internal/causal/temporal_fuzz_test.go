package causal

// temporal fuzzing (4.38). the causal engine must stay sane under the timing
// damage real captures suffer: jittered samples, equal timestamps, missing
// events, duplicated samples, sampling gaps, and process churn. these tests
// assert invariants (stable IDs, canonical order, acyclic validated graph,
// deterministic output, no fabricated claims) rather than one expected story,
// because there is no single correct chain for damaged evidence.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

const fuzzSpan = 120 * time.Second

// fuzzTemplate is a busy but valid capture: two memory episodes, connection
// churn, process state changes, coordinated exits, and a manual trigger.
func fuzzTemplate() *incident.Incident {
	inc := fxIncident("temporal-fuzz", fuzzSpan, 110*time.Second, "manual")
	states := []string{"S", "S", "R", "T", "T", "S"}
	for index := 0; index < 24; index++ {
		memory := 40 + float64((index*7)%45)
		if index >= 8 && index < 14 {
			memory = 91 + float64(index%7)
		}
		s := collector.Snapshot{System: fxSystem(memory, 40+float64(index%30))}
		s.Processes = []collector.ProcessSnapshot{
			fxProcess(500, 1, 500, 900, states[index%len(states)], float64(10+(index%5)*30)),
			fxProcess(501, 1, 500, 901, "S", 0),
		}
		s.Timestamp = fxTime(time.Duration(index) * 5 * time.Second)
		inc.Snapshots = append(inc.Snapshots, s)
	}
	inc.Metadata.Processes = []incident.ProcessMetadata{
		fxProcessMetadata(500, 1, 500, 900),
		fxProcessMetadata(501, 1, 500, 901),
	}
	inc.Events = []incident.Event{
		{Timestamp: fxTime(5 * time.Second), Type: incident.ConnectionOpened, Connection: fxConnection(77001, "ESTABLISHED", 500)},
		{Timestamp: fxTime(42 * time.Second), Type: incident.ProcessExited, PID: 501, StartTicks: 901},
		{Timestamp: fxTime(43 * time.Second), Type: incident.ProcessExited, PID: 502, StartTicks: 902},
		{Timestamp: fxTime(70 * time.Second), Type: incident.ConnectionClosed, Connection: fxConnection(77001, "CLOSE_WAIT", 500)},
	}
	return inc
}

// factOf strips storage-only fields: the content-addressed ID, the bundle
// position provenance refers to, and the derived sequence. two recordings of
// the same fact are the same evidence wherever they sat in the array.
func factOf(event Event) Event {
	event.ID = ""
	event.Sequence = 0
	event.Provenance = EventProvenance{}
	return event
}

// canonicalOrderHolds checks the deterministic tuple order while treating
// identical duplicate facts as unordered: they have no observable difference.
func canonicalOrderHolds(events []Event) bool {
	facts := make([]Event, len(events))
	for index := range events {
		facts[index] = factOf(events[index])
	}
	return sort.SliceIsSorted(facts, func(a, b int) bool { return lessEvent(facts[a], facts[b]) })
}

func fuzzAnalyze(t *testing.T, inc *incident.Incident) (*Timeline, *Graph) {
	t.Helper()
	timeline := BuildTimeline(inc)
	graph := NewGraph(timeline)
	if _, err := NewEngine(Rules(), timeline.Origin).Apply(graph, nil); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	return timeline, graph
}

// fuzzInvariants is the property set every damaged timeline must satisfy.
func fuzzInvariants(t *testing.T, label string, inc *incident.Incident) {
	t.Helper()
	timeline, graph := fuzzAnalyze(t, inc)
	if err := graph.Validate(); err != nil {
		t.Fatalf("%s: graph invalid: %v", label, err)
	}
	if len(timeline.Events) != graph.Count() {
		t.Fatalf("%s: timeline has %d events, graph has %d", label, len(timeline.Events), graph.Count())
	}
	ids := map[EventID]bool{}
	for index, event := range timeline.Events {
		if ids[event.ID] {
			t.Fatalf("%s: duplicate event ID %s", label, event.ID)
		}
		ids[event.ID] = true
		if event.Sequence != uint64(index) {
			t.Fatalf("%s: event %d has sequence %d", label, index, event.Sequence)
		}
		if index > 0 && event.Timestamp.Before(timeline.Events[index-1].Timestamp) {
			t.Fatalf("%s: events are not in timestamp order at %d", label, index)
		}
		for _, unobservable := range unobservableEventTypes {
			if event.Type == unobservable {
				t.Fatalf("%s: fabricated unobservable event %s", label, unobservable)
			}
		}
	}
	if !canonicalOrderHolds(timeline.Events) {
		t.Fatalf("%s: canonical event order is not deterministic", label)
	}
	for _, analysis := range graph.FailureAnalyses() {
		if analysis.Status == StatusExplained && len(analysis.Candidates) > 1 {
			t.Fatalf("%s: explained analysis carries competing candidates", label)
		}
		primary := 0
		for _, candidate := range analysis.Candidates {
			if candidate.Role == RolePrimary {
				primary++
			}
		}
		if primary > 1 {
			t.Fatalf("%s: anchor %s has %d PRIMARY candidates", label, analysis.AnchorType, primary)
		}
		if primary == 1 && analysis.Status == StatusUnknown {
			for _, candidate := range analysis.Candidates {
				if candidate.Role == RolePrimary && candidate.Kind != KindUnexplainedHead {
					t.Fatalf("%s: anchor %s has a PRIMARY root but UNKNOWN status", label, analysis.AnchorType)
				}
			}
		}
	}
	for _, edge := range graph.Edges {
		from, to := graph.Get(edge.From), graph.Get(edge.To)
		if edge.Relation == RelationPrecedes || edge.Relation == RelationRecoveryOf {
			if !from.Timestamp.Before(to.Timestamp) {
				t.Fatalf("%s: %s edge %s->%s lacks observed order", label, edge.Relation, from.Type, to.Type)
			}
		}
		if isCausal(edge.Relation) && to.Timestamp.Before(from.Timestamp) {
			t.Fatalf("%s: causal edge %s->%s runs backwards", label, from.Type, to.Type)
		}
	}
	// determinism: the same damaged input must produce byte-identical output.
	again, againgraph := fuzzAnalyze(t, inc)
	firstjson, err := json.Marshal([]any{timeline.Events, graph.Edges, graph.FailureAnalyses(), graph.Rejected})
	if err != nil {
		t.Fatal(err)
	}
	secondjson, err := json.Marshal([]any{again.Events, againgraph.Edges, againgraph.FailureAnalyses(), againgraph.Rejected})
	if err != nil {
		t.Fatal(err)
	}
	if string(firstjson) != string(secondjson) {
		t.Fatalf("%s: analysis is not deterministic", label)
	}
}

func TestTemporalJitterAndEqualTimestamps(t *testing.T) {
	t.Run("jitter", func(t *testing.T) {
		inc := fuzzTemplate()
		// keep samples strictly ordered while shifting each by up to 800ms.
		for index := range inc.Snapshots {
			offset := time.Duration(index%3-1) * 400 * time.Millisecond
			inc.Snapshots[index].Timestamp = inc.Snapshots[index].Timestamp.Add(offset)
		}
		for index := range inc.Events {
			inc.Events[index].Timestamp = inc.Events[index].Timestamp.Add(time.Duration(index%4) * 120 * time.Millisecond)
		}
		fuzzInvariants(t, "jitter", inc)
	})
	t.Run("equal-timestamps", func(t *testing.T) {
		inc := fuzzTemplate()
		// real bundles cannot carry equal sample timestamps, but BuildTimeline
		// must still be sane if a future schema or a hand-built incident does:
		// equal wall times carry no observed order, so no PRECEDES edge may
		// connect them and no threshold may fire twice.
		for index := range inc.Snapshots {
			if index%4 != 0 {
				inc.Snapshots[index].Timestamp = inc.Snapshots[index-1].Timestamp
			}
		}
		for index := range inc.Events {
			inc.Events[index].Timestamp = fxTime(42 * time.Second)
		}
		inc.TriggeredAt = fxTime(42 * time.Second)
		inc.CaptureEnd = fxTime(fuzzSpan)
		timeline, _ := fuzzAnalyze(t, inc)
		if got := countEvents(timeline, EventMemoryPressureStarted); got > 1 {
			t.Errorf("equal timestamps duplicated the pressure episode: %d", got)
		}
		if got := countEvents(timeline, EventMemoryLimitReached); got > 1 {
			t.Errorf("equal timestamps duplicated the limit crossing: %d", got)
		}
		fuzzInvariants(t, "equal-timestamps", inc)
	})
}

func TestTemporalMissingAndDuplicatedEvidence(t *testing.T) {
	t.Run("missing-events", func(t *testing.T) {
		inc := fuzzTemplate()
		kept := inc.Snapshots[:0]
		for index, snapshot := range inc.Snapshots {
			if index%5 == 3 {
				continue
			}
			kept = append(kept, snapshot)
		}
		inc.Snapshots = kept
		var events []incident.Event
		for index, event := range inc.Events {
			if index%3 == 1 {
				continue
			}
			events = append(events, event)
		}
		inc.Events = events
		fuzzInvariants(t, "missing-events", inc)
	})
	t.Run("duplicate-samples-and-events", func(t *testing.T) {
		inc := fuzzTemplate()
		duplicated := make([]collector.Snapshot, 0, len(inc.Snapshots)*2)
		for index, snapshot := range inc.Snapshots {
			duplicated = append(duplicated, snapshot)
			if index%4 == 0 {
				repeated := snapshot
				duplicated = append(duplicated, repeated)
			}
		}
		inc.Snapshots = duplicated
		events := make([]incident.Event, 0, len(inc.Events)*2)
		for _, event := range inc.Events {
			events = append(events, event, event)
		}
		inc.Events = events
		timeline, _ := fuzzAnalyze(t, inc)
		ids := map[EventID]bool{}
		for _, event := range timeline.Events {
			if ids[event.ID] {
				t.Fatalf("duplicate event evidence collapsed into one ID: %s", event.ID)
			}
			ids[event.ID] = true
		}
		// A duplicated sample is the same observation: episodes must not restart.
		if got := countEvents(timeline, EventMemoryPressureStarted); got > 1 {
			t.Errorf("duplicated samples restarted the pressure episode: %d", got)
		}
		fuzzInvariants(t, "duplicate-samples-and-events", inc)
	})
}

func TestTemporalSamplingGap(t *testing.T) {
	inc := fuzzTemplate()
	var gapped []collector.Snapshot
	for index, snapshot := range inc.Snapshots {
		if index >= 10 && index < 17 {
			continue // 35s observation hole, above the clock-jump threshold
		}
		gapped = append(gapped, snapshot)
	}
	inc.Snapshots = gapped
	timeline, graph := fuzzAnalyze(t, inc)
	if countEvents(timeline, EventTimelineGap) == 0 {
		t.Errorf("a 35s sampling hole did not produce TIMELINE_GAP")
	}
	// A hole is unknown telemetry: no recovery may be claimed across it.
	for _, edge := range graph.Edges {
		if edge.Relation == RelationRecoveryOf {
			t.Errorf("sampling gap produced a recovery claim: %v", edge)
		}
	}
	fuzzInvariants(t, "sampling-gap", inc)
}

// TestTemporalReorderingIsNotEvidence asserts the fact/derivation split
// (4.38 + §10.1): recorded bundle events carry their own timestamps and are
// never changed by array position, while snapshot array order IS capture
// order. a reversed array means the reverse capture order, and the backward
// steps must be DETECTED (A7), never silently re-sorted into fabricated
// history.
func TestTemporalReorderingIsNotEvidence(t *testing.T) {
	ordered := fuzzTemplate()
	shuffled := fuzzTemplate()
	// reverse both arrays: snapshot order becomes reversed capture order.
	for left, right := 0, len(shuffled.Snapshots)-1; left < right; left, right = left+1, right-1 {
		shuffled.Snapshots[left], shuffled.Snapshots[right] = shuffled.Snapshots[right], shuffled.Snapshots[left]
	}
	for left, right := 0, len(shuffled.Events)-1; left < right; left, right = left+1, right-1 {
		shuffled.Events[left], shuffled.Events[right] = shuffled.Events[right], shuffled.Events[left]
	}
	first, firstgraph := fuzzAnalyze(t, ordered)
	second, secondgraph := fuzzAnalyze(t, shuffled)
	// recorded facts (no derived RuleID) are order-invariant.
	recorded := func(tl *Timeline) []Event {
		out := make([]Event, 0, len(tl.Events))
		for _, event := range tl.Events {
			if event.Provenance.RuleID != "" {
				continue // derived event, capture-order dependent by design
			}
			out = append(out, factOf(event))
		}
		return out
	}
	a, err := json.Marshal(recorded(first))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(recorded(second))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("reversing input arrays changed the recorded facts")
	}
	// both captures stay structurally sane under either order.
	if err := firstgraph.Validate(); err != nil {
		t.Fatalf("ordered capture graph invalid: %v", err)
	}
	if err := secondgraph.Validate(); err != nil {
		t.Fatalf("reversed capture graph invalid: %v", err)
	}
	// the ordered capture observes a monotonic wall clock: no step and no
	// hole. the reversed capture MUST detect the backward steps instead of
	// silently repairing them (A7/§10.1).
	if countEvents(first, EventClockDiscontinuity) != 0 {
		t.Errorf("ordered capture detected a spurious clock step")
	}
	if countEvents(first, EventTimelineGap) != 0 {
		t.Errorf("ordered capture detected a spurious timeline gap")
	}
	if countEvents(second, EventClockDiscontinuity) == 0 {
		t.Errorf("reversed capture order was silently re-sorted into fake history (A7)")
	}
	fuzzInvariants(t, "reordered", shuffled)
}

func TestTemporalProcessChurn(t *testing.T) {
	inc := fuzzTemplate()
	// 30 processes appear, stop, resume, and exit inside the capture. only
	// recorded exits are lifecycle facts; the churn must not produce claims.
	var churn []incident.Event
	for index := 0; index < 30; index++ {
		offset := time.Duration(index) * 2 * time.Second
		churn = append(churn, incident.Event{
			Timestamp: fxTime(offset + 3*time.Second), Type: incident.ProcessExited,
			PID: 900 + index, StartTicks: int64(5000 + index),
		})
	}
	inc.Events = append(inc.Events, churn...)
	for index := range inc.Snapshots {
		s := &inc.Snapshots[index]
		s.Processes = append(s.Processes, fxProcess(1200, 1, 1200, 7000, "S", 0))
	}
	fuzzInvariants(t, "process-churn", inc)
	// churn is lifecycle noise: it must never become a causal claim about the
	// incident itself, and no churn identity may be reported as a cause.
	graph := analyzeForTest(t, inc)
	for _, edge := range graph.Edges {
		if isCausal(edge.Relation) && graph.Get(edge.To).Type == EventIncidentTriggered {
			t.Errorf("process churn produced a causal incident claim: %s->%s (%s)",
				graph.Get(edge.From).Type, graph.Get(edge.To).Type, edge.RuleID)
		}
	}
}

func analyzeForTest(t *testing.T, inc *incident.Incident) *Graph {
	t.Helper()
	_, graph := fuzzAnalyze(t, inc)
	return graph
}

// TestTemporalRandomMutations runs seeded, reproducible combinations of the
// mutations above and asserts the invariant set each time (4.38).
func TestTemporalRandomMutations(t *testing.T) {
	random := rand.New(rand.NewSource(20261027))
	for round := 0; round < 60; round++ {
		inc := fuzzTemplate()
		if random.Intn(2) == 0 {
			for index := range inc.Snapshots {
				shift := time.Duration(random.Intn(800)-400) * time.Millisecond
				inc.Snapshots[index].Timestamp = inc.Snapshots[index].Timestamp.Add(shift)
			}
		}
		if random.Intn(3) == 0 && len(inc.Snapshots) > 8 {
			drop := random.Intn(len(inc.Snapshots) / 3)
			inc.Snapshots = append(inc.Snapshots[:drop], inc.Snapshots[drop+random.Intn(3):]...)
		}
		if random.Intn(3) == 0 && len(inc.Snapshots) > 0 {
			index := random.Intn(len(inc.Snapshots))
			duplicate := inc.Snapshots[index]
			duplicate.Timestamp = duplicate.Timestamp.Add(time.Duration(random.Intn(200)) * time.Millisecond)
			inc.Snapshots = append(inc.Snapshots, duplicate)
		}
		if random.Intn(2) == 0 && len(inc.Events) > 0 {
			index := random.Intn(len(inc.Events))
			inc.Events = append(inc.Events, inc.Events[index])
		}
		if random.Intn(4) == 0 {
			for left, right := 0, len(inc.Snapshots)-1; left < right; left, right = left+1, right-1 {
				inc.Snapshots[left], inc.Snapshots[right] = inc.Snapshots[right], inc.Snapshots[left]
			}
		}
		if random.Intn(4) == 0 && len(inc.Events) > 1 {
			inc.Events[0], inc.Events[1] = inc.Events[1], inc.Events[0]
		}
		fuzzInvariants(t, fmt.Sprintf("random-mutation-%d", round), inc)
	}
}
