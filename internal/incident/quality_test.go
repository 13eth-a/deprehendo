package incident

import (
	"testing"

	"deprehendo/internal/collector"
)

// TestQualityOfClassifiesProvenance pins the mapping from recorded provenance
// to evidence class (6.32). the interesting cases are the two that must never
// be promoted: an unknown provenance string and an empty one.
func TestQualityOfClassifiesProvenance(t *testing.T) {
	cases := []struct {
		event Event
		want  Quality
	}{
		{Event{Provenance: ProvenanceTrace}, QualityDirectKernel},
		{Event{Provenance: ProvenanceTraceReplay}, QualityDirectKernel},
		{Event{}, QualityDerivedSnapshot},
		{Event{Provenance: "made_up_source"}, QualityUnknown},
	}
	for _, c := range cases {
		if got := QualityOf(c.event); got != c.want {
			t.Errorf("QualityOf(%+v) = %q, want %q", c.event, got, c.want)
		}
	}
	// corroboration is confidence, not class: a merged kernel event stays
	// DIRECT_KERNEL (contract §9.2).
	merged := Event{Provenance: ProvenanceTrace, CorroboratedBy: []string{ProvenanceSnapshotDiff}}
	if got := QualityOf(merged); got != QualityDirectKernel {
		t.Errorf("corroborated trace event = %q", got)
	}
}

// TestQualityIndexResolvesCausalRefs pins the key format the causal layer
// cites, so a rename on either side fails here instead of silently degrading
// every direct claim to unknown.
func TestQualityIndexResolvesCausalRefs(t *testing.T) {
	inc := &Incident{
		Events: []Event{
			{Type: TraceProcessExit, Provenance: ProvenanceTrace, PID: 42},
			{Type: ProcessExited, PID: 43},
		},
		Snapshots: []collector.Snapshot{{}, {}},
	}
	index := NewQualityIndex(inc)
	cases := []struct {
		kind, ref string
		want      Quality
		ok        bool
	}{
		{"event", "0", QualityDirectKernel, true},
		{"event", "1", QualityDerivedSnapshot, true},
		{"snapshot", "1", QualityDerivedSnapshot, true},
		{"trigger", "incident", QualityAgent, true},
		{"event", "2", QualityUnknown, false},    // out of range: never guessed
		{"snapshot", "9", QualityUnknown, false}, // out of range
		{"provider", "0", QualityUnknown, false}, // no provider class by ref
		{"", "", QualityUnknown, false},
	}
	for _, c := range cases {
		got, ok := index.Lookup(c.kind, c.ref)
		if ok != c.ok || got != c.want {
			t.Errorf("Lookup(%q,%q) = %q,%v want %q,%v", c.kind, c.ref, got, ok, c.want, c.ok)
		}
	}
	// A nil index is a valid "no bundle" state, not a panic.
	var empty *QualityIndex
	if _, ok := empty.Lookup("event", "0"); ok {
		t.Error("nil index claimed a source")
	}
	if index := NewQualityIndex(nil); index == nil {
		t.Error("nil incident produced a nil index")
	}
}

// TestAggregateWeakestPremise is the §9.2 rule made executable: a claim is
// direct only when every necessary premise is direct, and unknown never
// becomes a positive class.
func TestAggregateWeakestPremise(t *testing.T) {
	cases := []struct {
		name  string
		input []Quality
		want  string
	}{
		{"nothing cited", nil, ClaimUnknown},
		{"all kernel", []Quality{QualityDirectKernel, QualityDirectKernel}, ClaimDirect},
		{"kernel and process", []Quality{QualityDirectKernel, QualityDirectProcess}, ClaimDirect},
		{"kernel and snapshot", []Quality{QualityDirectKernel, QualityDerivedSnapshot}, ClaimMixed},
		{"snapshots only", []Quality{QualityDerivedSnapshot, QualityDerivedSnapshot}, ClaimInferred},
		{"provider only", []Quality{QualityProviderLog}, ClaimInferred},
		{"one unknown", []Quality{QualityDirectKernel, QualityUnknown}, ClaimUnknown},
		{"agent action", []Quality{QualityAgent}, ClaimInferred},
	}
	for _, c := range cases {
		if got := Aggregate(c.input); got != c.want {
			t.Errorf("%s: Aggregate(%v) = %q, want %q", c.name, c.input, got, c.want)
		}
	}
}

// TestQualityDirectVocabulary keeps the report words honest: only the two
// observation classes may report as direct.
func TestQualityDirectVocabulary(t *testing.T) {
	for _, q := range []Quality{QualityDirectKernel, QualityDirectProcess} {
		if !q.Direct() {
			t.Errorf("%q is not Direct", q)
		}
	}
	for _, q := range []Quality{QualityDerivedSnapshot, QualityProviderLog, QualityProviderAPI, QualityAgent, QualityUnknown} {
		if q.Direct() {
			t.Errorf("%q claims to be direct", q)
		}
	}
}
