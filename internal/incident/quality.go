package incident

import (
	"strconv"
)

// Evidence-quality reporting (6.32/6.61/6.62).
//
// quality is scoped to a claim, so this file only names the classes and
// aggregates them for one claim. it never ranks two unrelated facts against
// each other: a kernel trace event says nothing about a provider's job state,
// and a provider's log says nothing about who sent a signal.

// quality is the strongest class of evidence behind one premise (contract
// §9.2). values are stable strings: they appear in reports, and a stored
// report must keep meaning what it meant.
type Quality string

const (
	// QualityDirectKernel is a kernel trace event that observed the fact as
	// it happened (phase 6).
	QualityDirectKernel Quality = "DIRECT_KERNEL"
	// QualityDirectProcess is a reading taken from /proc or a cgroup file
	// about that process at that time (phase 1).
	QualityDirectProcess Quality = "DIRECT_PROCESS"
	// QualityDerivedSnapshot is inferred from the difference between two
	// snapshots: the fact happened somewhere inside an interval.
	QualityDerivedSnapshot Quality = "DERIVED_SNAPSHOT"
	// QualityProviderLog is stated in a provider's log.
	QualityProviderLog Quality = "PROVIDER_LOG"
	// QualityProviderAPI is stated by a provider's API.
	QualityProviderAPI Quality = "PROVIDER_API"
	// QualityAgent is the recorder's own observation (a trigger, a control
	// action): factual about the agent, never about the system.
	QualityAgent Quality = "AGENT"
	// QualityUnknown is the absence of a classifiable premise. unknown is
	// never promoted to any other value.
	QualityUnknown Quality = "UNKNOWN"
)

// direct reports whether the class observed the fact rather than inferring it.
func (q Quality) Direct() bool {
	switch q {
	case QualityDirectKernel, QualityDirectProcess:
		return true
	}
	return false
}

// Claim-level words used by reports (contract §10, 6.61): a claim is `direct`
// only when every necessary premise is direct.
const (
	ClaimDirect   = "direct"
	ClaimMixed    = "mixed"
	ClaimInferred = "inferred"
	ClaimUnknown  = "unknown"
)

// QualityOf classifies one recorded event. Trace-sourced events are kernel
// observations; an event corroborated by the other stream is still
// DIRECT_KERNEL (corroboration adds confidence, not class, contract §9.2);
// an event with no provenance came from the snapshot differ, so it is
// snapshot-derived. an unrecognised provenance string is UNKNOWN rather than
// a guess: the empty string is the only legacy spelling.
func QualityOf(e Event) Quality {
	switch e.Provenance {
	case ProvenanceTrace, ProvenanceTraceReplay:
		return QualityDirectKernel
	case "":
		return QualityDerivedSnapshot
	default:
		return QualityUnknown
	}
}

// QualityIndex maps the causal layer's provenance references back to the
// quality of the bundle evidence behind them. causal events cite the bundle
// they were extracted from (`Provenance.Sources{Kind, Ref}`), so the index is
// the bridge between the report's chain and the incident's sources without
// either package importing the other.
type QualityIndex struct {
	byRef map[string]Quality
}

// NewQualityIndex classifies every addressable source in the bundle:
//
//	event:<n>      recorded event n (rust_trace → DIRECT_KERNEL)
//	snapshot:<n>   snapshot n (DERIVED_SNAPSHOT)
//	trigger        the recorder's own trigger (AGENT)
//
// an out-of-range or unparsable ref stays unknown at lookup time; the index
// never guesses.
func NewQualityIndex(i *Incident) *QualityIndex {
	index := &QualityIndex{byRef: make(map[string]Quality)}
	if i == nil {
		return index
	}
	for n := range i.Events {
		index.byRef["event:"+strconv.Itoa(n)] = QualityOf(i.Events[n])
	}
	for n := range i.Snapshots {
		index.byRef["snapshot:"+strconv.Itoa(n)] = QualityDerivedSnapshot
	}
	index.byRef["trigger:incident"] = QualityAgent
	return index
}

// lookup resolves one provenance source. unknown kinds and refs report false
// with UNKNOWN as the value, so a caller that ignores the flag still cannot
// read an empty string as a class.
func (x *QualityIndex) Lookup(kind, ref string) (Quality, bool) {
	if x == nil || x.byRef == nil {
		return QualityUnknown, false
	}
	quality, ok := x.byRef[kind+":"+ref]
	if !ok {
		return QualityUnknown, false
	}
	return quality, true
}

// weaker returns the weaker of two premises' evidence classes, ordered only
// by directness (§9.2): a direct premise is worth no more than the weakest
// other premise it supports, and an UNKNOWN drains the comparison to
// UNKNOWN.
// Multi-source events use this so a fact is never stronger than the worst
// thing it cites.
func Weaker(a, b Quality) Quality {
	if a == QualityUnknown || b == QualityUnknown {
		return QualityUnknown
	}
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if a.Direct() && !b.Direct() {
		return b
	}
	return a
}

// aggregate reduces the qualities of one claim's necessary premises to the
// report vocabulary. the rules follow contract §9.2: every premise direct →
// "direct"; no premise direct → "inferred"; a mix → "mixed"; any premise
// whose class is unknown → "unknown", because a claim is never stronger than
// the weakest thing it rests on.
func Aggregate(qualities []Quality) string {
	if len(qualities) == 0 {
		return ClaimUnknown
	}
	direct, unknown := 0, 0
	for _, q := range qualities {
		switch {
		case q == QualityUnknown:
			unknown++
		case q.Direct():
			direct++
		}
	}
	switch {
	case unknown > 0:
		return ClaimUnknown
	case direct == len(qualities):
		return ClaimDirect
	case direct == 0:
		return ClaimInferred
	default:
		return ClaimMixed
	}
}
