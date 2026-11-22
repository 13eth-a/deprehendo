package causal

import "time"

// temporal helper predicates (4.5). they operate on facts only and never
// upgrade temporal adjacency to causality; the rule layer owns that claim.
// all helpers are SAT/stable and heavily tested.

// before reports whether a is canonically before b.
func Before(a, b *Event) bool { return lessEvent(*a, *b) }

// after reports whether a is canonically after b.
func After(a, b *Event) bool { return lessEvent(*b, *a) }

// within reports whether a and b are no more than d apart in real time.
// equal timestamps are within any non-negative duration.
func Within(a, b *Event, d time.Duration) bool {
	gap := a.Timestamp.Sub(b.Timestamp)
	if gap < 0 {
		gap = -gap
	}
	return gap <= d
}

// overlaps reports whether the events' recorded instants are indistinguishable
// at sampling resolution: strictly equal wall timestamps.
func Overlaps(a, b *Event) bool { return a.Timestamp.Equal(b.Timestamp) }

// DurationBetween is the observed time from a to b (absolute value). it is a
// sampling-resolution span, not a measurement of cause latency.
func DurationBetween(a, b *Event) time.Duration { return b.Timestamp.Sub(a.Timestamp) }

// ImmediatelyPrecedes reports whether a is before b and within threshold.
// this is the pre-condition to consider an upgrade beyond PRECEDES; the rule
// layer still has to supply evidence beyond adjacency (4.7, architecture-REVIEW).
func ImmediatelyPrecedes(a, b *Event, threshold time.Duration) bool {
	return a.Timestamp.Before(b.Timestamp) && DurationBetween(a, b) <= threshold
}

// SustainedAbove reports whether the numeric signal of the events marked
// with the given data key stayed above threshold for spans covering d.
// start/end paired events supply the span.
func SustainedAbove(start, end *Event, dataKey string, threshold float64, d time.Duration) bool {
	if !start.DurationOK || end == nil {
		return false
	}
	if value, ok := start.Data[dataKey].(float64); ok && value >= threshold {
		return end.Timestamp.Sub(start.Timestamp) >= d
	}
	return false
}

// SustainedBelow is SustainedAbove against the lower boundary.
func SustainedBelow(start, end *Event, dataKey string, threshold float64, d time.Duration) bool {
	if !start.DurationOK || end == nil {
		return false
	}
	if value, ok := start.Data[dataKey].(float64); ok && value <= threshold {
		return end.Timestamp.Sub(start.Timestamp) >= d
	}
	return false
}

// ChangedWithin reports whether b confirms an observed change no more than d
// after a. it deliberately reads only timestamps: content matching is the
// rule's job.
func ChangedWithin(a, b *Event, d time.Duration) bool {
	return ImmediatelyPrecedes(a, b, d)
}

// NoProgressFor is unobservable in v1 bundles (no byte counters or application
// progress telemetry). the helper exists so call sites encode intent instead
// of silently substituting other evidence, and always answers false: an event
// the bundle cannot observe cannot ground a claim.
func NoProgressFor(*Event, time.Duration) bool { return false }

// canonIndex gives each event its position in the normalized order; the
// O(1) index lives on graph (graph.go).
