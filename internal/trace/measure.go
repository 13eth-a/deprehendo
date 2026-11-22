package trace

// measurement primitives for the phase 6 performance budget (6.49–6.51).
//
// the numbers this file produces are what the acceptance gate asks for:
// events received, events lost, throughput, capture→receive latency and the
// tracer child's CPU/RSS. they are deliberately boring, allocation-light and
// O(1) per observation so measuring the pipeline cannot itself be the
// bottleneck (and cannot be mistaken for one).
//
// overhead honesty: the tracer-side bounded queue depth is a *rust* counter
// (trace-rs/src/transport.rs QUEUE_DEPTH); the go side never samples it, so
// it is reported as unknown rather than guessed. loss is still visible here
// because every dropped event leaves a sequence gap (6.26).

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// MaxLatencySamples bounds the latency reservoir. once full, new samples are
// counted as overflow rather than growing memory without limit: a benchmark
// must not be able to OOM the recorder it is measuring.
const MaxLatencySamples = 65536

// skewTolerance is how far "negative latency" is allowed to be clock rounding
// before it is treated as clock skew instead of noise. both sides read
// CLOCK_MONOTONIC on the same kernel (6.28), so a large negative value means
// the anchor pair was sampled inconsistently (or one side used wall time).
const skewTolerance = 5 * time.Millisecond

// LatencyStats samples capture→receive latency, in nanoseconds.
type LatencyStats struct {
	samples  []int64
	Overflow uint64
	Skewed   uint64
}

// observe records one non-negative latency sample.
func (s *LatencyStats) Observe(ns int64) {
	if ns < 0 {
		// A negative observation is not a fast event; it is a broken clock
		// relationship. count it so a skew regression is visible instead of
		// silently clamped into a flattering p99.
		s.Skewed++
		return
	}
	if len(s.samples) >= MaxLatencySamples {
		s.Overflow++
		return
	}
	s.samples = append(s.samples, ns)
}

// ObserveDuration is the time.Duration form.
func (s *LatencyStats) ObserveDuration(d time.Duration) { s.Observe(int64(d)) }

// count reports how many samples were retained.
func (s *LatencyStats) Count() int { return len(s.samples) }

// reset drops the reservoir and the skew/overflow counters.
func (s *LatencyStats) Reset() {
	s.samples = nil
	s.Overflow = 0
	s.Skewed = 0
}

// LatencySummary is an immutable percentile snapshot.
type LatencySummary struct {
	Count    int
	Overflow uint64
	Skewed   uint64
	Min      time.Duration
	Max      time.Duration
	P50      time.Duration
	P95      time.Duration
	P99      time.Duration
}

// summary sorts a copy of the reservoir and computes nearest-rank
// percentiles. it is O(n log n) and is meant for report time, not per event.
func (s *LatencyStats) Summary() LatencySummary {
	out := LatencySummary{Count: len(s.samples), Overflow: s.Overflow, Skewed: s.Skewed}
	if len(s.samples) == 0 {
		return out
	}
	sorted := append([]int64(nil), s.samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	out.Min = time.Duration(sorted[0])
	out.Max = time.Duration(sorted[len(sorted)-1])
	out.P50 = nearestRank(sorted, 0.50)
	out.P95 = nearestRank(sorted, 0.95)
	out.P99 = nearestRank(sorted, 0.99)
	return out
}

func nearestRank(sorted []int64, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return time.Duration(sorted[rank])
}

// string renders the percentile line used by reports and test logs.
func (s LatencySummary) String() string {
	return fmt.Sprintf("p50=%s p95=%s p99=%s max=%s n=%d skewed=%d overflow=%d",
		s.P50.Round(time.Microsecond), s.P95.Round(time.Microsecond),
		s.P99.Round(time.Microsecond), s.Max.Round(time.Microsecond),
		s.Count, s.Skewed, s.Overflow)
}

// latency estimates how long one event took from capture (the tracer's
// CLOCK_MONOTONIC reading) to receipt here, using the handshake anchor pair
// as the clock relationship (6.28). it returns ok=false when the sample
// cannot be interpreted: no monotonic reading, or a negative interval well
// beyond rounding, which means the anchor is wrong and the sample must not be
// averaged into the budget.
func (s *Session) Latency(e TraceEvent, now time.Time) (time.Duration, bool) {
	if e.MonotonicNs <= 0 {
		return 0, false
	}
	// ClockOffsetNs is agent-wall minus tracer-monotonic at the handshake
	// anchor, so adding it maps a tracer monotonic reading onto the agent's
	// wall clock at capture time.
	visible := e.MonotonicNs + s.ClockOffsetNs
	d := now.UnixNano() - visible
	if d < 0 {
		if -d <= int64(skewTolerance) {
			return 0, true
		}
		return 0, false
	}
	return time.Duration(d), true
}

// throughput accounts for one event stream: received count, sequence-gap
// loss, restarts and the observation window (6.25/6.26).
type Throughput struct {
	Received uint64
	Lost     uint64
	Gaps     uint64
	PeakGap  uint64
	Restarts uint64
	First    time.Time
	Last     time.Time

	lastSeq uint64
}

// observe records one received event at wall time at.
func (t *Throughput) Observe(e TraceEvent, at time.Time) {
	if t.First.IsZero() {
		t.First = at
	}
	t.Last = at
	t.Received++
	switch {
	case t.lastSeq == 0:
		// first event of the stream: any starting sequence is fine.
	case e.Sequence > t.lastSeq+1:
		gap := e.Sequence - t.lastSeq - 1
		t.Gaps++
		t.Lost += gap
		if gap > t.PeakGap {
			t.PeakGap = gap
		}
	case e.Sequence <= t.lastSeq:
		// sequence restarts at every handshake (a new tracer session). A
		// same-session duplicate is a peer bug but is still only counted,
		// never fatal to the recorder.
		t.Restarts++
	}
	t.lastSeq = e.Sequence
}

// duration is the observation window.
func (t *Throughput) Duration() time.Duration {
	if t.First.IsZero() || t.Last.Before(t.First) {
		return 0
	}
	return t.Last.Sub(t.First)
}

// EventsPerSecond is the mean received rate over the window.
func (t *Throughput) EventsPerSecond() float64 {
	d := t.Duration()
	if d <= 0 {
		return 0
	}
	return float64(t.Received) / d.Seconds()
}

// DropRate is lost / (received+lost). zero means "no gap was observed",
// which is weaker than "nothing was lost" (6.27).
func (t *Throughput) DropRate() float64 {
	total := t.Received + t.Lost
	if total == 0 {
		return 0
	}
	return float64(t.Lost) / float64(total)
}

// PipelineReport is one tracer measurement pass (6.49/6.50). zero CPU/RSS
// means "not measured on this platform", never "used nothing".
type PipelineReport struct {
	Name     string
	Backend  string
	Duration time.Duration
	Received uint64
	Lost     uint64
	Gaps     uint64
	PeakGap  uint64
	Restarts uint64
	Rate     float64
	Latency  LatencySummary
	CPU      time.Duration
	RSSBytes uint64
	PeakRSS  uint64
	Notes    []string
}

// lines renders the report as stable, copy-pasteable "key value" lines.
func (r PipelineReport) Lines() []string {
	lines := []string{
		fmt.Sprintf("pipeline           %s", r.Name),
		fmt.Sprintf("backend            %s", r.Backend),
		fmt.Sprintf("duration           %s", r.Duration.Round(time.Millisecond)),
		fmt.Sprintf("events received    %d", r.Received),
		fmt.Sprintf("events lost        %d (gaps=%d peak=%d)", r.Lost, r.Gaps, r.PeakGap),
		fmt.Sprintf("stream restarts    %d", r.Restarts),
		fmt.Sprintf("events/sec         %.1f", r.Rate),
		fmt.Sprintf("latency            %s", r.Latency),
	}
	if r.CPU > 0 || r.RSSBytes > 0 {
		lines = append(lines,
			fmt.Sprintf("tracer cpu         %s", r.CPU.Round(time.Millisecond)),
			fmt.Sprintf("tracer rss         %d KiB (peak %d KiB)", r.RSSBytes/1024, r.PeakRSS/1024),
		)
		if r.Duration > 0 {
			lines = append(lines, fmt.Sprintf("tracer cpu share   %.2f%%", 100*r.CPU.Seconds()/r.Duration.Seconds()))
		}
	}
	for _, note := range r.Notes {
		lines = append(lines, "note               "+note)
	}
	return lines
}

// string joins lines with newlines.
func (r PipelineReport) String() string { return strings.Join(r.Lines(), "\n") }
