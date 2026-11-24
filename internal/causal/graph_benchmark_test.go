package causal

import (
	"fmt"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

func benchmarkTimeline(n int) *Timeline {
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	events := make([]Event, n)
	for i := range events {
		eventtype := EventProcessStarted
		if i%2 == 1 {
			eventtype = EventProcessExited
		}
		events[i] = Event{
			Type: eventtype, Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Subject:    processSubject(i+1, int64(i+100)),
			Provenance: EventProvenance{Sources: []ProvenanceSource{{Kind: "event", Ref: fmt.Sprint(i)}}},
		}
	}
	assignIDs(events)
	for i := range events {
		events[i].Sequence = uint64(i)
	}
	return &Timeline{Events: events, Origin: base}
}

func BenchmarkGraphEngine(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("events_%d", size), func(b *testing.B) {
			tl := benchmarkTimeline(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				g := NewGraph(tl)
				engine := NewEngine(Rules(), tl.Origin)
				if _, err := engine.Apply(g, nil); err != nil {
					b.Fatal(err)
				}
				if err := g.Validate(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchmarkIncidentSamples builds a linear-capture incident with the given
// number of one-second samples. memory and disk oscillate across their
// thresholds, so extraction emits and closes real episodes rather than
// staying in one steady state (4.41).
func benchmarkIncidentSamples(n int) *incident.Incident {
	base := time.Date(2026, time.October, 27, 12, 0, 0, 0, time.UTC)
	inc := &incident.Incident{
		CaptureStart: base,
		CaptureEnd:   base.Add(time.Duration(n) * time.Second),
	}
	for index := 0; index < n; index++ {
		memory := 40 + float64((index*17)%60)
		free := 60 - float64((index*7)%58)
		const total = uint64(16 << 30)
		const diskTotal = uint64(1 << 40)
		inc.Snapshots = append(inc.Snapshots, collector.Snapshot{
			Timestamp: base.Add(time.Duration(index) * time.Second),
			System: &collector.SystemSnapshot{
				MemoryStatsAvailable: true, DiskStatsAvailable: true, ProcessCountAvailable: true,
				MemoryTotal: total, MemoryUsed: uint64(float64(total) * memory / 100),
				DiskTotal: diskTotal, DiskFree: uint64(float64(diskTotal) * free / 100),
				DiskFilesystem: "/data", CPUCount: 4, CPUPercent: 10,
			},
		})
	}
	return inc
}

// BenchmarkTimelineBuild measures event extraction, which dominates the
// observed cost for normal incident sizes (one sample per second, windows in
// the tens to hundreds of samples).
func BenchmarkTimelineBuild(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("samples_%d", size), func(b *testing.B) {
			inc := benchmarkIncidentSamples(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if tl := BuildTimeline(inc); len(tl.Events) == 0 {
					b.Fatal("extraction produced no events")
				}
			}
		})
	}
}

// BenchmarkEndToEndAnalysis is the operator-visible path: extraction, graph
// construction, rule application, validation, and root/chain analysis.
func BenchmarkEndToEndAnalysis(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("samples_%d", size), func(b *testing.B) {
			inc := benchmarkIncidentSamples(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tl := BuildTimeline(inc)
				g := NewGraph(tl)
				if _, err := NewEngine(Rules(), tl.Origin).Apply(g, nil); err != nil {
					b.Fatal(err)
				}
				if err := g.Validate(); err != nil {
					b.Fatal(err)
				}
				g.FailureAnalyses()
				g.Chains()
			}
		})
	}
}
