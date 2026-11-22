package diagnosis

import (
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// fixture helpers. timestamps are relative to a fixed origin so every test
// is deterministic; identity semantics follow phase 1 (PID + start ticks).

var testOrigin = time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)

const memTotal = 16 << 30 // 16 GiB

func at(offset time.Duration) time.Time { return testOrigin.Add(offset) }

// validIncident returns a minimal incident passing incident.Validate, with
// room for snapshots appended by the callers.
func validIncident(t *testing.T, span, end time.Time) *incident.Incident {
	t.Helper()
	id := "inc_" + "0123456789abcdef0123456789abcdef"
	i := &incident.Incident{
		SchemaVersion: incident.SchemaVersion,
		ID:            id,
		Trigger:       incident.Trigger{Type: "manual"},
		Window:        incident.DefaultWindow(),
	}
	i.CreatedAt = end
	i.TriggeredAt = end
	i.CaptureStart = span
	i.CaptureEnd = end
	i.Metadata.AgentVersion = incident.AgentVersion
	i.Metadata.Host = incident.HostMetadata{OS: "linux", Architecture: "arm64", CPUCount: 4, MemoryTotal: memTotal}
	return i
}

// mustValid runs incident.Validate and fails the test with the reason, so
// fixture mistakes surface as fixture errors rather than engine behavior.
func mustValid(t *testing.T, i *incident.Incident) {
	t.Helper()
	if err := incident.Validate(i); err != nil {
		t.Fatalf("fixture incident invalid: %v", err)
	}
}

func systemSnapshot(timestamp time.Time, memoryUsedPercent float64, diskFreePercent float64) collector.Snapshot {
	total := uint64(memTotal)
	used := uint64(float64(total) * memoryUsedPercent / 100)
	free := uint64(float64(1<<40) * diskFreePercent / 100)
	diskTotal := uint64(1 << 40)
	return collector.Snapshot{
		Timestamp: timestamp,
		System: &collector.SystemSnapshot{
			LoadAvailable: true, CPUAvailable: true, CPUPercentAvailable: true,
			MemoryStatsAvailable: true, DiskStatsAvailable: true, ProcessCountAvailable: true,
			MemoryTotal: total, MemoryUsed: used, DiskTotal: diskTotal, DiskFree: free,
			CPUCount: 4, CPUPercent: 10,
		},
	}
}

func withProcess(s collector.Snapshot, pid int, startTicks int64, state string, cpuPercent float64) collector.Snapshot {
	s.Processes = append(s.Processes, collector.ProcessSnapshot{
		Process:    platform.Process{PID: pid, PPID: 1, PGID: pid, SID: pid, Name: "proc", State: state, StartTicks: startTicks, RSSBytes: 0, CPUTicks: 0},
		CPUPercent: cpuPercent,
		OpenFDs:    -1,
	})
	return s
}

// psiSnapshot attaches pressure readings to a snapshot.
func withPressure(s collector.Snapshot, resource platform.Resource, some, full float64) collector.Snapshot {
	if s.Pressure == nil {
		s.Pressure = map[platform.Resource]platform.PressureSnapshot{}
	}
	s.Pressure[resource] = platform.PressureSnapshot{
		HasSome: true, Some: platform.Pressure{Avg10: some},
		HasFull: full > 0, Full: platform.Pressure{Avg10: full},
	}
	return s
}

func withConnection(s collector.Snapshot, inode uint64, localPort, remotePort uint16, state string, pid int) collector.Snapshot {
	s.Connections = append(s.Connections, collector.ConnectionSnapshot{
		LocalAddr: "127.0.0.1", LocalPort: localPort,
		RemoteAddr: "203.0.113.10", RemotePort: remotePort,
		State: state, Inode: inode, PID: pid, FD: 7,
	})
	return s
}

// sampleSeries builds evenly spaced snapshots from a generator.
func sampleSeries(t *testing.T, start time.Time, count int, step time.Duration, gen func(index int) collector.Snapshot) []collector.Snapshot {
	t.Helper()
	out := make([]collector.Snapshot, 0, count)
	for index := 0; index < count; index++ {
		s := gen(index)
		s.Timestamp = start.Add(time.Duration(index) * step)
		out = append(out, s)
	}
	return out
}

func TestBandBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		band  ConfidenceBand
	}{
		{0.0, BandNone}, {0.54, BandNone}, {0.55, BandModerate},
		{0.74, BandModerate}, {0.75, BandHigh}, {0.89, BandHigh},
		{0.90, BandVeryHigh}, {1.0, BandVeryHigh},
	}
	for _, want := range cases {
		if got := BandFor(want.score); got != want.band {
			t.Errorf("BandFor(%.2f) = %s, want %s", want.score, got, want.band)
		}
	}
}

// the engine must report UNKNOWN (no matches) rather than a diagnosis when
// no signature crosses the threshold, and must anchor the report with the
// strong factual observations it did record.
func TestUnknownReportForHealthyIncident(t *testing.T) {
	end := at(60 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, 5*time.Second, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s.Timestamp = at(time.Duration(index) * 5 * time.Second)
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !report.Unknown {
		t.Errorf("expected UNKNOWN report, got %d matches", len(report.Matches))
	}
	if len(report.StrongObservations) != 0 {
		t.Errorf("healthy fixture produced strong observations: %v", report.StrongObservations)
	}
	if report.MinConfidence != DefaultMinConfidence {
		t.Errorf("default threshold not applied: %v", report.MinConfidence)
	}
}

// determinism: the same incident must always produce an identical report.
func TestDeterministicOutput(t *testing.T) {
	end := at(60 * time.Second)
	build := func() *incident.Incident {
		i := validIncident(t, at(0), end)
		i.Snapshots = sampleSeries(t, at(0), 12, 5*time.Second, func(index int) collector.Snapshot {
			s := systemSnapshot(at(0), 50, 80)
			if index%2 == 0 {
				s = withProcess(s, 100, 1000, "S", 0)
			} else {
				s = withProcess(s, 100, 1000, "S", 0)
				s = withProcess(s, 200, 2000, "R", 150)
			}
			s.Timestamp = at(time.Duration(index) * 5 * time.Second)
			return s
		})
		mustValid(t, i)
		return i
	}
	first, err := Analyze(build(), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for round := 0; round < 20; round++ {
		next, err := Analyze(build(), Options{})
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
		if len(first.Matches) != len(next.Matches) {
			t.Fatalf("run %d: match count changed: %d vs %d", round, len(first.Matches), len(next.Matches))
		}
		for index := range first.Matches {
			if first.Matches[index].SignatureID != next.Matches[index].SignatureID || first.Matches[index].Confidence != next.Matches[index].Confidence {
				t.Fatalf("run %d: report changed at %d: %v vs %v", round, index, first.Matches[index], next.Matches[index])
			}
		}
	}
}
