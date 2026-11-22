package incident

import (
	"bytes"
	"fmt"
	"sort"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
)

// richSnapshot is a deliberately busy but policy-safe sample: the fields a
// real recorder emits for a small watched tree plus host sensors. names,
// addresses and paths are present locally and are replaced on export, so the
// measurement includes growth that survives redaction.
func richSnapshot(at time.Time, n int) collector.Snapshot {
	system := &collector.SystemSnapshot{
		LoadAvailable: true, CPUAvailable: true, CPUPercentAvailable: true,
		MemoryStatsAvailable: true, DiskStatsAvailable: true, ProcessCountAvailable: true,
		LoadAverage: 1.5 + float64(n%7)/10, CPUCount: 8, CPUPercent: float64(10 + n%70),
		MemoryTotal: 16 << 30, MemoryUsed: 9 << 30, MemoryFree: 1 << 30,
		MemoryAvailable: 7 << 30, MemoryBuffers: 128 << 20, MemoryCached: 2 << 30,
		SwapTotal: 4 << 30, SwapFree: 4 << 30,
		DiskFilesystem: "/", DiskAvailable: 300 << 30, DiskFree: 300 << 30,
		DiskTotal: 500 << 30, DiskUsed: 200 << 30, ProcessCount: 180 + n%20,
	}
	var processes []collector.ProcessSnapshot
	for p := 0; p < 12; p++ {
		if (n+p)%17 == 0 {
			continue
		}
		state := "S"
		switch {
		case (n+p)%11 == 0:
			state = "R"
		case (n+p)%29 == 0:
			state = "T"
		}
		processes = append(processes, collector.ProcessSnapshot{
			Process: platform.Process{
				PID: 1000 + p, PPID: 999, PGID: 999, SID: 999,
				Name: fmt.Sprintf("worker-%d", p), State: state, Threads: 2 + p%4,
				RSSBytes: uint64(8<<20 + (n+p)%16<<20), CPUTicks: uint64(n * (p + 1)),
				StartTicks: int64(5000 + p),
			},
			CPUPercent: float64((n + p) % 90),
			OpenFDs:    6 + (n+p)%10,
			Cgroup:     &platform.CgroupSnapshot{MemoryCurrentAvailable: true, MemoryMaxAvailable: true, CPUAvailable: true, Path: "/system.slice/worker.slice", MemoryCurrent: 8 << 20, MemoryMax: 64 << 20, CPUMax: "200000 100000"},
		})
	}
	var connections []collector.ConnectionSnapshot
	for c := 0; c < 8; c++ {
		if (n+c)%23 == 0 {
			continue
		}
		connections = append(connections, collector.ConnectionSnapshot{
			LocalAddr:  fmt.Sprintf("10.0.1.%d", c+1),
			LocalPort:  uint16(40000 + n%1000),
			RemoteAddr: fmt.Sprintf("10.0.2.%d", c+1),
			RemotePort: 443,
			State:      "ESTABLISHED",
			Inode:      uint64(90000 + c),
			PID:        1000 + c,
			FD:         10 + c,
		})
	}
	return collector.Snapshot{
		Timestamp:   at,
		System:      system,
		Pressure:    map[platform.Resource]platform.PressureSnapshot{platform.PressureCPU: {HasSome: true, Some: platform.Pressure{TotalMicros: uint64(n), Avg10: 1.5}, HasFull: true, Full: platform.Pressure{TotalMicros: uint64(n), Avg10: 0.5}}},
		Cgroup:      &platform.CgroupSnapshot{MemoryCurrentAvailable: true, MemoryMaxAvailable: true, CPUAvailable: true, Path: "/user.slice/agent.slice", MemoryCurrent: 12 << 20, MemoryMax: 512 << 20, CPUMax: "max 100000"},
		Processes:   processes,
		Connections: connections,
		Metrics:     []collector.CollectorTiming{{Name: "system"}, {Name: "processes"}, {Name: "connections"}},
	}
}

// richIncident is a valid 120-second incident for the default 90s/30s window.
func richIncident() *Incident {
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	i := &Incident{
		SchemaVersion: SchemaVersion,
		ID:            "inc_0123456789abcdef0123456789abcdef",
		CreatedAt:     start.Add(121 * time.Second),
		TriggeredAt:   start.Add(90 * time.Second),
		CaptureStart:  start,
		CaptureEnd:    start.Add(120 * time.Second),
		Window:        DefaultWindow(),
		Trigger:       Trigger{Type: "manual"},
		Metadata:      Metadata{AgentVersion: AgentVersion, Host: LocalHost()},
	}
	var differ Differ
	for n := 0; n < 120; n++ {
		snapshot := richSnapshot(start.Add(time.Duration(n)*time.Second), n)
		i.Events = append(i.Events, differ.Observe(snapshot)...)
		i.Snapshots = append(i.Snapshots, snapshot)
	}
	i.Events = append(i.Events, Event{Timestamp: i.TriggeredAt, Type: IncidentTriggered})
	sort.SliceStable(i.Events, func(a, b int) bool { return i.Events[a].Timestamp.Before(i.Events[b].Timestamp) })
	return i
}

func TestRepresentativeBundleSize(t *testing.T) {
	i := richIncident()
	plain := encoded(t, i, false)
	compressed := encoded(t, i, true)
	t.Logf("representative_bundle samples=%d events=%d store_bytes=%d deflate_bytes=%d ratio=%.2f",
		len(i.Snapshots), len(i.Events), len(plain), len(compressed), float64(len(plain))/float64(len(compressed)))
	if len(compressed) >= len(plain) {
		t.Fatalf("deflate %d did not beat store %d", len(compressed), len(plain))
	}
	if len(compressed) > 8<<20 {
		t.Fatalf("representative bundle unexpectedly large: %d bytes", len(compressed))
	}
	for _, raw := range [][]byte{plain, compressed} {
		if _, err := Read(bytes.NewReader(raw), int64(len(raw))); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
}

func BenchmarkBundleEncodeRich(b *testing.B) {
	i := richIncident()
	for _, compressed := range []bool{false, true} {
		name := "store"
		if compressed {
			name = "deflate"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var out bytes.Buffer
				if err := Encode(&out, i, compressed); err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(out.Len()), "bundle-bytes")
			}
		})
	}
}

func BenchmarkBundleDecodeRich(b *testing.B) {
	i := richIncident()
	for _, compressed := range []bool{false, true} {
		name := "store"
		if compressed {
			name = "deflate"
		}
		raw := encoded(b, i, compressed)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ReportMetric(float64(len(raw)), "bundle-bytes")
			b.ResetTimer()
			for b.Loop() {
				if _, err := Read(bytes.NewReader(raw), int64(len(raw))); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
