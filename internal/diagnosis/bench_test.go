package diagnosis

import (
	"fmt"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// benchmarkIncident builds a deterministic incident of the requested shape.
// identity is PID + start ticks; every snapshot repeats the same stable
// identities so metadata stays bounded and the record budget is respected.
// CPU and TCP states alternate to exercise sustained-run and transition scans
// rather than trivially quiet data.
func benchmarkIncident(t testing.TB, snapshots, processes, connections int) *incident.Incident {
	t.Helper()
	end := at(time.Duration(snapshots) * time.Second)
	i := &incident.Incident{
		SchemaVersion: incident.SchemaVersion,
		ID:            fmt.Sprintf("inc_%032x", 0xbe0c),
		CreatedAt:     end,
		TriggeredAt:   end,
		CaptureStart:  at(0),
		CaptureEnd:    end,
		Window:        incident.CaptureWindow{PreTrigger: end.Sub(at(0)), PostTrigger: 0},
		Trigger:       incident.Trigger{Type: "manual"},
		Metadata: incident.Metadata{
			AgentVersion: incident.AgentVersion,
			Host:         incident.HostMetadata{OS: "linux", Architecture: "arm64", CPUCount: 4, MemoryTotal: memTotal},
		},
	}
	i.Snapshots = make([]collector.Snapshot, 0, snapshots)
	for index := 0; index < snapshots; index++ {
		at := at(time.Duration(index) * time.Second)
		memory := 40.0
		if index%3 == 0 {
			memory = 70
		}
		s := systemSnapshot(at, memory, 60)
		s.Timestamp = at
		s = withPressure(s, platform.PressureIO, float64(index%12), 1)
		for pid := 1; pid <= processes; pid++ {
			state := "S"
			cpu := 0.0
			switch pid % 5 {
			case 0:
				state = "R"
				cpu = 120
			case 1:
				state = "T"
			}
			s.Processes = append(s.Processes, collector.ProcessSnapshot{
				Process: platform.Process{
					PID: 1000 + pid, PPID: 1, PGID: 1000 + pid%4, SID: 1,
					Name: "worker", State: state, Threads: 2, RSSBytes: uint64(pid) << 20,
					CPUTicks:   uint64(index * (pid % 3)),
					StartTicks: int64(1000 + pid),
				},
				CPUPercent: cpu,
				OpenFDs:    4,
			})
		}
		for slot := 0; slot < connections; slot++ {
			state := "ESTABLISHED"
			if (index+slot)%7 == 0 {
				state = "CLOSE_WAIT"
			}
			s.Connections = append(s.Connections, collector.ConnectionSnapshot{
				LocalAddr: "127.0.0.1", LocalPort: uint16(30000 + slot),
				RemoteAddr: "203.0.113.10", RemotePort: uint16(8000 + slot%3),
				State: state, Inode: uint64(10 + slot), PID: 1000 + slot%processes, FD: slot + 3,
			})
		}
		i.Snapshots = append(i.Snapshots, s)
	}
	if err := incident.Validate(i); err != nil {
		t.Fatalf("benchmark incident invalid: %v", err)
	}
	return i
}

func benchmarkAnalyze(b *testing.B, snapshots, processes, connections int) {
	b.Helper()
	i := benchmarkIncident(b, snapshots, processes, connections)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		report, err := Analyze(i, Options{})
		if err != nil {
			b.Fatal(err)
		}
		if report == nil {
			b.Fatal("nil report")
		}
	}
}

// small: a two-minute capture with a single watched process group.
func BenchmarkAnalyzeSmall(b *testing.B) { benchmarkAnalyze(b, 60, 20, 5) }

// medium: a ten-minute capture with a runner-sized process table.
func BenchmarkAnalyzeMedium(b *testing.B) { benchmarkAnalyze(b, 300, 80, 20) }

// large: near the v1 evidence record budget, to expose accidental quadratic
// scans in signatures.
func BenchmarkAnalyzeLarge(b *testing.B) { benchmarkAnalyze(b, 800, 200, 60) }

// BenchmarkBuildContext isolates feature extraction from signature scoring.
func BenchmarkBuildContextLarge(b *testing.B) {
	i := benchmarkIncident(b, 800, 200, 60)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if ctx := buildContext(i); ctx == nil {
			b.Fatal("nil context")
		}
	}
}
