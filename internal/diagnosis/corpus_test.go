package diagnosis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

// the synthetic phase 3 corpus (3.29/3.43). every case is built from the same
// snapshot model the recorder writes, then encoded as a real v1 bundle with an
// out-of-band ground-truth sidecar. fixtures are checked in so confusion-matrix
// runs and the evaluate command do not depend on generating them first; this
// test file is the source of truth. regenerate with:
//
//	DEPREHENDO_WRITE_FIXTURES=1 go test ./internal/diagnosis -run TestWriteIncidentCorpus
//
// the fixtures are deliberately synthetic. they exercise signature logic, not
// the accuracy of live capture: for example socket RX progress and kernel OOM
// events do not exist in the v1 format, and several fixtures are constructed to
// be indistinguishable from a healthy workload. watching a process or manually
// triggering capture does not establish an anomaly; these faults remain UNKNOWN
// without the required discriminating telemetry. ground truth keeps fault labels.

type corpusCase struct {
	Name     string
	Incident *incident.Incident
	Truth    GroundTruth
}

const corpusDir = "../../testdata/incidents"

func corpusIncident(t *testing.T, id int, end time.Time, trigger incident.Trigger) *incident.Incident {
	t.Helper()
	i := validIncident(t, at(0), end)
	i.ID = fmt.Sprintf("inc_%032x", id)
	i.Trigger = trigger
	i.Metadata.Processes = nil
	return i
}

// series stamps generated snapshots at a fixed step from the capture start.
func series(t *testing.T, end time.Time, step time.Duration, gen func(index int) collector.Snapshot) []collector.Snapshot {
	t.Helper()
	count := int(end.Sub(at(0))/step) + 1
	return sampleSeries(t, at(0), count, step, gen)
}

func withChild(s collector.Snapshot, pid int, startTicks int64, parentPID int, state string) collector.Snapshot {
	return withProcessAddr(s, pid, startTicks, parentPID, state, 0)
}

func corpusCases(t *testing.T) []corpusCase {
	t.Helper()
	const five = 5 * time.Second
	var cases []corpusCase

	// 1. OOM: memory hits 96% and a 6 GiB process disappears, never returns.
	end := at(75 * time.Second)
	oom := corpusIncident(t, 1, end, incident.Trigger{Type: "manual"})
	oom.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		memory := 50.0
		if index >= 6 {
			memory = 96
		}
		s := systemSnapshot(at(0), memory, 80)
		if index <= 5 {
			s = withProcess(s, 500, 500, "S", 0)
			s.Processes[len(s.Processes)-1].RSSBytes = 6 << 30
		}
		return s
	})
	cases = append(cases, corpusCase{"oom", oom, GroundTruth{ExpectedSignature: string(SignatureOOMKill)}})

	// 2. frozen watched worker.
	end = at(55 * time.Second)
	frozen := corpusIncident(t, 2, end, incident.Trigger{Type: "process_stopped", PID: 100, StartTicks: 100})
	frozen.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		return withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "T", 0)
	})
	cases = append(cases, corpusCase{"frozen-worker", frozen, GroundTruth{ExpectedSignature: string(SignatureFrozenProcess)}})

	// 3. CPU spin: one surviving process at 150% of a core for 65s, no
	// child churn. this is also consistent with productive single-process work;
	// v1 cannot distinguish them and the analyzer must abstain.
	end = at(65 * time.Second)
	spin := corpusIncident(t, 3, end, incident.Trigger{Type: "manual"})
	spin.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		return withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "R", 150)
	})
	cases = append(cases, corpusCase{"cpu-spin", spin, GroundTruth{ExpectedSignature: string(SignatureCPUSpin)}})

	// 4. disk exhaustion: 3% free for the whole capture, with modest IO
	// pressure (8% some / 3% full, below the fallback-starvation boundary).
	end = at(55 * time.Second)
	disk := corpusIncident(t, 4, end, incident.Trigger{Type: "manual"})
	disk.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		return withPressure(systemSnapshot(at(0), 30, 3), platform.PressureIO, 8, 3)
	})
	cases = append(cases, corpusCase{"disk-full", disk, GroundTruth{ExpectedSignature: string(SignatureDiskExhaustion)}})

	// 5. orphan: the parent vanishes, the child is adopted by PID 1 and
	// survives to the end.
	end = at(55 * time.Second)
	orphan := corpusIncident(t, 5, end, incident.Trigger{Type: "manual"})
	orphan.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index <= 5 {
			s = withProcess(s, 100, 100, "S", 0)
			return withChild(s, 500, 900, 100, "S")
		}
		return withChild(s, 500, 900, 1, "S")
	})
	cases = append(cases, corpusCase{"orphan", orphan, GroundTruth{ExpectedSignature: string(SignatureOrphanProcess)}})

	// 6. Process-group termination: three same-PGID workers vanish together.
	end = at(55 * time.Second)
	group := corpusIncident(t, 6, end, incident.Trigger{Type: "manual"})
	group.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index < 6 {
			for member := 0; member < 3; member++ {
				s = withProcessGroup(s, 700+member, int64(700+member), 700, "S", 0)
			}
		}
		return s
	})
	cases = append(cases, corpusCase{"process-group-kill", group, GroundTruth{ExpectedSignature: string(SignatureGroupKill)}})

	// 7. broker socket stall: an established socket owned by a surviving
	// runner, plus a memory episode that explains why the capture exists.
	// without RX counters this is only distinguishable because the trigger
	// is not a manual, quiet capture; the missing byte counters remain on
	// the record.
	end = at(55 * time.Second)
	stall := corpusIncident(t, 7, end, incident.Trigger{Type: "memory_threshold"})
	stall.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		memory := 40.0
		if index <= 5 {
			memory = 96
		}
		s := systemSnapshot(at(0), memory, 80)
		s = withProcessAddr(s, 300, 300, 1, "S", 0)
		return withConnectionAddr(s, 9, "203.0.113.10", 8000, "ESTABLISHED", 300)
	})
	cases = append(cases, corpusCase{"socket-stall", stall, GroundTruth{ExpectedSignature: string(SignatureBrokerStall)}})

	// 8. network path failure: an established socket leaves ESTABLISHED with
	// no replacement, and incomplete SYN attempts accumulate on two peers.
	end = at(55 * time.Second)
	network := corpusIncident(t, 8, end, incident.Trigger{Type: "manual"})
	network.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		state := "ESTABLISHED"
		if index >= 5 {
			state = "CLOSE_WAIT"
		}
		s = withConnectionAddr(s, 9, "203.0.113.10", 8000, state, 300)
		return withConnectionAddr(s, 100+uint64(index), "203.0.113.11", 9000, "SYN_SENT", 0)
	})
	cases = append(cases, corpusCase{"network-failure", network, GroundTruth{ExpectedSignature: string(SignatureNetworkFailure)}})

	// 9. resource starvation fallback: severe IO pressure with no more
	// specific cause observed. 65% some and 30% full stalled IO time is
	// genuinely severe; the earlier 20/8 fixture was mild enough to be
	// mislabeled once the severe boundary was calibrated.
	end = at(55 * time.Second)
	starvation := corpusIncident(t, 9, end, incident.Trigger{Type: "manual"})
	starvation.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withPressure(s, platform.PressureIO, 65, 30)
	})
	cases = append(cases, corpusCase{"io-starvation", starvation, GroundTruth{ExpectedSignature: string(SignatureStarvation)}})

	// 10. healthy idle baseline.
	end = at(55 * time.Second)
	healthy := corpusIncident(t, 10, end, incident.Trigger{Type: "manual"})
	healthy.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "S", 0)
	})
	cases = append(cases, corpusCase{"healthy-idle", healthy, GroundTruth{Healthy: true}})

	// 11. healthy CPU-heavy compile: the process sustains >1 core but spawns
	// short-lived children, which must prevent a CPU_SPIN diagnosis.
	end = at(65 * time.Second)
	cpuheavy := corpusIncident(t, 11, end, incident.Trigger{Type: "manual"})
	cpuheavy.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s = withProcess(s, 100, 100, "R", 120)
		if index >= 2 {
			// A new compiler/linker child appears in each of several samples.
			s = withChild(s, 600+index, int64(600+index), 100, "R")
		}
		return s
	})
	cases = append(cases, corpusCase{"healthy-cpu-heavy", cpuheavy, GroundTruth{Healthy: true}})

	// 12. healthy memory-heavy compile: 90% host memory with mild PSI, never
	// a departure near the exhaustion boundary.
	end = at(55 * time.Second)
	memheavy := corpusIncident(t, 12, end, incident.Trigger{Type: "manual"})
	memheavy.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := withPressure(systemSnapshot(at(0), 90, 60), platform.PressureMemory, 8, 2)
		return withProcess(s, 100, 100, "S", 0)
	})
	cases = append(cases, corpusCase{"healthy-memory-heavy", memheavy, GroundTruth{Healthy: true}})

	// 13. healthy long-lived idle socket on a quiet manual capture.
	end = at(55 * time.Second)
	idlesocket := corpusIncident(t, 13, end, incident.Trigger{Type: "manual"})
	idlesocket.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s = withProcessAddr(s, 300, 300, 1, "S", 0)
		return withConnectionAddr(s, 9, "203.0.113.10", 8000, "ESTABLISHED", 300)
	})
	cases = append(cases, corpusCase{"healthy-idle-socket", idlesocket, GroundTruth{Healthy: true}})

	// 14. healthy intended parent exit: the child is adopted but then exits
	// before capture end, so it is not a surviving orphan.
	end = at(65 * time.Second)
	parentexit := corpusIncident(t, 14, end, incident.Trigger{Type: "process_exit", PID: 100, StartTicks: 100})
	parentexit.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		switch {
		case index <= 7:
			s = withProcess(s, 100, 100, "S", 0)
			return withChild(s, 500, 900, 100, "S")
		case index == 8:
			return withChild(s, 500, 900, 1, "S")
		default:
			return s
		}
	})
	cases = append(cases, corpusCase{"healthy-parent-exit", parentexit, GroundTruth{Healthy: true}})

	// 15. healthy temporary stop: one sample in T state, far under the
	// five-second frozen-process minimum.
	end = at(55 * time.Second)
	blink := corpusIncident(t, 15, end, incident.Trigger{Type: "process_stopped", PID: 100, StartTicks: 100})
	blink.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		state := "S"
		if index == 5 {
			state = "T"
		}
		return withProcess(systemSnapshot(at(0), 30, 80), 100, 100, state, 0)
	})
	cases = append(cases, corpusCase{"healthy-temporary-stop", blink, GroundTruth{Healthy: true}})

	// 16. healthy temporary disk pressure: free space dips to 4% for a single
	// sample, then recovers.
	end = at(55 * time.Second)
	diskblip := corpusIncident(t, 16, end, incident.Trigger{Type: "manual"})
	diskblip.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		free := 80.0
		if index == 11 {
			free = 4
		}
		return systemSnapshot(at(0), 30, free)
	})
	cases = append(cases, corpusCase{"healthy-disk-brief", diskblip, GroundTruth{Healthy: true}})

	// 17. healthy reconnects: a client re-establishes to the same peer after
	// each normal close. replacement connections are application recovery,
	// not path failure.
	end = at(55 * time.Second)
	reconnects := corpusIncident(t, 17, end, incident.Trigger{Type: "manual"})
	reconnects.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s = withProcessAddr(s, 300, 300, 1, "S", 0)
		// socket i is ESTABLISHED at sample i and CLOSE_WAIT at sample i+1;
		// the next socket starts at i+2 to the same peer.
		for offset := 0; offset <= 1; offset++ {
			start := index - offset
			if start < 0 {
				continue
			}
			state := "ESTABLISHED"
			if offset == 1 {
				state = "CLOSE_WAIT"
			}
			s = withConnectionAddr(s, 300+uint64(start), "203.0.113.20", 7000, state, 300)
		}
		return s
	})
	cases = append(cases, corpusCase{"healthy-reconnects", reconnects, GroundTruth{Healthy: true}})

	// 18. healthy large file writes: plenty of free space and mild IO
	// pressure, below every evidentiary boundary.
	end = at(55 * time.Second)
	writes := corpusIncident(t, 18, end, incident.Trigger{Type: "manual"})
	writes.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := withPressure(systemSnapshot(at(0), 30, 40), platform.PressureIO, 8, 2)
		return withProcess(s, 100, 100, "S", 0)
	})
	cases = append(cases, corpusCase{"healthy-large-writes", writes, GroundTruth{Healthy: true}})

	// 19. healthy CPU contention: a noisy co-tenant keeps CPU "some" PSI at
	// 35% for the whole capture. that is routine multi-core load, well below
	// the severe boundary, and no watched process is spinning.
	end = at(55 * time.Second)
	contention := corpusIncident(t, 19, end, incident.Trigger{Type: "manual"})
	contention.Snapshots = series(t, end, five, func(index int) collector.Snapshot {
		s := withPressure(systemSnapshot(at(0), 30, 80), platform.PressureCPU, 35, 0)
		return withProcess(s, 100, 100, "R", 40)
	})
	cases = append(cases, corpusCase{"healthy-cpu-contention", contention, GroundTruth{Healthy: true}})

	for _, c := range cases {
		mustValid(t, c.Incident)
	}
	return cases
}

// TestWriteIncidentCorpus regenerates the checked-in fixtures. it is opt-in so
// a normal test run cannot silently rewrite repository data.
func TestWriteIncidentCorpus(t *testing.T) {
	if os.Getenv("DEPREHENDO_WRITE_FIXTURES") == "" {
		t.Skip("set DEPREHENDO_WRITE_FIXTURES=1 to regenerate the incident corpus")
	}
	if err := os.MkdirAll(corpusDir, 0755); err != nil {
		t.Fatal(err)
	}
	cases := corpusCases(t)
	keep := map[string]bool{"README.md": true}
	for _, c := range cases {
		keep[c.Name+".deprehendo"] = true
		keep[c.Name+".deprehendo.ground-truth.json"] = true
		var encoded bytes.Buffer
		if err := incident.Encode(&encoded, c.Incident, true); err != nil {
			t.Fatalf("%s: encode: %v", c.Name, err)
		}
		path := filepath.Join(corpusDir, c.Name+".deprehendo")
		if err := os.WriteFile(path, encoded.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
		truth, err := json.MarshalIndent(c.Truth, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".ground-truth.json", append(truth, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !keep[entry.Name()] {
			if err := os.Remove(filepath.Join(corpusDir, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("wrote %d corpus fixtures to %s", len(cases), corpusDir)
}
