package diagnosis

import (
	"math"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

func calibrationIncident(t *testing.T, count int, generate func(int) collector.Snapshot) *incident.Incident {
	t.Helper()
	i := validIncident(t, at(0), at(time.Duration(count-1)*step))
	i.Snapshots = sampleSeries(t, at(0), count, step, generate)
	mustValid(t, i)
	return i
}
func calibrationHealthy(s collector.Snapshot) collector.Snapshot {
	for _, r := range []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO} {
		s = withPressure(s, r, 0, 0)
	}
	return s
}
func calibrated(t *testing.T, sig Signature, i *incident.Incident) SignatureMatch {
	t.Helper()
	mustValid(t, i)
	m := sig.Analyze(buildContext(i))
	if math.IsNaN(m.Confidence) || m.Confidence < 0 || m.Confidence > 1 {
		t.Fatalf("invalid score: %+v", m)
	}
	return m
}
func closeScore(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("score %.6f, want %.6f", got, want)
	}
}

// these paired evidence interventions are the calibration specification, not
// fitted probabilities. each pair changes a sensor/observation independently
// of scenario labels; the expected number is an explicit reviewed score.
func TestConfidenceCalibrationLadder(t *testing.T) {
	t.Run("OOM-corroboration-keeps-cause-unknown", func(t *testing.T) {
		var previous float64
		for grade := 0; grade < 3; grade++ {
			i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
				s := systemSnapshot(at(0), 96, 80)
				if grade == 2 {
					s = withPressure(s, platform.PressureMemory, 30, 10)
				}
				if n < 6 {
					s = withProcess(s, 100, 100, "S", 0)
					if grade >= 1 {
						s.Processes[0].RSSBytes = 6 << 30
					}
				}
				return s
			})
			m := calibrated(t, OOMKillSignature{}, i)
			closeScore(t, m.Confidence, []float64{.35, .40, .50}[grade])
			if m.Confidence <= previous || m.Rejected == "" || !contains(m.MissingEvidence, "KERNEL_OOM_EVENT") {
				t.Fatalf("OOM grade %d lost ordering or causal gate: %+v", grade, m)
			}
			previous = m.Confidence
		}
	})
	t.Run("frozen-known-healthy-and-watch-priority", func(t *testing.T) {
		for grade := 0; grade < 3; grade++ {
			i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
				s := withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "T", 0)
				if grade == 2 {
					s = calibrationHealthy(s)
				}
				return s
			})
			if grade >= 1 {
				i.Trigger = incident.Trigger{Type: "process_stopped", PID: 100, StartTicks: 100}
			}
			m := calibrated(t, FrozenProcessSignature{}, i)
			closeScore(t, m.Confidence, []float64{.70, .85, .90}[grade])
			if m.Confidence > frozenCap {
				t.Fatal("frozen cap exceeded")
			}
		}
	})
	t.Run("disk-independent-pressure-and-inodes", func(t *testing.T) {
		for grade := 0; grade < 3; grade++ {
			i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
				s := systemSnapshot(at(0), 30, 3)
				if grade >= 1 {
					s = withPressure(s, platform.PressureIO, 30, 10)
				}
				if grade == 2 {
					s.System.DiskTotalInodes = 1000
					s.System.DiskFreeInodes = 1
				}
				return s
			})
			m := calibrated(t, DiskExhaustionSignature{}, i)
			closeScore(t, m.Confidence, []float64{.60, .75, .90}[grade])
			if m.Confidence > diskCap {
				t.Fatal("disk cap exceeded")
			}
		}
	})
	t.Run("starvation-full-stall-adds-support", func(t *testing.T) {
		for grade := 0; grade < 2; grade++ {
			i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
				return withPressure(systemSnapshot(at(0), 30, 80), platform.PressureIO, 65, float64(grade)*30)
			})
			m := calibrated(t, ResourceStarvationSignature{}, i)
			closeScore(t, m.Confidence, []float64{.55, .70}[grade])
		}
	})
	t.Run("CPU-health-not-inferred-from-missing-PSI", func(t *testing.T) {
		for grade := 0; grade < 2; grade++ {
			i := calibrationIncident(t, 14, func(n int) collector.Snapshot {
				s := withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "R", 150)
				if grade == 1 {
					s = calibrationHealthy(s)
				}
				return s
			})
			m := calibrated(t, CPUSpinSignature{}, i)
			closeScore(t, m.Confidence, []float64{.45, .50}[grade])
			if m.Rejected == "" || m.Confidence > spinCap {
				t.Fatal("productive CPU inferred to be spin")
			}
		}
	})
	t.Run("socket-watch-is-not-progress-evidence", func(t *testing.T) {
		i := socketFixture(t)
		i.Trigger = incident.Trigger{Type: "manual", PID: 300, StartTicks: 300}
		base := calibrated(t, BrokerSocketStallSignature{}, i)
		closeScore(t, base.Confidence, .35)
		for n := range i.Snapshots {
			i.Snapshots[n] = calibrationHealthy(i.Snapshots[n])
		}
		healthy := calibrated(t, BrokerSocketStallSignature{}, i)
		closeScore(t, healthy.Confidence, .40)
		if base.Rejected == "" || healthy.Rejected == "" {
			t.Fatal("idle socket became a diagnosed stall")
		}
	})
	t.Run("network-independent-failed-handshakes", func(t *testing.T) {
		for grade := 0; grade < 3; grade++ {
			i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
				s := systemSnapshot(at(0), 30, 80)
				state := "ESTABLISHED"
				if n >= 5 {
					state = "CLOSE_WAIT"
				}
				s = withConnectionAddr(s, 9, "203.0.113.10", 8000, state, 0)
				if grade >= 1 {
					s = withConnectionAddr(s, uint64(100+n), "203.0.113.11", 9000, "SYN_SENT", 0)
				}
				if grade == 2 {
					s = calibrationHealthy(s)
				}
				return s
			})
			m := calibrated(t, NetworkPathFailureSignature{}, i)
			closeScore(t, m.Confidence, []float64{.35, .65, .75}[grade])
			if grade == 0 && m.Rejected == "" {
				t.Fatal("normal peer close diagnosed as path failure")
			}
		}
	})
}

func TestCalibrationUnidentifiableCausesCannotBeEnabledByLowThreshold(t *testing.T) {
	cpu := calibrationIncident(t, 14, func(n int) collector.Snapshot {
		return calibrationHealthy(withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "R", 150))
	})
	idle := socketFixture(t)
	idle.Trigger = incident.Trigger{Type: "manual", PID: 300, StartTicks: 300}
	departure := calibrationIncident(t, 12, func(n int) collector.Snapshot {
		s := withPressure(systemSnapshot(at(0), 96, 80), platform.PressureMemory, 30, 10)
		if n < 6 {
			s = withProcess(s, 100, 100, "S", 0)
			s.Processes[0].RSSBytes = 6 << 30
		}
		return s
	})
	for _, tc := range []struct {
		name string
		i    *incident.Incident
		id   SignatureID
	}{
		{"productive-single-process-compute", cpu, SignatureCPUSpin},
		{"healthy-watched-keepalive", idle, SignatureBrokerStall},
		{"clean-departure-near-memory-limit", departure, SignatureOOMKill},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, threshold := range []float64{.01, DefaultMinConfidence, .99} {
				report, err := Analyze(tc.i, Options{MinConfidence: threshold})
				if err != nil {
					t.Fatal(err)
				}
				m := findRejected(t, report, tc.id)
				if len(m.Supporting) == 0 || len(m.MissingEvidence) == 0 || m.Confidence > .5 {
					t.Fatalf("unexplained causal rejection: %+v", m)
				}
			}
		})
	}
}

func TestCalibrationContradictionsReduceSupport(t *testing.T) {
	t.Run("disk-recovery", func(t *testing.T) {
		low := calibrationIncident(t, 12, func(n int) collector.Snapshot { return systemSnapshot(at(0), 30, 3) })
		base := calibrated(t, DiskExhaustionSignature{}, low)
		low.Snapshots[11].System.DiskFree = low.Snapshots[11].System.DiskTotal / 2
		recovered := calibrated(t, DiskExhaustionSignature{}, low)
		if recovered.Confidence >= base.Confidence || !contains(evidenceCodes(recovered.Contradicting), string(CodeDiskRecoveredMidIncident)) {
			t.Fatalf("recovery did not contradict: %+v", recovered)
		}
	})
	t.Run("orphan-child-trigger", func(t *testing.T) {
		i := orphanFixture(t, true)
		base := calibrated(t, OrphanProcessTreeSignature{}, i)
		i.Trigger = incident.Trigger{Type: "process_stopped", PID: 500, StartTicks: 900}
		contradicted := calibrated(t, OrphanProcessTreeSignature{}, i)
		closeScore(t, base.Confidence, .80)
		closeScore(t, contradicted.Confidence, .60)
	})
	t.Run("group-unrelated-trigger", func(t *testing.T) {
		i := groupFixture(t, 30*time.Second, 3)
		base := calibrated(t, ProcessGroupTerminationSignature{}, i)
		i.Trigger = incident.Trigger{Type: "process_exit", PID: 999, StartTicks: 999}
		contradicted := calibrated(t, ProcessGroupTerminationSignature{}, i)
		closeScore(t, base.Confidence, .80)
		closeScore(t, contradicted.Confidence, .60)
	})
	t.Run("no-known-healthy-bonus-from-one-missing-resource", func(t *testing.T) {
		i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
			return calibrationHealthy(withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "T", 0))
		})
		known := calibrated(t, FrozenProcessSignature{}, i)
		for n := range i.Snapshots {
			delete(i.Snapshots[n].Pressure, platform.PressureMemory)
		}
		missing := calibrated(t, FrozenProcessSignature{}, i)
		closeScore(t, known.Confidence-missing.Confidence, wFrozenHealthy)
		if contains(evidenceCodes(missing.Supporting), string(CodePressureHealthy)) {
			t.Fatal("missing PSI became healthy support")
		}
	})
}

func TestGroupDepartureWindowDoesNotChainBeyondBound(t *testing.T) {
	i := validIncident(t, at(0), at(16*time.Second))
	i.Snapshots = sampleSeries(t, at(0), 5, 4*time.Second, func(n int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		for member := 0; member < 3; member++ {
			if n <= member {
				s = withProcessGroup(s, 700+member, int64(700+member), 700, "S", 0)
			}
		}
		return s
	})
	ctx := buildContext(i)
	_, sites, _ := groupKillCandidate(ctx)
	if len(sites) != 2 || sites[len(sites)-1].gap.From.Sub(sites[0].gap.From) > coordinatedWindow {
		t.Fatalf("chained three departures across 8 seconds: %+v", sites)
	}
}

func TestCgroupHypothesisIsCandidateSpecificAndHostIndependent(t *testing.T) {
	for _, sameidentity := range []bool{false, true} {
		i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
			s := systemSnapshot(at(0), 30, 80)
			s.System.MemoryStatsAvailable = false
			for pid := 100; pid <= 101; pid++ {
				if n >= 6 && pid == 101 {
					continue
				}
				s = withProcess(s, pid, int64(pid), "S", 0)
				fraction := uint64(50)
				if (sameidentity && pid == 101) || (!sameidentity && pid == 100) {
					fraction = 98
				}
				p := &s.Processes[len(s.Processes)-1]
				p.Cgroup = &platform.CgroupSnapshot{PID: pid, StartTicks: int64(pid), Path: "/synthetic", MemoryCurrentAvailable: true, MemoryMaxAvailable: true, MemoryCurrent: fraction, MemoryMax: 100}
			}
			return s
		})
		m := calibrated(t, OOMKillSignature{}, i)
		has := contains(evidenceCodes(m.Supporting), string(CodeCgroupMemoryNearLimit))
		if has != sameidentity {
			t.Fatalf("cgroup borrowing or host gate: same=%v %+v", sameidentity, m)
		}
	}
}
