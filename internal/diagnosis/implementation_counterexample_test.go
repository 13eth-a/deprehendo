package diagnosis

import (
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

// implementation review: each case is a legitimate workload that satisfies as much of a
// signature as the v1 evidence allows. none may be reported as a diagnosis.

// A single-process compute job at full core for longer than the spin window,
// with no children, no stops and healthy pressure, is indistinguishable from
// a CPU spin without application progress telemetry. it must stay rejected.
func TestImplementationSingleProcessComputeIsNotDiagnosedAsSpin(t *testing.T) {
	i := calibrationIncident(t, 14, func(n int) collector.Snapshot {
		return calibrationHealthy(withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "R", 150))
	})
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range report.Matches {
		if m.SignatureID == SignatureCPUSpin {
			t.Fatalf("productive compute reported as CPU_SPIN: %+v", m)
		}
	}
	findRejected(t, report, SignatureCPUSpin)
}

// A compile driver that spawns children while busy must be refused by the
// child-churn gate, whatever its CPU readings.
func TestImplementationBuildDriverWithChildrenIsRefused(t *testing.T) {
	i := calibrationIncident(t, 14, func(n int) collector.Snapshot {
		s := withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "R", 150)
		if n >= 4 {
			s = withProcess(s, 101, 101, "R", 80)
		}
		// child identities are recorded with the parent as PPID.
		for k := range s.Processes {
			if s.Processes[k].PID == 101 {
				s.Processes[k].PPID = 100
			}
		}
		return s
	})
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m := findRejected(t, report, SignatureCPUSpin); m.Rejected == "" {
		t.Fatalf("build driver with children not refused: %+v", m)
	}
}

// healthy idle keepalive: a long ESTABLISHED socket owned by a live process
// with a manual trigger and no watched identity must never be diagnosed as a
// broker stall. the existing gate refuses this; lock the rejection in.
func TestImplementationIdleKeepaliveIsNotDiagnosedAsStall(t *testing.T) {
	i := socketFixture(t)
	i.Trigger = incident.Trigger{Type: "manual", PID: 300, StartTicks: 300}
	for n := range i.Snapshots {
		i.Snapshots[n] = calibrationHealthy(i.Snapshots[n])
	}
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range report.Matches {
		if m.SignatureID == SignatureBrokerStall {
			t.Fatalf("idle keepalive reported as BROKER_SOCKET_STALL: %+v", m)
		}
	}
}

// memory at 99% with a process that exits cleanly is the classic OOM
// counterexample: without kernel OOM telemetry the rule must cap at 0.50 and
// never produce a diagnosis.
func TestImplementationCleanExitNearMemoryLimitIsNotOOMDiagnosis(t *testing.T) {
	i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
		s := withPressure(systemSnapshot(at(0), 99, 80), platform.PressureMemory, 30, 10)
		if n < 6 {
			s = withProcess(s, 100, 100, "S", 0)
			s.Processes[0].RSSBytes = 6 << 30
		}
		return s
	})
	report, err := Analyze(i, Options{MinConfidence: 0.01})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range report.Matches {
		if m.SignatureID == SignatureOOMKill {
			t.Fatalf("clean exit near memory limit reported as OOM_KILL: %+v", m)
		}
	}
	if m := findRejected(t, report, SignatureOOMKill); m.Confidence > oOMCap {
		t.Fatalf("OOM confidence %.2f exceeds unobservable-cause cap %.2f", m.Confidence, oOMCap)
	}
}

// A brief SIGSTOP that resumes within the 5s frozen minimum must not be a
// frozen-process diagnosis.
func TestImplementationBriefStopIsNotFrozen(t *testing.T) {
	i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
		state := "S"
		if n == 2 {
			state = "T"
		}
		return withProcess(systemSnapshot(at(0), 30, 80), 100, 100, state, 0)
	})
	report, err := Analyze(i, Options{MinConfidence: 0.01})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range report.Matches {
		if m.SignatureID == SignatureFrozenProcess {
			t.Fatalf("brief stop reported as FROZEN_PROCESS: %+v", m)
		}
	}
}

func TestImplementationPendingAndPassiveHandshakesAreNotFailures(t *testing.T) {
	for _, passive := range []bool{false, true} {
		i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
			s := calibrationHealthy(systemSnapshot(at(0), 30, 80))
			state := "ESTABLISHED"
			if n >= 5 {
				state = "CLOSE_WAIT"
			}
			s = withConnectionAddr(s, 9, "203.0.113.10", 8000, state, 0)
			if passive || n == 11 {
				state = "SYN_SENT"
				if passive {
					state = "SYN_RECV"
				}
				for k := 0; k < 3; k++ {
					s = withConnectionAddr(s, uint64(100+3*n+k), "203.0.113.11", 9000, state, 0)
				}
			}
			return s
		})
		m := calibrated(t, NetworkPathFailureSignature{}, i)
		if contains(evidenceCodes(m.Supporting), string(CodeSynChurn)) || m.Rejected == "" {
			t.Fatalf("passive=%v pending/passive handshakes became failures: %+v", passive, m)
		}
	}
}

func TestImplementationMissingFinalDiskSampleCannotProvePersistence(t *testing.T) {
	i := calibrationIncident(t, 12, func(n int) collector.Snapshot { return systemSnapshot(at(0), 30, 3) })
	i.Snapshots[11].System.DiskStatsAvailable = false
	m := calibrated(t, DiskExhaustionSignature{}, i)
	if contains(evidenceCodes(m.Supporting), string(CodeDiskPersistedToAnalysisEnd)) {
		t.Fatalf("stale disk reading asserted persistence: %+v", m)
	}
}

func TestImplementationReturnedOrFutureParentGapDoesNotProveOrphan(t *testing.T) {
	for _, future := range []bool{false, true} {
		i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
			s := systemSnapshot(at(0), 30, 80)
			parent := true
			if future {
				parent = n <= 6
			} else {
				parent = n != 6
			}
			if parent {
				s = withProcess(s, 100, 100, "S", 0)
			}
			ppid := 100
			if n >= 6 {
				ppid = 1
			}
			return withProcessAddr(s, 500, 900, ppid, "S", 0)
		})
		m := calibrated(t, OrphanProcessTreeSignature{}, i)
		if m.Rejected == "" {
			t.Fatalf("future=%v parent absence falsely proved orphan: %+v", future, m)
		}
	}
}

func TestImplementationIsolatedPSIPeakIsNotSustainedStarvation(t *testing.T) {
	i := calibrationIncident(t, 12, func(n int) collector.Snapshot {
		some := 0.0
		if n == 4 {
			some = 65
		}
		return withPressure(systemSnapshot(at(0), 30, 80), platform.PressureIO, some, 0)
	})
	report, err := Analyze(i, Options{MinConfidence: .01})
	if err != nil {
		t.Fatal(err)
	}
	m := findRejected(t, report, SignatureStarvation)
	if m.Rejected == "" {
		t.Fatal("single PSI peak promoted at low threshold")
	}
}

// the whole coordination span is bounded, not merely each adjacent pair.
func TestImplementationGroupWindowIncludesOnlyPermanentDepartures(t *testing.T) {
	i := groupFixture(t, 30*time.Second, 3)
	for n := 8; n < len(i.Snapshots); n++ {
		for member := 0; member < 3; member++ {
			i.Snapshots[n] = withProcessGroup(i.Snapshots[n], 700+member, int64(700+member), 700, "S", 0)
		}
	}
	m := calibrated(t, ProcessGroupTerminationSignature{}, i)
	if m.Rejected == "" {
		t.Fatal("returned process group called terminated")
	}
}
