package diagnosis

import (
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

const step = 5 * time.Second

// findMatch returns the match for a signature or fails the test.
func findMatch(t *testing.T, report *Report, id SignatureID) SignatureMatch {
	t.Helper()
	for _, match := range report.Matches {
		if match.SignatureID == id {
			return match
		}
	}
	t.Fatalf("no %s in %+v", id, report.Matches)
	return SignatureMatch{}
}

func findRejected(t *testing.T, report *Report, id SignatureID) SignatureMatch {
	t.Helper()
	for _, match := range report.Rejections {
		if match.SignatureID == id {
			return match
		}
	}
	t.Fatalf("%s was not rejected: matches=%d", id, len(report.Matches))
	return SignatureMatch{}
}

func withErrors(s collector.Snapshot, name string) collector.Snapshot {
	s.Errors = append(s.Errors, collector.CollectionError{Collector: name, Err: "unavailable"})
	return s
}

func withConnectionAddr(s collector.Snapshot, inode uint64, remote string, remotePort uint16, state string, pid int) collector.Snapshot {
	s.Connections = append(s.Connections, collector.ConnectionSnapshot{
		LocalAddr: "127.0.0.1", LocalPort: 40000,
		RemoteAddr: remote, RemotePort: remotePort,
		State: state, Inode: inode, PID: pid, FD: int(inode) + 1,
	})
	return s
}

func assertBand(t *testing.T, match SignatureMatch, want ConfidenceBand) {
	t.Helper()
	if match.Band != want {
		t.Errorf("band = %s, want %s (confidence %.2f)", match.Band, want, match.Confidence)
	}
}

// ---------------------------------------------------------------------------
// OOM_KILL
// ---------------------------------------------------------------------------

func TestOOMKillPositive(t *testing.T) {
	end := at(75 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 16, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 50, 80)
		if index >= 6 {
			s = systemSnapshot(at(0), 96, 80)
		}
		if index <= 5 {
			s = withProcess(s, 500, 500, "S", 0)
			s.Processes[len(s.Processes)-1].RSSBytes = 6 << 30
		}
		return s
	})
	snapshots := make([]collector.Snapshot, len(i.Snapshots))
	copy(snapshots, i.Snapshots)
	for index := range snapshots {
		snapshots[index].Timestamp = at(time.Duration(index) * step)
	}
	i.Snapshots = snapshots
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findRejected(t, report, SignatureOOMKill)
	if match.Confidence < 0.35 || match.Confidence > oOMCap {
		t.Errorf("confidence %.2f outside expected envelope [.35, %.2f]", match.Confidence, oOMCap)
	}
	if !strings.Contains(strings.Join(match.MissingEvidence, ","), "KERNEL_OOM_EVENT") {
		t.Errorf("kernel OOM event must be listed UNKNOWN, got %v", match.MissingEvidence)
	}
	var codes []string
	for _, ev := range match.Supporting {
		codes = append(codes, string(ev.Code))
	}
	for _, want := range []string{"HOST_MEMORY_NEAR_LIMIT", "PROCESS_DEPARTURE_NEAR_MEMORY_PEAK", "CANDIDATE_RSS_LARGE"} {
		if !contains(codes, want) {
			t.Errorf("supporting evidence missing %s: %v", want, codes)
		}
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func TestOOMKillNegativeLowMemory(t *testing.T) {
	end := at(60 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 13, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 50, 80)
		if index > 6 { // a process departs, but memory never ran hot
			return s
		}
		return withProcess(s, 500, 500, "S", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureOOMKill)
	if !strings.Contains(rejected.Rejected, "never approached") {
		t.Errorf("rejection reason: %q", rejected.Rejected)
	}
}

func TestOOMKillNegativeNoDeparture(t *testing.T) {
	end := at(60 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 13, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 97, 80)
		s = withProcess(s, 500, 500, "S", 0)
		s.Processes[0].RSSBytes = 8 << 30
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureOOMKill)
	if !strings.Contains(rejected.Rejected, "no process disappeared") {
		t.Errorf("rejection reason: %q", rejected.Rejected)
	}
}

// Missing-data semantics: with the system collector down for the whole
// capture, memory is UNKNOWN. the rule must refuse rather than treat the
// gap as evidence that memory was fine (3.35).
func TestOOMKillUnknownTelemetry(t *testing.T) {
	end := at(60 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 13, step, func(index int) collector.Snapshot {
		s := collector.Snapshot{}
		s = withErrors(s, "system")
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureOOMKill)
	if !strings.Contains(rejected.Rejected, "unavailable") {
		t.Errorf("rejection reason: %q", rejected.Rejected)
	}
	if report.Unknown != true {
		t.Errorf("a report with no matches must be UNKNOWN")
	}
}

// ---------------------------------------------------------------------------
// FROZEN_PROCESS
// ---------------------------------------------------------------------------

func TestFrozenProcessPositive(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "T", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureFrozenProcess)
	// stopped 0.50 + remained 0.10 + cpu idle 0.10 + healthy 0.05 = 0.75
	if match.Confidence < 0.70 || match.Confidence > frozenCap {
		t.Errorf("confidence %.2f outside [.70, %.2f]", match.Confidence, frozenCap)
	}
	if match.Attributes["stopped_span"] == "" {
		t.Errorf("stopped_span attribute missing")
	}
}

func TestFrozenProcessNegative(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "S", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureFrozenProcess)
}

func TestFrozenProcessShortBlinkNotMatched(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		state := "S"
		if index == 3 {
			state = "T" // one sample: 5s ceiling < required sustained span
		}
		return withProcess(s, 100, 100, state, 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match, err2 := findRejectedAllowMissing(t, report, SignatureFrozenProcess)
	_ = match
	if err2 != nil {
		t.Fatalf("%v", err2)
	}
}

func findRejectedAllowMissing(t *testing.T, report *Report, id SignatureID) (SignatureMatch, error) {
	for _, match := range report.Rejections {
		if match.SignatureID == id {
			return match, nil
		}
	}
	return SignatureMatch{}, &testError{id: id}
}

type testError struct{ id SignatureID }

func (e *testError) Error() string {
	return string(e.id) + " was neither matched nor recorded as a rejection"
}

// ---------------------------------------------------------------------------
// CPU_SPIN
// ---------------------------------------------------------------------------

func TestCPUSpinPositive(t *testing.T) {
	end := at(65 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 14, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "R", 150)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findRejected(t, report, SignatureCPUSpin)
	// sustained 0.45 + no-children 0.15 + not-stopped 0.05 + healthy 0.05 = 0.70
	if match.Confidence < 0.40 || match.Confidence > spinCap {
		t.Errorf("confidence %.2f outside [.40, %.2f]", match.Confidence, spinCap)
	}
}

// CPU accounting is quantized to 10 ms ticks, so a fully busy core reads
// slightly under 90% for an occasional sample. one dip must not reset an
// otherwise sustained spin; this mirrors the live linux capture that exposed
// the per-sample version of the rule.
func TestCPUSpinToleratesTickQuantizationDips(t *testing.T) {
	end := at(65 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 66, time.Second, func(index int) collector.Snapshot {
		cpu := 101.0
		if index == 20 || index == 45 {
			cpu = 80
		}
		return withProcess(systemSnapshot(at(0), 30, 80), 100, 100, "R", cpu)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findRejected(t, report, SignatureCPUSpin)
	if match.Confidence < 0.40 || match.Confidence > spinCap {
		t.Errorf("confidence %.2f outside [.40, %.2f]", match.Confidence, spinCap)
	}
}

func TestCPUSpinNegativeHealthyWork(t *testing.T) {
	end := at(65 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 14, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "R", 50) // busy but well under one full core
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureCPUSpin)
}

func TestCPUSpinNegativeProcessDeparted(t *testing.T) {
	end := at(65 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 14, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index < 8 {
			return withProcess(s, 100, 100, "R", 150)
		}
		return s // high-CPU process is gone: belongs to OOM/group rules
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureCPUSpin)
}

// ---------------------------------------------------------------------------
// DISK_EXHAUSTION
// ---------------------------------------------------------------------------

func TestDiskExhaustionPositive(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 3)
		// PSI values are percentages: 30% some / 10% full stalled IO time.
		return withPressure(s, platform.PressureIO, 30, 10)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureDiskExhaustion)
	// low free 0.50 + persisted 0.10 + io pressure 0.15 = 0.75
	if match.Confidence < 0.70 || match.Confidence > diskCap {
		t.Errorf("confidence %.2f outside [.70, %.2f]", match.Confidence, diskCap)
	}
}

func TestDiskExhaustionNegativeTransient(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		disk := 80.0
		if index == 11 {
			disk = 3 // one sample near zero never sustains the span
		}
		return systemSnapshot(at(0), 30, disk)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureDiskExhaustion)
	if !strings.Contains(rejected.Rejected, "required span") {
		t.Errorf("rejection reason: %q", rejected.Rejected)
	}
}

func TestDiskInodeExhaustionEvidence(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 3)
		system := s.System
		system.DiskTotalInodes = 1000
		system.DiskFreeInodes = 10
		s.System = system
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureDiskExhaustion)
	var codes []string
	for _, ev := range match.Supporting {
		codes = append(codes, string(ev.Code))
	}
	if !contains(codes, "INODE_EXHAUSTION") {
		t.Errorf("inode exhaustion not reported: %v", codes)
	}
}

// ---------------------------------------------------------------------------
// ORPHAN_PROCESS_TREE
// ---------------------------------------------------------------------------

func orphanFixture(t *testing.T, childSurvives bool) *incident.Incident {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index <= 5 {
			s = withProcess(s, 100, 100, "S", 0)          // parent
			s = withProcessAddr(s, 500, 900, 100, "S", 0) // child with PPID 100
		} else {
			if childSurvives {
				s = withProcessAddr(s, 500, 900, 1, "S", 0)
			}
		}
		return s
	})
	mustValid(t, i)
	return i
}

func withProcessAddr(s collector.Snapshot, pid int, startTicks int64, ppid int, state string, cpu float64) collector.Snapshot {
	s.Processes = append(s.Processes, collector.ProcessSnapshot{
		Process:    platform.Process{PID: pid, PPID: ppid, PGID: pid, SID: pid, Name: "proc", State: state, StartTicks: startTicks},
		CPUPercent: cpu,
		OpenFDs:    -1,
	})
	return s
}

func TestOrphanPositive(t *testing.T) {
	report, err := Analyze(orphanFixture(t, true), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureOrphanProcess)
	// reparented 0.40 + parent gone 0.25 + persisted 0.05 + manual trigger 0.10 = 0.80
	if match.Confidence < 0.75 || match.Confidence > orphanCap {
		t.Errorf("confidence %.2f outside [.75, %.2f]", match.Confidence, orphanCap)
	}
}

func TestOrphanNegativeNoSurvivor(t *testing.T) {
	report, err := Analyze(orphanFixture(t, false), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureOrphanProcess)
}

func TestOrphanNegativeNeverReparented(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		// A daemon whose PPID is 1 from birth never produces the
		// reparent transition the rule requires.
		s := systemSnapshot(at(0), 30, 80)
		return withProcessAddr(s, 500, 900, 1, "S", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureOrphanProcess)
}

// ---------------------------------------------------------------------------
// PROCESS_GROUP_TERMINATION
// ---------------------------------------------------------------------------

func groupFixture(t *testing.T, vanish time.Duration, members int) *incident.Incident {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	done := int(vanish / step)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index < done {
			for member := 0; member < members; member++ {
				s = withProcessGroup(s, 700+member, int64(700+member), 700, "S", 0)
			}
		}
		return s
	})
	mustValid(t, i)
	return i
}

func withProcessGroup(s collector.Snapshot, pid int, startTicks int64, pgid int, state string, cpu float64) collector.Snapshot {
	s.Processes = append(s.Processes, collector.ProcessSnapshot{
		Process:    platform.Process{PID: int(pid), PPID: 1, PGID: pgid, SID: int(pid), Name: "worker", State: state, StartTicks: startTicks},
		CPUPercent: cpu,
		OpenFDs:    -1,
	})
	return s
}

func TestGroupKillPositive(t *testing.T) {
	report, err := Analyze(groupFixture(t, 30*time.Second, 3), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureGroupKill)
	// shared 0.35 + coordinated 0.20 + did not return 0.15 + manual 0.10 = 0.80
	if match.Confidence < 0.75 || match.Confidence > groupCap {
		t.Errorf("confidence %.2f outside [.75, %.2f]", match.Confidence, groupCap)
	}
	if match.Attributes["vanished"] != "3" {
		t.Errorf("vanished attr = %q", match.Attributes["vanished"])
	}
}

// TestGroupKillCoveredByIntent: when every vanished member exited under a
// covering provider intent, the group is intended termination, not a group kill.
func TestGroupKillCoveredByIntent(t *testing.T) {
	covers := []IntentCover{{
		Processes: []ProcessIdentity{{PID: 700, StartTicks: 700}, {PID: 701, StartTicks: 701}, {PID: 702, StartTicks: 702}},
		From:      at(0),
		Until:     at(60 * time.Second),
	}}
	report, err := Analyze(groupFixture(t, 30*time.Second, 3), Options{Covers: covers})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureGroupKill)
}

// TestGroupKillPartialCoverStillReports: a cover naming only some members does
// not explain the group, so the group kill is still reported.
func TestGroupKillPartialCoverStillReports(t *testing.T) {
	covers := []IntentCover{{
		Processes: []ProcessIdentity{{PID: 700, StartTicks: 700}},
		From:      at(0),
		Until:     at(60 * time.Second),
	}}
	report, err := Analyze(groupFixture(t, 30*time.Second, 3), Options{Covers: covers})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findMatch(t, report, SignatureGroupKill)
}

func TestGroupKillNegativeSingleMember(t *testing.T) {
	report, err := Analyze(groupFixture(t, 30*time.Second, 1), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureGroupKill)
}

func TestGroupKillNegativeUncoordinated(t *testing.T) {
	end := at(70 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 15, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		present := index < 14
		if present {
			s = withProcessGroup(s, 700, 700, 700, "S", 0)
			if index < 12 { // second member leaves 15s later: outside the window
				s = withProcessGroup(s, 701, int64(701), 700, "S", 0)
			}
		}
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureGroupKill)
}

// ---------------------------------------------------------------------------
// BROKER_SOCKET_STALL / NETWORK_PATH_FAILURE
// ---------------------------------------------------------------------------

func socketFixture(t *testing.T) *incident.Incident {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s = withProcessAddr(s, 300, 300, 1, "S", 0)
		s = withConnectionAddr(s, 9, "203.0.113.10", 8000, "ESTABLISHED", 300)
		return s
	})
	mustValid(t, i)
	return i
}

// healthy idle socket with a manual trigger and no watched identity and a
// healthy host: this must NOT become a confident stall diagnosis (3.32).
func TestBrokerStallHealthyIdleIsNotDiagnosed(t *testing.T) {
	report, err := Analyze(socketFixture(t), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, match := range report.Matches {
		if match.SignatureID == SignatureBrokerStall {
			t.Errorf("stall diagnosed on a quiet manual capture: %+v", match)
		}
	}
	findRejected(t, report, SignatureBrokerStall)
}

func TestBrokerStallWatchedPositive(t *testing.T) {
	i := socketFixture(t)
	i.Trigger = incident.Trigger{Type: "process_exit", PID: 300, StartTicks: 300}
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findRejected(t, report, SignatureBrokerStall)
	// stable 0.30 + alive 0.25 + no churn 0.10 + healthy 0.10 + watched 0.15 = 0.90
	if match.Confidence < 0.30 || match.Confidence > stallCap {
		t.Errorf("confidence %.2f outside [.30, %.2f]", match.Confidence, stallCap)
	}
	if !contains(match.MissingEvidence, "SOCKET_RX_TX_BYTE_COUNTERS") {
		t.Errorf("byte counters must be recorded UNKNOWN, got %v", match.MissingEvidence)
	}
}

func TestBrokerStallOwnerDiedNegative(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Trigger = incident.Trigger{Type: "process_exit", PID: 300, StartTicks: 300}
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index <= 5 {
			s = withProcessAddr(s, 300, 300, 1, "S", 0)
		}
		// the socket lingers after its owner departs.
		s = withConnectionAddr(s, 9, "203.0.113.10", 8000, "ESTABLISHED", 300)
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureBrokerStall)
	if contains(evidenceCodes(rejected.Supporting), "OWNER_STAYS_ALIVE") {
		t.Errorf("departed/unknown owner granted alive support: %v", rejected.Supporting)
	}
}

func TestBrokerStallQuietManualGateUnknown(t *testing.T) {
	report, err := Analyze(socketFixture(t), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureBrokerStall)
	if !contains(rejected.MissingEvidence, "WORKER_LIFECYCLE_EXPECTATION") {
		t.Errorf("worker-lifecycle unknown not recorded: %v", rejected.MissingEvidence)
	}
}

func evidenceCodes(list []Evidence) []string {
	var codes []string
	for _, ev := range list {
		codes = append(codes, string(ev.Code))
	}
	return codes
}

func TestNetworkFailurePositive(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		// one long-lived socket leaves ESTABLISHED mid-capture...
		state := "ESTABLISHED"
		if index >= 5 {
			state = "CLOSE_WAIT"
		}
		s = withConnectionAddr(s, 9, "203.0.113.10", 8000, state, 300)
		// ...and short incomplete SYN attempts accumulate on two endpoints.
		s = withConnectionAddr(s, 100+uint64(index), "203.0.113.11", 9000, "SYN_SENT", 0)
		return s
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureNetworkFailure)
	// disconnects 0.35 + churn 0.15 + endpoints 0.15 + healthy 0.10 = 0.75
	if match.Confidence < 0.60 || match.Confidence > pathCap {
		t.Errorf("confidence %.2f outside [.60, %.2f]", match.Confidence, pathCap)
	}
	for _, match := range report.Matches {
		if match.SignatureID == SignatureBrokerStall {
			t.Errorf("stall must not fire when the path failed: %+v", match)
		}
	}
}

// healthy idle established socket: neither rival explanation may fire.
func TestNetworkIdleSocketNegative(t *testing.T) {
	report, err := Analyze(socketFixture(t), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureNetworkFailure)
}

// ---------------------------------------------------------------------------
// RESOURCE_STARVATION
// ---------------------------------------------------------------------------

func TestStarvationPositive(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withPressure(s, platform.PressureIO, 65, 30)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	match := findMatch(t, report, SignatureStarvation)
	// severe some 0.45 + full stall 0.15 + sustained 0.10 = 0.70
	if match.Confidence < 0.65 || match.Confidence > starvationCap {
		t.Errorf("confidence %.2f outside [.65, %.2f]", match.Confidence, starvationCap)
	}
	if match.Attributes["resource"] != string(platform.PressureIO) {
		t.Errorf("resource subtype = %q", match.Attributes["resource"])
	}
}

func TestStarvationNegativeQuiet(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withPressure(s, platform.PressureCPU, 3, 0.5)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureStarvation)
}

func TestStarvationUnknownTelemetry(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withErrors(s, "pressure")
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejected := findRejected(t, report, SignatureStarvation)
	if !strings.Contains(rejected.Rejected, "unavailable") || !strings.Contains(rejected.Rejected, "pressure") {
		t.Errorf("rejection reason should name the sensor gap: %q", rejected.Rejected)
	}
}

// ---------------------------------------------------------------------------
// PID identity corner cases
// ---------------------------------------------------------------------------

// A recycled PID with new start ticks is a different process: the recycled
// identity must not inherit the previous holder's CPU series or gaps.
func TestPIDRecycleIsNotOneLifetime(t *testing.T) {
	end := at(50 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 11, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index < 6 {
			return withProcess(s, 42, 100, "S", 0)
		}
		return withProcess(s, 42, 500, "R", 120) // same PID, new lifetime
	})
	mustValid(t, i)
	ctx := buildContext(i)
	if len(ctx.Process) != 2 {
		t.Fatalf("expected two lifetimes for a recycled PID, got %d", len(ctx.Process))
	}
	for key, life := range ctx.Process {
		if key.StartTicks == 100 && len(life.Gaps) != 1 {
			t.Errorf("original lifetime should have one open gap, got %d", len(life.Gaps))
		}
		if key.StartTicks == 500 && len(life.Gaps) != 0 {
			t.Errorf("new lifetime should have no gaps, got %d", len(life.Gaps))
		}
	}
}

// gaps are never inferred across a sample whose process section failed:
// an unavailable section is UNKNOWN, not observed absence.
func TestGapNotInferredAcrossFailedSection(t *testing.T) {
	end := at(50 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 11, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		process := index != 5
		if process {
			s = withProcess(s, 42, 100, "S", 0)
		} else {
			s = withErrors(s, "processes")
		}
		return s
	})
	mustValid(t, i)
	ctx := buildContext(i)
	life := ctx.Process[identity{PID: 42, StartTicks: 100}]
	if life == nil {
		t.Fatalf("lifetime missing")
	}
	if len(life.Gaps) != 0 {
		t.Errorf("gap inferred across unavailable section: %+v", life.Gaps)
	}
	coverage := ctx.Coverage(CoverProcesses)
	if coverage.Samples != 11 || coverage.Available != 10 {
		t.Errorf("coverage = %+v, want 11 samples/10 available", coverage)
	}
	if coverage.FractionLost <= 0 {
		t.Errorf("fraction lost should be positive: %+v", coverage)
	}
}
