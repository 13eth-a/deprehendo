package diagnosis

import (
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

// oomDirectFixture mirrors oomCounterFixture, but the cgroup counter never
// rises: the only kernel evidence is the phase 6 tracer's oom:mark_victim
// record. eventPID/eventTicks let a case claim a different incarnation.
func oomDirectFixture(t *testing.T, eventPID int, eventTicks int64) SignatureMatch {
	t.Helper()
	i := validIncident(t, at(0), at(75*time.Second))
	snapshots := sampleSeries(t, at(0), 16, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 50, 80)
		if index >= 6 {
			s = systemSnapshot(at(0), 96, 80)
		}
		if index <= 5 {
			s = withProcess(s, 500, 500, "S", 0)
			s.Processes[len(s.Processes)-1].RSSBytes = 6 << 30
			s = withCgroup(s, 500, oomRunnerCgroup, 0)
		}
		s = withProcess(s, 600, 600, "S", 0)
		s = withCgroup(s, 600, oomOtherCgroup, 0)
		return s
	})
	for index := range snapshots {
		snapshots[index].Timestamp = at(time.Duration(index) * step)
	}
	i.Snapshots = snapshots
	i.Events = []incident.Event{{
		Type: incident.TraceOomKill, Timestamp: at(30 * time.Second),
		PID: eventPID, StartTicks: eventTicks, Provenance: incident.ProvenanceTrace,
	}}
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, m := range append(append([]SignatureMatch{}, report.Matches...), report.Rejections...) {
		if m.SignatureID == SignatureOOMKill {
			return m
		}
	}
	t.Fatal("OOM_KILL neither matched nor rejected")
	return SignatureMatch{}
}

// OOM_KILL@5: the tracer's victim-naming record is the strongest OOM evidence
// a bundle can carry, so it must lift the v1 cap that exists only because a
// disappearance plus memory pressure cannot distinguish OOM from a clean exit.
func TestOOMKillDirectKernelVictimRecordIsReported(t *testing.T) {
	match := oomDirectFixture(t, 500, 500)
	if !contains(evidenceCodes(match.Supporting), string(CodeKernelOOMVictim)) {
		t.Fatalf("supporting evidence lacks %s: %v", CodeKernelOOMVictim, evidenceCodes(match.Supporting))
	}
	if match.Confidence < DefaultMinConfidence {
		t.Fatalf("confidence %.2f below the report threshold %.2f", match.Confidence, DefaultMinConfidence)
	}
	if match.Confidence <= oomKernelCap {
		t.Fatalf("confidence %.2f: a victim-naming record must outrank the sampled-counter cap %.2f", match.Confidence, oomKernelCap)
	}
	if match.Confidence > oomDirectCap {
		t.Fatalf("confidence %.2f above the direct-evidence cap %.2f", match.Confidence, oomDirectCap)
	}
	if contains(match.MissingEvidence, "KERNEL_OOM_EVENT") {
		t.Fatalf("kernel OOM evidence present but still listed missing: %v", match.MissingEvidence)
	}
	if match.Rejected != "" {
		t.Fatalf("direct kernel evidence still rejects the match: %q", match.Rejected)
	}
}

// A record for another incarnation of the same PID is not this victim: the
// signature must stay at the v1 cap and keep naming the missing telemetry.
func TestOOMKillDirectRecordForAnotherIncarnationIsNotEvidence(t *testing.T) {
	match := oomDirectFixture(t, 500, 999)
	if contains(evidenceCodes(match.Supporting), string(CodeKernelOOMVictim)) {
		t.Fatalf("another incarnation's record was attributed: %v", evidenceCodes(match.Supporting))
	}
	if match.Confidence > oOMCap {
		t.Fatalf("confidence %.2f above the v1 cap %.2f", match.Confidence, oOMCap)
	}
	if !contains(match.MissingEvidence, "KERNEL_OOM_EVENT") {
		t.Fatalf("kernel OOM event must remain missing: %v", match.MissingEvidence)
	}
}
