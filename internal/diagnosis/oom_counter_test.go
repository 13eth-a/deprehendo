package diagnosis

import (
	"strings"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
)

// OOM_KILL@3: the kernel's memory.events oom_kill counter of the victim's own
// cgroup, rising across the interval in which the victim vanished, is the
// kernel OOM evidence that OOM_KILL@2 never had. Real-runner scenario S11:
// the job (victim) is OOM-killed and the listener and worker stay in the same
// service cgroup for a moment, so the next sample reads the risen counter.

const (
	oomRunnerCgroup = "/system.slice/actions.runner.acme-service.r1.service"
	oomOtherCgroup  = "/system.slice/other.service"
)

func withCgroup(s collector.Snapshot, pid int, path string, kills uint64) collector.Snapshot {
	for i := range s.Processes {
		if s.Processes[i].PID == pid {
			s.Processes[i].Cgroup = &platform.CgroupSnapshot{Path: path, OOMEventsAvailable: true, OOMKills: kills}
		}
	}
	return s
}

// oomCounterFixture: victim 500 lives through sample 5 and vanishes at
// sample 6 with host memory at 96%; sibling 600 stays in siblingCgroup for
// the whole capture. the sibling's counter reads 0 before riseAt and 1 from
// riseAt on.
func oomCounterFixture(t *testing.T, siblingCgroup string, riseAt int) SignatureMatch {
	t.Helper()
	i := validIncident(t, at(0), at(75*time.Second))
	snapshots := sampleSeries(t, at(0), 16, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 50, 80)
		if index >= 6 {
			s = systemSnapshot(at(0), 96, 80)
		}
		kills := uint64(0)
		if index >= riseAt {
			kills = 1
		}
		if index <= 5 {
			s = withProcess(s, 500, 500, "S", 0)
			s.Processes[len(s.Processes)-1].RSSBytes = 6 << 30
			s = withCgroup(s, 500, oomRunnerCgroup, kills)
		}
		s = withProcess(s, 600, 600, "S", 0)
		s = withCgroup(s, 600, siblingCgroup, kills)
		return s
	})
	for index := range snapshots {
		snapshots[index].Timestamp = at(time.Duration(index) * step)
	}
	i.Snapshots = snapshots
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

func TestOOMKillKernelCounterRiseIsReported(t *testing.T) {
	match := oomCounterFixture(t, oomRunnerCgroup, 6)
	if match.Confidence < DefaultMinConfidence {
		t.Fatalf("confidence %.2f: a kernel oom_kill rise in the victim's cgroup must clear the report threshold %.2f", match.Confidence, DefaultMinConfidence)
	}
	if !contains(evidenceCodes(match.Supporting), string(CodeKernelOOMCounter)) {
		t.Fatalf("supporting evidence lacks %s: %v", CodeKernelOOMCounter, evidenceCodes(match.Supporting))
	}
	if contains(match.MissingEvidence, "KERNEL_OOM_EVENT") {
		t.Fatalf("kernel OOM evidence present but still listed missing: %v", match.MissingEvidence)
	}
	if match.Confidence > oomKernelCap {
		t.Fatalf("confidence %.2f above the cap %.2f", match.Confidence, oomKernelCap)
	}
	// the cgroup path (a runner unit name embeds the repository) never
	// reaches the diagnosis.
	for _, ev := range match.Supporting {
		if strings.Contains(strings.ToLower(evidenceString(ev)), "acme") {
			t.Fatalf("cgroup path leaked into evidence: %+v", ev)
		}
	}
}

func TestOOMKillWithoutCounterRiseStaysCapped(t *testing.T) {
	match := oomCounterFixture(t, oomRunnerCgroup, 99)
	if match.Confidence > oOMCap {
		t.Fatalf("no counter rise: confidence %.2f above the v1 cap %.2f", match.Confidence, oOMCap)
	}
	if !contains(match.MissingEvidence, "KERNEL_OOM_EVENT") {
		t.Fatalf("kernel OOM event must stay missing: %v", match.MissingEvidence)
	}
}

// A rise in some other cgroup is not this victim's kill.
func TestOOMKillCounterRiseInAnotherCgroupIsNotEvidence(t *testing.T) {
	match := oomCounterFixture(t, oomOtherCgroup, 6)
	if contains(evidenceCodes(match.Supporting), string(CodeKernelOOMCounter)) || match.Confidence > oOMCap {
		t.Fatalf("another cgroup's rise was attributed to the victim: %.2f %v", match.Confidence, evidenceCodes(match.Supporting))
	}
}

// the first reading after the departure shows no rise; a rise read 10 s
// after the victim was last seen is outside the window and is not its kill.
func TestOOMKillLateCounterRiseIsNotEvidence(t *testing.T) {
	match := oomCounterFixture(t, oomRunnerCgroup, 7)
	if contains(evidenceCodes(match.Supporting), string(CodeKernelOOMCounter)) {
		t.Fatalf("a late rise was attributed: %v", evidenceCodes(match.Supporting))
	}
}

// Real-runner S11 (inc_2b729576, run 41264326503): the collector reads the
// process table before the cgroup counters, so the sample that last listed the
// OOM-killed job process already carried the risen counter (2 -> 3). measuring
// only from the next reading missed it and the fresh run reported no OOM_KILL.
func TestOOMKillCounterRiseInTheVictimsFinalSampleIsEvidence(t *testing.T) {
	match := oomCounterFixture(t, oomRunnerCgroup, 5)
	if !contains(evidenceCodes(match.Supporting), string(CodeKernelOOMCounter)) {
		t.Fatalf("a rise recorded in the victim's final sample was not attributed: %v", evidenceCodes(match.Supporting))
	}
	if match.Confidence < DefaultMinConfidence {
		t.Fatalf("confidence %.2f: the rise must clear the report threshold %.2f", match.Confidence, DefaultMinConfidence)
	}
}

// A rise that already happened before the victim's final sample is part of the
// baseline and is not this victim's kill.
func TestOOMKillCounterRiseBeforeTheFinalSampleIsNotAttributed(t *testing.T) {
	match := oomCounterFixture(t, oomRunnerCgroup, 3)
	if contains(evidenceCodes(match.Supporting), string(CodeKernelOOMCounter)) {
		t.Fatalf("a rise from before the victim vanished was attributed: %v", evidenceCodes(match.Supporting))
	}
}

func evidenceString(ev Evidence) string {
	var b strings.Builder
	b.WriteString(string(ev.Code))
	if m, ok := ev.Observed.(map[string]any); ok {
		for k, v := range m {
			b.WriteString(k)
			if s, ok := v.(string); ok {
				b.WriteString(s)
			}
		}
	}
	return b.String()
}
