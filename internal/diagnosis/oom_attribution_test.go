package diagnosis

import (
	"testing"
	"time"

	"runopsy/internal/collector"
)

// principal review of secondary L2 (2026-11-02). L2 lets the sample in which the victim
// was last listed carry its own kill: a sample reads the process table before
// the cgroup counters. but that same reading also holds the kill of any
// cgroup member that vanished just before. A sibling that was still listed in
// that sample must not inherit the kernel evidence for an earlier departure.
//
// victim 500 (big) is last listed in sample 5. sibling 501 (the step's shell)
// is still listed in sample 6 and exits after it. the oom_kill counter is
// first read as risen in sample 6. the kill is 500's; 501 gets no kernel
// evidence. A 600 process keeps the cgroup readable throughout.
func oomSiblingContext(t *testing.T) *AnalysisContext {
	t.Helper()
	i := validIncident(t, at(0), at(75*time.Second))
	snapshots := sampleSeries(t, at(0), 16, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 50, 80)
		if index >= 6 {
			s = systemSnapshot(at(0), 96, 80)
		}
		kills := uint64(0)
		if index >= 6 {
			kills = 1
		}
		if index <= 5 {
			s = withProcess(s, 500, 500, "S", 0)
			s.Processes[len(s.Processes)-1].RSSBytes = 6 << 30
			s = withCgroup(s, 500, oomRunnerCgroup, kills)
		}
		if index <= 6 {
			s = withProcess(s, 501, 501, "S", 0)
			s = withCgroup(s, 501, oomRunnerCgroup, kills)
		}
		s = withProcess(s, 600, 600, "S", 0)
		s = withCgroup(s, 600, oomRunnerCgroup, kills)
		return s
	})
	for index := range snapshots {
		snapshots[index].Timestamp = at(time.Duration(index) * step)
	}
	i.Snapshots = snapshots
	mustValid(t, i)
	return buildContext(i)
}

func TestOOMRiseIsNotGivenToASiblingThatOutlivedTheVictim(t *testing.T) {
	ctx := oomSiblingContext(t)
	if _, _, ok := ctx.kernelOOMRise(ctx.Process[identity{500, 500}]); !ok {
		t.Fatal("the victim lost its own kernel evidence")
	}
	if delta, _, ok := ctx.kernelOOMRise(ctx.Process[identity{501, 501}]); ok {
		t.Fatalf("a sibling listed after the victim vanished inherited the kill (delta %d)", delta)
	}
}

// the real S11 shape L2 was written for still holds: the victim is listed in
// the very sample whose counter already shows its kill, and no other member
// departed in that interval.
func TestOOMRiseInTheVictimsFinalSampleStillCounts(t *testing.T) {
	i := validIncident(t, at(0), at(75*time.Second))
	snapshots := sampleSeries(t, at(0), 16, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 50, 80)
		if index >= 6 {
			s = systemSnapshot(at(0), 96, 80)
		}
		kills := uint64(0)
		if index >= 5 {
			kills = 1
		}
		if index <= 5 {
			s = withProcess(s, 500, 500, "S", 0)
			s = withCgroup(s, 500, oomRunnerCgroup, kills)
		}
		s = withProcess(s, 600, 600, "S", 0)
		s = withCgroup(s, 600, oomRunnerCgroup, kills)
		return s
	})
	for index := range snapshots {
		snapshots[index].Timestamp = at(time.Duration(index) * step)
	}
	i.Snapshots = snapshots
	mustValid(t, i)
	ctx := buildContext(i)
	if _, _, ok := ctx.kernelOOMRise(ctx.Process[identity{500, 500}]); !ok {
		t.Fatal("a rise read in the victim's final sample was not attributed")
	}
}
