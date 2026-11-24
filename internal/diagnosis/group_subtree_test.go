package diagnosis

import (
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

// Real-runner S2 (2026-11-02, bundle inc_ace0ee27 on the disposable linux VM):
// a healthy job finished and the analyzer reported PROCESS_GROUP_TERMINATION at
// HIGH/CRITICAL. nothing was killed as a group. GitHub's runner does not put a
// job in its own process group, so the job's shell, the worker and the listener
// all share one PGID; when the job ends only the job's subtree leaves and the
// listener keeps running. "several members of one group vanished" therefore
// describes every normal job teardown, and the group was never terminated.
func runnerSubtreeFixture(t *testing.T) *incident.Incident {
	t.Helper()
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		// the listener (and its service tree) survives the whole capture.
		s = withProcessGroup(s, 3322, 146233, 3297, "S", 0)
		if index < 6 {
			s = withProcessGroup(s, 3803, 188507, 3297, "S", 0) // step shell
			s = withProcessGroup(s, 3820, 188584, 3297, "S", 0) // Runner.Worker
			s = withProcessGroup(s, 3822, 188585, 3297, "S", 0) // job process
		}
		return s
	})
	mustValid(t, i)
	return i
}

func TestGroupKillRejectsAJobTreeEndingUnderALiveRunner(t *testing.T) {
	report, err := Analyze(runnerSubtreeFixture(t), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	rejection := findRejected(t, report, SignatureGroupKill)
	if !strings.Contains(rejection.Rejected, "kept running") {
		t.Fatalf("rejection reason does not name the surviving group member: %q", rejection.Rejected)
	}
	for _, match := range report.Matches {
		if match.SignatureID == SignatureGroupKill {
			t.Fatalf("a normal job teardown was reported as a group kill: %+v", match)
		}
	}
}

func wholeGroupLeavesFixture(t *testing.T) *incident.Incident {
	t.Helper()
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		if index < 6 {
			s = withProcessGroup(s, 3322, 146233, 3297, "S", 0)
			s = withProcessGroup(s, 3820, 188584, 3297, "S", 0)
			s = withProcessGroup(s, 3822, 188585, 3297, "S", 0)
		}
		return s
	})
	mustValid(t, i)
	return i
}

// the group kill is still found when the whole group really goes: here the
// supervisor leaves with its job tree in the same coordinated window.
func TestGroupKillStillMatchesWhenTheWholeGroupLeaves(t *testing.T) {
	report, err := Analyze(wholeGroupLeavesFixture(t), Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findMatch(t, report, SignatureGroupKill)
}

// A stated runner stop or self-update ends the runner's tree, so the whole
// collapse is the intent's business even though the section could only name
// the role-tagged supervisor (real-runner bundle inc_571d5dba: a self-update
// left six untagged processes whose exit was reported as a group kill).
func TestGroupKillTheRunnerTreeIntentExplainsIsRejected(t *testing.T) {
	covers := []IntentCover{{
		Processes:  []ProcessIdentity{{PID: 3322, StartTicks: 146233}},
		From:       at(20 * time.Second),
		Until:      at(50 * time.Second),
		RunnerTree: true,
	}}
	report, err := Analyze(wholeGroupLeavesFixture(t), Options{Covers: covers})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureGroupKill)
}

// Real-runner regression (2026-11-04, selfhosted-e2e run 41935809421): with
// the tracer active and lossless, a job GitHub reports SUCCEEDED produced
// PROCESS_GROUP_TERMINATION. the job's shell and worker exited normally into a
// process group of their own, so the group emptied; the kernel had recorded
// both exits and the signature never read them. A traced normal exit is direct
// evidence that the process exited on its own.
func TestGroupKillIgnoresTracedNormalExits(t *testing.T) {
	i := wholeGroupLeavesFixture(t)
	exits := map[int]int64{3322: 146233, 3820: 188584, 3822: 188585}
	for pid, ticks := range exits {
		i.Events = append(i.Events, incident.Event{
			Type: incident.TraceProcessExit, PID: pid, StartTicks: ticks,
			Timestamp: at(30 * time.Second), ExitStatus: "exit:0",
			Provenance: incident.ProvenanceTrace,
		})
	}
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureGroupKill)
	for _, match := range report.Matches {
		if match.SignatureID == SignatureGroupKill {
			t.Fatalf("normal traced exits were reported as a group kill: %+v", match)
		}
	}
}

// the negative side: a signalled exit is exactly what a group kill looks like,
// so the same group must still match when the tracer says SIGKILL.
func TestGroupKillStillMatchesTracedSignalledExits(t *testing.T) {
	i := wholeGroupLeavesFixture(t)
	exits := map[int]int64{3322: 146233, 3820: 188584, 3822: 188585}
	for pid, ticks := range exits {
		i.Events = append(i.Events, incident.Event{
			Type: incident.TraceProcessExit, PID: pid, StartTicks: ticks,
			Timestamp: at(30 * time.Second), ExitStatus: "signal:9",
			Provenance: incident.ProvenanceTrace,
		})
	}
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findMatch(t, report, SignatureGroupKill)
}

// A job-scoped cancellation names its own members; it must not absorb an
// untagged group collapse.
func TestGroupKillJobScopedCoverDoesNotExplainTheGroup(t *testing.T) {
	covers := []IntentCover{{
		Processes: []ProcessIdentity{{PID: 3322, StartTicks: 146233}},
		From:      at(20 * time.Second),
		Until:     at(50 * time.Second),
	}}
	report, err := Analyze(wholeGroupLeavesFixture(t), Options{Covers: covers})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findMatch(t, report, SignatureGroupKill)
}

// jobTreeFixture keeps the runner worker alive while the job's own process
// group (job root 910 and its child 911) leaves together. that is the real
// runner's shape: the job gets its own PGID under the worker.
func jobTreeFixture(t *testing.T) *incident.Incident {
	t.Helper()
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s = withProcessAddr(s, 900, 9000, 1, "S", 0) // runner worker
		if index < 6 {
			s = withProcessAddr(s, 910, 9100, 900, "S", 0) // job root
			s = withProcessAddr(s, 911, 9101, 910, "S", 0) // job process
			for n := range s.Processes {
				if s.Processes[n].PID == 910 || s.Processes[n].PID == 911 {
					s.Processes[n].PGID = 910
				}
			}
		}
		return s
	})
	mustValid(t, i)
	return i
}

// Real-runner regression (2026-11-04, selfhosted-e2e run 41950041166): the
// runner SIGKILLs leftover job processes at the end of a successful job. the
// provider names only the role-tagged worker, so a stated job outcome covers
// the worker's observed tree and the job's own group collapse is cleanup.
func TestGroupKillJobTreeCoverExplainsTheJobsOwnGroup(t *testing.T) {
	covers := []IntentCover{{
		Processes: []ProcessIdentity{{PID: 900, StartTicks: 9000}},
		From:      at(20 * time.Second),
		Until:     at(50 * time.Second),
		JobTree:   true,
	}}
	report, err := Analyze(jobTreeFixture(t), Options{Covers: covers})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findRejected(t, report, SignatureGroupKill)
}

// the safety side: a job-tree cover must not absorb a group that the job did
// not start, even inside the same window.
func TestGroupKillJobTreeCoverDoesNotExplainAnUnrelatedGroup(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, step, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		s = withProcessAddr(s, 900, 9000, 1, "S", 0) // job's worker, alive throughout
		if index < 6 {
			s = withProcessAddr(s, 920, 9200, 1, "S", 0)   // unrelated parent
			s = withProcessAddr(s, 921, 9201, 920, "S", 0) // and child
			for n := range s.Processes {
				if s.Processes[n].PID == 920 || s.Processes[n].PID == 921 {
					s.Processes[n].PGID = 920
				}
			}
		}
		return s
	})
	mustValid(t, i)
	covers := []IntentCover{{
		Processes: []ProcessIdentity{{PID: 900, StartTicks: 9000}},
		From:      at(20 * time.Second),
		Until:     at(50 * time.Second),
		JobTree:   true,
	}}
	report, err := Analyze(i, Options{Covers: covers})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findMatch(t, report, SignatureGroupKill)
}
