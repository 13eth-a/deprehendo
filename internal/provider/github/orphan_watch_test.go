package github

import (
	"context"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
)

// Real-runner scenario S8 (docs/github/real-runner-verification.md): a step
// starts `sleep 600` without RUNNER_TRACKING_ID and ends. the step's shell
// exits first, so the sleep is reparented to init; then the worker exits.
// under `github watch` the recorder keeps only the listener's tree. with the
// stateless filter the reparented sleep vanished from every later sample, so
// GITHUB_JOB_ORPHANED could never fire on a real runner. the scheduler's
// TreeSelection retains it.

const procSurvivor = 400

func s8Sequence(base time.Time) []struct {
	at    time.Time
	table []platform.Process
} {
	listener := platform.Process{PID: procListener, PPID: 1, StartTicks: ticksListener, Name: "Runner.Listener", State: "S"}
	worker := platform.Process{PID: procWorker, PPID: procListener, StartTicks: ticksWorker, Name: "Runner.Worker", State: "S"}
	step := platform.Process{PID: procJobRoot, PPID: procWorker, StartTicks: ticksJobRoot, Name: "bash", State: "S"}
	survivor := platform.Process{PID: procSurvivor, PPID: procJobRoot, StartTicks: 40, Name: "sleep", State: "S"}
	reparented := survivor
	reparented.PPID = 1
	initp := platform.Process{PID: 1, PPID: 0, StartTicks: 1, Name: "systemd", State: "S"}
	type sample = struct {
		at    time.Time
		table []platform.Process
	}
	seq := []sample{
		{base, []platform.Process{initp, listener, worker, step, survivor}},
		{base.Add(2 * time.Second), []platform.Process{initp, listener, worker, step, survivor}},
		{base.Add(5 * time.Second), []platform.Process{initp, listener, worker, reparented}}, // step ended
		{base.Add(8 * time.Second), []platform.Process{initp, listener, reparented}},         // worker exited
	}
	for at := 10 * time.Second; at <= 30*time.Second; at += 2 * time.Second {
		seq = append(seq, sample{base.Add(at), []platform.Process{initp, listener, reparented}})
	}
	return seq
}

func orphanEvents(t *testing.T, sticky bool) int {
	t.Helper()
	host, _, base := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs",
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan 6f1c job 0d2e received.")
	s := attachSession(t, host)
	filter := collector.Filter{PIDs: []int{procListener}, Descendants: true}
	selection := collector.TreeSelection{Filter: filter}
	var last time.Time
	for _, sample := range s8Sequence(base) {
		host.table = sample.table
		var all []collector.ProcessSnapshot
		for _, p := range sample.table {
			all = append(all, collector.ProcessSnapshot{Process: p})
		}
		var kept []collector.ProcessSnapshot
		if sticky {
			kept = selection.Select(all)
		} else {
			kept = filter.Select(all)
		}
		s.Observe(context.Background(), collector.Snapshot{Timestamp: sample.at, Processes: kept})
		last = sample.at
	}
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), last.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	n := 0
	for _, ev := range section.Events {
		if ev.Type == EventJobOrphaned && ev.Process != nil && ev.Process.PID == procSurvivor {
			n++
		}
	}
	return n
}

func TestS8OrphanSurvivesTheWatchFilter(t *testing.T) {
	if got := orphanEvents(t, true); got != 1 {
		t.Fatalf("GITHUB_JOB_ORPHANED for the reparented sleep under github watch = %d, want 1", got)
	}
}

// the root cause, pinned: with the stateless per-sample filter the survivor
// is invisible after reparenting, so nothing can be reported.
func TestS8StatelessFilterLosesTheOrphan(t *testing.T) {
	if got := orphanEvents(t, false); got != 0 {
		t.Fatalf("stateless filter unexpectedly kept the orphan (%d events); the S8 diagnosis in the docs is wrong", got)
	}
}
