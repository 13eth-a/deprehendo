package tests

// GitHub runner integration for the tracer bridge (6.60).
//
// the fake runner from phase 5 starts Runner.Listener, which spawns
// Runner.Worker, which spawns the job tree, and then terminates its own
// process group. this test checks two things the trace work must not lose:
//
//  1. correlation: the listener/worker/job roles are identifiable by real
//     PPID/PGID relationships on live processes, so a trace event can be
//     attributed to the right role even after the worker exec'd the job
//     binary;
//  2. merging: kernel-trace edges and snapshot-derived edges for the same
//     PIDs collapse into one timeline, keeping both evidence sources and
//     ranking the direct one above the inferred one.
//
// the trace stream itself is synthesized from the real process identities.
// this test does not need a kernel tracer to check correlation and merge
// semantics, and it says so rather than pretending a backend ran.

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
	"deprehendo/internal/simhelper"
	"deprehendo/internal/trace"
)

func TestGitHubRunnerTraceCorrelation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("fake runner harness requires Linux or macOS, got %s", runtime.GOOS)
	}
	root := t.TempDir()
	var stderr bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, simPath, "github", simhelper.GitHubRunnerSelfKill,
		"--root", root, "--duration", "3s", "--keep")
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake runner: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			t.Errorf("fake runner did not stop; stderr: %s", stderr.String())
		}
	})

	state := waitForRunnerTree(t, root, 15*time.Second)
	listener, worker, job := runnerProcesses(t, state)

	if err := correlateRunnerTree(listener, worker, job); err != nil {
		t.Fatalf("%v\nprocesses: listener=%+v worker=%+v job=%+v", err, listener, worker, job)
	}

	// build the stream a capable kernel backend would have produced for this
	// tree: execs in parent order, one group signal, then the exits.
	basems := time.Now().UnixMilli() - 100
	monobase := time.Now().UnixNano() - int64(100*time.Millisecond)
	source := trace.SourceProcConnector
	seq := uint64(0)
	next := func(offsetMs int64) trace.TraceEvent {
		seq++
		return trace.TraceEvent{
			SchemaVersion: trace.SchemaVersion,
			Sequence:      seq,
			MonotonicNs:   monobase + offsetMs*int64(time.Millisecond),
			WallUnixMs:    basems + offsetMs,
			Source:        source,
		}
	}
	execevent := func(pid, ppid, pgid int, path string, offsetMs int64) trace.TraceEvent {
		e := next(offsetMs)
		e.Type, e.PID, e.PPID, e.PGID, e.ExecPath = trace.EventEXEC, uint32(pid), uint32(ppid), uint32(pgid), path
		return e
	}
	exitevent := func(pid int, signal uint8, offsetMs int64) trace.TraceEvent {
		e := next(offsetMs)
		e.Type, e.PID, e.Signal = trace.EventEXIT, uint32(pid), signal
		if signal != 0 {
			e.Fact = trace.SignalDeliveredToExit
		}
		return e
	}

	groupsignal := next(100)
	groupsignal.Type = trace.EventSIGNAL
	groupsignal.PID = uint32(worker.PID)
	groupsignal.PGID = uint32(worker.PGID)
	groupsignal.SenderPID = uint32(job.PID)
	groupsignal.Signal = 9
	groupsignal.Fact = trace.SignalSent

	traced := []incident.Event{
		incident.FromTrace(execevent(listener.PID, listener.PPID, listener.PGID, "Runner.Listener", 0), incident.ProvenanceTrace),
		incident.FromTrace(execevent(worker.PID, listener.PID, worker.PGID, "Runner.Worker", 10), incident.ProvenanceTrace),
		incident.FromTrace(execevent(job.PID, worker.PID, job.PGID, "_work/job", 20), incident.ProvenanceTrace),
		incident.FromTrace(groupsignal, incident.ProvenanceTrace),
		incident.FromTrace(exitevent(job.PID, 9, 160), incident.ProvenanceTrace),
		incident.FromTrace(exitevent(worker.PID, 9, 161), incident.ProvenanceTrace),
		incident.FromTrace(exitevent(listener.PID, 9, 162), incident.ProvenanceTrace),
	}
	// the polling stream saw the worker and listener vanish one sample later.
	polling := []incident.Event{
		{Timestamp: time.UnixMilli(basems + 400), Type: incident.ProcessExited, PID: worker.PID, StartTicks: worker.StartTicks},
		{Timestamp: time.UnixMilli(basems + 401), Type: incident.ProcessExited, PID: listener.PID, StartTicks: listener.StartTicks},
	}

	merged := incident.Merge(polling, traced, 2*time.Second)

	var execs, exits, signals, pollingExits int
	var workerExit, listenerExit, jobExit *incident.Event
	for i := range merged {
		e := merged[i]
		switch e.Type {
		case incident.TraceProcessExec:
			execs++
		case incident.TraceProcessExit:
			exits++
			switch e.PID {
			case worker.PID:
				workerExit = &merged[i]
			case listener.PID:
				listenerExit = &merged[i]
			case job.PID:
				jobExit = &merged[i]
			}
		case incident.ProcessExited:
			pollingExits++
		default:
			if e.SignalFact == "SIGNAL_SENT" {
				signals++
			}
		}
	}
	if execs != 3 || exits != 3 {
		t.Errorf("merged timeline has exec=%d exit=%d, want 3/3 (one entry per process, no duplicates)", execs, exits)
	}
	if pollingExits != 0 {
		t.Errorf("merged timeline still shows %d snapshot-only exits; the trace copies must own the normalized entry", pollingExits)
	}
	if signals != 1 {
		t.Errorf("merged timeline has %d signal events, want 1", signals)
	}
	for name, e := range map[string]*incident.Event{"worker": workerExit, "listener": listenerExit, "job": jobExit} {
		if e == nil {
			t.Fatalf("no exit entry for %s", name)
		}
		if e.Provenance != incident.ProvenanceTrace {
			t.Errorf("%s exit provenance = %q, want %q", name, e.Provenance, incident.ProvenanceTrace)
		}
		if e.Signal != 9 || e.SignalFact != "EXITED_BY_SIGNAL" {
			t.Errorf("%s exit does not record the signal fact: %+v", name, *e)
		}
	}
	// corroboration survives; stronger evidence does not delete weaker
	// evidence (6.30/6.31).
	if workerExit == nil || listenerExit == nil {
		t.Fatal("missing exits")
	}
	for name, e := range map[string]*incident.Event{"worker": workerExit, "listener": listenerExit} {
		if len(e.CorroboratedBy) != 1 || e.CorroboratedBy[0] != incident.ProvenanceSnapshotDiff {
			t.Errorf("%s exit did not keep its snapshot corroboration: %v", name, e.CorroboratedBy)
		}
		if q := incident.EvidenceQuality(*e); q != "direct_corroborated" {
			t.Errorf("%s exit evidence quality = %q, want direct_corroborated", name, q)
		}
	}
	if q := incident.EvidenceQuality(*jobExit); q != "direct_kernel" {
		t.Errorf("job exit evidence quality = %q, want direct_kernel", q)
	}

	// ordering: the group signal must precede every exit, and the whole
	// chain must be non-decreasing on the monotonic key.
	signalindex, firstexit := -1, -1
	for i, e := range merged {
		if e.SignalFact == "SIGNAL_SENT" && signalindex < 0 {
			signalindex = i
		}
		if e.Type == incident.TraceProcessExit && firstexit < 0 {
			firstexit = i
		}
	}
	if signalindex < 0 || firstexit < 0 || signalindex > firstexit {
		t.Errorf("causal order lost: signal index=%d first exit index=%d", signalindex, firstexit)
	}
	for i := 1; i < len(merged); i++ {
		if merged[i].MonotonicNs != 0 && merged[i-1].MonotonicNs != 0 && merged[i].MonotonicNs < merged[i-1].MonotonicNs {
			t.Errorf("timeline not monotonic at %d: %d < %d", i, merged[i].MonotonicNs, merged[i-1].MonotonicNs)
		}
	}
}

// waitForRunnerTree polls the harness state until the worker and job tree are
// published, so the caller never correlates against a half-started runner.
func waitForRunnerTree(t *testing.T, root string, within time.Duration) simhelper.GitHubState {
	t.Helper()
	deadline := time.Now().Add(within)
	var last simhelper.GitHubState
	for {
		state, err := simhelper.ReadGitHubState(root)
		if err == nil {
			last = state
			if state.Listener > 0 && state.Worker > 0 && state.JobRoot > 0 {
				return state
			}
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("runner tree never appeared; last state: %+v", last)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// runnerProcesses resolves the published PIDs in one snapshot. A PID that
// vanished between publication and the snapshot is a harness scheduling
// problem, not a correlation failure, so it fails with the ids named.
func runnerProcesses(t *testing.T, state simhelper.GitHubState) (platform.Process, platform.Process, platform.Process) {
	t.Helper()
	procs, err := platform.Processes()
	if err != nil {
		t.Fatalf("process snapshot: %v", err)
	}
	bypid := make(map[int]platform.Process, len(procs))
	for _, p := range procs {
		bypid[p.PID] = p
	}
	require := func(name string, pid int) platform.Process {
		p, ok := bypid[pid]
		if !ok {
			t.Fatalf("%s pid %d is not in the process table", name, pid)
		}
		return p
	}
	return require("listener", state.Listener), require("worker", state.Worker), require("job", state.JobRoot)
}

// correlateRunnerTree checks the role topology a trace consumer relies on.
func correlateRunnerTree(listener, worker, job platform.Process) error {
	if listener.PGID == 0 || listener.PGID != listener.PID {
		return fmt.Errorf("listener %d is not its own process-group leader (pgid=%d)", listener.PID, listener.PGID)
	}
	if worker.PPID != listener.PID {
		return fmt.Errorf("worker %d ppid=%d, want listener %d", worker.PID, worker.PPID, listener.PID)
	}
	if worker.PGID == 0 || worker.PGID != worker.PID {
		return fmt.Errorf("worker %d is not its own process-group leader (pgid=%d)", worker.PID, worker.PGID)
	}
	if job.PPID != worker.PID {
		return fmt.Errorf("job %d ppid=%d, want worker %d", job.PID, job.PPID, worker.PID)
	}
	if job.PGID == 0 || job.PGID != job.PID {
		return fmt.Errorf("job %d is not its own process-group leader (pgid=%d)", job.PID, job.PGID)
	}
	return nil
}
