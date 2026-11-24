//go:build linux

package trace

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// live §11.1 attack cases against the real tracer and kernel. like the other
// live tests they skip unless DEPREHENDO_TRACE_BINARY names a working tracer.
// the expected outcome in every case is the contract's: the recorder keeps
// going, and anything the tracer could not deliver is reported, never silent.

// procStartTicks reads a live process's identity: field 22 of
// /proc/<pid>/stat (start time in clock ticks), the same key the tracer uses.
func procStartTicks(t *testing.T, pid uint32) int64 {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatalf("read stat of %d: %v", pid, err)
	}
	s := string(raw)
	fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		t.Fatalf("short stat for %d: %q", pid, s)
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		t.Fatalf("start time of %d: %v", pid, err)
	}
	return ticks
}

// TestLiveRefusesWatchOfReusedIdentity: "a restart while a watched PID has
// been reused". after a restart the agent re-pushes PIDs with the identity it
// observed earlier; if a PID now belongs to another process, its start time
// differs. that is reproduced here by claiming a wrong identity for a live
// PID. the tracer must refuse that PID alone, apply the rest, and report
// nothing about the process it was not asked to watch.
func TestLiveRefusesWatchOfReusedIdentity(t *testing.T) {
	log := newLiveEventLog()
	live := startLiveTracer(t, log.sink)
	starts, pids := spawnGatedStarts(t, 2)
	kept, reused := pids[0], pids[1]

	tracker := NewWatchTracker()
	tracker.SetWatched([]Watched{
		{PID: kept, StartTicks: procStartTicks(t, kept)},
		{PID: reused, StartTicks: procStartTicks(t, reused) + 1},
	})
	if err := tracker.Drive(live.session, 3*time.Second); err != nil {
		t.Fatalf("a stale PID must not fail the push: %v", err)
	}
	if got := tracker.Stale(); got != 1 {
		t.Fatalf("stale refusals = %d, want 1", got)
	}
	if got := tracker.View(); len(got) != 1 || got[0] != kept {
		t.Fatalf("desired set = %v, want [%d]", got, kept)
	}

	releaseGatedStarts(starts)
	sawexit := func(pid uint32) bool {
		_, exits, _ := log.snapshot()
		return exits[pid] > 0
	}
	deadline := time.Now().Add(5 * time.Second)
	for !sawexit(kept) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !sawexit(kept) {
		t.Fatalf("the correctly identified PID %d was not traced", kept)
	}
	for _, s := range starts {
		_, _ = s.cmd.Process.Wait()
	}
	time.Sleep(300 * time.Millisecond) // any event for the refused PID would be here by now
	execs, exits, _ := log.snapshot()
	if n := execs[reused] + exits[reused]; n != 0 {
		t.Fatalf("the refused PID %d produced %d events: its watch was adopted", reused, n)
	}
}

// TestLiveSocketFillWhileAgentStalled: "the tracer filling its socket while
// the agent is stopped". the agent stops reading for two seconds while a
// watched shell churns through short-lived processes, so the socket and the
// tracer's bounded queue fill. afterwards the same session must still be
// alive and delivering, and every process the agent did not see must be
// accounted for as reported loss.
func TestLiveSocketFillWhileAgentStalled(t *testing.T) {
	const n = 3000
	const stall = 2 * time.Second
	var (
		mu       sync.Mutex
		execs    = map[uint32]bool{}
		exits    = map[uint32]bool{}
		stalled  bool
		released time.Time
		after    int
	)
	gate := make(chan struct{})
	sink := func(e TraceEvent) {
		mu.Lock()
		first := !stalled
		stalled = true
		mu.Unlock()
		if first {
			<-gate // the agent stops reading
		}
		mu.Lock()
		defer mu.Unlock()
		switch e.Type {
		case EventEXEC:
			execs[e.PID] = true
		case EventEXIT:
			exits[e.PID] = true
		}
		if !released.IsZero() {
			after++
		}
	}
	live := startLiveTracer(t, sink)

	script := fmt.Sprintf(`read x; i=0; while [ "$i" -lt %d ]; do /bin/true; i=$((i+1)); done`, n)
	driver := exec.Command("sh", "-c", script)
	stdin, err := driver.StdinPipe()
	if err != nil {
		t.Fatalf("driver stdin: %v", err)
	}
	if err := driver.Start(); err != nil {
		t.Fatalf("start driver: %v", err)
	}
	t.Cleanup(func() { _ = driver.Process.Kill(); _, _ = driver.Process.Wait() })
	if err := live.session.Control(Control{Op: OpReset, PIDs: []uint32{uint32(driver.Process.Pid)}}, 3*time.Second); err != nil {
		t.Fatalf("watch the driver: %v", err)
	}
	_ = stdin.Close()

	time.Sleep(stall)
	mu.Lock()
	released = time.Now()
	mu.Unlock()
	close(gate)

	done := make(chan error, 1)
	go func() { done <- driver.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("driver did not finish")
	}
	// drain: stop when the counts hold still for half a second.
	last, still := -1, time.Now()
	for time.Since(still) < 500*time.Millisecond {
		mu.Lock()
		cur := len(execs) + len(exits)
		mu.Unlock()
		if cur != last {
			last, still = cur, time.Now()
		}
		time.Sleep(25 * time.Millisecond)
	}

	if err := live.session.Err(); err != nil {
		t.Fatalf("the session did not survive the stall: %v", err)
	}
	select {
	case <-live.session.Done():
		t.Fatal("the session ended during the stall")
	default:
	}
	mu.Lock()
	gotexec, gotexit, delivered := len(execs), len(exits), after
	mu.Unlock()
	lost := live.session.Lost()
	if up := live.session.LostUpstream(); up > lost {
		lost = up
	}
	t.Logf("stall %s: exec %d/%d, exit %d/%d, %d events after the stall, reported loss at least %d (gaps %d, upstream %d)",
		stall, gotexec, n, gotexit, n, delivered, lost, live.session.Lost(), live.session.LostUpstream())
	if delivered == 0 {
		t.Fatal("nothing was delivered after the agent resumed reading")
	}
	if (gotexec < n || gotexit < n) && lost == 0 {
		t.Fatalf("silent loss: saw exec %d and exit %d of %d processes with no loss reported", gotexec, gotexit, n)
	}
}
