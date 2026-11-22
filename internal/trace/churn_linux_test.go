//go:build linux

package trace

// the live churn run from contract §14 (integration): the real tracer, the real
// kernel, a 100k burst of short-lived processes, measured as whatever user the
// test is started as. its reason to exist is the case the principal measurements
// did not cover: a non-root user with stock net.core.rmem_max, where the
// tracer cannot force a 16 MiB receive buffer and overruns become visible
// gaps instead of being absorbed.
//
// Opt-in (RUNOPSY_LIVE_CHURN=N) because it takes minutes, not because it is
// synthetic: every process here is real and every event crosses the real
// socket. the assertions are the invariants, not a flattering number:
//
//   - a shortfall in captured processes is reported loss, never silence;
//   - the tracer's memory does not grow with churn;
//   - CPU per event stays inside the 6.50 budget;
//   - the session is one uninterrupted stream (no restarts, no protocol error).
//
// observed loss is not itself a failure: under stock rmem_max it is the
// expected outcome, and the driver shell's own exit is a watched event outside
// the churn count. what fails the run is loss the session cannot account for,
// or a missing process with no loss reported.

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

// liveChurnCount is the opt-in size for TestLiveChurn. zero means "not
// requested": an ordinary `go test ./...` must not spawn a hundred thousand
// processes, and a measurement that was not run is never reported as passed.
func liveChurnCount(t *testing.T) int {
	t.Helper()
	raw := os.Getenv("RUNOPSY_LIVE_CHURN")
	if raw == "" {
		t.Skip("live churn skipped: set RUNOPSY_LIVE_CHURN=N (make trace-churn-live uses 100000)")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 500000 {
		t.Fatalf("RUNOPSY_LIVE_CHURN must be 1..500000, got %q", raw)
	}
	return n
}

// churnSink counts distinct exec/exit PIDs and the stream health without
// retaining per-event state beyond the bounded latency reservoir.
type churnSink struct {
	mu        sync.Mutex
	execs     map[uint32]struct{}
	exits     map[uint32]struct{}
	through   Throughput
	lastSeq   uint64
	restarts  int
	contig    bool
	samples   []churnSample
	sampleCap int
	seen      int
	stride    int
}

type churnSample struct {
	mono int64
	at   time.Time
}

func newChurnSink(n int) *churnSink {
	stride := n / MaxLatencySamples
	if stride < 1 {
		stride = 1
	}
	return &churnSink{
		execs:     make(map[uint32]struct{}),
		exits:     make(map[uint32]struct{}),
		contig:    true,
		sampleCap: MaxLatencySamples,
		stride:    stride,
	}
}

func (c *churnSink) sink(e TraceEvent) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.through.Observe(e, now)
	switch {
	case c.lastSeq == 0:
	case e.Sequence > c.lastSeq+1:
		c.contig = false
	case e.Sequence <= c.lastSeq:
		c.restarts++
	}
	if e.Sequence > c.lastSeq {
		c.lastSeq = e.Sequence
	}
	// sampling by stride rather than "first 65k" keeps the latency picture
	// spread across the whole run without growing the reservoir.
	if c.seen%c.stride == 0 && len(c.samples) < c.sampleCap && e.MonotonicNs > 0 {
		c.samples = append(c.samples, churnSample{mono: e.MonotonicNs, at: now})
	}
	c.seen++
	switch e.Type {
	case EventEXEC:
		c.execs[e.PID] = struct{}{}
	case EventEXIT:
		c.exits[e.PID] = struct{}{}
	}
}

func (c *churnSink) counts() (execs, exits int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.execs), len(c.exits)
}

func (c *churnSink) results() (through Throughput, contig bool, restarts int, samples []churnSample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.through, c.contig, c.restarts, append([]churnSample(nil), c.samples...)
}

// TestLiveChurn runs N real short-lived processes under one watched driver and
// reports what the kernel-to-agent path actually delivered.
func TestLiveChurn(t *testing.T) {
	n := liveChurnCount(t)
	sink := newChurnSink(n)
	live := startLiveTracer(t, sink.sink)

	// /proc/net/netlink reports per-socket netlink drops and the current
	// receive-queue depth. the row disappears with the socket, so it has to be
	// sampled while the tracer lives: a kernel-side drop is the concrete form
	// of the unaccounted gap this test fails on, and a growing rmem is that
	// gap forming before any sequence number is skipped.
	var (
		netlinkOnce sync.Once
		netlinkDone = make(chan struct{})
		netlinkWG   sync.WaitGroup
	)
	var peakDrops, peakRmem uint64
	var sampledNetlink bool
	stopnetlink := func() {
		netlinkOnce.Do(func() { close(netlinkDone); netlinkWG.Wait() })
	}
	netlinkWG.Add(1)
	go func() {
		defer netlinkWG.Done()
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			if drops, rmem, ok := netlinkSocketStats(live.pid); ok {
				sampledNetlink = true
				if drops > peakDrops {
					peakDrops = drops
				}
				if rmem > peakRmem {
					peakRmem = rmem
				}
			}
			select {
			case <-netlinkDone:
				return
			case <-tick.C:
			}
		}
	}()
	t.Cleanup(stopnetlink)

	before, metricserr := ReadProcessMetrics(live.pid)
	if metricserr != nil {
		t.Logf("tracer metrics before the burst unavailable: %v", metricserr)
	}

	// the driver is a shell blocked on stdin, so its PID is known and can be
	// put in the watch set before it forks anything. every child is then
	// watched from fork, which is the path a real agent relies on between
	// watch-set pushes.
	// the driver reports how many processes it actually started. without that
	// count a driver that dies early (fork exhaustion, a killed shell) is
	// indistinguishable from a tracer that dropped events silently. the
	// difference the gates below exist to make.
	script := fmt.Sprintf("trap 'echo spawned=$i >&2' EXIT\ni=0\nread x\nwhile [ \"$i\" -lt %d ]; do /bin/true; i=$((i+1)); done", n)
	driver := exec.Command("sh", "-c", script)
	var driverErr strings.Builder
	driver.Stderr = &driverErr
	stdin, err := driver.StdinPipe()
	if err != nil {
		t.Fatalf("driver stdin: %v", err)
	}
	if err := driver.Start(); err != nil {
		t.Fatalf("start driver: %v", err)
	}
	t.Cleanup(func() {
		_ = driver.Process.Kill()
		_, _ = driver.Process.Wait()
	})
	if err := live.session.Control(Control{Op: OpReset, PIDs: []uint32{uint32(driver.Process.Pid)}}, 3*time.Second); err != nil {
		t.Fatalf("watch set: %v", err)
	}

	started := time.Now()
	_ = stdin.Close()

	waitdone := make(chan error, 1)
	go func() { waitdone <- driver.Wait() }()

	// the driver exits when the loop is done; the events for the last
	// processes can still be in flight, so drain until the counters stop
	// moving rather than racing the final exit.
	deadline := time.Now().Add(30*time.Second + time.Duration(n)*3*time.Millisecond)
	driverdone := false
	var driverExit error
	lastseen, stablesince := -1, time.Now()
	for {
		select {
		case werr := <-waitdone:
			driverdone = true
			driverExit = werr
			if werr != nil {
				t.Logf("driver exited with %v", werr)
			}
		default:
		}
		execs, exits := sink.counts()
		if driverdone && execs >= n && exits >= n {
			break
		}
		// A run that lost part of the burst never reaches n. once the driver
		// is done, stop when the stream goes quiet instead of burning the
		// whole deadline: the deadline is a bound, not the churn duration any
		// report should quote (it was 5m30s for a ~105s burst).
		if driverdone {
			if seen := execs + exits; seen != lastseen {
				lastseen, stablesince = seen, time.Now()
			} else if time.Since(stablesince) >= 2*time.Second {
				break
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !driverdone {
		select {
		case <-waitdone:
		case <-time.After(10 * time.Second):
			t.Errorf("driver did not exit before the deadline")
		}
	}

	// let the last frames drain: stop when neither count moves for 500ms.
	lastexecs, lastexits := -1, -1
	stablesince = time.Now()
	execs, exits := sink.counts()
	for time.Since(stablesince) < 500*time.Millisecond {
		execs, exits = sink.counts()
		if execs != lastexecs || exits != lastexits {
			lastexecs, lastexits, stablesince = execs, exits, time.Now()
		}
		time.Sleep(25 * time.Millisecond)
	}
	stopnetlink()
	elapsed := time.Since(started)

	// how much of the burst the driver produced. the harness can neither claim
	// 100k coverage nor blame the tracer for processes that never existed.
	spawned := n
	if out := driverErr.String(); strings.Contains(out, "spawned=") {
		if idx := strings.LastIndex(out, "spawned="); idx >= 0 {
			rest := out[idx+len("spawned="):]
			if end := strings.IndexByte(rest, '\n'); end >= 0 {
				rest = rest[:end]
			}
			if v, perr := strconv.Atoi(strings.TrimSpace(rest)); perr == nil {
				spawned = v
			}
		}
	}
	driverstatus := "exit 0"
	if driverExit != nil {
		driverstatus = driverExit.Error()
	}

	after, err := ReadProcessMetrics(live.pid)
	if err != nil {
		t.Logf("tracer metrics after the burst unavailable: %v", err)
	}

	through, _, restarts, samples := sink.results()
	latency := &LatencyStats{}
	for _, s := range samples {
		if d, ok := live.session.Latency(TraceEvent{MonotonicNs: s.mono}, s.at); ok {
			latency.ObserveDuration(d)
		}
	}
	summary := latency.Summary()

	lostgaps := live.session.Lost()
	lostUpstream := live.session.LostUpstream()
	bystage := live.session.LostUpstreamByStage()
	sessionerr := live.session.Err()
	// A kernel drop that bumps the loss counters also skips sequence numbers
	// (the tracer marks a gap and reports the stage), so the two counts can
	// describe the same lost events. summing them would inflate the number;
	// the honest lower bound is the larger of the two.
	lostobserved := lostgaps
	if lostUpstream > lostobserved {
		lostobserved = lostUpstream
	}

	uid := os.Getuid()
	report := PipelineReport{
		Name:     fmt.Sprintf("live-churn-%d", n),
		Backend:  live.session.Caps.Backend,
		Duration: elapsed,
		Received: through.Received,
		Lost:     lostobserved,
		Gaps:     through.Gaps,
		PeakGap:  through.PeakGap,
		Restarts: through.Restarts,
		Rate:     through.EventsPerSecond(),
		Latency:  summary,
	}
	if metricserr == nil && err == nil {
		report.CPU = after.CPUTime - before.CPUTime
		report.RSSBytes = after.RSSBytes
		report.PeakRSS = after.PeakRSSBytes
	}
	notes := []string{
		fmt.Sprintf("uid=%d backend=%s caps(exec=%t exit=%t signals=%t)", uid, live.session.Caps.Backend,
			live.session.Caps.ProcessExec, live.session.Caps.ProcessExit, live.session.Caps.Signals),
		fmt.Sprintf("processes: requested=%d spawned=%d exec_pids=%d exit_pids=%d driver=%s", n, spawned, execs, exits, driverstatus),
		fmt.Sprintf("loss: sequence gaps=%d upstream=%d (stages kernel/proc/queue/other=%v)",
			lostgaps, lostUpstream, bystage),
		"coverage of the driver shell itself is excluded: its exec predates the watch set",
	}
	if sampledNetlink {
		notes = append(notes, fmt.Sprintf("netlink socket: drops=%d rmem_peak=%d", peakDrops, peakRmem))
	} else {
		notes = append(notes, "netlink socket: no /proc/net/netlink row for the tracer")
	}
	report.Notes = notes
	t.Logf("%s", report)

	// the invariants this measurement exists to check.
	if execs == 0 || exits == 0 {
		t.Fatalf("the tracer delivered no lifecycle edges for %d processes; session error=%v", n, sessionerr)
	}
	if sessionerr != nil {
		t.Errorf("session ended with an error during the burst: %v", sessionerr)
	}
	// the failure this run exists to catch is evidence vanishing *without* a
	// loss report, not loss itself: a 100k burst under stock rmem_max is
	// expected to overrun. comparing the missing sequence numbers the sink
	// observed against what the session accounted for is the real gate; any
	// gap alone is not (that check failed on accounted loss, contradicting
	// this test's own stated outcome).
	if through.Lost > lostobserved {
		t.Errorf("sink observed %d missing sequence numbers but the session accounted for only %d (gaps=%d upstream=%d): unaccounted loss",
			through.Lost, lostobserved, lostgaps, lostUpstream)
	}
	if restarts > 1 {
		t.Errorf("unexpected sequence restarts during one session: %d", restarts)
	}
	if summary.Count == 0 {
		t.Errorf("no latency samples were computable; the clock anchor is broken")
	}

	// silent loss is the failure that matters: a missing process must map to
	// an accounted drop. under stock rmem_max this is expected to fire on a
	// large burst; on root with a forced 16 MiB buffer it must not.
	missingexec, missingexit := spawned-execs, spawned-exits
	if missingexec < 0 {
		missingexec = 0
	}
	if missingexit < 0 {
		missingexit = 0
	}
	if missingexec > 0 || missingexit > 0 {
		if lostobserved == 0 {
			t.Errorf("%d execs and %d exits of %d spawned were missing but no loss was reported: evidence vanished silently",
				missingexec, missingexit, spawned)
		} else {
			t.Logf("accounted loss: %d execs and %d exits missing of %d spawned; %d gaps + %d upstream drops reported",
				missingexec, missingexit, spawned, lostgaps, lostUpstream)
		}
	}
	// A driver that could not start the whole burst is an environment limit,
	// not a tracer result: the 100k measurement was not taken. skipping is
	// only honest when every process that did exist was delivered.
	if spawned < n && !t.Failed() && missingexec == 0 && missingexit == 0 {
		t.Skipf("driver spawned %d of %d requested processes (wait: %s); the tracer delivered every one that existed (%d execs, %d exits, %d accounted loss)",
			spawned, n, driverstatus, execs, exits, lostobserved)
	}
	// reported loss while every burst process was captured is not a
	// contradiction: the driver shell's own exit is a watched event outside
	// the churn count, so it can be the lost one (exit_pids is then n+1).
	// the reverse (missing processes, no loss) and unaccounted gaps are the
	// failures, checked above and against through.Lost.

	// budgets are the same order-of-magnitude guards 6.49/6.50 uses, applied
	// to a much longer run: a leak shows up across 100k processes.
	if total := through.Received; total > 0 && report.CPU > 0 {
		if perevent := report.CPU / time.Duration(total); perevent > 5*time.Millisecond {
			t.Errorf("tracer CPU per event %s exceeds the 5ms budget", perevent)
		}
	}
	if report.PeakRSS > 128<<20 {
		t.Errorf("tracer peak RSS %d MiB exceeds the 128 MiB budget", report.PeakRSS>>20)
	}
}

// netlinkSocketStats sums the per-socket drops and receive-queue depth that
// /proc/net/netlink reports for pid, the tracer's netlink subscription. columns
// are: sk eth pid groups rmem wmem dump locks drops Inode.
func netlinkSocketStats(pid int) (drops, rmem uint64, ok bool) {
	raw, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(raw), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		rowpid, err := strconv.Atoi(f[2])
		if err != nil || rowpid != pid {
			continue
		}
		r, _ := strconv.ParseUint(f[4], 10, 64)
		d, _ := strconv.ParseUint(f[8], 10, 64)
		rmem += r
		drops += d
		ok = true
	}
	return drops, rmem, ok
}
