//go:build linux

package trace

// live measurements against the real tracer and the real kernel (6.37,
// 6.49, 6.50). these tests are skipped, with an explicit reason, when no
// tracer binary is available or the backend advertises no exec support: a
// measurement that cannot be taken is reported as missing, never invented.
//
// the watch set starts empty and the backend filters by PID (6.22), so the
// tests add the exact PIDs they care about. each target is a shell that waits
// on stdin and then `exec`s a short-lived program in the same PID: the watch
// entry stays valid across the exec, which is what makes deterministic
// short-lived capture possible without racing process creation.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runopsy/internal/platform"
)

// liveEventLog is the race-safe sink for live tests.
type liveEventLog struct {
	mu    sync.Mutex
	execs map[uint32]int
	exits map[uint32]int
	total int
}

func newLiveEventLog() *liveEventLog {
	return &liveEventLog{execs: map[uint32]int{}, exits: map[uint32]int{}}
}

func (l *liveEventLog) sink(e TraceEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total++
	switch e.Type {
	case EventEXEC:
		l.execs[e.PID]++
	case EventEXIT:
		l.exits[e.PID]++
	}
}

func (l *liveEventLog) snapshot() (execs, exits map[uint32]int, total int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	execs = make(map[uint32]int, len(l.execs))
	for pid, n := range l.execs {
		execs[pid] = n
	}
	exits = make(map[uint32]int, len(l.exits))
	for pid, n := range l.exits {
		exits[pid] = n
	}
	return execs, exits, l.total
}

type liveTracer struct {
	session *Session
	pid     int
}

// startLiveTracer locates and starts the real tracer, then connects to it.
// any inability to trace is a skip: these tests measure the environment, they
// do not assert that every host supports kernel tracing.
func startLiveTracer(t *testing.T, sink Sink) *liveTracer {
	t.Helper()
	bin, why := ResolveBinary(os.Getenv("RUNOPSY_TRACE_BINARY"))
	if why != "" {
		t.Skipf("live tracer test skipped: %s", why)
	}
	dir, err := os.MkdirTemp("", "runopsy-live")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "t.sock")
	var stderr strings.Builder
	cmd := exec.Command(bin, "--socket", socket)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = os.RemoveAll(dir)
	})
	if err := waitForSocket(socket, 5*time.Second); err != nil {
		t.Skipf("tracer never bound %s: %v (stderr: %s)", socket, err, stderr.String())
	}
	session, err := Connect(SessionOptions{Socket: socket, Sink: sink, HandshakeTimeout: 3 * time.Second})
	if err != nil {
		t.Skipf("tracer refused the session: %v (stderr: %s)", err, stderr.String())
	}
	t.Cleanup(func() { _ = session.Close(time.Second) })
	if !session.Caps.ProcessExec || !session.Caps.ProcessExit {
		t.Skipf("backend advertises no exec/exit support, so there is nothing to measure: %+v", session.Caps)
	}
	return &liveTracer{session: session, pid: cmd.Process.Pid}
}

// spawnGatedStarts starts n shells that block on stdin and exec a short-lived
// program when released. their PIDs are stable and known before the exec, so
// the watch set can be updated first.
type gatedStart struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func spawnGatedStarts(t *testing.T, n int) ([]gatedStart, []uint32) {
	t.Helper()
	starts := make([]gatedStart, 0, n)
	pids := make([]uint32, 0, n)
	for i := 0; i < n; i++ {
		cmd := exec.Command("sh", "-c", "read x; exec /bin/true")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatalf("stdin pipe: %v", err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("start gated process: %v", err)
		}
		starts = append(starts, gatedStart{cmd: cmd, stdin: stdin})
		pids = append(pids, uint32(cmd.Process.Pid))
	}
	t.Cleanup(func() {
		for _, start := range starts {
			_ = start.cmd.Process.Kill()
			_, _ = start.cmd.Process.Wait()
		}
	})
	return starts, pids
}

func releaseGatedStarts(starts []gatedStart) {
	for _, start := range starts {
		_ = start.stdin.Close()
	}
}

// TestLiveShortLivedProcessCapture is item 6.37: high-resolution lifecycle
// capture versus polling. each target lives only microseconds after its exec;
// a 1s (or even 5ms) poll cannot see most of them, while the tracer must see
// both edges for nearly all of them.
func TestLiveShortLivedProcessCapture(t *testing.T) {
	const n = 24
	log := newLiveEventLog()
	live := startLiveTracer(t, log.sink)

	starts, pids := spawnGatedStarts(t, n)
	if err := live.session.Control(Control{Op: OpReset, PIDs: pids}, 2*time.Second); err != nil {
		t.Fatalf("watch set: %v", err)
	}

	// polling comparison: a 5ms process-table scan, faster than the product's
	// 1s default, so this is the most favourable possible polling baseline.
	observed := map[int]bool{}
	var pollMu sync.Mutex
	stoppoll := make(chan struct{})
	polldone := make(chan struct{})
	go func() {
		defer close(polldone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stoppoll:
				return
			case <-ticker.C:
				procs, err := platform.Processes()
				if err != nil {
					continue
				}
				want := make(map[int]bool, len(pids))
				for _, pid := range pids {
					want[int(pid)] = true
				}
				pollMu.Lock()
				for _, p := range procs {
					if want[p.PID] {
						observed[p.PID] = true
					}
				}
				pollMu.Unlock()
			}
		}
	}()

	releaseGatedStarts(starts)

	deadline := time.Now().Add(15 * time.Second)
	for {
		execs, exits, _ := log.snapshot()
		if len(execs) >= n && len(exits) >= n {
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stoppoll)
	<-polldone

	execs, exits, total := log.snapshot()
	pollMu.Lock()
	polled := len(observed)
	pollMu.Unlock()

	// trace capture: at least 80% of the burst must be visible on both edges,
	// which is far above what polling can reach for microsecond lifetimes.
	if want := n * 8 / 10; len(execs) < want || len(exits) < want {
		t.Fatalf("tracer captured exec=%d exit=%d of %d short-lived processes (want >= %d), total events=%d",
			len(execs), len(exits), n, want, total)
	}
	if len(execs) < polled {
		t.Errorf("tracer coverage (%d) is below polling coverage (%d); the direct sensor must not be weaker",
			len(execs), polled)
	}
	t.Logf("live short-lived capture: exec=%d exit=%d of %d; polling observed %d; total events=%d",
		len(execs), len(exits), n, polled, total)
}

// TestLiveTracerOverhead measures what 6.49 asks for on a real tracer: CPU,
// memory, throughput, loss. it runs a burst, not an idle soak: a sensor that
// cannot keep up with a burst will also lose events during a real incident.
func TestLiveTracerOverhead(t *testing.T) {
	const n = 200
	log := newLiveEventLog()
	live := startLiveTracer(t, log.sink)

	before, err := ReadProcessMetrics(live.pid)
	if err != nil {
		t.Skipf("tracer metrics unavailable: %v", err)
	}

	starts, pids := spawnGatedStarts(t, n)
	if err := live.session.Control(Control{Op: OpReset, PIDs: pids}, 3*time.Second); err != nil {
		t.Fatalf("watch set: %v", err)
	}
	started := time.Now()
	releaseGatedStarts(starts)

	deadline := time.Now().Add(30 * time.Second)
	for {
		_, _, total := log.snapshot()
		if total >= 2*n {
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	elapsed := time.Since(started)

	after, err := ReadProcessMetrics(live.pid)
	if err != nil {
		t.Skipf("tracer metrics unavailable after the burst: %v", err)
	}

	execs, exits, total := log.snapshot()
	lost := live.session.Lost()
	report := PipelineReport{
		Name:     fmt.Sprintf("live-burst-%d", n),
		Backend:  live.session.Caps.Backend,
		Duration: elapsed,
		Received: uint64(total),
		Lost:     lost,
		Rate:     float64(total) / elapsed.Seconds(),
		CPU:      after.CPUTime - before.CPUTime,
		RSSBytes: after.RSSBytes,
		PeakRSS:  after.PeakRSSBytes,
		Notes: []string{
			fmt.Sprintf("exec=%d exit=%d", len(execs), len(exits)),
			"tracer-side queue depth is a Rust counter and is not sampled from Go",
		},
	}
	t.Logf("%s", report)

	if total < 2*n/2 {
		t.Errorf("tracer delivered %d events for a %d-process burst; expected most of %d edges", total, n, 2*n)
	}
	if lost != 0 {
		t.Errorf("session reported %d lost events during a bounded burst", lost)
	}
	// budgets are deliberately loose: the point is to catch an order of
	// magnitude regression, not to police a few percent on shared CI.
	if perevent := report.CPU / time.Duration(maxInt(total, 1)); perevent > 5*time.Millisecond {
		t.Errorf("tracer CPU per event %s exceeds the 5ms budget", perevent)
	}
	if report.RSSBytes > 128<<20 {
		t.Errorf("tracer RSS %d MiB exceeds the 128 MiB budget", report.RSSBytes>>20)
	}
	if elapsed.Seconds() > 0 && report.CPU.Seconds()/elapsed.Seconds() > 0.5 {
		t.Errorf("tracer used %.0f%% of one CPU during the burst", 100*report.CPU.Seconds()/elapsed.Seconds())
	}
}
