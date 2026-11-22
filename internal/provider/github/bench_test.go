package github

// phase 5 performance budget (5.49). GitHub support is extra work on top of a
// recorder that must stay light, so the cost is measured where the recorder
// pays it: once per snapshot (observe) and once per incident (freeze). the
// scenarios mirror the plan: an idle runner, an active job, several runners on
// one host, and high process churn.
//
// the fixtures are generated rather than committed because they have to scale
// to thousands of samples. they still go through the real fixture host, so an
// observe pass opens real diagnostic files, reads real process tables and
// classifies real socket rows; nothing here measures a stub.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github/fixtures"
)

// sampleInterval is the fastest interval the recorder documents; overhead per
// sample has to stay well inside it.
const sampleInterval = 100 * time.Millisecond

type shape struct {
	runners     int // installations, each with its own listener
	jobProcs    int // job processes under each worker
	samples     int
	churn       int // short-lived unrelated processes per sample
	logLines    int // runner diagnostic lines appended per sample
	sockets     int // ESTABLISHED sockets per listener
	assignEvery int // append an assignment record every N samples (0: never)
}

// buildSynthetic materializes a shape as a real installation plus a snapshot
// sequence the session can observe in order.
func buildSynthetic(tb testing.TB, s shape) (*fixtures.Host, []int) {
	tb.Helper()
	fixture := &fixtures.Fixture{Name: "bench"}
	for r := 0; r < s.runners; r++ {
		fixture.Install = append(fixture.Install, fixtures.Install{
			Key:     fmt.Sprintf("r%d", r),
			Name:    fmt.Sprintf("runner-%02d", r),
			Version: "2.320.0",
			RunnerLog: []string{
				"2026-10-28 11:59:59.000 +00:00 [RUNNER 1] Listening for Jobs",
			},
		})
	}
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	churnpids := make([]int, 0, s.samples*s.churn)
	for sample := 0; sample < s.samples; sample++ {
		snap := fixtures.Snapshot{At: base.Add(time.Duration(sample) * 200 * time.Millisecond)}
		for r := 0; r < s.runners; r++ {
			listenerpid := 5000 + r
			snap.Processes = append(snap.Processes, fixtures.Process{
				PID: listenerpid, PPID: 1, PGID: listenerpid, StartTicks: int64(10 + r),
				Name: "Runner.Listener", State: "S", Install: fmt.Sprintf("r%d", r),
			})
			for k := 0; k < s.sockets; k++ {
				snap.Connections = append(snap.Connections, fixtures.Connection{
					LocalAddr: "10.0.0.7", LocalPort: uint16(52000 + r*8 + k), RemoteAddr: "140.82.121.3",
					RemotePort: 443, State: "ESTABLISHED", Inode: uint64(9000 + r*8 + k),
					PID: listenerpid, StartTicks: int64(10 + r), FD: 5,
				})
			}
			if sample == 0 {
				continue // the worker appears after the listener
			}
			workerpid := 6000 + r
			snap.Processes = append(snap.Processes, fixtures.Process{
				PID: workerpid, PPID: listenerpid, PGID: workerpid, StartTicks: int64(20 + r),
				Name: "Runner.Worker", State: "S",
			})
			for k := 0; k < s.jobProcs; k++ {
				snap.Processes = append(snap.Processes, fixtures.Process{
					PID: 7000 + r*100 + k, PPID: workerpid, PGID: workerpid,
					StartTicks: int64(30 + k), Name: "make", State: "R",
					CPUPercent: float64((sample + k) % 100),
				})
			}
		}
		for k := 0; k < s.churn; k++ {
			pid := 9000 + sample*s.churn + k
			churnpids = append(churnpids, pid)
			snap.Processes = append(snap.Processes, fixtures.Process{
				PID: pid, PPID: 1, PGID: pid, StartTicks: int64(sample*10 + k),
				Name: "short-lived", State: "R",
			})
		}
		if s.logLines > 0 && s.runners == 1 {
			line := fmt.Sprintf("2026-10-28 12:00:%02d.000 +00:00 [RUNNER 1] Job progress heartbeat",
				sample%60)
			snap.RunnerLog = []string{line}
		}
		if s.assignEvery > 0 && sample%s.assignEvery == 0 && sample > 0 && s.runners == 1 {
			snap.RunnerLog = append(snap.RunnerLog,
				"2026-10-28 12:00:00.000 +00:00 [RUNNER 1] Received job message")
		}
		fixture.Snapshots = append(fixture.Snapshots, snap)
	}

	host, err := fixture.Materialize(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	return host, churnpids
}

// runSession attaches a real session, which is the exact work a live recorder
// would ask of the provider: one log tail per installation, one process table.
func runSession(tb testing.TB, host *fixtures.Host) *session {
	tb.Helper()
	roots := host.Roots()
	for _, root := range roots[1:] {
		// the fixture host refuses incremental log lines with multiple
		// installations, but a real host has one tail per runner; give every
		// extra installation a line so its tail has work to do.
		appendInstallLog(tb, root)
	}
	s, err := newSession(context.Background(), host, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers,
		Budget:  provider.DefaultBudget(),
	})
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func appendInstallLog(tb testing.TB, root string) {
	tb.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "_diag", "Runner_*.log"))
	if err != nil || len(paths) == 0 {
		tb.Fatalf("no runner log under %s", root)
	}
	file, err := os.OpenFile(paths[0], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("2026-10-28 12:00:30.000 +00:00 [RUNNER 1] Job progress heartbeat\n"); err != nil {
		tb.Fatal(err)
	}
}

func benchmarkObserve(b *testing.B, s shape) {
	ctx := context.Background()
	b.ReportAllocs()
	var measured time.Duration
	var samples int
	for i := 0; i < b.N; i++ {
		// A fixture host cannot replay its snapshots, so each iteration gets
		// its own host. setup is excluded from the timing.
		b.StopTimer()
		host, _ := buildSynthetic(b, s)
		session := runSession(b, host)
		b.StartTimer()
		start := time.Now()
		for sample := 0; sample < host.Count(); sample++ {
			if err := host.SetSnapshot(sample); err != nil {
				b.Fatal(err)
			}
			session.Observe(ctx, host.CollectorSnapshot(sample))
		}
		measured += time.Since(start)
		samples += host.Count()
		b.StopTimer()
		from, to := host.Window()
		if _, err := session.Freeze(ctx, from, to); err != nil {
			b.Fatalf("freeze: %v", err)
		}
		b.StartTimer()
	}
	b.ReportMetric(float64(measured.Microseconds())/float64(samples), "us/sample")
}

func BenchmarkObserveIdleRunner(b *testing.B) {
	benchmarkObserve(b, shape{runners: 1, samples: 100, sockets: 1})
}

func BenchmarkObserveActiveJob(b *testing.B) {
	benchmarkObserve(b, shape{runners: 1, jobProcs: 8, samples: 100, sockets: 1, logLines: 1})
}

func BenchmarkObserveMultipleRunners(b *testing.B) {
	benchmarkObserve(b, shape{runners: 4, jobProcs: 4, samples: 100, sockets: 2})
}

func BenchmarkObserveProcessChurn(b *testing.B) {
	benchmarkObserve(b, shape{runners: 1, jobProcs: 4, samples: 100, churn: 60, sockets: 1})
}

func BenchmarkFreezeActiveJob(b *testing.B) {
	host, _ := buildSynthetic(b, shape{runners: 1, jobProcs: 8, samples: 200, sockets: 2, logLines: 1})
	session := runSession(b, host)
	ctx := context.Background()
	for sample := 0; sample < host.Count(); sample++ {
		if err := host.SetSnapshot(sample); err != nil {
			b.Fatal(err)
		}
		session.Observe(ctx, host.CollectorSnapshot(sample))
	}
	from, to := host.Window()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := session.Freeze(ctx, from, to); err != nil {
			b.Fatal(err)
		}
	}
}

// TestObserveOverheadWithinBudget is the guardrail the benchmarks inform. the
// ceiling is deliberately loose (a quarter of the fastest documented sampling
// interval, on one active runner) so it catches an accidental per-sample
// process-table scan or unbounded allocation, not a slow laptop.
func TestObserveOverheadWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guardrail")
	}
	host, _ := buildSynthetic(t, shape{runners: 1, jobProcs: 8, samples: 300, sockets: 1, logLines: 1})
	session := runSession(t, host)
	ctx := context.Background()
	start := time.Now()
	for sample := 0; sample < host.Count(); sample++ {
		if err := host.SetSnapshot(sample); err != nil {
			t.Fatal(err)
		}
		session.Observe(ctx, host.CollectorSnapshot(sample))
	}
	persample := time.Since(start) / time.Duration(host.Count())
	ceiling := sampleInterval / 4
	t.Logf("Observe over %d active-job samples: %s per sample (ceiling %s)", host.Count(), persample, ceiling)
	if persample > ceiling {
		t.Fatalf("Observe costs %s per sample, above the %s guardrail", persample, ceiling)
	}
	// freezing is once per incident, so it may cost far more, but it must not
	// be quadratic in the tracked process count: an active job of ~10 tagged
	// processes stays in the low milliseconds.
	from, to := host.Window()
	freezestart := time.Now()
	section, err := session.Freeze(ctx, from, to)
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	freeze := time.Since(freezestart)
	t.Logf("Freeze: %s for %d roles and %d events", freeze, len(section.ProcessRoles), len(section.Events))
	if freeze > 250*time.Millisecond {
		t.Fatalf("Freeze costs %s, above the 250ms guardrail", freeze)
	}
	if len(section.Events) == 0 || len(section.ProcessRoles) == 0 {
		t.Fatal("budget run captured nothing to measure")
	}
}

// TestChurnKeepsProviderStateBounded proves the per-sample cost stays flat
// because the bookkeeping stays bounded: tracked identities cap at the budget,
// stored events trim, closed channels are dropped, and pending assignments
// expire with the C6 window.
func TestChurnKeepsProviderStateBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("thousands of synthetic samples")
	}
	const samples = 1500
	spec := shape{runners: 1, jobProcs: 2, samples: samples, churn: 20, sockets: 1, logLines: 1, assignEvery: 3}
	host, _ := buildSynthetic(t, spec)
	session := runSession(t, host)
	ctx := context.Background()

	// time the two halves separately: bounded bookkeeping is what keeps the
	// per-sample cost flat as an incident's history grows.
	var firstHalf, secondHalf time.Duration
	for sample := 0; sample < host.Count(); sample++ {
		if err := host.SetSnapshot(sample); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		session.Observe(ctx, host.CollectorSnapshot(sample))
		cost := time.Since(start)
		if sample < samples/2 {
			firstHalf += cost
		} else {
			secondHalf += cost
		}
	}

	budget := provider.DefaultBudget()
	if len(session.workers) > budget.MaxTrackedProcesses {
		t.Errorf("workers = %d, above the %d budget", len(session.workers), budget.MaxTrackedProcesses)
	}
	if len(session.jobTree) > budget.MaxTrackedProcesses {
		t.Errorf("job tree = %d, above the %d budget", len(session.jobTree), budget.MaxTrackedProcesses)
	}
	if len(session.events) > maxStoredEvents {
		t.Errorf("events = %d, above the %d retention bound", len(session.events), maxStoredEvents)
	}
	// assignments are appended every third sample (600ms); only those inside
	// the C6 window may remain pending.
	windowsamples := int(jobBindingTolerance / (200 * time.Millisecond))
	if limit := windowsamples + 2; len(session.pending) > limit {
		t.Errorf("pending assignments = %d, want at most %d (C6 window)", len(session.pending), limit)
	}
	// sockets are all long-lived here, so tracking them is expected; the
	// point is that the map does not grow with the sample count.
	if len(session.channels) > spec.runners*spec.sockets {
		t.Errorf("tracked channels = %d, want at most %d", len(session.channels), spec.runners*spec.sockets)
	}
	if session.dropped > 0 {
		t.Errorf("provider dropped %d samples of bookkeeping; the bounds were hit", session.dropped)
	}
	// the second half of the run carries twice the history of the first; it
	// may not cost more than three times as much per sample.
	perfirst := firstHalf / time.Duration(samples/2)
	persecond := secondHalf / time.Duration(samples-samples/2)
	t.Logf("per-sample cost: first half %s, second half %s", perfirst, persecond)
	if perfirst > 0 && persecond > 3*perfirst {
		t.Fatalf("per-sample cost grew from %s to %s over %d samples", perfirst, persecond, samples)
	}
}
