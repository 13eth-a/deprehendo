package simulator

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// cpuSink keeps the busy loops from being optimized away.
var cpuSink atomic.Uint64

// spinChunk is one slice of busy work; bigger chunks amortize deadline and
// channel checks, so a worker is only cancellable at chunk boundaries. at
// roughly 50-100us of work per chunk the worst-case latency before noticing a
// cancel is far below any observation interval.
const spinChunk = 20000

// spinTick is how often the scenario reports aggregated CPU progress. small
// enough that even a sub-second run produces several reports.
const spinTick = 250 * time.Millisecond

// CPUSpin pegs CPU with plain arithmetic. it is the "process is burning a
// core while the logical story looks fine" failure deprehendo will have to
// separate from restful-but-stuck processes.
type CPUSpin struct {
	Workers int
}

func init() { Register(&CPUSpin{}) }

func (c *CPUSpin) Name() string { return "cpu-spin" }

func (c *CPUSpin) Description() string {
	return "busy worker goroutines that peg CPU with arithmetic"
}

func (c *CPUSpin) RegisterFlags(fs *flag.FlagSet) {
	fs.IntVar(&c.Workers, "workers", 0, "number of busy goroutines; 0 means one per CPU core")
}

func (c *CPUSpin) Run(ctx context.Context, cfg Config) error {
	duration := cfg.Duration
	if duration <= 0 {
		duration = DefaultDuration
	}
	workers := c.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	start := time.Now()
	cfg.Emit("started", map[string]any{
		"pid":         os.Getpid(),
		"workers":     workers,
		"duration_ms": duration.Milliseconds(),
	})
	cfg.Say(fmt.Sprintf("Workers: %d (busy for %s)", workers, duration))

	runctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	var (
		wg    sync.WaitGroup
		done  atomic.Bool
		units atomic.Uint64
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				if done.Load() {
					return
				}
				if runctx.Err() != nil {
					return
				}
				n := busyChunk(id)
				units.Add(uint64(n))
			}
		}(i)
	}

	ticker := time.NewTicker(spinTick)
	defer ticker.Stop()

reason:
	for {
		select {
		case <-runctx.Done():
			break reason
		case <-deadline.C:
			break reason
		case <-ticker.C:
			cfg.Emit("work_report", map[string]any{
				"units":     units.Load(),
				"workers":   workers,
				"uptime_ms": time.Since(start).Milliseconds(),
			})
			if cfg.Verbose {
				cfg.Say(fmt.Sprintf("running: %d busy workers, %d work units", workers, units.Load()))
			}
		}
	}

	done.Store(true)
	wg.Wait()
	reason := "duration_elapsed"
	if ctx.Err() != nil { // the parent was cancelled, not our own timer
		reason = "interrupted"
	}
	cfg.Emit("exited", map[string]any{
		"code":       0,
		"reason":     reason,
		"work_units": units.Load(),
		"workers":    workers,
		"uptime_ms":  time.Since(start).Milliseconds(),
	})
	cfg.Say("Exit: 0")
	return nil
}

// busyChunk spins one fixed slice of bit-mixing arithmetic and reports the
// iterations done, so the aggregate is observable in the event stream.
func busyChunk(id int) int {
	x := uint64(0x9e3779b97f4a7c15) ^ uint64(id)
	for i := 0; i < spinChunk; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
	}
	cpuSink.Store(x)
	return spinChunk
}
