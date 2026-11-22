package simulator

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// normalTick is how often the simulated process wakes up to do a little work.
const normalTick = 500 * time.Millisecond

// work is deliberately small: enough to be visible in a CPU profile, not
// enough to matter.
const normalWorkIterations = 20000

// normalSink keeps the compiler from optimizing the busy work away.
var normalSink atomic.Uint64

// normal is the healthy control case: a process that runs for a while, does a
// little work, sleeps in between, and exits 0. every other scenario is
// described relative to this baseline.
type Normal struct{}

func (n *Normal) Name() string { return "normal" }

func (n *Normal) Description() string {
	return "healthy baseline process: small CPU work, sleeps, exits 0"
}

func (n *Normal) Run(ctx context.Context, cfg Config) error {
	duration := cfg.Duration
	if duration <= 0 {
		duration = DefaultDuration
	}

	start := time.Now()
	pid := os.Getpid()

	cfg.Say(fmt.Sprintf("PID: %d", pid))
	cfg.Say("State: running")
	cfg.Say(fmt.Sprintf("Duration: %s", duration))
	cfg.Emit("started", map[string]any{
		"pid":         pid,
		"state":       "running",
		"duration_ms": duration.Milliseconds(),
	})

	ticker := time.NewTicker(normalTick)
	defer ticker.Stop()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()

	iteration := 0
	for {
		select {
		case <-ctx.Done():
			cfg.Emit("stop_requested", map[string]any{
				"reason":     "context_canceled",
				"iterations": iteration,
				"uptime_ms":  time.Since(start).Milliseconds(),
			})
			cfg.Say("Shutting down.")
			cfg.Emit("exited", map[string]any{
				"code":       0,
				"reason":     "interrupted",
				"iterations": iteration,
				"uptime_ms":  time.Since(start).Milliseconds(),
			})
			return nil
		case <-deadline.C:
			cfg.Emit("exited", map[string]any{
				"code":       0,
				"reason":     "duration_elapsed",
				"iterations": iteration,
				"uptime_ms":  time.Since(start).Milliseconds(),
			})
			cfg.Say("Exit: 0")
			return nil
		case <-ticker.C:
			iteration++
			workfor := normalWork()
			cfg.Emit("heartbeat", map[string]any{
				"iteration":   iteration,
				"cpu_work_us": workfor.Microseconds(),
				"uptime_ms":   time.Since(start).Milliseconds(),
			})
			if cfg.Verbose {
				cfg.Say(fmt.Sprintf("iteration %d: %s of CPU work", iteration, workfor))
			}
		}
	}
}

// normalWork burns a bounded, predictable amount of CPU and reports how long it
// took, which is what makes the baseline observable without a profiler.
func normalWork() time.Duration {
	start := time.Now()
	x := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < normalWorkIterations; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
	}
	normalSink.Store(x)
	return time.Since(start)
}
