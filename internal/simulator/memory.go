package simulator

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// defaultMemoryLimit is the safe default: pressure without threatening the
// host. only someone who passes --limit explicitly can do better (worse).
const defaultMemoryRate = "50MB"
const defaultMemoryLimit = "256MB"

// MemoryPressure allocates and *retains* memory at a steady rate.
// A go GC happily collects everything that is not referenced, so the scenario
// keeps strong references to every chunk and touches one byte per page so the
// memory is actually resident, not just address space.
type MemoryPressure struct {
	Rate     string
	Interval time.Duration
	Limit    string
}

func init() { Register(&MemoryPressure{}) }

func (m *MemoryPressure) Name() string { return "memory-pressure" }

func (m *MemoryPressure) Description() string {
	return "retained, resident memory allocations up to a limit"
}

func (m *MemoryPressure) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&m.Rate, "rate", defaultMemoryRate, "bytes per step, e.g. 50MB or 256KB")
	fs.DurationVar(&m.Interval, "interval", time.Second, "time between allocation steps")
	fs.StringVar(&m.Limit, "limit", defaultMemoryLimit, "stop once this much is retained, e.g. 1GB")
}

func maxInt() int { return int(^uint(0) >> 1) }

func (m *MemoryPressure) Run(ctx context.Context, cfg Config) error {
	rate, err := parseBytes(m.Rate)
	if err != nil {
		return fmt.Errorf("bad --rate: %w", err)
	}
	limit, err := parseBytes(m.Limit)
	if err != nil {
		return fmt.Errorf("bad --limit: %w", err)
	}
	if rate <= 0 {
		return fmt.Errorf("--rate must be positive")
	}
	if limit <= 0 {
		return fmt.Errorf("--limit must be positive")
	}
	if rate > maxInt() || limit > maxInt() {
		return fmt.Errorf("--rate and --limit must not exceed %d bytes", maxInt())
	}
	interval := m.Interval
	if interval <= 0 {
		interval = time.Second
	}
	duration := cfg.Duration
	if duration <= 0 {
		duration = DefaultDuration
	}

	start := time.Now()
	cfg.Emit("started", map[string]any{
		"pid":         os.Getpid(),
		"rate_bytes":  rate,
		"interval_ms": interval.Milliseconds(),
		"limit_bytes": limit,
		"duration_ms": duration.Milliseconds(),
	})
	cfg.Say(fmt.Sprintf("Rate: %d bytes/step, limit: %d bytes (%s retained total)", rate, limit, humanBytes(limit)))

	runctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var retained [][]byte // strong references: the GC must not reclaim these
	reason := "duration_elapsed"

loop:
	for total := 0; total < limit; {
		select {
		case <-runctx.Done():
			reason = stopReason(ctx, true)
			break loop
		case <-deadline.C:
			reason = stopReason(ctx, true)
			break loop
		case <-ticker.C:
			if runctx.Err() != nil {
				reason = stopReason(ctx, true)
				break loop
			}
			remaining := limit - total
			step := rate
			if step > remaining {
				step = remaining
			}
			chunk := make([]byte, step)
			touchPages(chunk)
			retained = append(retained, chunk)
			total += step

			stats := heapStats()
			cfg.Emit("memory_allocated", map[string]any{
				"bytes":         step,
				"total_bytes":   total,
				"limit_bytes":   limit,
				"chunks":        len(retained),
				"heap_alloc_mb": stats,
				"uptime_ms":     time.Since(start).Milliseconds(),
			})
			cfg.Say(fmt.Sprintf("%s retained (%d steps)", humanBytes(total), len(retained)))
			if total >= limit {
				reason = "limit_reached"
				break loop
			}
			if errors.Is(runctx.Err(), context.DeadlineExceeded) {
				reason = stopReason(ctx, true)
				break loop
			}
		}
	}

	// runtime.KeepAlive makes the execution story explicit: nothing in the
	// allocation loop may collect `retained` before this line.
	runtime.KeepAlive(retained)

	cfg.Emit("exited", map[string]any{
		"code":        0,
		"reason":      reason,
		"total_bytes": runtime0(retained),
		"chunks":      len(retained),
		"uptime_ms":   time.Since(start).Milliseconds(),
	})
	cfg.Say(fmt.Sprintf("Exit: 0 (%s, %s retained)", reason, humanBytes(runtime0(retained))))
	return nil
}

func runtime0(retained [][]byte) int {
	total := 0
	for _, c := range retained {
		total += len(c)
	}
	return total
}

// heapStats returns the live heap in MiB for the event stream.
func heapStats() float64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.Alloc) / (1024 * 1024)
}

// touchPages writes one byte per OS page so pages are resident. without this,
// large zero-value allocations may be mapped lazily by the runtime and RSS
// would understate the pressure that was actually applied.
func touchPages(chunk []byte) {
	for i := 0; i < len(chunk); i += 4096 {
		chunk[i] = 0xFF
	}
	if len(chunk) > 0 {
		chunk[len(chunk)-1] = 0xFF
	}
}

// parseBytes accepts "50MB", "256KB", "1.5GB", or a bare byte count. units are
// binary (KB = 1024), matching how people talk about memory.
func parseBytes(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty size")
	}
	// split numeric prefix from unit.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.' || s[i] == '_') {
		i++
	}
	numstr := strings.ReplaceAll(s[:i], "_", "")
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))
	value, err := strconv.ParseFloat(numstr, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", numstr)
	}
	if value < 0 {
		return 0, errors.New("size must not be negative")
	}
	var mult float64 = 1
	switch unit {
	case "", "B":
	case "K", "KB", "KIB":
		mult = 1024
	case "M", "MB", "MIB":
		mult = 1024 * 1024
	case "G", "GB", "GIB":
		mult = 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}
	bytes := value * mult
	if bytes >= float64(maxInt()) {
		return 0, fmt.Errorf("size %q exceeds the supported byte count", s)
	}
	return int(bytes), nil
}

func humanBytes(b int) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1fGB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}
