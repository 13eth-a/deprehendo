package trace

import (
	"errors"
	"time"
)

// ProcessMetrics is one resource observation of the tracer child process,
// used by the performance budget (6.49). it describes the *tracer*, not the
// workload: the point of the budget is that the sensor stays cheap.
type ProcessMetrics struct {
	PID          int
	CPUTime      time.Duration // user+system CPU consumed so far
	RSSBytes     uint64        // current resident set
	PeakRSSBytes uint64        // high-water mark, when the platform exposes it
}

// ErrMetricsUnsupported means this platform does not expose per-process
// resource counters through a supported interface. it is never a reason to
// fail a capture: the report simply omits the numbers.
var ErrMetricsUnsupported = errors.New("trace: tracer process metrics are Linux-only")
