//go:build !linux

package platform

import "time"

// processStart anchors this package's monotonic base (contract §8 / 6.28).
// on non-Linux hosts there is no tracer process to share a kernel clock
// with, so go's own monotonic reading (time.Since(processStart)) stands
// in for CLOCK_MONOTONIC.
var processStart = time.Now()

// MonotonicNs is CLOCK_MONOTONIC in nanoseconds: the same clock basis the
// tracer stamps its events with on linux, and go's monotonic clock elsewhere.
// zero means the reading failed; consumers must fall back to ordering by
// wall time rather than mixing a zero with real monotonic stamps.
func MonotonicNs() int64 {
	// time.Since strips the wall component and uses the monotonic one.
	d := time.Since(processStart)
	if d < 0 {
		return 0
	}
	return int64(d)
}
