//go:build !linux

package trace

// ReadProcessMetrics is unavailable off linux: there is no supported
// per-process CPU/RSS interface the tracer budget can trust. reporting the
// gap explicitly is the point (never a fabricated zero-cost claim).
func ReadProcessMetrics(pid int) (ProcessMetrics, error) {
	return ProcessMetrics{}, ErrMetricsUnsupported
}
