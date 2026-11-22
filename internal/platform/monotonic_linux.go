//go:build linux

package platform

import (
	"syscall"
	"unsafe"
)

// MonotonicNs is CLOCK_MONOTONIC in nanoseconds (contract §8 / 6.28): the
// agent's ordering clock, comparable with every tracer-derived monotonic
// stamp because both processes read the same kernel clock. zero means the
// reading failed; consumers must fall back to ordering by wall time rather
// than mixing a zero with real monotonic stamps.
func MonotonicNs() int64 {
	var ts syscall.Timespec
	// CLOCK_MONOTONIC is 1 on every linux architecture; syscall does not
	// export the constant on all go versions.
	const clockMonotonic = 1
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, uintptr(clockMonotonic), uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0
	}
	return ts.Nano()
}
