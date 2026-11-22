//go:build !linux

package platform

import (
	"fmt"
	"runtime"
	"time"
)

func readCPUTimes() (CPUTimes, error) {
	return CPUTimes{}, fmt.Errorf("platform: aggregate cpu accounting not implemented on %s", runtime.GOOS)
}

// ProcessStartTime reports unavailable off linux: start ticks are not exposed
// there, so callers keep their own fallback.
func ProcessStartTime(Process) (time.Time, bool) {
	return time.Time{}, false
}
