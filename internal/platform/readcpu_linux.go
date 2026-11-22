//go:build linux

package platform

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// linuxClockTicksPerSecond is the userland ABI value of _SC_CLK_TCK. the
// kernel reports /proc/<pid>/stat start time in these ticks.
const linuxClockTicksPerSecond = 100

func readCPUTimes() (CPUTimes, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return CPUTimes{}, fmt.Errorf("platform: open /proc/stat: %w", err)
	}
	defer f.Close()
	return ParseCPUTimes(f)
}

// ProcessStartTime converts a process incarnation's start ticks into the wall
// clock. it is false when the start ticks or the boot time are unavailable,
// so callers keep their own fallback.
func ProcessStartTime(p Process) (time.Time, bool) {
	if p.StartTicks <= 0 {
		return time.Time{}, false
	}
	boot, err := readBootTime()
	if err != nil {
		return time.Time{}, false
	}
	return boot.Add(time.Duration(p.StartTicks) * (time.Second / linuxClockTicksPerSecond)), true
}

// readBootTime reads the btime line (seconds since the epoch) of /proc/stat.
func readBootTime() (time.Time, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "btime" {
			continue
		}
		sec, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("platform: malformed btime %q: %w", fields[1], err)
		}
		return time.Unix(sec, 0), nil
	}
	return time.Time{}, fmt.Errorf("platform: /proc/stat has no btime line")
}
