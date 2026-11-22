// aggregate CPU accounting. the parser reads the first "cpu " line of
// /proc/stat; the reader is per-OS. CPU utilisation is derived between
// consecutive samples by the caller, so this file holds no state.
package platform

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// CPUTimes is one aggregate CPU accounting sample in kernel clock ticks.
// idle includes iowait, which is how `top` counts it; busy is Total-Idle.
type CPUTimes struct {
	Total uint64
	Idle  uint64
}

// ReadCPUTimes reads aggregate CPU accounting. linux reads /proc/stat; other
// platforms report not-implemented, which the system collector records as a
// partial failure.
func ReadCPUTimes() (CPUTimes, error) {
	return readCPUTimes()
}

// ParseCPUTimes parses the first "cpu ..." line of a /proc/stat stream. the
// per-CPU ("cpu0") lines are ignored. the kernel layout is:
// user nice system idle iowait irq softirq steal [guest guest_nice].
//
// guest/guest_nice are already included in user/nice and are deliberately not
// counted in total, matching how the kernel reports aggregate time.
func ParseCPUTimes(r io.Reader) (CPUTimes, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if fields := strings.Fields(line); len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		fields := strings.Fields(line)[1:]
		if len(fields) < 4 {
			return CPUTimes{}, fmt.Errorf("platform: malformed cpu stat line %q", line)
		}
		var ticks [8]uint64
		for i := 0; i < len(ticks) && i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("platform: malformed cpu stat field %q: %w", fields[i], err)
			}
			ticks[i] = v
		}
		var total uint64
		for _, v := range ticks {
			if total > math.MaxUint64-v {
				return CPUTimes{}, fmt.Errorf("platform: aggregate CPU counters overflow")
			}
			total += v
		}
		// idle + iowait are both "not doing work" from a utilisation view.
		return CPUTimes{Total: total, Idle: ticks[3] + ticks[4]}, nil
	}
	if err := scanner.Err(); err != nil {
		return CPUTimes{}, fmt.Errorf("platform: read cpu stat: %w", err)
	}
	return CPUTimes{}, fmt.Errorf("platform: no aggregate cpu line found")
}

// UsageSince returns the percentage of aggregate CPU time spent busy between
// prev and cur, in the range 0..100. it returns 0 when the counters did not
// advance or went backwards (a fresh boot/container counter reset).
func (cur CPUTimes) UsageSince(prev CPUTimes) float64 {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0
	}
	totaldelta := cur.Total - prev.Total
	idledelta := cur.Idle - prev.Idle
	if idledelta > totaldelta {
		return 0
	}
	return float64(totaldelta-idledelta) / float64(totaldelta) * 100
}
