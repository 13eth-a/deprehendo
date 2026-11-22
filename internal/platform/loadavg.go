// load average collection. the parser handles both the linux /proc/loadavg
// layout and the macOS sysctl "{ 1.23 0.75 0.42 }" form, so fixture tests run
// anywhere; the readers are per-OS files.
package platform

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// LoadAverage is the kernel's 1/5/15-minute load average.
type LoadAverage struct {
	One     float64
	Five    float64
	Fifteen float64
}

// ReadLoadAverage reads the host load average (linux /proc/loadavg, macOS
// sysctl vm.loadavg). the first cycle of a recorder has a load value; this
// needs no delta state.
func ReadLoadAverage() (LoadAverage, error) {
	return readLoadAverage()
}

// ParseLoadAverage parses either "1.23 0.75 0.42 2/128 4242" (linux) or
// "{ 1.23 0.75 0.42 }" (macOS sysctl vm.loadavg).
func ParseLoadAverage(r io.Reader) (LoadAverage, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// strip the sysctl braces and the linux run-queue/last-pid tail
		// falls out naturally because only the first three fields are read.
		fields := strings.Fields(strings.NewReplacer("{", " ", "}", " ").Replace(line))
		if len(fields) < 3 {
			return LoadAverage{}, fmt.Errorf("platform: malformed load average %q", line)
		}
		values := make([]float64, 3)
		for i := 0; i < 3; i++ {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
				return LoadAverage{}, fmt.Errorf("platform: malformed load average field %q", fields[i])
			}
			values[i] = v
		}
		return LoadAverage{One: values[0], Five: values[1], Fifteen: values[2]}, nil
	}
	if err := scanner.Err(); err != nil {
		return LoadAverage{}, fmt.Errorf("platform: read load average: %w", err)
	}
	return LoadAverage{}, fmt.Errorf("platform: empty load average input")
}
