// memory accounting from /proc/meminfo. the parser is portable so fixture
// tests run on any OS; the reader is Linux-only.
package platform

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// MemInfo is the memory state phase 1 records, normalized to bytes.
// MemAvailable is the kernel's estimate of memory available to new work
// (including reclaimable cache); MemFree is the unallocated pool. they are
// deliberately distinct: using MemFree as "free" overstates pressure.
type MemInfo struct {
	MemTotal     uint64
	MemAvailable uint64
	MemFree      uint64
	Buffers      uint64
	Cached       uint64
	SwapTotal    uint64
	SwapFree     uint64
}

// used returns total minus available, the consistent used-memory definition
// used by the snapshot model. it clamps to zero on inconsistent input.
func (m MemInfo) Used() uint64 {
	if m.MemAvailable >= m.MemTotal {
		return 0
	}
	return m.MemTotal - m.MemAvailable
}

// ReadMemInfo reads host memory accounting. linux reads /proc/meminfo; other
// platforms report not-implemented, which the system collector records as a
// partial failure.
func ReadMemInfo() (MemInfo, error) {
	return readMemInfo()
}

// ParseMemInfo parses /proc/meminfo. values are reported in kB by the kernel
// and converted to bytes here; unitless entries are treated as counts in bytes.
// unknown keys are ignored so new kernel fields do not break collection.
//
// if MemAvailable is absent (kernels older than 3.14), it is approximated as
// MemFree + buffers + cached, the classic pre-availability estimate.
func ParseMemInfo(r io.Reader) (MemInfo, error) {
	var info MemInfo
	sawavailable := false
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, rest, found := strings.Cut(line, ":")
		if !found {
			return MemInfo{}, fmt.Errorf("platform: malformed meminfo line %q", line)
		}
		switch key {
		case "MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SwapTotal", "SwapFree":
		default:
			continue
		}
		if seen[key] {
			return MemInfo{}, fmt.Errorf("platform: duplicate meminfo key %s", key)
		}
		seen[key] = true
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return MemInfo{}, fmt.Errorf("platform: malformed meminfo value for %q", key)
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return MemInfo{}, fmt.Errorf("platform: malformed meminfo value for %q: %w", key, err)
		}
		if len(fields) > 1 {
			if fields[1] != "kB" || len(fields) != 2 || value > math.MaxUint64/1024 {
				return MemInfo{}, fmt.Errorf("platform: unsupported meminfo unit %q for %q", fields[1], key)
			}
			value *= 1024 // the kernel prints kB, i.e. 1024-byte blocks
		}
		switch key {
		case "MemTotal":
			info.MemTotal = value
		case "MemAvailable":
			info.MemAvailable = value
			sawavailable = true
		case "MemFree":
			info.MemFree = value
		case "Buffers":
			info.Buffers = value
		case "Cached":
			info.Cached = value
		case "SwapTotal":
			info.SwapTotal = value
		case "SwapFree":
			info.SwapFree = value
		}
	}
	if err := scanner.Err(); err != nil {
		return MemInfo{}, fmt.Errorf("platform: read meminfo: %w", err)
	}
	if info.MemTotal == 0 {
		return MemInfo{}, fmt.Errorf("platform: meminfo missing MemTotal")
	}
	if !sawavailable {
		for _, key := range []string{"MemFree", "Buffers", "Cached"} {
			if !seen[key] {
				return MemInfo{}, fmt.Errorf("platform: meminfo missing %s for availability estimate", key)
			}
		}
		if info.MemFree > math.MaxUint64-info.Buffers || info.MemFree+info.Buffers > math.MaxUint64-info.Cached {
			return MemInfo{}, fmt.Errorf("platform: available memory overflow")
		}
		info.MemAvailable = min(info.MemTotal, info.MemFree+info.Buffers+info.Cached)
	}
	return info, nil
}
