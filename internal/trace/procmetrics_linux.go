//go:build linux

package trace

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// userHz is linux's USER_HZ ABI value: /proc/<pid>/stat reports CPU time in
// these ticks on every architecture go supports. it is a kernel ABI constant,
// not a host heuristic.
const userHz = 100

// ReadProcessMetrics reads one /proc observation of pid. both /proc/<pid>/stat
// and /proc/<pid>/status are parsed by hand: no subprocess, no cgo, no
// dependency, and the cost stays at two small reads per sample.
func ReadProcessMetrics(pid int) (ProcessMetrics, error) {
	if pid <= 0 {
		return ProcessMetrics{}, fmt.Errorf("trace: invalid pid %d", pid)
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ProcessMetrics{}, fmt.Errorf("trace: metrics for pid %d: %w", pid, err)
	}
	metrics, err := parseProcStat(pid, string(raw))
	if err != nil {
		return ProcessMetrics{}, err
	}
	// status is optional: RSS is already available from stat (in pages).
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		applyProcStatus(&metrics, string(status))
	}
	return metrics, nil
}

// parseProcStat parses the fields phase 6 needs. the comm field can contain
// spaces and parentheses, so parsing starts after the *last* ')'; everything
// before it is the pid and the (possibly decorated) process name.
func parseProcStat(pid int, stat string) (ProcessMetrics, error) {
	close := strings.LastIndexByte(stat, ')')
	if close < 0 || close+2 > len(stat) {
		return ProcessMetrics{}, fmt.Errorf("trace: unparsable /proc/%d/stat", pid)
	}
	// fields[0] is kernel field 3 ("state"): fields 14/15 (utime/stime) are
	// at offsets 11/12, and field 24 (rss, in pages) is at offset 21.
	fields := strings.Fields(stat[close+1:])
	if len(fields) < 22 {
		return ProcessMetrics{}, fmt.Errorf("trace: short /proc/%d/stat (%d fields)", pid, len(fields))
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return ProcessMetrics{}, fmt.Errorf("trace: /proc/%d/stat utime: %w", pid, err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return ProcessMetrics{}, fmt.Errorf("trace: /proc/%d/stat stime: %w", pid, err)
	}
	pages, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return ProcessMetrics{}, fmt.Errorf("trace: /proc/%d/stat rss: %w", pid, err)
	}
	if pages < 0 {
		pages = 0 // kernel reports a negative rss only for unreaped states
	}
	ticks := utime + stime
	return ProcessMetrics{
		PID:      pid,
		CPUTime:  time.Duration(ticks) * time.Second / userHz,
		RSSBytes: uint64(pages) * uint64(os.Getpagesize()),
	}, nil
}

// applyProcStatus fills RSS/peak RSS from the status file's kB fields.
func applyProcStatus(m *ProcessMetrics, status string) {
	for _, line := range strings.Split(status, "\n") {
		var target *uint64
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			target = &m.RSSBytes
		case strings.HasPrefix(line, "VmHWM:"):
			target = &m.PeakRSSBytes
		default:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		*target = kb * 1024
	}
}
