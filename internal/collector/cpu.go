package collector

import (
	"sync"
	"time"

	"deprehendo/internal/platform"
)

// linuxUserHZ is the fixed userland ABI value of _SC_CLK_TCK on linux: the
// kernel tick accounting exposed via /proc/<pid>/stat is always expressed in
// hundredths of a second, regardless of the kernel's internal HZ.
const linuxUserHZ = 100.0

// CPUPercentFor converts a tick delta and its wall-time span into a
// percentage of one CPU core. A multi-threaded process can legitimately
// exceed 100; callers must pass non-negative deltas.
func CPUPercentFor(tickDelta uint64, elapsed time.Duration) float64 {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return 0
	}
	return float64(tickDelta) / (seconds * linuxUserHZ) * 100
}

type procKey struct {
	pid        int
	startTicks int64
}

type procSample struct {
	ticks uint64
	at    time.Time
}

// CPUTracker derives per-process CPU percentages from consecutive samples,
// keyed on PID + start ticks: a recycled PID is treated as a new process
// rather than producing a nonsense (possibly negative or huge) delta against
// the previous holder of that PID. the first sample of any process reports 0
// percent. exited processes are forgotten automatically because the tracker
// only retains the immediately preceding sample.
type CPUTracker struct {
	mu   sync.Mutex
	prev map[procKey]procSample
}

// observe converts one raw process-table sample, stamped at now, into
// snapshots with CPUPercent filled in. missing start identity reports zero
// rather than comparing CPU counters across a potentially recycled PID.
func (t *CPUTracker) Observe(processes []platform.Process, now time.Time) []ProcessSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prev == nil {
		t.prev = make(map[procKey]procSample, len(processes))
	}
	current := make(map[procKey]procSample, len(processes))
	snapshots := make([]ProcessSnapshot, 0, len(processes))
	for _, p := range processes {
		key := procKey{pid: p.PID, startTicks: p.StartTicks}
		current[key] = procSample{ticks: p.CPUTicks, at: now}
		snapshot := ProcessSnapshot{Process: p, OpenFDs: -1}
		if prev, ok := t.prev[key]; ok && p.StartTicks > 0 {
			if p.CPUTicks > prev.ticks {
				snapshot.CPUPercent = CPUPercentFor(p.CPUTicks-prev.ticks, now.Sub(prev.at))
			}
		}
		snapshots = append(snapshots, snapshot)
	}
	t.prev = current
	return snapshots
}
