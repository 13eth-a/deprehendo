package collector

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"deprehendo/internal/platform"
)

// HostSystemCollector samples host-level load, aggregate CPU utilisation,
// memory, and disk capacity. Sub-sensors are independent: a failing sensor is
// reported in the returned error while the sensors that succeeded remain
// populated, matching the snapshot-level partial-failure rule.
//
// aggregate CPU percentage is derived from consecutive /proc/stat samples and
// is 0 on the collector's first cycle (no baseline yet). Linux-only; macOS
// exposes load and disk but not aggregate CPU accounting, which shows up as a
// partial system error rather than a blank system section.
type HostSystemCollector struct {
	mu      sync.Mutex
	WatchFS string

	readLoad func() (platform.LoadAverage, error)
	readCPU  func() (platform.CPUTimes, error)
	readMem  func() (platform.MemInfo, error)
	readDisk func(string) (platform.DiskStats, error)

	prevCPU     platform.CPUTimes
	havePrevCPU bool
}

// NewHostSystemCollector creates the production collector for the filesystem
// containing watchFS. an empty path defaults to "/", matching the CLI default.
func NewHostSystemCollector(watchFS string) *HostSystemCollector {
	if watchFS == "" {
		watchFS = "/"
	}
	return &HostSystemCollector{
		WatchFS:  watchFS,
		readLoad: platform.ReadLoadAverage,
		readCPU:  platform.ReadCPUTimes,
		readMem:  platform.ReadMemInfo,
		readDisk: platform.DiskUsage,
	}
}

// CollectSystem samples every host sensor and returns the partial snapshot
// plus a combined error naming the sensors that failed.
func (c *HostSystemCollector) CollectSystem() (SystemSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := SystemSnapshot{CPUCount: runtime.NumCPU()}
	var failures []string

	if load, err := c.readLoad(); err != nil {
		failures = append(failures, "load: "+err.Error())
	} else {
		snapshot.LoadAvailable = true
		snapshot.LoadAverage = load.One
	}

	if times, err := c.readCPU(); err != nil {
		failures = append(failures, "cpu: "+err.Error())
	} else {
		snapshot.CPUAvailable = true
		if c.havePrevCPU {
			snapshot.CPUPercentAvailable = true
			snapshot.CPUPercent = times.UsageSince(c.prevCPU)
		}
		c.prevCPU = times
		c.havePrevCPU = true
	}

	if mem, err := c.readMem(); err != nil {
		failures = append(failures, "memory: "+err.Error())
	} else {
		snapshot.MemoryStatsAvailable = true
		snapshot.MemoryTotal = mem.MemTotal
		snapshot.MemoryUsed = mem.Used()
		snapshot.MemoryFree = mem.MemFree
		snapshot.MemoryAvailable = mem.MemAvailable
		snapshot.MemoryBuffers = mem.Buffers
		snapshot.MemoryCached = mem.Cached
		snapshot.SwapTotal = mem.SwapTotal
		snapshot.SwapFree = mem.SwapFree
	}

	if disk, err := c.readDisk(c.WatchFS); err != nil {
		failures = append(failures, "disk: "+err.Error())
	} else {
		snapshot.DiskStatsAvailable = true
		snapshot.DiskTotal = disk.TotalBytes
		snapshot.DiskFree = disk.FreeBytes
		snapshot.DiskUsed = disk.UsedBytes
		snapshot.DiskAvailable = disk.AvailableBytes
		snapshot.DiskFilesystem = disk.Filesystem
		snapshot.DiskTotalInodes = disk.TotalInodes
		snapshot.DiskFreeInodes = disk.FreeInodes
	}

	if len(failures) > 0 {
		return snapshot, fmt.Errorf("system: %s", strings.Join(failures, "; "))
	}
	return snapshot, nil
}
