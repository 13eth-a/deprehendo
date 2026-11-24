package collector

import (
	"errors"
	"strings"
	"testing"

	"deprehendo/internal/platform"
)

// stubHostSystem replaces every host sensor so tests never depend on the live
// machine.
func stubHostSystem() *HostSystemCollector {
	collector := &HostSystemCollector{
		WatchFS: "/",
		readLoad: func() (platform.LoadAverage, error) {
			return platform.LoadAverage{One: 1.25, Five: 0.5, Fifteen: 0.25}, nil
		},
		readCPU: func() (platform.CPUTimes, error) {
			return platform.CPUTimes{Total: 1000, Idle: 800}, nil
		},
		readMem: func() (platform.MemInfo, error) {
			return platform.MemInfo{MemTotal: 16 << 30, MemAvailable: 6 << 30, MemFree: 1 << 30}, nil
		},
		readDisk: func(string) (platform.DiskStats, error) {
			return platform.DiskStats{TotalBytes: 500 << 30, FreeBytes: 100 << 30, UsedBytes: 400 << 30}, nil
		},
	}
	return collector
}

func TestHostSystemCollectorFillsAllSections(t *testing.T) {
	collector := stubHostSystem()
	first, err := collector.CollectSystem()
	if err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if first.LoadAverage != 1.25 || first.CPUCount == 0 {
		t.Fatalf("load/cpu count = %+v", first)
	}
	if first.CPUPercent != 0 {
		t.Fatalf("first cycle cpu percent = %f, want 0 (no baseline)", first.CPUPercent)
	}
	if first.MemoryTotal != 16<<30 || first.MemoryUsed != 10<<30 || first.MemoryFree != 1<<30 || first.MemoryAvailable != 6<<30 {
		t.Fatalf("memory = %+v", first)
	}
	if first.DiskTotal != 500<<30 || first.DiskUsed != 400<<30 || first.DiskFree != 100<<30 {
		t.Fatalf("disk = %+v", first)
	}

	// second cycle: counters advance 50 busy ticks out of 100 → 50%.
	collector.readCPU = func() (platform.CPUTimes, error) {
		return platform.CPUTimes{Total: 1100, Idle: 850}, nil
	}
	second, err := collector.CollectSystem()
	if err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if second.CPUPercent != 50 {
		t.Fatalf("cpu percent = %f, want 50", second.CPUPercent)
	}
}

func TestHostSystemCollectorKeepsPartialResults(t *testing.T) {
	collector := stubHostSystem()
	collector.readMem = func() (platform.MemInfo, error) {
		return platform.MemInfo{}, errors.New("meminfo unavailable")
	}
	snapshot, err := collector.CollectSystem()
	if err == nil {
		t.Fatal("expected a combined system error")
	}
	if !strings.Contains(err.Error(), "memory") {
		t.Fatalf("error = %v, want a memory failure", err)
	}
	if snapshot.LoadAverage != 1.25 {
		t.Fatalf("load lost on memory failure: %+v", snapshot)
	}
	if snapshot.DiskTotal != 500<<30 {
		t.Fatalf("disk lost on memory failure: %+v", snapshot)
	}
	if snapshot.MemoryTotal != 0 {
		t.Fatalf("failed memory sensor should leave zeroes: %+v", snapshot)
	}
}

func TestHostSystemCollectorCombinesFailures(t *testing.T) {
	collector := stubHostSystem()
	collector.readLoad = func() (platform.LoadAverage, error) {
		return platform.LoadAverage{}, errors.New("no loadavg")
	}
	collector.readCPU = func() (platform.CPUTimes, error) {
		return platform.CPUTimes{}, errors.New("no proc stat")
	}
	_, err := collector.CollectSystem()
	if err == nil {
		t.Fatal("expected a combined error")
	}
	message := err.Error()
	if !strings.Contains(message, "load") || !strings.Contains(message, "cpu") {
		t.Fatalf("combined error = %q, want both load and cpu", message)
	}
	if strings.Contains(message, "memory") {
		t.Fatalf("healthy sensor reported as failed: %q", message)
	}
}

func TestHostSystemCollectorDefaultWatchFS(t *testing.T) {
	if got := NewHostSystemCollector("").WatchFS; got != "/" {
		t.Fatalf("default watch fs = %q, want /", got)
	}
	if got := NewHostSystemCollector("/tmp").WatchFS; got != "/tmp" {
		t.Fatalf("watch fs = %q, want /tmp", got)
	}
}
