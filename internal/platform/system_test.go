package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLoadAverageLinuxFixture(t *testing.T) {
	f, err := os.Open("../../testdata/proc/loadavg")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ParseLoadAverage(f)
	if err != nil {
		t.Fatalf("ParseLoadAverage: %v", err)
	}
	if got.One != 1.23 || got.Five != 0.75 || got.Fifteen != 0.42 {
		t.Fatalf("load average = %+v", got)
	}
}

func TestParseLoadAverageDarwinSysctlForm(t *testing.T) {
	got, err := ParseLoadAverage(strings.NewReader("{ 1.50 2.25 3.75 }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.One != 1.50 || got.Five != 2.25 || got.Fifteen != 3.75 {
		t.Fatalf("sysctl load average = %+v", got)
	}
}

func TestParseLoadAverageRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{"", "\n", "1.2 3.4\n", "a b c\n", "-1 0 0\n"} {
		if _, err := ParseLoadAverage(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseLoadAverage(%q) succeeded, want error", bad)
		}
	}
}

func TestParseCPUTimesFixture(t *testing.T) {
	f, err := os.Open("../../testdata/proc/cpu_stat")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ParseCPUTimes(f)
	if err != nil {
		t.Fatalf("ParseCPUTimes: %v", err)
	}
	// user 100 + system 100 + idle 800 = 1000 total, idle 800.
	if got.Total != 1000 || got.Idle != 800 {
		t.Fatalf("cpu times = %+v, want total 1000 idle 800", got)
	}
}

func TestCPUTimesUsageSince(t *testing.T) {
	prev := CPUTimes{Total: 1000, Idle: 800}
	if got := (CPUTimes{Total: 1100, Idle: 850}).UsageSince(prev); got != 50 {
		t.Fatalf("usage = %f, want 50", got)
	}
	// Idle-only advance: zero busy time.
	if got := (CPUTimes{Total: 1100, Idle: 900}).UsageSince(prev); got != 0 {
		t.Fatalf("idle-only usage = %f, want 0", got)
	}
	// counter reset (container restart) must not go negative or divide by zero.
	if got := (CPUTimes{Total: 10, Idle: 9}).UsageSince(prev); got != 0 {
		t.Fatalf("reset usage = %f, want 0", got)
	}
	if got := prev.UsageSince(prev); got != 0 {
		t.Fatalf("no-advance usage = %f, want 0", got)
	}
}

func TestParseCPUTimesRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{"", "intr 1\n", "cpu 1 2\n", "cpu a b c d\n"} {
		if _, err := ParseCPUTimes(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseCPUTimes(%q) succeeded, want error", bad)
		}
	}
}

func TestParseMemInfoFixture(t *testing.T) {
	f, err := os.Open("../../testdata/proc/meminfo")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ParseMemInfo(f)
	if err != nil {
		t.Fatalf("ParseMemInfo: %v", err)
	}
	const kb = 1024
	if got.MemTotal != 16384256*kb || got.MemAvailable != 6291456*kb || got.MemFree != 1048576*kb {
		t.Fatalf("meminfo totals = %+v", got)
	}
	if got.Buffers != 524288*kb || got.Cached != 3145728*kb {
		t.Fatalf("meminfo cache = %+v", got)
	}
	if got.SwapTotal != 2097152*kb || got.SwapFree != 1572864*kb {
		t.Fatalf("meminfo swap = %+v", got)
	}
	if want := uint64((16384256 - 6291456) * kb); got.Used() != want {
		t.Fatalf("used = %d, want %d (total - available)", got.Used(), want)
	}
}

func TestParseMemInfoWithoutAvailableFallsBack(t *testing.T) {
	input := "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\n"
	got, err := ParseMemInfo(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got.MemAvailable != 350*1024 {
		t.Fatalf("fallback available = %d, want free+buffers+cached", got.MemAvailable)
	}
}

func TestParseMemInfoRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{
		"MemTotal 1000 kB\n",
		"MemTotal:\n",
		"MemTotal: lots kB\n",
		"MemTotal: 1000 MB\n",
		"MemFree: 100 kB\n",
	} {
		if _, err := ParseMemInfo(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseMemInfo(%q) succeeded, want error", bad)
		}
	}
}

func TestDiskUsageOnTempDir(t *testing.T) {
	dir := t.TempDir()
	got, err := DiskUsage(dir)
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}
	if got.TotalBytes == 0 {
		t.Fatal("total bytes = 0 on a real filesystem")
	}
	if got.UsedBytes != got.TotalBytes-got.FreeBytes {
		t.Fatalf("used %d != total %d - free %d", got.UsedBytes, got.TotalBytes, got.FreeBytes)
	}
	if got.AvailableBytes > got.FreeBytes {
		t.Fatalf("available %d exceeds free %d", got.AvailableBytes, got.FreeBytes)
	}
	if got.TotalInodes > 0 && got.FreeInodes > got.TotalInodes {
		t.Fatalf("free inodes %d exceed total %d", got.FreeInodes, got.TotalInodes)
	}
	if _, err := DiskUsage(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestCountOpenFDsAtFixture(t *testing.T) {
	root := t.TempDir()
	fddir := filepath.Join(root, "4242", "fd")
	if err := os.MkdirAll(fddir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0", "1", "2"} {
		if err := os.WriteFile(filepath.Join(fddir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := CountOpenFDsAt(root, 4242)
	if err != nil {
		t.Fatalf("CountOpenFDsAt: %v", err)
	}
	if got != 3 {
		t.Fatalf("fd count = %d, want 3", got)
	}
	if _, err := CountOpenFDsAt(root, 9999); err == nil {
		t.Fatal("missing process should be an error")
	}
	if _, err := CountOpenFDsAt(root, 0); err == nil {
		t.Fatal("non-positive pid accepted")
	}
}
