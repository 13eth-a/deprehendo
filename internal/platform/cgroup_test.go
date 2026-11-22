package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCgroupFileV2(t *testing.T) {
	input := "12:pids:/\n8:cpu,cpuacct:/pod-1\n0::/system.slice/agent.service\n"
	path, err := ParseCgroupFile(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/system.slice/agent.service" {
		t.Fatalf("v2 path = %q, want /system.slice/agent.service", path)
	}
}

func TestParseCgroupFileV1LayoutReportsEmpty(t *testing.T) {
	input := "12:pids:/\n8:cpu,cpuacct:/pod-1\n3:memory:/runner\n"
	path, err := ParseCgroupFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("v1 layout: %v", err)
	}
	if path != "" {
		t.Fatalf("v1 layout path = %q, want empty", path)
	}
}

func TestParseCgroupFileRejectsMalformedLines(t *testing.T) {
	if _, err := ParseCgroupFile(strings.NewReader("12:pids\n")); err == nil {
		t.Fatal("two-part line accepted")
	}
}

func TestLoadCgroupStatsUnbounded(t *testing.T) {
	root := t.TempDir()
	writeCgroupFixture(t, root, "pod-a", "131072\n", "max\n", "max 100000\n")
	snapshot, err := LoadCgroupStats(root, "/pod-a")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Path != "/pod-a" {
		t.Fatalf("path = %q", snapshot.Path)
	}
	if snapshot.MemoryCurrent != 131072 {
		t.Fatalf("memory.current = %d", snapshot.MemoryCurrent)
	}
	if !snapshot.MemoryMaxSet || snapshot.MemoryMax != 0 {
		t.Fatalf("memory.max = %+v, want unset/max", snapshot.MemoryMaxSet)
	}
	if snapshot.CPUMax != "max 100000" {
		t.Fatalf("cpu.max = %q", snapshot.CPUMax)
	}
}

func TestLoadCgroupStatsBounded(t *testing.T) {
	root := t.TempDir()
	writeCgroupFixture(t, root, "limits", "9437184\n", "10485760\n", "100000 100000\n")
	snapshot, err := LoadCgroupStats(root, "/limits")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.MemoryMaxSet {
		t.Fatal("numeric memory.max must not be marked unset")
	}
	if snapshot.MemoryMax != 10485760 {
		t.Fatalf("memory.max = %d", snapshot.MemoryMax)
	}
	if snapshot.CPUMax == "" {
		t.Fatal("cpu.max raw value expected")
	}
}

func TestLoadCgroupStatsMissingControllersDegrade(t *testing.T) {
	// A valid cgroup whose memory controller is not mounted: current/max
	// degrade to zero rather than failing collection.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bare"), 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadCgroupStats(root, "/bare")
	if err != nil {
		t.Fatalf("missing controller files: %v", err)
	}
	if snapshot.MemoryCurrent != 0 || snapshot.MemoryMax != 0 || snapshot.MemoryMaxSet {
		t.Fatalf("bare cgroup = %+v", snapshot)
	}
}

func TestLoadCgroupStatsRejectsGarbageValues(t *testing.T) {
	root := t.TempDir()
	writeCgroupFixture(t, root, "broken", "not-a-number\n", "max\n", "")
	if _, err := LoadCgroupStats(root, "/broken"); err == nil {
		t.Fatal("garbage memory.current accepted")
	}
}

// memory.events oom_kill is the sampled OOM evidence the causal engine's
// counter rule consumes (causal-semantics §3.2). missing, future and
// non-OOM keys are not errors.
func TestLoadCgroupStatsReadsOOMCounters(t *testing.T) {
	root := t.TempDir()
	writeCgroupFixture(t, root, "pod-2", "131072\n", "10485760\n", "")
	dir := filepath.Join(root, "pod-2")
	if err := os.WriteFile(filepath.Join(dir, "memory.events"), []byte(
		"oom 2\noom_kill 3\noom_group_kill 1\nfuture_key 44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadCgroupStats(root, "/pod-2")
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.OOMEventsAvailable || snapshot.OOMKills != 3 || snapshot.OOMGroupKills != 1 {
		t.Fatalf("counters = %+v, want oom_kill 3 group 1", snapshot)
	}

	// A cgroup without memory.events: "not captured", not zero.
	writeCgroupFixture(t, root, "pod-3", "0\n", "max\n", "")
	snapshot, err = LoadCgroupStats(root, "/pod-3")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OOMEventsAvailable {
		t.Fatal("missing memory.events read as captured")
	}
}

func TestLoadCgroupStatsRejectsGarbageOOMCounter(t *testing.T) {
	root := t.TempDir()
	writeCgroupFixture(t, root, "pod-4", "0\n", "max\n", "")
	if err := os.WriteFile(filepath.Join(root, "pod-4", "memory.events"), []byte("oom_kill not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCgroupStats(root, "/pod-4"); err == nil {
		t.Fatal("garbage oom_kill accepted")
	}
}

func TestCgroupForPID(t *testing.T) {
	procroot := t.TempDir()
	cgrouproot := t.TempDir()
	piddir := filepath.Join(procroot, "777")
	if err := os.MkdirAll(piddir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(piddir, "cgroup"), []byte("0::/pod-7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCgroupFixture(t, cgrouproot, "pod-7", "4096\n", "max\n", "")

	snapshot, err := CgroupFor(777, procroot, cgrouproot)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Path != "/pod-7" || snapshot.MemoryCurrent != 4096 || !snapshot.MemoryMaxSet {
		t.Fatalf("cgroup snapshot = %+v", snapshot)
	}
	// A pid without a proc entry: an error, not a zero snapshot.
	if _, err := CgroupFor(99999, procroot, cgrouproot); err == nil {
		t.Fatal("missing proc pid should error")
	}
}

// writeCgroupFixture creates cgroupRoot/<name>/ with the three controller files.
func writeCgroupFixture(t *testing.T, root, name, current, max, cpumax string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"memory.current": current, "memory.max": max, "cpu.max": cpumax}
	for file, content := range files {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
