package platform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func statFixture(pid int, start int64) string {
	return fmt.Sprintf("%d (worker ) with spaces) S 1 4242 4242 0 -1 4194304 10 2 0 0 15 7 0 0 20 0 3 0 %d 987654 42\n", pid, start)
}
func writeStatFixture(t testing.TB, root string, pid int, start int64) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(statFixture(pid, start)), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestLinuxStatRejectsInvalidIdentityAndOverflow(t *testing.T) {
	base := statFixture(42, 123)
	for _, bad := range []string{
		strings.Replace(base, "42 (", "43 (", 1),
		strings.Replace(base, " S ", " WHAT ", 1),
		strings.Replace(base, " 123 ", " -1 ", 1),
		strings.Replace(base, " 15 7 ", " 18446744073709551615 7 ", 1),
		strings.Replace(base, "987654 42", "987654 18446744073709551615", 1),
	} {
		if _, err := parseLinuxStat(42, []byte(bad)); err == nil {
			t.Errorf("accepted malformed stat: %s", bad)
		}
	}
}
func TestProcessScanPartialAndExitRace(t *testing.T) {
	root := t.TempDir()
	writeStatFixture(t, root, 42, 123)
	if err := os.Mkdir(filepath.Join(root, "43"), 0755); err != nil {
		t.Fatal(err)
	}
	rows, err := ProcessesAt(context.Background(), root)
	if err != nil || len(rows) != 1 {
		t.Fatalf("exit race: %v %v", rows, err)
	}
	if err := os.WriteFile(filepath.Join(root, "43", "stat"), []byte("broken"), 0644); err != nil {
		t.Fatal(err)
	}
	rows, err = ProcessesAt(context.Background(), root)
	if err == nil || len(rows) != 1 {
		t.Fatalf("partial scan: %v %v", rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProcessesAt(ctx, root); err == nil {
		t.Fatal("canceled scan succeeded")
	}
}
func TestSocketOwnersRequiresIdentity(t *testing.T) {
	root := t.TempDir()
	writeStatFixture(t, root, 42, 123)
	dir := filepath.Join(root, "42", "fd")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[345]", filepath.Join(dir, "7")); err != nil {
		t.Fatal(err)
	}
	owners, err := SocketOwners(root)
	if err != nil || owners[345].StartTicks != 123 {
		t.Fatalf("owners=%v error=%v", owners, err)
	}
	if err := os.Remove(filepath.Join(root, "42", "stat")); err != nil {
		t.Fatal(err)
	}
	owners, err = SocketOwners(root)
	if err != nil || len(owners) != 0 {
		t.Fatalf("vanished owner retained: %v %v", owners, err)
	}
	if _, ok := socketInode("socket:[0]"); ok {
		t.Fatal("zero inode accepted")
	}
}
func TestConnectionsRetainPartialFamilies(t *testing.T) {
	root := t.TempDir()
	valid := "0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n"
	if err := os.WriteFile(filepath.Join(root, "tcp"), []byte(valid+"malformed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tcp6"), []byte("sl local_address\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rows, err := ConnectionsAt(context.Background(), root)
	if err == nil || len(rows) != 1 {
		t.Fatalf("partial TCP rows=%v error=%v", rows, err)
	}
	if err := os.Remove(filepath.Join(root, "tcp")); err != nil {
		t.Fatal(err)
	}
	if _, err := ConnectionsAt(context.Background(), root); err == nil {
		t.Fatal("missing IPv4 table treated as success")
	}
}
func TestPressureRejectsMissingNonfiniteAndDuplicateData(t *testing.T) {
	valid := "some avg10=1 avg60=2 avg300=3 total=10\n"
	for _, bad := range []string{"", "full avg10=1 avg60=2 avg300=3 total=10\n", "some avg10=1\n", valid + valid,
		strings.Replace(valid, "avg10=1", "avg10=NaN", 1), strings.Replace(valid, "avg60=2", "avg60=+Inf", 1),
		strings.Replace(valid, "avg10=1", "avg10=101", 1), strings.Replace(valid, "total=10", "total=-1", 1),
		strings.Replace(valid, "total=10", "avg10=1 total=10", 1)} {
		if _, err := ParsePressure(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted invalid PSI %q", bad)
		}
	}
	got, err := ParsePressure(strings.NewReader(strings.ReplaceAll(valid, " ", "\t")))
	if err != nil || !got.HasSome || got.Some.TotalMicros != 10 {
		t.Fatalf("tab PSI=%+v %v", got, err)
	}
}
func TestCgroupRejectsUnsafePathsMissingGroupsAndBadCPU(t *testing.T) {
	for _, path := range []string{"", "relative", "/../outside", "/a/../../outside"} {
		if _, err := LoadCgroupStats(t.TempDir(), path); err == nil {
			t.Errorf("accepted path %q", path)
		}
	}
	if _, err := LoadCgroupStats(t.TempDir(), "/gone"); err == nil {
		t.Fatal("missing cgroup accepted")
	}
	root := t.TempDir()
	writeCgroupFixture(t, root, "bad", "0", "0", "bad")
	got, err := LoadCgroupStats(root, "/bad")
	if err == nil || !got.MemoryCurrentAvailable || !got.MemoryMaxAvailable || got.CPUAvailable {
		t.Fatalf("partial cgroup=%+v %v", got, err)
	}
}
func TestCgroupForSubtreeMount(t *testing.T) {
	procroot, root := t.TempDir(), t.TempDir()
	writeStatFixture(t, procroot, 42, 123)
	if err := os.WriteFile(filepath.Join(procroot, "42", "cgroup"), []byte("0::/tenant/child\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(procroot, "self"), 0755); err != nil {
		t.Fatal(err)
	}
	mount := fmt.Sprintf("1 2 0:1 /tenant %s rw - cgroup2 cgroup rw\n", root)
	if err := os.WriteFile(filepath.Join(procroot, "self", "mountinfo"), []byte(mount), 0644); err != nil {
		t.Fatal(err)
	}
	writeCgroupFixture(t, root, "child", "4096", "max", "max 100000")
	got, err := processCgroupAt(42, procroot, root)
	if err != nil || got.Path != "/tenant/child" || got.MemoryCurrent != 4096 || got.StartTicks != 123 || got.PID != 42 {
		t.Fatalf("subtree cgroup=%+v %v", got, err)
	}
}
func TestSystemParsersRejectNonfiniteAndOverflow(t *testing.T) {
	for _, raw := range []string{"NaN 1 2", "+Inf 1 2"} {
		if _, err := ParseLoadAverage(strings.NewReader(raw)); err == nil {
			t.Errorf("accepted load %q", raw)
		}
	}
	if _, err := ParseCPUTimes(strings.NewReader("cpu 18446744073709551615 1 0 0")); err == nil {
		t.Fatal("CPU overflow accepted")
	}
	if _, err := ParseMemInfo(strings.NewReader("MemTotal: 18446744073709551615 kB")); err == nil {
		t.Fatal("memory overflow accepted")
	}
	if _, err := ParseMemInfo(strings.NewReader("MemFree: 10 kB")); err == nil {
		t.Fatal("missing total accepted")
	}
}

func TestScopedSocketOwnersSkipUnwatchedAndStalePIDs(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []int{42, 43} {
		writeStatFixture(t, root, pid, 123)
		dir := filepath.Join(root, fmt.Sprint(pid), "fd")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fmt.Sprintf("socket:[%d]", pid), filepath.Join(dir, "7")); err != nil {
			t.Fatal(err)
		}
	}
	owners, err := SocketOwnersForContext(context.Background(), root, []Process{{PID: 42, StartTicks: 123}})
	if err != nil || len(owners) != 1 || owners[42].PID != 42 {
		t.Fatalf("scoped owners=%v %v", owners, err)
	}
	owners, err = SocketOwnersForContext(context.Background(), root, []Process{{PID: 42, StartTicks: 122}})
	if err != nil || len(owners) != 0 {
		t.Fatalf("stale owners=%v %v", owners, err)
	}
}
func TestPartialOwnerErrorsPreserveUsableMappings(t *testing.T) {
	root := t.TempDir()
	writeStatFixture(t, root, 42, 123)
	writeStatFixture(t, root, 43, 123)
	if err := os.Mkdir(filepath.Join(root, "42", "fd"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[42]", filepath.Join(root, "42", "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "43", "fd"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	owners, err := SocketOwners(root)
	if err == nil || len(owners) != 1 || owners[42].PID != 42 {
		t.Fatalf("partial owners=%v %v", owners, err)
	}
}
