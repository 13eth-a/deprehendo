package platform

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSnapshotIncludesSelf(t *testing.T) {
	if runtime.GOOS == "darwin" {
		self, err := darwinProcesses()
		if err != nil {
			t.Fatalf("darwinProcesses: %v", err)
		}
		found := false
		for _, p := range self {
			if p.PID == os.Getpid() {
				found = true
				if p.Threads != 0 {
					t.Errorf("darwin thread count = %d, want zero (unavailable)", p.Threads)
				}
			}
		}
		if !found {
			t.Errorf("darwin process listing does not include self pid %d", os.Getpid())
		}
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("no process snapshot on %s", runtime.GOOS)
	}
	all, err := Processes()
	if err != nil {
		t.Fatalf("Processes: %v", err)
	}
	// A container PID namespace may have only a handful of processes.
	// verify a known process instead of assuming the host's process count.
	foundself := false
	for _, process := range all {
		if process.PID == os.Getpid() && process.PPID == os.Getppid() {
			foundself = true
		}
	}
	if !foundself {
		t.Errorf("snapshot does not contain self with expected parent: %+v", all)
	}
	self, ok, err := Find(os.Getpid())
	if err != nil || !ok {
		t.Fatalf("Find(self): ok=%v err=%v; snapshot=%d entries", ok, err, len(all))
	}
	if self.PPID <= 0 {
		t.Errorf("self ppid = %d, want > 0", self.PPID)
	}
	if self.PGID <= 0 {
		t.Errorf("self pgid = %d, want > 0", self.PGID)
	}
	if self.State == "" {
		t.Error("self state missing")
	}
	if runtime.GOOS == "linux" && self.Threads < 1 {
		t.Errorf("self thread count = %d, want at least 1", self.Threads)
	}
}

func TestParseLinuxStatThreadCountAndExtendedMetadata(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/proc/stat")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseLinuxStat(4242, raw)
	if err != nil {
		t.Fatalf("parseLinuxStat: %v", err)
	}
	if got.PID != 4242 || got.PPID != 1 || got.PGID != 4242 || got.SID != 4242 || got.State != "S" {
		t.Errorf("process identity = %+v", got)
	}
	if got.Threads != 3 {
		t.Errorf("threads = %d, want 3", got.Threads)
	}
	if got.CPUTicks != 22 { // utime 15 + stime 7 in fixture
		t.Errorf("cpu ticks = %d, want 22", got.CPUTicks)
	}
	if got.StartTicks != 123456 {
		t.Errorf("start ticks = %d, want 123456", got.StartTicks)
	}
	if want := uint64(42 * os.Getpagesize()); got.RSSBytes != want {
		t.Errorf("rss bytes = %d, want %d", got.RSSBytes, want)
	}
}

func TestParseLinuxStatZombieExitStatus(t *testing.T) {
	// after-comm indices: state(0) ... utime(11) stime(12) threads(17)
	// starttime(19) vsize(20) rss(21) ... exit_code(49).
	statrow := func(state string, count int, exitCode string) []byte {
		fields := make([]string, max(count, 22))
		fields[0] = state
		fields[1], fields[2], fields[3] = "1", "4242", "4242"
		fields[11], fields[12] = "15", "7"
		fields[17] = "3"
		fields[19], fields[20], fields[21] = "123456", "987654", "42"
		if count > 49 {
			fields[49] = exitCode
		}
		for i, f := range fields {
			if f == "" {
				fields[i] = "0"
			}
		}
		return []byte("4242 (worker) " + strings.Join(fields, " ") + "\n")
	}

	wantexit := func(t *testing.T, raw []byte, state, exitStatus string) {
		t.Helper()
		p, err := parseLinuxStat(4242, raw)
		if err != nil {
			t.Fatalf("parseLinuxStat(state %s, code %q): %v", state, exitStatus, err)
		}
		captured := state == "Z" && exitStatus != ""
		if captured {
			if p.ExitStatus != exitStatus {
				t.Errorf("state %s with status %q: got %q", state, exitStatus, p.ExitStatus)
			}
		} else if p.ExitStatus != "" {
			t.Errorf("state %s with status %q: got %q, want empty", state, exitStatus, p.ExitStatus)
		}
	}

	// A zombie's wait status: 10<<8 exited with code 10; 9 = killed by
	// signal 9 (WIFSIGNALED); 0 = "exited 0", still recorded.
	wantexit(t, statrow("Z", 51, "2560"), "Z", "exit:10")
	wantexit(t, statrow("Z", 51, "9"), "Z", "signal:9")
	wantexit(t, statrow("Z", 51, "0"), "Z", "exit:0")
	// A malformed bookkeeping value is unavailable, not fatal.
	wantexit(t, statrow("Z", 51, "banana"), "Z", "")
	// older kernels with a short stat row, and a live process: never reported.
	wantexit(t, statrow("Z", 22, "2560"), "Z", "")
	wantexit(t, statrow("S", 51, "2560"), "S", "")
}

func TestParseDarwinThreadCounts(t *testing.T) {
	out := []byte("" +
		"USER PID TT %CPU STAT PRI STIME UTIME COMMAND\n" +
		"alice 42 ?? 0.0 S 31T 0:00.00 0:00.00 /usr/bin/worker\n" +
		"       42 0.0 S 31T 0:00.00 0:00.00\n" +
		"       42 0.2 S 31T 0:00.01 0:00.00\n" +
		"bob 77 ?? 0.0 S 31T 0:00.00 0:00.00 /usr/bin/other\n" +
		"       77 0.1 S 31T 0:00.01 0:00.00\n")
	got := parseDarwinThreadCounts(out)
	if got[42] != 2 || got[77] != 1 {
		t.Fatalf("thread counts = %#v, want pid 42:2 and pid 77:1", got)
	}
	if len(got) != 2 {
		t.Fatalf("unexpected processes in parsed thread counts: %#v", got)
	}
}

func TestParseLinuxStatRejectsMalformedInput(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("123 no-parens S 1"), []byte("123 (worker) S 1 2 3")} {
		if _, err := parseLinuxStat(123, raw); err == nil {
			t.Errorf("parseLinuxStat(%q) succeeded, want malformed-input error", raw)
		}
	}
}

func TestChildrenAndGroupKill(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("no process snapshot on %s", runtime.GOOS)
	}
	self := os.Getpid()

	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	var kid Process
	deadline := time.Now().Add(3 * time.Second)
Ok:
	for {
		kids, err := Children(self)
		if err != nil {
			t.Fatalf("Children: %v", err)
		}
		for _, k := range kids {
			if k.PID == cmd.Process.Pid {
				kid = k
				break Ok
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never appeared in snapshot; children=%v", kids)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if kid.PPID != self {
		t.Errorf("child ppid = %d, want %d", kid.PPID, self)
	}
	// A process started with setpgid leads its own group: pgid == pid.
	if kid.PGID != kid.PID {
		t.Errorf("child pgid = %d, want = pid %d", kid.PGID, kid.PID)
	}

	if err := KillGroup(kid.PID, syscall.SIGKILL); err != nil {
		t.Fatalf("KillGroup: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Error("expected the killed child to report a wait error")
	}
	waitGone(t, kid.PID)

	if err := KillGroup(kid.PID, syscall.SIGKILL); err != nil {
		t.Errorf("KillGroup on a dead group should be a no-op, got %v", err)
	}
}

func TestKillGroupRejectsUnsafeIDs(t *testing.T) {
	for _, pgid := range []int{0, -1, -42} {
		if err := KillGroup(pgid, syscall.SIGKILL); err == nil {
			t.Errorf("KillGroup(%d) unexpectedly succeeded", pgid)
		}
	}
}

func TestStopStateVisible(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("no process state on %s", runtime.GOOS)
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	pid := cmd.Process.Pid

	if err := SignalProcess(pid, syscall.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP: %v", err)
	}
	if !waitState(t, pid, "T", 2*time.Second) {
		t.Fatalf("child never reached stopped state")
	}
	if err := SignalProcess(pid, syscall.SIGCONT); err != nil {
		t.Fatalf("SIGCONT: %v", err)
	}
	if !waitNotState(t, pid, "T", 2*time.Second) {
		t.Fatalf("child never resumed")
	}
	_ = SignalProcess(pid, syscall.SIGKILL)
	_ = cmd.Wait()
	waitGone(t, pid)
}

func waitState(t *testing.T, pid int, state string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		p, ok, err := Find(pid)
		if err != nil {
			t.Fatalf("Find(%d): %v", pid, err)
		}
		if ok && strings.HasPrefix(p.State, state) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func waitNotState(t *testing.T, pid int, state string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		p, ok, err := Find(pid)
		if err != nil {
			t.Fatalf("Find(%d): %v", pid, err)
		}
		if !ok {
			return true
		}
		if !strings.HasPrefix(p.State, state) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// waitGone polls until pid is not in the snapshot at all.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !Alive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if p, ok, _ := Find(pid); ok {
		t.Fatalf("pid %d still present: %s", pid, p.State)
	}
}
