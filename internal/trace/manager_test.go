package trace

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fake persistent child: sleeps until killed, exercising the supervision
// loop's child ownership without the rust binary.
func sleepForeverCmd(t *testing.T) func(string) *exec.Cmd {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("process model test")
	}
	return func(string) *exec.Cmd {
		return exec.Command("sleep", "300")
	}
}

func TestManagerMissingBinaryDegrades(t *testing.T) {
	m := NewManager(ManagerConfig{Binary: "/nonexistent/runopsy-trace"})
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()

	deadline := time.After(2 * time.Second)
	for {
		h := m.Health()
		if h.State == StateUnavailable && h.GaveUp {
			break
		}
		select {
		case <-done:
			// run returns promptly on permanent give-up.
			h = m.Health()
			if h.State != StateUnavailable {
				t.Fatalf("state after give-up: %q", h.State)
			}
			goto ok
		case <-deadline:
			t.Fatalf("manager did not degrade; state=%q", m.Health().State)
		case <-time.After(10 * time.Millisecond):
		}
	}
ok:
	_ = m.Health()
	// the recording agent keeps running: stop is safe and cheap.
	m.Stop()
}

func TestManagerGiveUpAfterConsecutiveFailures(t *testing.T) {
	m := NewManager(ManagerConfig{
		BaseBackoff:        5 * time.Millisecond,
		MaxBackoff:         15 * time.Millisecond,
		StartTimeout:       150 * time.Millisecond, // a child that never binds must not stall the test
		MaxConsecutiveFail: 3,
		linuxAllowed:       func() bool { return true },
		spawnCmd:           func(string) *exec.Cmd { return exec.Command("false") },
	})
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not stop after give-up; health=%+v", m.Health())
	}
	h := m.Health()
	if !h.GaveUp || h.State != StateUnavailable {
		t.Fatalf("expected gave-up unavailable state, got %+v", h)
	}
	if h.Attempts != 3 {
		t.Fatalf("expected exactly 3 attempts before give-up, got %d", h.Attempts)
	}
	if h.Restarts > h.Attempts-1 {
		t.Fatalf("restart count %d exceeds attempt count %d", h.Restarts, h.Attempts)
	}
	m.Stop()
}

func TestManagerStopsCleanlyWithLiveChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process model test")
	}
	m := NewManager(ManagerConfig{
		Binary:       "sleep",
		BaseBackoff:  5 * time.Millisecond,
		StartTimeout: 150 * time.Millisecond, // the child never binds: keep each attempt short
		spawnCmd:     sleepForeverCmd(t),
		linuxAllowed: func() bool { return true },
	})
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()

	// wait for the session to become active against the sleep child... the
	// dial will fail because the sleep child never creates the socket, so
	// this test exercises the connect-failure restart path; verify it stays
	// alive across at least two attempts and that stop terminates quickly.
	deadline := time.After(3 * time.Second)
	attempts := 0
	for attempts < 2 {
		if h := m.Health(); h.Attempts > attempts {
			attempts = h.Attempts
		}
		select {
		case <-deadline:
			t.Fatalf("restart loop stalled with attempts=%d", attempts)
		case <-done:
			t.Fatal("Run ended prematurely")
		case <-time.After(5 * time.Millisecond):
		}
	}
	start := time.Now()
	m.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("Stop took %v; shutdown grace leaked", elapsed)
	}
	if h := m.Health(); h.State != StateStopped {
		t.Fatalf("state after Stop: %q", h.State)
	}
}

func TestManagerLinuxGate(t *testing.T) {
	// the platform gate is compile-time honest: on non-Linux the manager
	// never spawns anything. on linux this test still passes trivially.
	if runtime.GOOS != "linux" {
		m := NewManager(ManagerConfig{Binary: "/nonexistent/runopsy-trace"})
		done := make(chan struct{})
		go func() { _ = m.Run(context.Background()); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("non-Linux Run did not return immediately")
		}
		h := m.Health()
		if h.State != StateUnavailable || h.Reason == "" {
			t.Fatalf("non-Linux expected unavailable+reason, got %+v", h)
		}
		if h.Attempts != 0 {
			t.Fatalf("non-Linux must not spawn: attempts=%d", h.Attempts)
		}
		m.Stop()
	}
}

func TestManagerStoppedBeforeRunIsSafe(t *testing.T) {
	m := NewManager(ManagerConfig{Binary: "/nonexistent/runopsy-trace"})
	m.Stop() // before run: must not panic or block
	h := m.Health()
	if h.State != "" && h.State != StateStopped && h.State != StateUnavailable {
		t.Fatalf("unexpected post-Stop state %q", h.State)
	}
}

func TestResolveBinaryOverride(t *testing.T) {
	// an explicit override is never silently replaced by a PATH lookup. when
	// it does not exist the supervisor degrades at once with a reason (6.52),
	// instead of spending its restart budget spawning a missing file (principal
	// phase 6 review).
	bin, why := ResolveBinary("/explicit/runopsy-trace")
	if bin != "" || !strings.Contains(why, "/explicit/runopsy-trace") {
		t.Fatalf("missing override: bin=%q why=%q", bin, why)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if bin, why := ResolveBinary(self); bin != self || why != "" {
		t.Fatalf("existing override replaced: bin=%q why=%q", bin, why)
	}
}

func TestSocketPathPreferredIsNotDeleted(t *testing.T) {
	dir, err := os.MkdirTemp("", "runopsy-trace-sockpath")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := dir + "/given.sock"
	sock, cleanup, err := socketPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if sock != path {
		t.Fatalf("preferred socket path changed: %q != %q", sock, path)
	}
	cleanup() // preferred path: cleanup must be a no-op
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("preferred-path cleanup removed the parent dir: %v", err)
	}
}
