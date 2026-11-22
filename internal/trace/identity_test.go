package trace

// §6.3 b identity checks on the go side of the handshake. the rust tracer
// stamps boot_id, the PID-namespace inode and event_clock into its reply, and
// the agent must refuse a tracer whose environment cannot be its own instead
// of mistranslating every PID or ordering events on incomparable clocks. the
// identity source (identity.go) is a seam here: tests fix the agent's local
// identity, so these run on every host, not just Linux.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withLocalIdentity fixes the agent's own §6.3 b identity for the test.
func withLocalIdentity(t *testing.T, id LocalIdentity) {
	t.Helper()
	old := localIdentityFn
	localIdentityFn = func() LocalIdentity { return id }
	t.Cleanup(func() { localIdentityFn = old })
}

// listeningSocket keeps the path short: macOS sun_path size is 104, and a
// long t.TempDir prefix with the test name busts it.
var identitySocket = 0

func listeningSocket(t *testing.T) string {
	t.Helper()
	identitySocket++
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("run-id-%d-%d.sock", os.Getpid(), identitySocket))
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })
	return sock
}

// answeringServer accepts one connection and answers its handshake with hs.
// the session's checks are synchronous inside connect, so a brief hold after
// the reply is enough for every case here.
func answeringServer(t *testing.T, hs Handshake, hold time.Duration) string {
	t.Helper()
	sock := listeningSocket(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		f := newFramer(conn, conn)
		frame, err := f.readFrame()
		if err != nil || frame.Kind != KindHandshake {
			return
		}
		raw, err := encodeHandshake(hs)
		if err != nil {
			return
		}
		_ = f.writeFrame(KindHandshake, SchemaVersion, raw)
		time.Sleep(hold)
	}()
	return sock
}

// procCaps is a coherent proc-connector handshake reply: both base
// capabilities attached, the rest not collected by this backend, each with
// its why (§6.3 b).
func procCaps() Capabilities {
	return Capabilities{
		ProcessExec:      true,
		ProcessExit:      true,
		Backend:          "proc_connector",
		ExecState:        CapStateAttached,
		ExitState:        CapStateAttached,
		SignalsState:     CapStateNotCollected,
		SignalsReason:    "sent/delivered signals need the eBPF backend",
		StopResumeState:  CapStateNotCollected,
		StopResumeReason: "job-control stop/resume needs the eBPF backend",
		OomState:         CapStateNotCollected,
		OomReason:        "OOM victim needs the eBPF backend",
	}
}

func tracerHandshake(caps Capabilities, boot string, ns uint64, clock string) Handshake {
	return Handshake{
		ProtocolVersion:   ProtocolVersion,
		MinVersion:        ProtocolVersionMin,
		TracerVersion:     "fake",
		Capabilities:      caps,
		MonotonicNs:       time.Now().UnixNano(),
		WallUnixMs:        time.Now().UnixMilli(),
		SchemaVersion:     SchemaVersion,
		BootID:            boot,
		PIDNamespaceInode: ns,
		EventClock:        clock,
	}
}

func TestConnectRefusesIdentityMismatches(t *testing.T) {
	caps := procCaps()
	attachedbutfalse := procCaps()
	attachedbutfalse.ProcessExec = false
	claimedbutunavailable := procCaps()
	claimedbutunavailable.Signals = true
	claimedbutunavailable.SignalsState = CapStateUnavailable

	// Capability-state contradictions are a lying handshake (protocol
	// violation), not an environment mismatch.
	cases := []struct {
		name      string
		local     LocalIdentity
		hs        Handshake
		wantText  string
		wantClass error
	}{
		{
			// A stale socket file surviving a reboot must not produce a
			// session that bundles evidence from a kernel that was not
			// running (§11.1).
			name:      "another boot",
			local:     LocalIdentity{BootID: "boot-agent"},
			hs:        tracerHandshake(caps, "boot-stale", 0, EventClockMonotonic),
			wantText:  "boot_id differs",
			wantClass: ErrIdentityMismatch,
		},
		{
			name:      "another PID namespace",
			local:     LocalIdentity{PIDNamespaceInode: 4026531836},
			hs:        tracerHandshake(caps, "", 4044444444, EventClockMonotonic),
			wantText:  "PIDs are not the agent's PIDs",
			wantClass: ErrIdentityMismatch,
		},
		{
			name:      "another event clock",
			local:     LocalIdentity{BootID: "boot-agent", PIDNamespaceInode: 42},
			hs:        tracerHandshake(caps, "boot-agent", 42, "CLOCK_REALTIME"),
			wantText:  "events on clock",
			wantClass: ErrIdentityMismatch,
		},
		{
			name:      "capability state attached but boolean false",
			local:     LocalIdentity{},
			hs:        tracerHandshake(attachedbutfalse, "", 0, EventClockMonotonic),
			wantText:  "state attached",
			wantClass: ErrProtocol,
		},
		{
			name:      "capability observable but attach state unavailable",
			local:     LocalIdentity{},
			hs:        tracerHandshake(claimedbutunavailable, "", 0, EventClockMonotonic),
			wantText:  "unavailable",
			wantClass: ErrProtocol,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withLocalIdentity(t, tc.local)
			sock := answeringServer(t, tc.hs, 5*time.Second)
			sess, err := Connect(SessionOptions{Socket: sock, Sink: func(TraceEvent) {}})
			if err == nil {
				_ = sess.Close(time.Second)
				t.Fatalf("refusal expected, session connected with caps %+v", sess.Caps)
			}
			if !errors.Is(err, tc.wantClass) {
				t.Fatalf("wrong refusal class: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("refusal text must name the mismatch %q: %v", tc.wantText, err)
			}
		})
	}
}

// the happy path: a coherent handshake connects, records the identity and the
// capability states, and keeps working.
func TestConnectAcceptsCoherentIdentity(t *testing.T) {
	withLocalIdentity(t, LocalIdentity{BootID: "boot-agent", PIDNamespaceInode: 4026531836})
	hs := tracerHandshake(procCaps(), "boot-agent", 4026531836, EventClockMonotonic)
	hs.SelectionReason = ""
	sock := answeringServer(t, hs, 5*time.Second)
	sess, err := Connect(SessionOptions{Socket: sock, Sink: func(TraceEvent) {}})
	if err != nil {
		t.Fatalf("coherent handshake refused: %v", err)
	}
	defer sess.Close(time.Second)
	if sess.Caps.ExecState != CapStateAttached {
		t.Fatalf("capability states not carried: %+v", sess.Caps)
	}
	if sess.Identity.BootID != "boot-agent" || sess.Identity.PIDNamespaceInode != 4026531836 {
		t.Fatalf("agent identity not recorded: %+v", sess.Identity)
	}
}

// unknown on either side never mismatches (§6.3 b): a tracer without boot_id
// (or the agent on an OS without the fact) is accepted, not guessed.
func TestConnectUnknownIdentityFactsAreNotGuessed(t *testing.T) {
	if runtime.GOOS != "linux" {
		// the host does not produce these facts; the identity of this
		// process is the empty one, exactly the case under test.
		withLocalIdentity(t, localIdentity())
	}
	hs := tracerHandshake(procCaps(), "", 0, EventClockMonotonic)
	sock := answeringServer(t, hs, 5*time.Second)
	sess, err := Connect(SessionOptions{Socket: sock, Sink: func(TraceEvent) {}})
	if err != nil {
		t.Fatalf("unknown facts must not refuse: %v", err)
	}
	_ = sess.Close(time.Second)
}

// A state this build does not know yet is ignored for coherence (additive
// policy §6.4), but a contradiction with the boolean still fails.
func TestCapabilityConflictVocabulary(t *testing.T) {
	c := procCaps()
	if got := c.Conflict(); got != "" {
		t.Fatalf("coherent caps reported %q", got)
	}
	c.ExecState = "decorated_nested_cgroup_v2" // future minor vocabulary
	if got := c.Conflict(); got != "" {
		t.Fatalf("unknown state must stay forward-compatible, got %q", got)
	}
	c.ExecState = CapStateAttached
	c.ProcessExec = false
	if got := c.Conflict(); got == "" {
		t.Fatal("attached-state-without-capability must conflict")
	}
	c.ProcessExec = true
	c.ExecState = CapStateUnavailable
	if got := c.Conflict(); got == "" {
		t.Fatal("unavailable-state-with-capability must conflict")
	}
}

// at the supervisor level: a §6.3 b identity refusal is a property of the
// machine (a stale socket file from another boot cannot be fixed by
// respawning a tracer), so the manager degrades once to unavailable (the
// GaveUp path, reason always promising the polling-mode fallback) instead
// of spending the restart budget.
func TestManagerIdentityRefusalDegradesCleanly(t *testing.T) {
	withLocalIdentity(t, LocalIdentity{BootID: "boot-agent"})
	m := NewManager(ManagerConfig{
		Mode:         ModeAuto,
		BaseBackoff:  5 * time.Millisecond,
		StartTimeout: 2 * time.Second,
		linuxAllowed: func() bool { return true },
		spawnCmd: func(socket string) *exec.Cmd {
			return fakeTracerCommandEnv(fakeModeStream, socket, 5, map[string]string{
				fakeTracerBootEnv: "boot-stale",
			})
		},
	})
	done := make(chan struct{})
	go func() {
		_ = m.Run(context.Background())
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for {
		h := m.Health()
		if h.State == StateUnavailable && h.GaveUp && strings.Contains(h.Reason, "boot_id") && strings.Contains(h.Reason, "polling mode") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("identity refusal never degraded cleanly; health=%+v", h)
		case <-time.After(5 * time.Millisecond):
		}
	}
	m.Stop()
	<-done
}
