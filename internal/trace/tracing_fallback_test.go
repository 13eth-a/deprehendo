package trace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fallback tests (6.52, 6.53). when the kernel or the privilege level cannot
// provide the tracer's mechanism, tracing must degrade to polling with a
// stated reason. it must never fail the agent, and it must never churn
// through restarts against a refusal that will not change.

// runUntilDone runs the manager and waits for run to return on its own, the
// way a permanent refusal ends the supervisor.
func runUntilDone(t *testing.T, m *Manager, within time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(within):
		m.Stop()
		t.Fatal("Run did not return after a permanent refusal")
	}
}

func assertPollingFallback(t *testing.T, h Health, wantReason string) {
	t.Helper()
	if h.State != StateUnavailable || !h.GaveUp {
		t.Fatalf("want unavailable+gaveUp, got %+v", h)
	}
	if !strings.Contains(h.Reason, wantReason) {
		t.Errorf("reason %q does not name %q", h.Reason, wantReason)
	}
	if !strings.Contains(h.Reason, "continuing in polling mode") {
		t.Errorf("reason %q does not say the agent keeps polling", h.Reason)
	}
	// the handshake succeeded, so this is not a spawn failure: the property
	// that matters is that the refusal is not retried.
	if h.Restarts != 0 || h.ConsecutiveFailures != 0 {
		t.Errorf("restarts=%d failures=%d: a permanent refusal must not churn", h.Restarts, h.ConsecutiveFailures)
	}
}

// TestFallbackWhenTracerRefusesMechanism: the tracer answers its handshake
// honestly that the mechanism is unavailable. the supervisor degrades once.
func TestFallbackWhenTracerRefusesMechanism(t *testing.T) {
	m := isolationManager(t, fakeModeUnsupported, nil)
	runUntilDone(t, m, 10*time.Second)
	h := m.Health()
	assertPollingFallback(t, h, "kernel does not offer the connector")
	if !h.Caps.Unsupported {
		t.Errorf("health lost the refusal: %+v", h.Caps)
	}
}

// TestFallbackOnRealKernelRefusal runs the real tracer in a network namespace
// other than the initial one. the proc connector answers ECONNREFUSED there,
// so this is an actual kernel refusal, not a fake one. it needs root and
// unshare; otherwise it skips with the reason.
func TestFallbackOnRealKernelRefusal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("network namespaces are Linux-only")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for unshare -n")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare not available: %v", err)
	}
	bin, why := ResolveBinary(os.Getenv("RUNOPSY_TRACE_BINARY"))
	if bin == "" {
		t.Skipf("tracer binary not available: %s", why)
	}
	wrapper := filepath.Join(t.TempDir(), "runopsy-trace-netns")
	script := "#!/bin/sh\nexec " + unshare + " -n " + bin + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	// the eBPF backend attaches inside a network namespace on kernels and
	// builds where it is available, so this host no longer refuses the
	// tracer there. skip rather than fail on a stale premise; the
	// permission-refusal path is covered by
	// TestFallbackOnRealPermissionRefusal.
	if out, err := exec.Command(wrapper, "capabilities").CombinedOutput(); err != nil || !strings.Contains(string(out), "kernel refused      yes") {
		t.Skip("no kernel refusal inside unshare -n on this build (eBPF may attach there); see TestFallbackOnRealPermissionRefusal")
	}
	m := NewManager(ManagerConfig{
		Binary:             wrapper,
		BaseBackoff:        10 * time.Millisecond,
		MaxBackoff:         40 * time.Millisecond,
		StartTimeout:       5 * time.Second,
		CommandTimeout:     time.Second,
		MaxConsecutiveFail: 5,
	})
	runUntilDone(t, m, 20*time.Second)
	assertPollingFallback(t, m.Health(), "kernel does not offer the connector")
}

// TestUnavailableReasonAlwaysPromisesPolling pins the wording that every
// refusal path shares, including an empty tracer reason.
func TestUnavailableReasonAlwaysPromisesPolling(t *testing.T) {
	for _, r := range []string{"", "insufficient permission: x", "kernel does not offer the connector: y"} {
		got := unavailableReason(r)
		if !strings.HasPrefix(got, "tracing unavailable: ") || !strings.HasSuffix(got, "; continuing in polling mode") {
			t.Errorf("unavailableReason(%q) = %q", r, got)
		}
	}
}
