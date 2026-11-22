package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"runopsy/internal/platform"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// agentHostView is the agent's provider.HostView (phase 5 §4.2). it exposes
// the full host process table (never the recorder's filtered view) and
// live-only process detail with the incarnation check that keeps a provider
// from mistaking a reused PID for the process it tagged.
type agentHostView struct {
	stateDir string

	saltOnce sync.Once
	salt     []byte
	saltErr  error
}

func newHostView(stateDir string) *agentHostView {
	return &agentHostView{stateDir: stateDir}
}

func (v *agentHostView) Processes(ctx context.Context) ([]platform.Process, error) {
	return platform.ProcessesContext(ctx)
}

func (v *agentHostView) Now() time.Time { return time.Now() }

// StartTime is the wall-clock start of a process incarnation, when the
// platform exposes it (linux: start ticks plus boot time).
func (v *agentHostView) StartTime(p platform.Process) (time.Time, bool) {
	return platform.ProcessStartTime(p)
}

// salt returns the agent's provider salt (§3.2): one per installation, stored
// in the agent state directory with private permissions, created on first
// use, never exported. A nil salt means "not loadable"; providers must fail
// identity derivation rather than derive from an empty salt.
func (v *agentHostView) Salt() []byte {
	v.saltOnce.Do(func() { v.salt, v.saltErr = v.loadSalt() })
	return v.salt
}

// SaltErr reports why salt is nil, when it is.
func (v *agentHostView) SaltErr() error { return v.saltErr }

func (v *agentHostView) loadSalt() ([]byte, error) {
	if v.stateDir == "" {
		return nil, fmt.Errorf("agent: provider salt unavailable without a state directory")
	}
	path := filepath.Join(v.stateDir, "provider-salt")
	if data, err := os.ReadFile(path); err == nil && len(data) >= 64 {
		salt := make([]byte, 32)
		if n, err := hex.Decode(salt, data[:64]); err == nil && n == 32 {
			return salt, nil
		}
		// A malformed salt file is regenerated rather than trusted.
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("agent: generate provider salt: %w", err)
	}
	if err := os.MkdirAll(v.stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: state directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(salt)), 0o600); err != nil {
		return nil, fmt.Errorf("agent: write provider salt: %w", err)
	}
	return salt, nil
}

// inspect resolves live-only details of exactly one process incarnation: it
// fails when the PID now exists with a different start time (§4.2).
// linux reads argv, exe and cwd from procfs; macOS supports only the
// executable name via ps and cannot verify incarnations, so inspect refuses
// a bare PID there rather than trust it (C1).
func (v *agentHostView) Inspect(ctx context.Context, ref evidence.ProcessRef) (provider.ProcessDetail, error) {
	if ref.PID <= 0 {
		return provider.ProcessDetail{}, fmt.Errorf("agent: inspect needs a positive pid")
	}
	p, ok, err := platform.Find(ref.PID)
	if err != nil {
		return provider.ProcessDetail{}, fmt.Errorf("agent: inspect pid %d: %w", ref.PID, err)
	}
	if !ok {
		return provider.ProcessDetail{}, fmt.Errorf("agent: pid %d is gone", ref.PID)
	}
	if runtime.GOOS == "linux" {
		if p.StartTicks != ref.StartTicks {
			return provider.ProcessDetail{}, fmt.Errorf("agent: pid %d changed incarnation (%d now)", ref.PID, p.StartTicks)
		}
		return v.inspectLinux(p), nil
	}
	_ = ref.StartTicks
	detail := provider.ProcessDetail{Process: p}
	detail.Executable = darwinExecutable(ctx, ref.PID)
	return detail, nil
}

func (v *agentHostView) inspectLinux(p platform.Process) provider.ProcessDetail {
	detail := provider.ProcessDetail{Process: p}
	if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.PID)); err == nil {
		detail.Executable = link
	}
	if link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.PID)); err == nil {
		detail.WorkingDir = link
	}
	if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.PID)); err == nil {
		detail.Argv = splitArgv(string(raw))
	}
	return detail
}

func splitArgv(s string) []string {
	s = strings.TrimSuffix(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

func darwinExecutable(ctx context.Context, pid int) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	return darwinExecutableName(ctx, pid)
}
