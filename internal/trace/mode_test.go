package trace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestParseModeAcceptsOperatorSpellings pins 6.21's configuration surface:
// the canonical values plus the spellings an operator types, with an unknown
// value refused rather than silently defaulted to auto.
func TestParseModeAcceptsOperatorSpellings(t *testing.T) {
	cases := map[string]Mode{
		"":               ModeAuto,
		"auto":           ModeAuto,
		" AUTO ":         ModeAuto,
		"ebpf":           ModeEBPF,
		"BPF":            ModeEBPF,
		"proc":           ModeProc,
		"proc_connector": ModeProc,
		"netlink":        ModeProc,
		"disabled":       ModeDisabled,
		"off":            ModeDisabled,
		"polling":        ModeDisabled,
	}
	for input, want := range cases {
		got, err := ParseMode(input)
		if err != nil {
			t.Errorf("ParseMode(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", input, got, want)
		}
	}
	for _, bad := range []string{"tor", "ebpf2", "auto,ebpf"} {
		if _, err := ParseMode(bad); err == nil {
			t.Errorf("ParseMode(%q) accepted an unknown mode", bad)
		}
	}
}

// TestModeAcceptsBackend pins the mode discipline: auto takes either backend,
// an explicit mode takes only its own, and nothing accepts an empty backend
// (which is a tracer that attached nothing).
func TestModeAcceptsBackend(t *testing.T) {
	cases := []struct {
		mode    Mode
		backend string
		want    bool
	}{
		{ModeAuto, BackendEBPF, true},
		{ModeAuto, BackendProc, true},
		{ModeEBPF, BackendEBPF, true},
		{ModeEBPF, BackendProc, false},
		{ModeProc, BackendProc, true},
		{ModeProc, BackendEBPF, false},
		{ModeAuto, "", false},
		{ModeProc, "", false},
		{ModeDisabled, BackendProc, false},
	}
	for _, c := range cases {
		if got := c.mode.AcceptsBackend(c.backend); got != c.want {
			t.Errorf("%s.AcceptsBackend(%q) = %v, want %v", c.mode, c.backend, got, c.want)
		}
	}
	// the auto chain is ordered by capability, not alphabetically: eBPF is
	// the only backend that can observe signals (contract §2.1).
	candidates := ModeAuto.Candidates()
	if len(candidates) != 2 || candidates[0] != ModeEBPF || candidates[1] != ModeProc {
		t.Fatalf("auto candidates = %v", candidates)
	}
}

func TestModeDescribeStatesFallback(t *testing.T) {
	if got := ModeAuto.Describe(); !strings.Contains(got, "eBPF") || !strings.Contains(got, "polling") {
		t.Errorf("auto description hides the fallback chain: %q", got)
	}
	if got := ModeEBPF.Describe(); !strings.Contains(got, "unavailable") {
		t.Errorf("explicit ebpf must state the no-fallback consequence: %q", got)
	}
	for _, mode := range []Mode{ModeAuto, ModeEBPF, ModeProc, ModeDisabled} {
		if !mode.Valid() {
			t.Errorf("%q is not Valid", mode)
		}
		if mode.String() != string(mode) {
			t.Errorf("%q.String() = %q", mode, mode.String())
		}
	}
	if Mode("").Valid() {
		t.Error("the zero mode must not be valid")
	}
}

func TestModeUnavailableReason(t *testing.T) {
	proc := Capabilities{Backend: BackendProc, ProcessExec: true, ProcessExit: true}
	if reason := ModeAuto.UnavailableReason(proc); reason != "" {
		t.Errorf("auto refused the proc connector: %q", reason)
	}
	reason := ModeEBPF.UnavailableReason(proc)
	if !strings.Contains(reason, "proc_connector") || !strings.Contains(reason, "ebpf") {
		t.Errorf("ebpf mode accepted a proc session or gave an unusable reason: %q", reason)
	}
	if reason := ModeProc.UnavailableReason(Capabilities{}); reason == "" {
		t.Error("an empty backend satisfied proc mode")
	}
	if reason := ModeDisabled.UnavailableReason(proc); reason != "" {
		t.Errorf("disabled mode produced a rejection reason: %q", reason)
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{Mode: ModeAuto}
	if err := good.Validate(); err != nil {
		t.Fatalf("auto config rejected: %v", err)
	}
	if err := (Config{Mode: ModeDisabled, DebugOutput: "trace.bin"}).Validate(); err == nil {
		t.Error("disabled mode accepted a recording path it can never fill")
	}
	if err := (Config{Mode: Mode("sometimes")}).Validate(); err == nil {
		t.Error("invalid mode accepted")
	}
	if got := (Config{Mode: ModeEBPF, DebugOutput: "/tmp/t.bin"}).Describe(); !strings.Contains(got, "/tmp/t.bin") {
		t.Errorf("describe hides the debug recording: %q", got)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	cfg, err := ConfigFromEnv(env(map[string]string{EnvTracing: "proc"}))
	if err != nil || cfg.Mode != ModeProc {
		t.Fatalf("env proc = %+v, %v", cfg, err)
	}
	cfg, err = ConfigFromEnv(env(nil))
	if err != nil || cfg.Mode != ModeAuto {
		t.Fatalf("unset env = %+v, %v", cfg, err)
	}
	// A typo in the environment must not silently become auto: the mode
	// decides which evidence the agent will claim to have.
	if _, err := ConfigFromEnv(env(map[string]string{EnvTracing: "ebpf " + "typo"})); err == nil {
		t.Error("invalid env mode accepted")
	}
}

// TestManagerDisabledModeNeverSpawns pins 6.21's disabled mode: no child, no
// attempts, an explicit reason, and the recorder is a decision not a failure.
func TestManagerDisabledModeNeverSpawns(t *testing.T) {
	spawned := 0
	m := NewManager(ManagerConfig{
		Mode:         ModeDisabled,
		linuxAllowed: func() bool { return true },
		spawnCmd: func(string) *exec.Cmd {
			spawned++
			return exec.Command("sleep", "30")
		},
	})
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("disabled mode did not return immediately")
	}
	h := m.Health()
	if spawned != 0 || h.Attempts != 0 {
		t.Fatalf("disabled mode spawned a tracer: spawned=%d attempts=%d", spawned, h.Attempts)
	}
	if h.State != StateStopped || !strings.Contains(h.Reason, "disabled") {
		t.Fatalf("disabled mode state = %q reason = %q", h.State, h.Reason)
	}
	m.Stop()
}

// TestManagerRefusesWrongBackendForMode is the 6.21 guarantee with teeth: a
// proc-connector session under `--tracing ebpf` is refused, because that
// backend can never produce the signal evidence the mode was chosen for.
func TestManagerRefusesWrongBackendForMode(t *testing.T) {
	m := NewManager(ManagerConfig{
		Mode:               ModeEBPF,
		BaseBackoff:        5 * time.Millisecond,
		MaxBackoff:         15 * time.Millisecond,
		StartTimeout:       2 * time.Second,
		MaxConsecutiveFail: 2,
		linuxAllowed:       func() bool { return true },
		spawnCmd: func(socket string) *exec.Cmd {
			return fakeTracerCommand(fakeModeStream, socket, 1)
		},
	})
	var events int
	m.cfg.Events = func(TraceEvent) { events++ }
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("supervision did not give up; health=%+v", m.Health())
	}
	h := m.Health()
	if !h.GaveUp || h.State != StateUnavailable {
		t.Fatalf("expected unavailable after refusal, got %+v", h)
	}
	if !strings.Contains(h.Reason, "does not satisfy tracing mode ebpf") {
		t.Fatalf("reason does not name the mode mismatch: %q", h.Reason)
	}
	if h.Attempts != 2 {
		t.Fatalf("refusal should exhaust the failure budget, attempts=%d", h.Attempts)
	}
	m.Stop()
}

// TestManagerRecordsAndReplaysSession covers 6.46 end to end: the manager's
// debug recorder writes the frames of a live session, and the production
// replay decoder reads them back with the same events in the same order.
func TestManagerRecordsAndReplaysSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket test")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "trace.bin")
	m := NewManager(ManagerConfig{
		Mode:               ModeAuto,
		DebugOutput:        record,
		BaseBackoff:        5 * time.Millisecond,
		StartTimeout:       2 * time.Second,
		CommandTimeout:     time.Second,
		MaxConsecutiveFail: 1,
		linuxAllowed:       func() bool { return true },
		spawnCmd: func(socket string) *exec.Cmd {
			return fakeTracerCommand(fakeModeStream, socket, 5)
		},
	})
	var mu sync.Mutex
	seen := 0
	m.cfg.Events = func(TraceEvent) {
		mu.Lock()
		seen++
		mu.Unlock()
	}
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()

	deadline := time.After(10 * time.Second)
	for {
		mu.Lock()
		got := seen
		mu.Unlock()
		if got >= 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("session delivered %d events", got)
		case <-time.After(5 * time.Millisecond):
		}
	}
	m.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
	h := m.Health()
	if h.RecordFile != record || h.RecordedEvents != 5 {
		t.Fatalf("recording health = %+v", h)
	}
	if h.RecordTruncated {
		t.Fatalf("recording truncated: %q", h.RecordReason)
	}
	info, err := os.Stat(record)
	if err != nil {
		t.Fatalf("recording file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recording is not owner-only: %v", info.Mode().Perm())
	}
	var seqs []uint64
	stats, err := ReplayFile(record, func(e TraceEvent) { seqs = append(seqs, e.Sequence) })
	if err != nil {
		t.Fatalf("replay recording: %v", err)
	}
	if stats.Events != 5 || stats.Lost != 0 {
		t.Fatalf("replay stats = %+v", stats)
	}
	for i, seq := range seqs {
		if seq != uint64(i+1) {
			t.Fatalf("replayed sequences = %v", seqs)
		}
	}
}

// TestManagerRecordingOpenFailureKeepsTracing: a bad --trace-debug-output path
// is a recording problem, not a tracing problem (6.40's invariant).
func TestManagerRecordingOpenFailureKeepsTracing(t *testing.T) {
	m := NewManager(ManagerConfig{
		Mode:         ModeAuto,
		DebugOutput:  "/nonexistent-dir/trace.bin",
		BaseBackoff:  5 * time.Millisecond,
		StartTimeout: 2 * time.Second,
		linuxAllowed: func() bool { return true },
		spawnCmd: func(socket string) *exec.Cmd {
			return fakeTracerCommand(fakeModeStream, socket, 1)
		},
	})
	done := make(chan struct{})
	go func() { _ = m.Run(context.Background()); close(done) }()
	deadline := time.After(5 * time.Second)
	for {
		h := m.Health()
		if h.State == StateActive {
			if !strings.Contains(h.Reason, "debug recording unavailable") {
				t.Fatalf("active session lost the recording reason: %q", h.Reason)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("session never became active; health=%+v", h)
		case <-time.After(5 * time.Millisecond):
		}
	}
	m.Stop()
}
