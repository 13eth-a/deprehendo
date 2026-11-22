package trace

import (
	"fmt"
	"strings"
)

// Tracing-mode configuration (6.21).
//
// the mode is the agent's request about the collection mechanism, not a wish:
// `auto` lets the tracer fall back, while an explicit `ebpf` or `proc` refuses
// a session served by any other backend. that distinction matters because the
// two backends observe different facts (contract §2.1/§3): a proc-connector
// session can never report a signal, so silently accepting one under
// `--tracing ebpf` would let the agent report complete coverage it does not
// have.
//
// configuration sources, in order of precedence:
//
//	CLI flag  --tracing VALUE
//	env       RUNOPSY_TRACING=VALUE
//	default   auto
//
// there is deliberately no YAML/TOML file: the go module is stdlib-only and a
// single scalar does not justify a parser dependency (contract §6.1 records
// the same reasoning for the wire encoding).
type Mode string

const (
	// ModeAuto prefers eBPF, then the proc connector, then polling-only.
	ModeAuto Mode = "auto"
	// ModeEBPF requires the eBPF backend: no silent fallback to the proc
	// connector, whose capability set is strictly smaller.
	ModeEBPF Mode = "ebpf"
	// ModeProc requires the proc connector. it is the honest choice on
	// kernels without eBPF support and never pretends signals are observed.
	ModeProc Mode = "proc"
	// ModeDisabled runs in polling-only mode; no tracer process is started.
	ModeDisabled Mode = "disabled"
)

// backend names as advertised in the handshake (schema.go Capabilities.Backend).
const (
	BackendEBPF = "ebpf"
	BackendProc = "proc_connector"
)

// EnvTracing is the environment variable read by ConfigFromEnv.
const EnvTracing = "RUNOPSY_TRACING"

// ParseMode accepts the canonical values plus the spellings an operator is
// likely to type. an empty string means "not configured" and selects auto.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto", "automatic":
		return ModeAuto, nil
	case "ebpf", "bpf":
		return ModeEBPF, nil
	case "proc", "proc_connector", "procconnector", "netlink":
		return ModeProc, nil
	case "disabled", "off", "none", "polling":
		return ModeDisabled, nil
	}
	return "", fmt.Errorf("trace: unknown tracing mode %q (want auto, ebpf, proc or disabled)", s)
}

// valid reports whether m is one of the defined modes. the zero value is not
// valid so an unset configuration cannot be mistaken for a choice.
func (m Mode) Valid() bool {
	switch m {
	case ModeAuto, ModeEBPF, ModeProc, ModeDisabled:
		return true
	}
	return false
}

// enabled reports whether the mode starts a tracer at all.
func (m Mode) Enabled() bool { return m != ModeDisabled }

// candidates lists the backends this mode accepts, in preference order. it is
// the single source of truth for both the agent's report and the manager's
// handshake check, so the two can never disagree about what `auto` means.
func (m Mode) Candidates() []Mode {
	switch m {
	case ModeAuto:
		return []Mode{ModeEBPF, ModeProc}
	case ModeEBPF:
		return []Mode{ModeEBPF}
	case ModeProc:
		return []Mode{ModeProc}
	}
	return nil
}

// AcceptsBackend reports whether a tracer that advertised backend b satisfies
// this mode. an empty backend (no collection mechanism compiled in, or a
// kernel that supports none) satisfies nothing.
func (m Mode) AcceptsBackend(b string) bool {
	if b == "" {
		return false
	}
	for _, c := range m.Candidates() {
		if c == ModeEBPF && b == BackendEBPF {
			return true
		}
		if c == ModeProc && b == BackendProc {
			return true
		}
	}
	return false
}

// string renders the canonical value.
func (m Mode) String() string {
	if m == "" {
		return string(ModeAuto)
	}
	return string(m)
}

// describe renders the mode as the one-line consequence an operator sees. it
// states the fallback chain rather than just echoing the flag, because the
// chain is what decides whether signal evidence will exist.
func (m Mode) Describe() string {
	switch m {
	case ModeEBPF:
		return "ebpf (eBPF required; if it cannot attach, tracing is unavailable and polling continues)"
	case ModeProc:
		return "proc (proc connector required; no signal, stop/resume or OOM evidence)"
	case ModeDisabled:
		return "disabled (polling only)"
	default:
		return "auto (eBPF → proc connector → polling only)"
	}
}

// UnavailableReason renders why a session advertising caps cannot honour this
// mode. it returns "" when the mode accepts the session, and for a disabled
// mode (which never starts a tracer).
func (m Mode) UnavailableReason(caps Capabilities) string {
	if !m.Enabled() {
		return ""
	}
	if caps.Backend == "" {
		return "tracer reported no collection backend"
	}
	if !m.AcceptsBackend(caps.Backend) {
		return fmt.Sprintf("tracer backend %q does not satisfy tracing mode %s", caps.Backend, m)
	}
	return ""
}

// config is the validated tracing configuration of one agent run. it is
// deliberately transport-level: the incident bundle's reliability section
// (6.48) is written from the tracer's own report, never from this request.
type Config struct {
	// mode is the requested collection mode.
	Mode Mode
	// binary overrides runopsy-trace resolution.
	Binary string
	// SocketPath overrides the private socket path (tests, debugging).
	SocketPath string
	// DebugOutput records the raw event stream to this file for replay
	// (6.46). Debug-only: the path is never written into a bundle.
	DebugOutput string
}

// validate checks the mode and rejects contradictory settings. A disabled mode
// with debug settings configured is refused: recording an event stream that
// will not exist is a configuration mistake, not a no-op.
func (c Config) Validate() error {
	if !c.Mode.Valid() {
		return fmt.Errorf("trace: invalid tracing mode %q", c.Mode)
	}
	if !c.Mode.Enabled() {
		if c.DebugOutput != "" || c.SocketPath != "" {
			return fmt.Errorf("trace: tracing mode disabled cannot record a trace stream")
		}
	}
	return nil
}

// describe is the human-readable summary printed by `runopsy-agent trace
// status` and the start banner.
func (c Config) Describe() string {
	parts := []string{c.Mode.Describe()}
	if c.Binary != "" {
		parts = append(parts, "binary "+c.Binary)
	}
	if c.DebugOutput != "" {
		parts = append(parts, "recording to "+c.DebugOutput)
	}
	return strings.Join(parts, "; ")
}

// ConfigFromEnv builds the configuration from an environment lookup
// (os.Getenv in production, a map in tests). an invalid RUNOPSY_TRACING value
// is an error rather than a silent auto: a typo must not change which
// evidence the agent will claim to have.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	mode, err := ParseMode(getenv(EnvTracing))
	if err != nil {
		return Config{}, err
	}
	return Config{Mode: mode}, nil
}
