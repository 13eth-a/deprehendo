package incident

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
	provider "runopsy/internal/provider/evidence"
)

// PrivacyPolicy is the identifier of the only redaction policy the writer
// applies (contract docs/cloud/contract.md §7.2): readers verify a bundle by
// reapplying it, and the analysis document records the policy name as part of
// the engine identity.
const PrivacyPolicy = "conservative-v1"

// ConservativeRedactor reconstructs exported records from reviewed fields.
// all free text is removed or replaced with bounded enumerations. this is not
// a regex secret detector. optional future collection must extend this policy.
type ConservativeRedactor struct{}

func (ConservativeRedactor) RedactIncident(i *Incident) error {
	if i == nil {
		return fmt.Errorf("incident: nil incident")
	}
	if !validTrigger(i.Trigger.Type) {
		return fmt.Errorf("incident: unknown trigger")
	}
	if len(i.Trigger.Note) > 1024 {
		return fmt.Errorf("incident: note exceeds 1024 bytes")
	}
	// notes are optional human-authored context, so permit them only as valid
	// UTF-8 and strip control characters; arbitrary control bytes can forge CLI
	// output or hide text in exported artifacts.
	if !utf8.ValidString(i.Trigger.Note) {
		return fmt.Errorf("incident: note is not valid UTF-8")
	}
	i.Trigger.Note = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, i.Trigger.Note)
	// presence describes which classes have fields in the exported evidence,
	// not whether their original identifying values survive redaction.
	hasnetwork, haspaths, hasprocessnames := false, false, false
	for _, s := range i.Snapshots {
		hasnetwork = hasnetwork || len(s.Connections) > 0
		haspaths = haspaths || s.System != nil || s.Cgroup != nil
		hasprocessnames = hasprocessnames || len(s.Processes) > 0
		for _, p := range s.Processes {
			haspaths = haspaths || p.Cgroup != nil
		}
	}
	for _, e := range i.Events {
		hasnetwork = hasnetwork || e.Connection != nil
	}
	hasprocessnames = hasprocessnames || len(i.Metadata.Processes) > 0
	i.Metadata.AgentVersion = AgentVersion
	switch i.Metadata.Host.OS {
	case "linux", "darwin":
	default:
		i.Metadata.Host.OS = "unknown"
	}
	switch i.Metadata.Host.Architecture {
	case "amd64", "arm64", "386", "arm", "riscv64", "ppc64", "ppc64le", "s390x":
	default:
		i.Metadata.Host.Architecture = "unknown"
	}
	for n := range i.Metadata.Processes {
		i.Metadata.Processes[n].Name = "[REDACTED]"
	}
	redactcg := func(c *platform.CgroupSnapshot) {
		if c == nil {
			return
		}
		c.Path = "[REDACTED]"
		f := strings.Fields(c.CPUMax)
		if len(f) == 2 && len(f[0]) <= 20 && len(f[1]) <= 20 {
			_, err := strconv.ParseUint(f[1], 10, 64)
			_, qerr := strconv.ParseUint(f[0], 10, 64)
			if err == nil && (qerr == nil || f[0] == "max") {
				c.CPUMax = strings.Join(f, " ")
				return
			}
		}
		c.CPUMax = ""
		c.CPUAvailable = false
	}
	for n := range i.Snapshots {
		s := &i.Snapshots[n]
		if s.System != nil {
			s.System.DiskFilesystem = "[REDACTED]"
		}
		redactcg(s.Cgroup)
		for j := range s.Processes {
			p := &s.Processes[j]
			p.Name = "[REDACTED]"
			p.State = cleanState(p.State)
			redactcg(p.Cgroup)
		}
		for j := range s.Connections {
			redactConnection(&s.Connections[j])
		}
		for j := range s.Errors {
			s.Errors[j].Collector = cleanCollector(s.Errors[j].Collector)
			s.Errors[j].Err = "collector unavailable"
		}
		for j := range s.Metrics {
			s.Metrics[j].Name = cleanCollector(s.Metrics[j].Name)
		}
		for k := range s.Pressure {
			if k != platform.PressureCPU && k != platform.PressureMemory && k != platform.PressureIO {
				delete(s.Pressure, k)
			}
		}
	}
	for n := range i.Events {
		e := &i.Events[n]
		if !validEvent(e.Type) {
			return fmt.Errorf("incident: unknown event")
		}
		e.From = cleanState(e.From)
		e.To = cleanState(e.To)
		if e.Collector != "" {
			e.Collector = cleanCollector(e.Collector)
		}
		if e.Connection != nil {
			redactConnection(e.Connection)
		}
	}
	providerIdentifiers := false
	if i.Tracing != nil {
		// 6.48 mirror of the provider rule: reliability enum fields survive,
		// the free-text reason is bounded and made printable, and nothing
		// else about the tracer stream leaks into a conservative bundle.
		i.Tracing.Reason = sanitizeTraceReason(i.Tracing.Reason)
	}
	for n := range i.Providers {
		// §3.3/§9.2: the capture-time privacy level governs each provider
		// section; encoding re-applies it so provider text always obeys the
		// policy, and the report shows when identifiers were exported.
		level := i.Providers[n].Privacy
		if level == "" {
			level = provider.PrivacyConservative
		}
		i.Providers[n].Redact(level)
		providerIdentifiers = providerIdentifiers || level == provider.PrivacyIdentifiers
	}
	i.Privacy = PrivacyReport{
		Policy: PrivacyPolicy, NetworkAddresses: hasnetwork,
		FilesystemPaths: haspaths, ProcessNames: hasprocessnames,
		UserNote: i.Trigger.Note != "", ProviderIdentifiers: providerIdentifiers,
	}
	return nil
}

// cleanState reduces a process state to its state letter from a closed
// alphabet, so no free text can pass through the field. linux reports a single
// letter; macOS ps appends flags ("T<", "ss", "S+"). requiring the whole value
// to be one letter turned every macOS state into "?", which erased the stopped
// and zombie evidence from macOS bundles. the flags carry nothing the analysis
// uses, so only the leading letter is kept. U is macOS's uninterruptible wait.
// the result is idempotent: "?" and single letters map to themselves, so
// bundles written before this change still verify when the policy is reapplied.
func cleanState(s string) string {
	if s != "" && strings.IndexByte("RSDZTtXxKWPIU", s[0]) >= 0 {
		return s[:1]
	}
	return "?"
}
func cleanCollector(s string) string {
	switch s {
	case "system", "processes", "connections", "pressure", "cgroups", "socket-owners", "process-cgroups", "open-fds":
		return s
	}
	return "unknown"
}
func redactConnection(c *collector.ConnectionSnapshot) {
	c.LocalAddr = "[REDACTED]"
	c.RemoteAddr = "[REDACTED]"
	switch c.State {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV":
	default:
		c.State = "UNKNOWN"
	}
}
