package incident

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"runopsy/internal/trace"
)

// TraceReliability is the tracer component's stamped self-report in a bundle
// (6.48). A later reader must be able to see whether the trace stream was
// complete: incomplete stream ⇒ incomplete signal evidence, never "no signal
// occurred" (6.27). additive field; a nil tracing pointer means the recording
// agent had no tracer configured, indistinguishable for older readers.
type TraceReliability struct {
	// state is the supervision state at finalize time (trace.ManagerState).
	State string `json:"state"`
	// backend names the actual collection mechanism when active.
	Backend string `json:"backend,omitempty"`
	// reason carries a bounded, self-produced degradation reason. it never
	// contains caller/provider data.
	Reason string `json:"reason,omitempty"`
	// EventsLost reports sequence-gap losses observed over the session
	// (6.25/6.26). zero only means no gap was observed on the wire.
	EventsLost uint64 `json:"events_lost,omitempty"`
	// CaptureLost counts live events this recorder refused (closed buffer,
	// out-of-order delivery, section bounds), distinct from the tracer's
	// own wire losses, so a later reader sees each consumer's honesty
	// separately (6.27).
	CaptureLost uint64 `json:"capture_lost,omitempty"`
}

func validTraceState(s string) bool {
	switch s {
	case "unavailable", "starting", "active", "restarting", "stopped":
		return true
	}
	return false
}

func validTraceBackend(s string) bool {
	switch s {
	case "", "proc_connector":
		return true
	}
	return false
}

const maxTraceReason = 256

func (t TraceReliability) validate() error {
	if !validTraceState(t.State) {
		return fmt.Errorf("incident: invalid tracing state %q", t.State)
	}
	if !validTraceBackend(t.Backend) {
		return fmt.Errorf("incident: invalid tracing backend")
	}
	if len(t.Reason) > maxTraceReason {
		return fmt.Errorf("incident: tracing reason exceeds budget")
	}
	return nil
}

// TraceReliabilityFromHealth converts a tracer supervisor's health report
// into the bundle form. it lives here (not in internal/trace) because the
// incident package already owns the trace dependency and the trace package
// must not depend on incident bundles.
func TraceReliabilityFromHealth(h trace.Health) TraceReliability {
	state := string(h.State)
	reason := h.Reason
	if state == "" {
		// A capture can finalize before the supervisor reports its first
		// state. an empty state is not a valid bundle state and must not be
		// recorded as one: the honest reading is "tracing was not available",
		// which keeps the bundle valid and the evidence gap explicit (6.27).
		state = "unavailable"
		if reason == "" {
			reason = "tracer supervisor reported no state"
		}
	}
	return TraceReliability{
		State:      state,
		Backend:    h.Caps.Backend,
		Reason:     reason,
		EventsLost: h.Lost,
	}
}

// sanitizeTraceReason keeps free-text reasons bounded and printable. reason
// strings are produced by the supervisor itself, but the redactor policy is
// that no free text survives unbounded.
func sanitizeTraceReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxTraceReason {
		// cut at maxTraceReason bytes, always on a rune boundary so the
		// visible text stays valid UTF-8 after the byte cap.
		s = truncateRunes(s, maxTraceReason)
	}
	return s
}

// truncateRunes returns the longest prefix of s of at most limit bytes that
// ends on a rune boundary.
func truncateRunes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:cut])
		if r != utf8.RuneError || size != 1 {
			break
		}
		cut--
	}
	return s[:cut]
}
