package simulator

// trace expectations per scenario (6.59).
//
// A simulator scenario says what failure it injects. this file says what the
// phase 6 tracer must be able to *prove* about that failure, and
// what it must not claim when the active backend cannot observe
// it. the distinction is the whole point of capabilities (6.8): the
// proc-connector backend cannot see stop/resume or signals, so a frozen
// worker's freeze is direct evidence only when a backend that supports it is
// active; otherwise the freeze stays polling-derived inference and the report
// says so.
//
// this is data plus a pure resolution function: no processes, no clock, no
// side effects, so it can be asserted in unit tests and consumed by reports.

import (
	"sort"
	"strings"

	"deprehendo/internal/trace"
)

// TraceExpectation is the trace-evidence contract for one scenario.
type TraceExpectation struct {
	// scenario is the simulator scenario name.
	Scenario string
	// why explains why this scenario needs high-resolution tracing at all.
	Why string
	// direct lists the trace event types a capable backend must produce to
	// explain the scenario without inference.
	Direct []trace.EventType
	// PollingFallback lists the lifecycle facts polling can still establish
	// when the direct capability is missing.
	PollingFallback []string
}

// capabilityFor maps an event type to the capability that must be advertised
// before the event can be considered available (6.8).
var capabilityFor = map[trace.EventType]string{
	trace.EventEXEC:   "process_exec",
	trace.EventEXIT:   "process_exit",
	trace.EventSIGNAL: "signals",
	trace.EventSTOP:   "stop_resume",
	trace.EventCONT:   "stop_resume",
	trace.EventOOM:    "oom_kill",
}

// knownCapabilities is the closed set accepted by Resolve.
var knownCapabilities = map[string]bool{
	"process_exec": true,
	"process_exit": true,
	"signals":      true,
	"stop_resume":  true,
	"oom_kill":     true,
}

// TraceExpectations returns the expectation table in a stable order.
func TraceExpectations() []TraceExpectation {
	return []TraceExpectation{
		{
			Scenario: "frozen-worker",
			Why:      "a stopped worker is indistinguishable from a slow one without a direct stop observation",
			Direct:   []trace.EventType{trace.EventEXEC, trace.EventSTOP, trace.EventCONT, trace.EventEXIT},
			PollingFallback: []string{
				"PROCESS_STATE_CHANGED (state starts with T)",
				"PROCESS_EXITED",
			},
		},
		{
			Scenario: "signal",
			Why:      "sent-vs-delivered is a fact about the kernel, not about the snapshot diff",
			Direct:   []trace.EventType{trace.EventEXIT},
			PollingFallback: []string{
				"PROCESS_EXITED (exit_status signal:<n> when the zombie was sampled)",
			},
		},
		{
			Scenario: "exit",
			Why:      "a short-lived process can start and die between two polls",
			Direct:   []trace.EventType{trace.EventEXEC, trace.EventEXIT},
			PollingFallback: []string{
				"PROCESS_STARTED / PROCESS_EXITED (only when a sample caught it)",
			},
		},
		{
			Scenario: "process-tree",
			Why:      "branch-level kills are only attributable with per-process exit observations",
			Direct:   []trace.EventType{trace.EventEXEC, trace.EventEXIT},
			PollingFallback: []string{
				"PROCESS_EXITED per branch member",
			},
		},
		{
			Scenario: "orphan-process",
			Why:      "an orphan outlives its parent; only exec/exit edges show when that started",
			Direct:   []trace.EventType{trace.EventEXEC, trace.EventEXIT},
			PollingFallback: []string{
				"PROCESS_STARTED with PPID 1 (reparenting)",
			},
		},
		{
			Scenario: "zombie",
			Why:      "a zombie is an exit with an unreaped parent; the exit edge is the evidence",
			Direct:   []trace.EventType{trace.EventEXEC, trace.EventEXIT},
			PollingFallback: []string{
				"PROCESS_STATE_CHANGED (state Z)",
			},
		},
		{
			Scenario: "cpu-spin",
			Why:      "polling already measures CPU; the tracer adds nothing here",
			PollingFallback: []string{
				"CPU metrics from the collector",
			},
		},
		{
			Scenario: "memory-pressure",
			Why:      "polling already measures memory; OOM attribution needs a capable backend (6.16)",
			PollingFallback: []string{
				"memory metrics from the collector",
				"PROCESS_EXITED for the victim",
			},
		},
		{
			Scenario: "socket-stall",
			Why:      "socket stalls are a polling/TCP-state question, not a lifecycle one",
			PollingFallback: []string{
				"connection stall evidence from the collector",
			},
		},
		{
			Scenario: "normal",
			Why:      "baseline scenario: no trace evidence is required to explain it",
			PollingFallback: []string{
				"normal snapshot stream",
			},
		},
	}
}

// TraceExpectationFor returns the expectation for one scenario.
func TraceExpectationFor(scenario string) (TraceExpectation, bool) {
	for _, e := range TraceExpectations() {
		if e.Scenario == scenario {
			return e, true
		}
	}
	return TraceExpectation{}, false
}

// TraceCoverage is the outcome of resolving an expectation against one
// tracer's advertised capabilities.
type TraceCoverage struct {
	Scenario string
	Backend  string
	Kernel   string
	// provable lists direct trace event names this backend can supply.
	Provable []string
	// degraded lists direct event names it cannot supply; each one must fall
	// back to polling evidence, never to silence.
	Degraded []string
	// reason is a short, reportable explanation of the degradation.
	Reason string
	// PollingFallback is carried through for the report.
	PollingFallback []string
}

// resolve decides which direct evidence this capability set supports. it is
// deliberately conservative: an unknown capability is treated as absent.
func (e TraceExpectation) Resolve(caps trace.Capabilities) TraceCoverage {
	out := TraceCoverage{
		Scenario:        e.Scenario,
		Backend:         caps.Backend,
		Kernel:          caps.Kernel,
		PollingFallback: append([]string(nil), e.PollingFallback...),
	}
	if len(e.Direct) == 0 {
		return out
	}
	if caps.Unsupported {
		for _, typ := range e.Direct {
			out.Degraded = append(out.Degraded, typ.String())
		}
		out.Reason = "tracer backend is unsupported on this platform; polling-only evidence"
		sort.Strings(out.Degraded)
		return out
	}
	missing := map[string]bool{}
	for _, typ := range e.Direct {
		capability, known := capabilityFor[typ]
		if !known || !advertised(caps, capability) {
			out.Degraded = append(out.Degraded, typ.String())
			if known {
				missing[capability] = true
			}
			continue
		}
		out.Provable = append(out.Provable, typ.String())
	}
	sort.Strings(out.Provable)
	sort.Strings(out.Degraded)
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for name := range missing {
			names = append(names, name)
		}
		sort.Strings(names)
		out.Reason = "backend " + backendName(caps) + " does not observe " + strings.Join(names, ", ") +
			"; those facts stay polling-derived inference, not direct evidence"
	}
	return out
}

func backendName(caps trace.Capabilities) string {
	if caps.Backend == "" {
		return "(none)"
	}
	return caps.Backend
}

// advertised reports one capability. an unrecognized name is false: a typo in
// an expectation must degrade evidence, never invent it.
func advertised(caps trace.Capabilities, name string) bool {
	if !knownCapabilities[name] {
		return false
	}
	switch name {
	case "process_exec":
		return caps.ProcessExec
	case "process_exit":
		return caps.ProcessExit
	case "signals":
		return caps.Signals
	case "stop_resume":
		return caps.StopResume
	case "oom_kill":
		return caps.OOMKill
	}
	return false
}
