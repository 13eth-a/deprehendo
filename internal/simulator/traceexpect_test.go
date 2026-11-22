package simulator

import (
	"strings"
	"testing"

	"runopsy/internal/trace"
)

// every registered scenario must state its trace expectation, so a new
// scenario cannot silently skip the question "what can tracing prove here?".
func TestEveryScenarioHasTraceExpectation(t *testing.T) {
	for _, scenario := range Scenarios() {
		expectation, ok := TraceExpectationFor(scenario.Name())
		if !ok {
			t.Errorf("scenario %q has no trace expectation (add one to traceexpect.go)", scenario.Name())
			continue
		}
		if expectation.Why == "" && len(expectation.Direct) > 0 {
			t.Errorf("scenario %q requires direct trace evidence but does not explain why", scenario.Name())
		}
		for _, typ := range expectation.Direct {
			if typ == trace.EventHANDSHAKE {
				t.Errorf("scenario %q lists HANDSHAKE as a stream event", scenario.Name())
			}
			if _, known := capabilityFor[typ]; !known {
				t.Errorf("scenario %q requires %s, which has no capability mapping", scenario.Name(), typ)
			}
		}
	}
}

// the proc-connector backend honestly advertises exec/exit only. A frozen
// worker's stop/resume must therefore be reported as degraded (polling
// inference), never as direct kernel evidence.
func TestFrozenWorkerStopIsDegradedOnProcConnector(t *testing.T) {
	expectation, ok := TraceExpectationFor("frozen-worker")
	if !ok {
		t.Fatal("missing frozen-worker expectation")
	}
	caps := trace.Capabilities{
		Backend:     "proc_connector",
		ProcessExec: true,
		ProcessExit: true,
	}
	coverage := expectation.Resolve(caps)
	if coverage.Reason == "" {
		t.Fatal("degraded stop/resume must be explained")
	}
	for _, want := range []string{"stop_resume"} {
		if !strings.Contains(coverage.Reason, want) {
			t.Errorf("reason %q does not name the missing capability %q", coverage.Reason, want)
		}
	}
	degraded := strings.Join(coverage.Degraded, ",")
	if !strings.Contains(degraded, "PROCESS_STOPPED") || !strings.Contains(degraded, "PROCESS_RESUMED") {
		t.Errorf("degraded set %v does not name stop/resume", coverage.Degraded)
	}
	provable := strings.Join(coverage.Provable, ",")
	if !strings.Contains(provable, "PROCESS_EXEC") || !strings.Contains(provable, "PROCESS_EXIT") {
		t.Errorf("provable set %v lost exec/exit", coverage.Provable)
	}
	if len(coverage.PollingFallback) == 0 {
		t.Error("a degraded expectation must say what polling still establishes")
	}
}

// A backend with stop/resume support turns the same expectation into direct
// evidence: the table is about capabilities, not about the scenario.
func TestCapableBackendProvesStopResume(t *testing.T) {
	expectation, _ := TraceExpectationFor("frozen-worker")
	caps := trace.Capabilities{
		Backend:     "ebpf",
		ProcessExec: true,
		ProcessExit: true,
		StopResume:  true,
	}
	coverage := expectation.Resolve(caps)
	if len(coverage.Degraded) != 0 {
		t.Errorf("capable backend still degraded: %v (%s)", coverage.Degraded, coverage.Reason)
	}
	if len(coverage.Provable) != len(expectation.Direct) {
		t.Errorf("provable = %v, want all of %v", coverage.Provable, expectation.Direct)
	}
}

// an unsupported platform must degrade everything with a single clear reason.
func TestUnsupportedPlatformDegradesEverything(t *testing.T) {
	for _, expectation := range TraceExpectations() {
		coverage := expectation.Resolve(trace.Capabilities{Backend: "proc_connector", Unsupported: true})
		if len(expectation.Direct) > 0 && len(coverage.Provable) != 0 {
			t.Errorf("scenario %q proved %v on an unsupported platform", expectation.Scenario, coverage.Provable)
		}
		if len(expectation.Direct) > 0 && !strings.Contains(coverage.Reason, "polling-only") {
			t.Errorf("scenario %q degradation reason %q does not say polling-only", expectation.Scenario, coverage.Reason)
		}
	}
}

// OOM attribution stays gated (6.16): no backend currently advertises it, and
// the resolver must not invent support.
func TestOOMIsNeverAssumed(t *testing.T) {
	expectation := TraceExpectation{
		Scenario: "synthetic-oom",
		Direct:   []trace.EventType{trace.EventOOM},
	}
	coverage := expectation.Resolve(trace.Capabilities{Backend: "proc_connector", ProcessExec: true, ProcessExit: true})
	if len(coverage.Provable) != 0 {
		t.Fatalf("OOM proved without the capability: %v", coverage.Provable)
	}
	if !strings.Contains(strings.Join(coverage.Degraded, ","), "OOM_KILL") {
		t.Errorf("degraded set %v does not name OOM_KILL", coverage.Degraded)
	}
}
