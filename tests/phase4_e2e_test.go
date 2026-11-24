package tests

// phase 4 end-to-end tests (4.46/4.47): simulator -> recorder -> persisted
// bundle -> phase 3 diagnosis -> phase 4 causal report through the shipped
// binaries. they assert the report's honesty contract, not a scripted story:
// every causal claim must be rule-backed and evidence-bounded, and events v1
// cannot observe must never be invented.
//
// gated behind DEPREHENDO_E2E_CAUSAL because both cases run live recorders and
// simulators (roughly 20 seconds).

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/diagnosis"
)

type causalEvent struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Timestamp    time.Time      `json:"timestamp"`
	Sequence     uint64         `json:"sequence"`
	OnsetUnknown bool           `json:"onset_unknown"`
	Data         map[string]any `json:"data"`
	Provenance   struct {
		RuleID  string `json:"rule_id"`
		Sources []struct {
			Kind string `json:"kind"`
			Ref  string `json:"ref"`
		} `json:"sources"`
	} `json:"provenance"`
}

type causalEdge struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Relation   string `json:"relation"`
	Confidence string `json:"confidence"`
	Rule       string `json:"rule"`
	Evidence   []struct {
		Code string `json:"code"`
	} `json:"evidence"`
}

type causalRoot struct {
	Event        string `json:"event"`
	Kind         string `json:"kind"`
	Anchor       string `json:"anchor"`
	Role         string `json:"role"`
	Confidence   string `json:"confidence"`
	OnsetUnknown bool   `json:"onset_unknown"`
}

// causalFailure is one per-anchor analysis (causal-semantics.md §4.2, the
// "failures" array that replaced root_candidates/unknown_cause).
type causalFailure struct {
	Anchor          string       `json:"anchor"`
	AnchorType      string       `json:"anchor_type"`
	Status          string       `json:"status"`
	Candidates      []causalRoot `json:"candidates"`
	KnownChain      []string     `json:"known_chain"`
	MissingEvidence []string     `json:"missing_evidence"`
	Alternatives    []string     `json:"alternatives"`
}

type causalTimelineOutput struct {
	IncidentID    string            `json:"incident_id"`
	Events        []causalEvent     `json:"events"`
	Edges         []causalEdge      `json:"edges"`
	RejectedEdges []causalEdge      `json:"rejected_edges"`
	Failures      []causalFailure   `json:"failures"`
	Diagnosis     *diagnosis.Report `json:"diagnosis"`
}

func TestPhase4CausalEndToEnd(t *testing.T) {
	if os.Getenv("DEPREHENDO_E2E_CAUSAL") == "" {
		t.Skip("set DEPREHENDO_E2E_CAUSAL=1 to run simulator -> recorder -> causal timeline end-to-end")
	}
	if testing.Short() {
		t.Skip("live simulator/recorder causal analysis")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("requires Linux or macOS, got %s", runtime.GOOS)
	}
	t.Run("memory-pressure", testPhase4MemoryPressure)
	t.Run("socket-stall", testPhase4SocketStall)
}

// phase4Timeline runs the shipped timeline binary exactly as an operator would
// and decodes the combined report.
func phase4Timeline(t *testing.T, bundle string) causalTimelineOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentPath, "timeline", bundle, "--report", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("timeline %s: %v\n%s", bundle, err, out)
	}
	var report causalTimelineOutput
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("timeline returned invalid JSON: %v\n%s", err, out)
	}
	if report.IncidentID == "" {
		t.Fatalf("timeline report has no incident id: %s", out)
	}
	return report
}

// requireCausalHonesty asserts the invariants common to every phase 4 report:
// no unobservable event is invented, every edge is directional and versioned,
// and every edge endpoint exists with its own provenance.
func requireCausalHonesty(t *testing.T, report causalTimelineOutput) {
	t.Helper()
	if len(report.Events) == 0 {
		t.Fatal("timeline report contains no events")
	}
	// every phase 2 bundle is triggered, so its normalized timeline must carry
	// the trigger fact; a missing one means the pipeline lost evidence.
	triggered := false
	byid := map[string]causalEvent{}
	for index, event := range report.Events {
		if _, duplicate := byid[event.ID]; duplicate {
			t.Errorf("duplicate event ID %s", event.ID)
		}
		byid[event.ID] = event
		if event.Type == "INCIDENT_TRIGGERED" {
			triggered = true
		}
		if event.Sequence != uint64(index) {
			t.Errorf("event %s has sequence %d at position %d", event.ID, event.Sequence, index)
		}
		if len(event.Provenance.Sources) == 0 {
			t.Errorf("event %s (%s) has no provenance", event.ID, event.Type)
		}
		switch event.Type {
		case "OOM_EVENT", "NETWORK_PROGRESS_STOPPED", "NETWORK_PROGRESS_RESUMED",
			"RUNNER_STARTED", "WORKER_STARTED", "WORKER_EXITED":
			t.Errorf("v1 bundle fabricated unobservable event %s", event.Type)
		}
	}
	if !triggered {
		t.Error("timeline is missing the INCIDENT_TRIGGERED event")
	}
	for _, edge := range report.Edges {
		from, fromok := byid[edge.From]
		to, took := byid[edge.To]
		if !fromok || !took {
			t.Errorf("edge %s references a missing endpoint", edge.ID)
			continue
		}
		if !strings.Contains(edge.Rule, "@") {
			t.Errorf("edge %s uses unversioned rule %q", edge.ID, edge.Rule)
		}
		if len(edge.Evidence) == 0 {
			t.Errorf("edge %s has no evidence record", edge.ID)
		}
		switch edge.Relation {
		case "PRECEDES":
			if !from.Timestamp.Before(to.Timestamp) {
				t.Errorf("PRECEDES edge %s->%s lacks observed order", from.Type, to.Type)
			}
		case "RECOVERY_OF":
			if !from.Timestamp.Before(to.Timestamp) {
				t.Errorf("RECOVERY_OF edge %s->%s lacks observed order", from.Type, to.Type)
			}
		case "CAUSES", "CONTRIBUTES_TO":
			if to.Timestamp.Before(from.Timestamp) {
				t.Errorf("causal edge %s->%s runs backwards", from.Type, to.Type)
			}
		}
	}
	// every root must be an event in the graph with a causal edge leaving it.
	causalout := map[string]bool{}
	for _, edge := range report.Edges {
		if edge.Relation == "CAUSES" || edge.Relation == "CONTRIBUTES_TO" {
			causalout[edge.From] = true
		}
	}
	for _, failure := range report.Failures {
		if _, ok := byid[failure.Anchor]; !ok {
			t.Errorf("failure analysis references a missing anchor %s", failure.Anchor)
		}
		for _, root := range failure.Candidates {
			if _, ok := byid[root.Event]; !ok {
				t.Errorf("candidate references a missing event %s", root.Event)
			}
			if root.Event == failure.Anchor {
				t.Errorf("anchor %s lists itself as a candidate (spec §5.2)", failure.AnchorType)
			}
			if root.Kind == "ROOT_CAUSE" && !causalout[root.Event] {
				t.Errorf("ROOT_CAUSE candidate %s has no causal consequence", root.Event)
			}
		}
		if failure.Status == "UNKNOWN" {
			for _, root := range failure.Candidates {
				if root.Kind == "ROOT_CAUSE" {
					t.Errorf("UNKNOWN anchor %s carries a ROOT_CAUSE candidate", failure.AnchorType)
				}
			}
			if len(failure.MissingEvidence) == 0 {
				t.Errorf("UNKNOWN anchor %s lists no missing evidence", failure.AnchorType)
			}
		}
		if failure.Alternatives == nil {
			t.Errorf("anchor %s omits alternatives; [] means checked-empty (I2)", failure.AnchorType)
		}
	}
}

// requireNoFalseMemoryClaims keeps phase 4 memory claims tied to the readings
// that justified them.
func requireNoFalseMemoryClaims(t *testing.T, report causalTimelineOutput) {
	t.Helper()
	byid := map[string]causalEvent{}
	for _, event := range report.Events {
		byid[event.ID] = event
		switch event.Type {
		case "MEMORY_PRESSURE_STARTED", "MEMORY_PRESSURE_ACTIVE":
			if percent, ok := memoryPercent(event); ok && percent < 90 {
				t.Errorf("%s emitted at %.1f%% memory, below the 90%% pressure threshold", event.Type, percent)
			}
		case "MEMORY_LIMIT_REACHED":
			if percent, ok := memoryPercent(event); ok && percent < 98 {
				t.Errorf("MEMORY_LIMIT_REACHED emitted at %.1f%%, below the 98%% limit threshold", percent)
			}
		}
	}
	limits, pressures := 0, 0
	for _, event := range report.Events {
		switch event.Type {
		case "MEMORY_LIMIT_REACHED":
			limits++
		case "MEMORY_PRESSURE_STARTED", "MEMORY_PRESSURE_ACTIVE":
			pressures++
		}
	}
	limitedges := 0
	for _, edge := range report.Edges {
		if edge.Rule != "MEMORY_PRESSURE_CAUSES_LIMIT_BREACH@1" {
			continue
		}
		limitedges++
		if byid[edge.From].Type != "MEMORY_PRESSURE_STARTED" || byid[edge.To].Type != "MEMORY_LIMIT_REACHED" {
			t.Errorf("memory limit rule connected %s->%s", byid[edge.From].Type, byid[edge.To].Type)
		}
		if edge.Relation != "CAUSES" {
			t.Errorf("memory limit rule produced %s, want CAUSES", edge.Relation)
		}
	}
	if limits == 0 && limitedges != 0 {
		t.Errorf("causal limit edges exist without any MEMORY_LIMIT_REACHED event")
	}
	if limits > 0 && pressures == 0 {
		t.Errorf("MEMORY_LIMIT_REACHED exists without a pressure episode")
	}
	if limitedges > limits {
		t.Errorf("%d limit edges for %d limit events", limitedges, limits)
	}
}

func memoryPercent(event causalEvent) (float64, bool) {
	value, ok := event.Data["memory_percent"]
	if !ok {
		return 0, false
	}
	percent, ok := value.(float64)
	return percent, ok
}

// requireNoFalseStallClaims keeps phase 4 from inventing the socket-stall story
// the flagship demo shows conceptually but v1 cannot observe.
func requireNoFalseStallClaims(t *testing.T, report causalTimelineOutput) {
	t.Helper()
	if report.Diagnosis != nil {
		for _, match := range report.Diagnosis.Matches {
			if match.SignatureID == diagnosis.SignatureBrokerStall {
				t.Errorf("BROKER_SOCKET_STALL diagnosed without byte-progress telemetry")
			}
			if match.SignatureID == diagnosis.SignatureOOMKill {
				t.Errorf("OOM_KILL diagnosed without a kernel OOM record")
			}
		}
	}
	networkevents := 0
	for _, event := range report.Events {
		if event.Type == "CONNECTION_OPENED" || event.Type == "CONNECTION_CLOSED" {
			networkevents++
		}
		if event.Type == "NETWORK_PROGRESS_STOPPED" || event.Type == "NETWORK_PROGRESS_RESUMED" {
			t.Errorf("network progress event %s cannot be observed in v1", event.Type)
		}
	}
	for _, edge := range report.Edges {
		if strings.Contains(edge.Rule, "NETWORK") {
			t.Errorf("network causal edge claimed without progress telemetry: %s", edge.Rule)
		}
	}
	if networkevents == 0 && runtime.GOOS == "linux" {
		t.Logf("no socket facts observed; the TCP table collector may be unavailable in this environment")
	}
	// 4.47: a green run of this test is a no-fabrication check only. the
	// flagship stall chain needs network-progress and worker-progress
	// telemetry v1 does not capture, so say so explicitly in every run.
	t.Logf("SUMMARY: flagship chain not exercised (v1 has no network-progress telemetry; %d socket facts observed). This pass verifies only that no stall chain was fabricated.", networkevents)
}

func testPhase4MemoryPressure(t *testing.T) {
	h := startDiagnosisRecorder(t, 60*time.Second,
		"--window", "20s",
		"--capture-pre", "15s",
		"--capture-post", "2s",
		"--collect-network=false",
		"--collect-pressure=false",
		"--collect-cgroups=false",
	)
	h.runSimulator("memory-pressure", "--rate", "4MB", "--interval", "20ms", "--limit", "48MB")
	// give the simulator time to allocate and exit inside the pre-trigger
	// window, then freeze the capture.
	time.Sleep(1500 * time.Millisecond)
	out, err := exec.CommandContext(h.ctx, agentPath, "trigger", "--socket", h.socket).CombinedOutput()
	if err != nil {
		t.Fatalf("manual trigger: %v\n%s\nrecorder log:\n%s", err, out, h.out.String())
	}
	bundle := h.waitBundle(30 * time.Second)
	report := phase4Timeline(t, bundle)
	requireCausalHonesty(t, report)
	requireNoFalseMemoryClaims(t, report)

	// the simulator allocates in its own address space; unless this host was
	// already near its own limit, no host memory episode is observable. the
	// report must then stay silent instead of echoing the simulated scenario.
	memoryevents := 0
	for _, event := range report.Events {
		if strings.HasPrefix(event.Type, "MEMORY_") {
			memoryevents++
		}
	}
	if memoryevents == 0 {
		t.Logf("host memory stayed below the pressure boundary during the capture; no memory episode claimed (honest outcome)")
	}
	for _, event := range report.Events {
		if event.Type == "MEMORY_LIMIT_REACHED" && !hasCausalOrTemporalLink(report, event.ID) {
			t.Logf("MEMORY_LIMIT_REACHED at %.1f%% has no rule-backed relation", mustMemoryPercent(event))
		}
	}
	// every failure the capture contains gets its own analysis; with v1
	// telemetry none of them may be EXPLAINED (no OOM records).
	for _, failure := range report.Failures {
		if failure.Status == "EXPLAINED" {
			t.Errorf("anchor %s EXPLAINED without kernel OOM records", failure.AnchorType)
		}
	}
	// phase 3 may legitimately match other signatures, but nothing may claim
	// OOM without a kernel record.
	requireNoFalseStallClaims(t, report)
}

func hasCausalOrTemporalLink(report causalTimelineOutput, eventID string) bool {
	for _, edge := range report.Edges {
		if edge.From == eventID || edge.To == eventID {
			return true
		}
	}
	return false
}

func mustMemoryPercent(event causalEvent) float64 {
	percent, _ := memoryPercent(event)
	return percent
}

func testPhase4SocketStall(t *testing.T) {
	// network collection stays on: on linux the TCP table provides the
	// established-connection facts; elsewhere the recorder reports the sensor
	// gap instead of inventing traffic.
	h := startDiagnosisRecorder(t, 45*time.Second,
		"--window", "12s",
		"--capture-pre", "8s",
		"--capture-post", "2s",
		"--collect-pressure=false",
		"--collect-cgroups=false",
	)
	h.runSimulator("socket-stall",
		"--ping-interval", "20ms",
		"--stall-threshold", "100ms",
		"--stall-duration", "1s",
		"--stall-after", "1",
	)
	time.Sleep(2500 * time.Millisecond)
	out, err := exec.CommandContext(h.ctx, agentPath, "trigger", "--socket", h.socket).CombinedOutput()
	if err != nil {
		t.Fatalf("manual trigger: %v\n%s\nrecorder log:\n%s", err, out, h.out.String())
	}
	bundle := h.waitBundle(30 * time.Second)
	report := phase4Timeline(t, bundle)
	requireCausalHonesty(t, report)
	requireNoFalseStallClaims(t, report)

	// the flagship honesty assertion: with no validated causal root, the
	// human-readable report says so rather than drawing a stall chain.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	text, err := exec.CommandContext(ctx, agentPath, "timeline", bundle, "--causal").CombinedOutput()
	if err != nil {
		t.Fatalf("timeline --causal: %v\n%s", err, text)
	}
	// no stall chain may be drawn: the text never names a root cause other
	// than UNKNOWN, and no connection event is a candidate.
	for _, line := range strings.Split(string(text), "\n") {
		if strings.Contains(line, "oot cause:") && !strings.Contains(line, "Root cause: UNKNOWN") {
			t.Errorf("socket-stall capture rendered a root cause without progress telemetry: %q", line)
		}
	}
	for _, failure := range report.Failures {
		for _, root := range failure.Candidates {
			for _, event := range report.Events {
				if event.ID == root.Event && strings.HasPrefix(event.Type, "CONNECTION_") {
					t.Errorf("connection event %s reported as a candidate without progress telemetry", event.Type)
				}
			}
		}
	}
}
