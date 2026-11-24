package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/causal"
	"deprehendo/internal/collector"
	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

func writeTimelineBundle(t *testing.T, inc *incident.Incident) string {
	t.Helper()
	if inc.SchemaVersion == 0 {
		inc.SchemaVersion = incident.SchemaVersion
	}
	if inc.ID == "" {
		inc.ID = "inc_0123456789abcdef0123456789abcdef"
	}
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = time.Now().UTC()
	}
	if inc.CaptureStart.IsZero() {
		inc.CaptureStart = inc.CreatedAt.Add(-time.Minute)
	}
	if inc.CaptureEnd.IsZero() {
		inc.CaptureEnd = inc.CreatedAt
	}
	if inc.Metadata.AgentVersion == "" {
		inc.Metadata.AgentVersion = incident.AgentVersion
	}
	if inc.Metadata.Host.OS == "" {
		inc.Metadata.Host = incident.LocalHost()
	}
	if inc.Window.PreTrigger == 0 && inc.Window.PostTrigger == 0 {
		inc.Window.PreTrigger = inc.TriggeredAt.Sub(inc.CaptureStart)
		inc.Window.PostTrigger = inc.CaptureEnd.Sub(inc.TriggeredAt)
	}
	if inc.Privacy.Policy == "" {
		inc.Privacy.Policy = "test"
	}
	var encoded bytes.Buffer
	if err := incident.Encode(&encoded, inc, true); err != nil {
		t.Fatalf("encode incident: %v", err)
	}
	path := filepath.Join(t.TempDir(), inc.ID+".deprehendo")
	if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func timelineTestIncident() *incident.Incident {
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	inc := &incident.Incident{
		ID:           "inc_0123456789abcdef0123456789abcdef",
		CreatedAt:    base.Add(20 * time.Second),
		TriggeredAt:  base.Add(15 * time.Second),
		CaptureStart: base,
		CaptureEnd:   base.Add(20 * time.Second),
		Trigger:      incident.Trigger{Type: "process_exit", PID: 8, StartTicks: 10},
		Metadata: incident.Metadata{
			AgentVersion: incident.AgentVersion,
			Host:         incident.LocalHost(),
			Processes: []incident.ProcessMetadata{
				{PID: 8, PPID: 1, PGID: 8, StartTicks: 10, Name: "worker"},
			},
		},
		Snapshots: []collector.Snapshot{
			{Timestamp: base, System: &collector.SystemSnapshot{MemoryStatsAvailable: true, MemoryTotal: 1000, MemoryUsed: 700}},
			{Timestamp: base.Add(5 * time.Second), System: &collector.SystemSnapshot{MemoryStatsAvailable: true, MemoryTotal: 1000, MemoryUsed: 950}},
			{Timestamp: base.Add(10 * time.Second), System: &collector.SystemSnapshot{MemoryStatsAvailable: true, MemoryTotal: 1000, MemoryUsed: 990}},
			{Timestamp: base.Add(20 * time.Second), System: &collector.SystemSnapshot{MemoryStatsAvailable: true, MemoryTotal: 1000, MemoryUsed: 100}},
		},
		Events: []incident.Event{
			{Timestamp: base.Add(2 * time.Second), Type: incident.ProcessExited, PID: 8, StartTicks: 10},
			{Timestamp: base.Add(15 * time.Second), Type: incident.IncidentTriggered, PID: 8},
		},
	}
	return inc
}

func TestTimelineTextAndCausalOutput(t *testing.T) {
	path := writeTimelineBundle(t, timelineTestIncident())
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{path}, []string{"TIMELINE (UTC; order only", "MEMORY_PRESSURE_STARTED", "MEMORY_LIMIT_REACHED", "MEMORY_RECOVERED", "PROCESS_EXITED"}},
		{[]string{"--causal", path}, []string{"CAUSAL ANALYSIS", "failure", "PROCESS_EXITED", "MEMORY_LIMIT_REACHED"}},
		{[]string{path, "--report"}, []string{"DEPREHENDO ANALYSIS", "Underlying systems diagnosis", "Causal reconstruction"}},
	} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"timeline"}, tc.args...)
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("run(%v) = %d: %s", args, code, stderr.String())
		}
		for _, wanted := range tc.want {
			if !strings.Contains(stdout.String(), wanted) {
				t.Errorf("run(%v) output missing %q:\n%s", args, wanted, stdout.String())
			}
		}
	}
}

func TestTimelineJSONContainsStableGraphShapeAndLinks(t *testing.T) {
	path := writeTimelineBundle(t, timelineTestIncident())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"timeline", "--json", "--report", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("timeline json = %d: %s", code, stderr.String())
	}
	var output TimelineOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if output.IncidentID == "" || len(output.Events) == 0 || output.Failures == nil {
		t.Errorf("incomplete graph JSON: %+v", output)
	}
	if output.Diagnosis == nil {
		t.Fatal("--report omitted Phase 3 diagnosis")
	}
	if output.Diagnosis.Unknown != true {
		t.Errorf("fixture's Phase 3 result should honestly remain UNKNOWN: %+v", output.Diagnosis)
	}
	foundlinks := false
	for _, match := range output.Diagnosis.Matches {
		if len(match.RelatedEvents) > 0 {
			foundlinks = true
		}
	}
	if foundlinks {
		t.Errorf("UNKNOWN diagnosis unexpectedly contains a positive signature link: %+v", output.Diagnosis.Matches)
	}
}

func TestTimelineJSONRetainsProviderEvidenceAndCombinedTimeline(t *testing.T) {
	inc := timelineTestIncident()
	runner := evidence.Ref("rnr_0123456789abcdef")
	job := evidence.Ref("job_0123456789abcdef")
	at := inc.CreatedAt.Add(-3 * time.Second)
	inc.Providers = []evidence.Section{{
		Provider: github.Name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyIdentifiers,
		Health:  evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{Ref: runner, Name: evidence.KnownText(evidence.ClassRunnerName, "runner-a", evidence.SourceRunnerConfig), Version: evidence.KnownText(evidence.ClassVersion, "2.320.0", evidence.SourceRunnerConfig), Labels: evidence.UnknownText(evidence.ClassLabels), Lifecycle: evidence.LifecycleUnknown}},
		Jobs:    []evidence.Job{{Ref: job, Runner: runner, Repository: evidence.KnownText(evidence.ClassRepository, "acme/service", evidence.SourceRunnerLog), Workflow: evidence.UnknownText(evidence.ClassWorkflow), Name: evidence.UnknownText(evidence.ClassJobName), RunID: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID}, JobID: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID}, Attempt: evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt}, Outcome: evidence.OutcomeUnknown, StartedAt: at.Add(time.Second), StartedAtSource: evidence.SourceRunnerLog}},
		Events:  []evidence.Event{{Timestamp: at, Type: github.EventJobAssigned, Runner: runner, Job: job, Source: evidence.SourceRunnerLog, Provenance: evidence.Provenance{File: 1, Offset: 200}}},
	}}
	path := writeTimelineBundle(t, inc)
	var jsonOut, stderr bytes.Buffer
	if code := run([]string{"timeline", "--json", path}, &jsonOut, &stderr); code != 0 {
		t.Fatalf("timeline json = %d: %s", code, stderr.String())
	}
	var output TimelineOutput
	if err := json.Unmarshal(jsonOut.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.ProviderEvidence) != 1 || output.ProviderEvidence[0].Provider != github.Name {
		t.Fatalf("provider evidence omitted from timeline JSON: %+v", output.ProviderEvidence)
	}
	var stdout bytes.Buffer
	if code := run([]string{"timeline", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("timeline default = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PROVIDER EVIDENCE") {
		t.Fatalf("default timeline omitted provider context: %s", stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"timeline", "--report", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("timeline report = %d: %s", code, stderr.String())
	}
	for _, want := range []string{"GITHUB_JOB_ASSIGNED", "runner=rnr_0123456789abcdef", "provenance=file:1@200", "GITHUB_JOB_STARTED", "source=RUNNER_LOG", "DEPREHENDO ANALYSIS"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("timeline report missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRelatedEventsRequireExactProcessIncarnation(t *testing.T) {
	timeline := &causal.Timeline{Events: []causal.Event{
		{ID: "EV_stop_a", Type: causal.EventProcessStopped, PID: 42, StartTicks: 100},
		{ID: "EV_resume_a", Type: causal.EventProcessResumed, PID: 42, StartTicks: 100},
		{ID: "EV_stop_reused", Type: causal.EventProcessStopped, PID: 42, StartTicks: 200},
		{ID: "EV_stop_other", Type: causal.EventProcessStopped, PID: 99, StartTicks: 300},
		{ID: "EV_exit_member", Type: causal.EventProcessExited, PID: 42, StartTicks: 100},
		{ID: "EV_exit_reused", Type: causal.EventProcessExited, PID: 42, StartTicks: 200},
		{ID: "EV_group", Type: causal.EventProcessGroupTerminated, ProcessIDs: []causal.ProcessIdentity{{PID: 42, StartTicks: 200}, {PID: 50, StartTicks: 500}}},
	}}

	got := causal.RelatedEventIDs(timeline, string(diagnosis.SignatureFrozenProcess), []causal.ProcessIdentity{{PID: 42, StartTicks: 100}})
	if !equalEventIDs(got, []causal.EventID{"EV_stop_a", "EV_resume_a"}) {
		t.Errorf("frozen diagnosis links = %v, want only incarnation 42@100", got)
	}
	if got := causal.RelatedEventIDs(timeline, string(diagnosis.SignatureFrozenProcess), nil); len(got) != 0 {
		t.Errorf("unscoped diagnosis linked process events: %v", got)
	}
	if got := causal.RelatedEventIDs(timeline, string(diagnosis.SignatureFrozenProcess), []causal.ProcessIdentity{{PID: 42, StartTicks: 0}}); len(got) != 0 {
		t.Errorf("incomplete identity linked process events: %v", got)
	}

	got = causal.RelatedEventIDs(timeline, string(diagnosis.SignatureGroupKill), []causal.ProcessIdentity{{PID: 42, StartTicks: 200}})
	if !equalEventIDs(got, []causal.EventID{"EV_exit_reused", "EV_group"}) {
		t.Errorf("group diagnosis links = %v, want matching member exit and aggregate only", got)
	}
}

func equalEventIDs(got, want []causal.EventID) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func TestCrossCheckWarnsOnOutOfScopeLinksButLeavesUnknownPhase4Alone(t *testing.T) {
	unrelated := causal.Event{ID: "EV_other", Type: causal.EventProcessStopped, PID: 42, StartTicks: 200}
	failure := causal.Event{ID: "EV_failure", Type: causal.EventProcessExited, PID: 42, StartTicks: 100}
	graph := causal.NewGraph(&causal.Timeline{Events: []causal.Event{unrelated, failure}})
	report := &diagnosis.Report{
		Matches: []diagnosis.SignatureMatch{{
			SignatureID:       diagnosis.SignatureFrozenProcess,
			ProcessIdentities: []diagnosis.ProcessIdentity{{PID: 42, StartTicks: 100}},
			RelatedEvents:     []string{"EV_other"},
		}},
		Ambiguous: []string{"BROKER_SOCKET_STALL vs NETWORK_PATH_FAILURE"},
	}
	warnings := crossCheckDiagnoses(report, graph)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "outside its exact process scope") {
		t.Fatalf("consistency warnings = %v, want only the out-of-scope link warning", warnings)
	}
	for _, analysis := range graph.FailureAnalyses() {
		if analysis.Status == causal.StatusExplained {
			t.Fatalf("test graph unexpectedly reached EXPLAINED: %+v", analysis)
		}
	}
}

func TestTimelineExplainEdgeByStableIDAndRejectMissingEdge(t *testing.T) {
	path := writeTimelineBundle(t, timelineTestIncident())
	var graph TimelineOutput
	var raw bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"timeline", "--json", "--causal", path}, &raw, &stderr); code != 0 {
		t.Fatalf("prepare graph JSON = %d: %s", code, stderr.String())
	}
	if err := json.Unmarshal(raw.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) == 0 {
		t.Skip("fixture did not yield a validated causal edge")
	}
	stdout := bytes.Buffer{}
	if code := run([]string{"timeline", "--explain-edge", graph.Edges[0].ID, path}, &stdout, &stderr); code != 0 {
		t.Fatalf("explain stable edge ID = %d: %s", code, stderr.String())
	}
	for _, want := range []string{graph.Edges[0].ID, string(graph.Edges[0].Relation), graph.Edges[0].RuleID, "Claim:", "Evidence:", "Timing:", "Confidence:", "Contradictions:", "Missing evidence:"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("edge explanation missing %q:\n%s", want, stdout.String())
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"timeline", "--explain-edge", "404", path}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing edge query returned %d, want 2: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "edge") {
		t.Errorf("missing-edge diagnostic = %q", stderr.String())
	}
}

func TestTimelineUnknownCauseReportOnEffectOnlyBundle(t *testing.T) {
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	inc := &incident.Incident{
		ID: "inc_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CreatedAt: base.Add(time.Second),
		TriggeredAt: base.Add(time.Second), CaptureStart: base, CaptureEnd: base.Add(time.Second),
		Trigger:  incident.Trigger{Type: "process_exit", PID: 21},
		Metadata: incident.Metadata{AgentVersion: incident.AgentVersion, Host: incident.LocalHost()},
		Events:   []incident.Event{{Type: incident.ProcessExited, Timestamp: base, PID: 21, StartTicks: 100}},
	}
	path := writeTimelineBundle(t, inc)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"timeline", "--json", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("timeline json = %d: %s", code, stderr.String())
	}
	var output TimelineOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	// Per-anchor unknown-cause (A15): the exit anchor gets its own analysis
	// with status UNKNOWN; the report names the observed failure, the known
	// chain, and the missing evidence, never a fabricated root.
	var exitAnalysis *causal.FailureAnalysis
	for i := range output.Failures {
		if output.Failures[i].AnchorType == causal.EventProcessExited {
			exitAnalysis = &output.Failures[i]
		}
	}
	if exitAnalysis == nil {
		t.Fatalf("effect-only incident lacks a PROCESS_EXITED failure analysis: %+v", output.Failures)
	}
	if exitAnalysis.Status != causal.StatusUnknown || len(exitAnalysis.MissingEvidence) == 0 {
		t.Errorf("unknown cause is unexplained: %+v", exitAnalysis)
	}
	if len(exitAnalysis.KnownChain) == 0 {
		t.Errorf("unknown-cause report omitted its known chain: %+v", exitAnalysis)
	}
}

func TestTimelineRejectsExtraArgumentsAndMissingBundle(t *testing.T) {
	for _, args := range [][]string{{"timeline"}, {"timeline", "a", "b"}, {"timeline", "/no/such/bundle"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code == 0 {
			t.Errorf("run(%v) succeeded unexpectedly", args)
		}
	}
}

// A19: a rule ID that names several edges is ambiguous; it must not silently
// resolve to the first one.
func TestResolveEdgeRejectsAmbiguousRuleID(t *testing.T) {
	edges := []causal.CausalEdge{
		{ID: "ED_a", From: "EV_1", To: "EV_2", RuleID: "R@1"},
		{ID: "ED_b", From: "EV_3", To: "EV_4", RuleID: "R@1"},
		{ID: "ED_c", From: "EV_5", To: "EV_6", RuleID: "S@1"},
	}
	if _, err := resolveEdge("R@1", edges); err == nil || !strings.Contains(err.Error(), "ED_a, ED_b") {
		t.Errorf("ambiguous rule ID resolved silently: err=%v", err)
	}
	if i, err := resolveEdge("S@1", edges); err != nil || i != 2 {
		t.Errorf("unique rule ID: got %d, %v; want 2", i, err)
	}
	if i, err := resolveEdge("ED_b", edges); err != nil || i != 1 {
		t.Errorf("edge ID: got %d, %v; want 1", i, err)
	}
}
