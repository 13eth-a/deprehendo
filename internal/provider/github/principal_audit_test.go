package github

// regression tests for the principal phase 5 audit (docs/reviews/phase5-principal-audit.md).
// each test names its finding; each one fails on the code as it was before
// the fix (checked by reverting the fix, see the audit's verification notes).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
)

// realDiag lines are copied verbatim (message text) from public runner
// diagnostic excerpts (actions/runner#4670, #2140); the header shape is the
// runner's trace format "[<UTC time>Z <LEVEL> <component>] ".
var realDiag = []string{
	"[2026-09-03 18:34:20Z INFO Terminal] Listening for Jobs",
	"[2026-09-03 18:34:34Z INFO JobDispatcher] Job request 0 for plan 79b62e68 job 029e843d received.",
	"[2026-09-03 18:34:35Z INFO Terminal] Running job: build-and-test (postgresql)",
	"[2026-09-03 18:34:29Z INFO Terminal] Job build-and-test (sqlite) completed with result: Succeeded",
	"[2026-09-03 18:34:34Z INFO JobDispatcher] Send job cancellation message to worker for job fd42305a.",
	"[2026-09-03 19:03:41Z INFO Terminal] Job Container build completed with result: Canceled",
	"[2026-09-03 19:04:00Z ERR  Terminal] Runner connect error: The HTTP request timed out after 00:01:00. Retrying until reconnected.",
	"[2026-09-03 19:04:30Z INFO Terminal] Runner reconnected.",
}

func readOnce(t *testing.T, dir, name string, lines ...string) []logEvent {
	t.Helper()
	writeDiag(t, dir, name, strings.Join(lines, "\n")+"\n")
	events, _, readable := newLogTail(dir).readPass(1 << 20)
	if !readable {
		t.Fatal("diag directory unreadable")
	}
	return events
}

// R1: the reader understood only the fake-harness record shape, so a real
// runner's `_diag` logs produced no facts at all.
func TestAuditR1RealRunnerDiagFormatParses(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log", realDiag...)
	var got []string
	for _, ev := range events {
		got = append(got, ev.Type+"/"+string(ev.Outcome))
	}
	want := []string{
		EventRunnerStarted + "/",
		EventJobAssigned + "/",
		EventJobAccepted + "/",
		EventJobCompleted + "/" + string(evidence.OutcomeSucceeded),
		EventJobCancellation + "/",
		EventJobCancellation + "/" + string(evidence.OutcomeCancelled),
		EventRunnerDisconnected + "/",
		EventRunnerReconnected + "/",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("real runner records =\n  %v\nwant\n  %v", got, want)
	}
	if at := events[1].Timestamp; !at.Equal(time.Date(2026, 9, 3, 18, 34, 34, 0, time.UTC)) {
		t.Fatalf("record time = %v, want 18:34:34Z", at)
	}
	for _, ev := range events {
		if ev.Type == EventJobCancellation && ev.Intent != intentKindCancelled {
			t.Fatalf("stated cancellation lost its intent: %+v", ev)
		}
	}
}

// R2 (and T1): worker trace lines that merely mention exit codes, timeouts
// or cancellation plumbing are not facts. process exit is LOCAL_PROCESS
// authority (P1); intent needs a statement (T1).
func TestAuditR2WorkerTraceNoiseIsNotAFact(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Worker_20260903-183435-utc.log",
		"[2026-09-03 18:35:00Z INFO ProcessInvokerWrapper] Finished process 4242 with exit code 0, and elapsed time 00:00:01.",
		"[2026-09-03 18:35:01Z INFO ProcessInvokerWrapper] Job process exited with 137",
		"[2026-09-03 18:35:02Z INFO JobRunner] Job timeout set to 360 minutes",
		"[2026-09-03 18:35:03Z INFO HostContext] Register CancellationToken for job",
		"[2026-09-03 18:35:04Z INFO StepsRunner] Step cancellation callback registered",
	)
	if len(events) != 0 {
		t.Fatalf("trace noise produced facts: %+v", events)
	}
	stated := readOnce(t, t.TempDir(), "Worker_20260903-183435-utc.log",
		"[2026-09-03 18:36:00Z INFO JobRunner] Job was cancelled",
		"[2026-09-03 18:36:01Z INFO JobRunner] The job running on runner r1 has exceeded the maximum execution time of 1 minutes.",
	)
	if len(stated) != 2 || stated[0].Type != EventJobCancellation || stated[1].Type != EventJobTimeout {
		t.Fatalf("stated intents = %+v", stated)
	}
}

// R3: "runner connect error: … retrying until reconnected." was classified
// as a reconnection because the reconnect pattern was tried first.
func TestAuditR3ConnectErrorIsNotAReconnect(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log", realDiag[6])
	if len(events) != 1 || events[0].Type != EventRunnerDisconnected {
		t.Fatalf("connect error = %+v, want %s", events, EventRunnerDisconnected)
	}
}

// R4: a real `.runner` carries keys outside the allowlist (pool, URLs) and a
// UTF-8 BOM; the strict decoder rejected it, so the runner name and the
// ephemeral flag were never known on a real host.
func TestAuditR4RealRunnerConfigDecodesAllowlistOnly(t *testing.T) {
	root := t.TempDir()
	content := "\xef\xbb\xbf" + `{
  "agentId": 17,
  "agentName": "ci-linux-03",
  "poolId": 1,
  "poolName": "Default",
  "serverUrl": "https://pipelines.example.invalid/SECRET-PATH",
  "gitHubUrl": "https://github.com/acme/service",
  "workFolder": "_work",
  "ephemeral": true
}`
	if err := os.WriteFile(filepath.Join(root, ".runner"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readRunnerConfig(root)
	if err != nil {
		t.Fatalf("real .runner rejected: %v", err)
	}
	if cfg.AgentName != "ci-linux-03" || !cfg.Ephemeral || cfg.AgentID != 17 {
		t.Fatalf("decoded = %+v", cfg)
	}
	if dump, _ := json.Marshal(cfg); strings.Contains(string(dump), "SECRET-PATH") || strings.Contains(string(dump), "github.com") {
		t.Fatalf("non-allowlisted value retained: %s", dump)
	}
	if err := os.WriteFile(filepath.Join(root, ".runner"), []byte(`{"agentName": 5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRunnerConfig(root); err == nil {
		t.Fatal("a mistyped allowlisted key must not decode")
	}
}

// ephemeralRunner builds the fake runner as EPHEMERAL with real-format logs.
func ephemeralRunner(t *testing.T, diary ...string) (*fakeHost, time.Time) {
	t.Helper()
	host, root, base := fakeRunner(t, diary...)
	if err := os.WriteFile(filepath.Join(root, ".runner"),
		[]byte(`{"agentId":7,"agentName":"eph-1","ephemeral":true,"workFolder":"_work"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return host, base
}

func freezeAll(t *testing.T, s provider.Session, base time.Time) evidence.Section {
	t.Helper()
	section, err := s.Freeze(context.Background(), base.Add(-time.Minute), base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return section
}

func eventsOf(section evidence.Section, typ string) []evidence.Event {
	var out []evidence.Event
	for _, ev := range section.Events {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

// R5/R6: a stated job result was never bound to its worker, no SUCCEEDED
// outcome was reachable, and EPHEMERAL_COMPLETE (T1) could never fire.
func TestAuditR5R6StatedResultBindsAndEphemeralCompletes(t *testing.T) {
	host, base := ephemeralRunner(t,
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan p job j received.",
		"[2026-10-28 12:00:03Z INFO Terminal] Job build completed with result: Succeeded",
	)
	s := attachSession(t, host)
	ctx := context.Background()
	s.Observe(ctx, snapshotAt(host, base, 10))
	s.Observe(ctx, snapshotAt(host, base.Add(3*time.Second), 0, procWorker, procJobRoot))
	s.Observe(ctx, snapshotAt(host, base.Add(4*time.Second), 0, procListener, procWorker, procJobRoot))
	section := freezeAll(t, s, base)

	completed := eventsOf(section, EventJobCompleted)
	if len(completed) != 1 || completed[0].Worker == "" || completed[0].Job == "" || completed[0].Outcome != evidence.OutcomeSucceeded {
		t.Fatalf("completion record = %+v, want bound to worker and job with SUCCEEDED", completed)
	}
	if len(section.Jobs) != 1 || section.Jobs[0].Outcome != evidence.OutcomeSucceeded || section.Jobs[0].OutcomeSource != evidence.SourceRunnerLog {
		t.Fatalf("job = %+v, want SUCCEEDED from RUNNER_LOG", section.Jobs)
	}
	ephemeral := eventsOf(section, EventRunnerEphemeralComplete)
	if len(ephemeral) != 1 || ephemeral[0].Worker != completed[0].Worker {
		t.Fatalf("ephemeral completion = %+v", ephemeral)
	}
	interp, err := GitHubProvider{}.Interpret(section, nil)
	if err != nil {
		t.Fatal(err)
	}
	intents := 0
	for _, ge := range interp.Generic {
		if ge.Kind == provider.GenericTerminationIntended && ge.Intent == provider.IntentEphemeralComplete {
			intents++
		}
	}
	if intents != 1 {
		t.Fatalf("generic EPHEMERAL_COMPLETE intents = %d, want 1", intents)
	}
}

// R6 (T1 negative): an ephemeral runner whose listener dies with no stated
// job result is not an intended termination.
func TestAuditR6EphemeralDeathWithoutStatedResultIsNotIntended(t *testing.T) {
	host, base := ephemeralRunner(t,
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan p job j received.",
	)
	s := attachSession(t, host)
	ctx := context.Background()
	s.Observe(ctx, snapshotAt(host, base, 10))
	s.Observe(ctx, snapshotAt(host, base.Add(2*time.Second), 0, procListener, procWorker, procJobRoot))
	section := freezeAll(t, s, base)
	if got := eventsOf(section, EventRunnerEphemeralComplete); len(got) != 0 {
		t.Fatalf("unexplained ephemeral death reported as intended: %+v", got)
	}
}

// R6: a stated cancellation reaches the job's outcome.
func TestAuditR6StatedCancellationReachesJobOutcome(t *testing.T) {
	host, _, base := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan p job j received.",
		"[2026-10-28 12:00:02Z INFO JobDispatcher] Send job cancellation message to worker for job j.",
		"[2026-10-28 12:00:03Z INFO Terminal] Job build completed with result: Canceled",
	)
	s := attachSession(t, host)
	ctx := context.Background()
	s.Observe(ctx, snapshotAt(host, base, 10))
	s.Observe(ctx, snapshotAt(host, base.Add(3*time.Second), 0, procWorker, procJobRoot))
	section := freezeAll(t, s, base)
	if len(section.Jobs) != 1 || section.Jobs[0].Outcome != evidence.OutcomeCancelled {
		t.Fatalf("job = %+v, want CANCELLED", section.Jobs)
	}
	for _, ev := range eventsOf(section, EventJobCancellation) {
		if ev.Worker == "" {
			t.Fatalf("cancellation not bound to its worker: %+v", ev)
		}
	}
}

func channelConn(inode uint64) collector.ConnectionSnapshot {
	return collector.ConnectionSnapshot{
		RemotePort: 443, State: "ESTABLISHED", Inode: inode,
		PID: procListener, StartTicks: ticksListener,
	}
}

// R7: every normal long-poll reconnect (a new socket) was reported as a
// communication stall after 5 s, and so was a runner that had simply died.
func TestAuditR7CommunicationStallNeedsALiveRunnerWithoutAChannel(t *testing.T) {
	ctx := context.Background()
	observe := func(s provider.Session, host *fakeHost, at time.Time, drop []int, conns ...collector.ConnectionSnapshot) {
		snap := snapshotAt(host, at, 10, drop...)
		snap.Connections = conns
		s.Observe(ctx, snap)
	}

	// normal cycle: inode 1 qualifies, closes, inode 2 replaces it at once.
	host, _, base := fakeRunner(t, "[2026-10-28 12:00:00Z INFO Terminal] Listening for Jobs")
	s := attachSession(t, host)
	for i := 0; i < 3; i++ {
		observe(s, host, base.Add(time.Duration(i)*time.Second), nil, channelConn(1))
	}
	observe(s, host, base.Add(3*time.Second), nil, channelConn(2))
	for i := 4; i < 20; i++ {
		observe(s, host, base.Add(time.Duration(i)*time.Second), nil, channelConn(2))
	}
	section := freezeAll(t, s, base)
	if got := eventsOf(section, EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("normal reconnect reported as a communication stall: %+v", got)
	}
	var replaced *evidence.SocketRole
	for i := range section.SocketRoles {
		if section.SocketRoles[i].Inode == 2 {
			replaced = &section.SocketRoles[i]
		}
	}
	if replaced == nil || replaced.Role != SocketRoleControlChannel {
		t.Fatalf("replacement channel = %+v, want CONTROL_CHANNEL", section.SocketRoles)
	}

	// real stall: the channel drops and nothing replaces it while the
	// listener lives: one event, once.
	host2, _, _ := fakeRunner(t, "[2026-10-28 12:00:00Z INFO Terminal] Listening for Jobs")
	s2 := attachSession(t, host2)
	for i := 0; i < 3; i++ {
		observe(s2, host2, base.Add(time.Duration(i)*time.Second), nil, channelConn(1))
	}
	for i := 3; i < 15; i++ {
		observe(s2, host2, base.Add(time.Duration(i)*time.Second), nil)
	}
	if got := eventsOf(freezeAll(t, s2, base), EventCommunicationStalled); len(got) != 1 {
		t.Fatalf("stall events = %d, want 1", len(got))
	}

	// dead runner: the listener is gone with its channel: lifecycle, not a
	// communication stall.
	host3, _, _ := fakeRunner(t, "[2026-10-28 12:00:00Z INFO Terminal] Listening for Jobs")
	s3 := attachSession(t, host3)
	for i := 0; i < 3; i++ {
		observe(s3, host3, base.Add(time.Duration(i)*time.Second), nil, channelConn(1))
	}
	for i := 3; i < 15; i++ {
		observe(s3, host3, base.Add(time.Duration(i)*time.Second), []int{procListener, procWorker, procJobRoot})
	}
	if got := eventsOf(freezeAll(t, s3, base), EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("dead runner reported as a communication stall: %+v", got)
	}
}

// R8: the communication stall was translated to the generic
// WORKER_PROGRESS_STOPPED, merging the two stall labels (§10A S1).
func TestAuditR8CommunicationStallHasNoGenericTranslation(t *testing.T) {
	if _, ok := genericByEvent[EventCommunicationStalled]; ok {
		t.Fatal("GITHUB_COMMUNICATION_STALLED must not share a generic kind with job progress")
	}
}

// R10: Worker.Exited carried the freeze-time clock, not the exit.
func TestAuditR10WorkerExitTimeIsTheObservedExit(t *testing.T) {
	host, _, base := fakeRunner(t)
	s := attachSession(t, host)
	ctx := context.Background()
	s.Observe(ctx, snapshotAt(host, base, 10))
	s.Observe(ctx, snapshotAt(host, base.Add(2*time.Second), 0, procWorker, procJobRoot))
	for i := 3; i < 30; i++ {
		s.Observe(ctx, snapshotAt(host, base.Add(time.Duration(i)*time.Second), 0, procWorker, procJobRoot))
	}
	section := freezeAll(t, s, base)
	if len(section.Workers) != 1 || !section.Workers[0].Exited.Equal(base.Add(2*time.Second)) {
		t.Fatalf("worker = %+v, want exit at +2 s", section.Workers)
	}
}

// R11: a supervisor restart (C9) recorded two RUNNER_STARTED events for the
// new incarnation.
func TestAuditR11RestartRecordsOneStartPerIncarnation(t *testing.T) {
	host, _, base := fakeRunner(t)
	s := attachSession(t, host)
	ctx := context.Background()
	s.Observe(ctx, snapshotAt(host, base, 0))
	s.Observe(ctx, snapshotAt(host, base.Add(time.Second), 0, procListener, procWorker, procJobRoot))
	host.table = host.table[:1]
	host.table[0].StartTicks = ticksListener + 1000
	s.Observe(ctx, snapshotAt(host, base.Add(2*time.Second), 0))
	section := freezeAll(t, s, base)
	if len(section.Runners) != 1 || len(section.Runners[0].Supervisors) != 2 {
		t.Fatalf("runners = %+v, want one runner with two incarnations", section.Runners)
	}
	if got := eventsOf(section, EventRunnerStarted); len(got) != 2 {
		t.Fatalf("RUNNER_STARTED events = %d, want 2 (one per incarnation)", len(got))
	}
}

// R12: a supervisor the user named but that did not verify was reported as
// a HIGH, layout-verified supervisor (C2: MEDIUM, USER_OVERRIDE).
func TestAuditR12UnverifiedOverrideIsMedium(t *testing.T) {
	host, _, base := fakeRunner(t)
	host.exe[procListener] = filepath.Join(t.TempDir(), "bin", "Runner.Listener") // no install layout
	s, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers, SupervisorPIDs: []int{procListener},
	})
	if err != nil {
		t.Fatal(err)
	}
	section := freezeAll(t, s, base)
	found := false
	for _, role := range section.ProcessRoles {
		if role.Role != evidence.RoleSupervisor {
			continue
		}
		found = true
		if role.Confidence != evidence.ConfidenceMedium || !hasCode(role.Evidence, EvidenceUserOverride) || hasCode(role.Evidence, EvidenceInstallLayoutMatch) {
			t.Fatalf("override-only supervisor role = %+v", role)
		}
	}
	if !found {
		t.Fatal("override supervisor not tagged")
	}

	// R12b: an override whose install root cannot be resolved has no runner
	// identity (C1) and must not be tagged: tagging it with an empty runner
	// made the whole section invalid.
	host.exe[procListener] = "/opt/Runner.Listener"
	s2, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers, SupervisorPIDs: []int{procListener},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Freeze(context.Background(), base.Add(-time.Minute), base.Add(time.Hour)); err != nil {
		t.Fatalf("unresolvable override invalidated the section: %v", err)
	}
}

// R16 (T4): a cancellation that arrives after the worker already died does
// not explain the death: TERMINATION_INTENT conflict, and the section stays
// valid. A cancellation followed by the worker's exit is a sequence: no
// conflict at all.
func TestAuditR16TerminationIntentAfterDeathIsAConflict(t *testing.T) {
	ctx := context.Background()
	host, _, base := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan p job j received.",
		"[2026-10-28 12:00:20Z INFO JobDispatcher] Send job cancellation message to worker for job j.",
	)
	s := attachSession(t, host)
	s.Observe(ctx, snapshotAt(host, base, 10))
	s.Observe(ctx, snapshotAt(host, base.Add(2*time.Second), 0, procWorker, procJobRoot))
	section := freezeAll(t, s, base)
	var topics []string
	for _, c := range section.Conflicts {
		topics = append(topics, c.Question)
	}
	if len(topics) != 1 || topics[0] != ConflictTopicTermination {
		t.Fatalf("conflicts = %v, want one %s", topics, ConflictTopicTermination)
	}

	host2, _, _ := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan p job j received.",
		"[2026-10-28 12:00:02Z INFO JobDispatcher] Send job cancellation message to worker for job j.",
		"[2026-10-28 12:00:03Z INFO Terminal] Job build completed with result: Canceled",
	)
	s2 := attachSession(t, host2)
	s2.Observe(ctx, snapshotAt(host2, base, 10))
	s2.Observe(ctx, snapshotAt(host2, base.Add(3*time.Second), 0, procWorker, procJobRoot))
	if got := freezeAll(t, s2, base).Conflicts; len(got) != 0 {
		t.Fatalf("cancel-then-exit sequence reported as conflict: %+v", got)
	}
}

// R13: a finished local job (SUCCEEDED) that the API reports cancelled
// produced a conflict claim outside the claim vocabulary, so the enriched
// bundle failed validation and api-enrich aborted.
func TestAuditR13EnrichmentConflictUsesClaimVocabulary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/service/actions/runs/42":
			_, _ = w.Write([]byte(`{"id":42,"name":"CI","status":"completed","conclusion":"cancelled","repository":{"full_name":"acme/service"}}`))
		case "/repos/acme/service/actions/runs/42/jobs":
			_, _ = w.Write([]byte(`{"jobs":[{"id":84,"run_id":42,"name":"t","status":"completed","conclusion":"cancelled","run_attempt":1}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	section := apiTestSection()
	section.Jobs[0].Outcome = evidence.OutcomeSucceeded
	section.Jobs[0].OutcomeSource = evidence.SourceRunnerLog
	section.Jobs[0].OutcomeObservedAt = time.Date(2026, 10, 28, 12, 0, 4, 0, time.UTC)
	(GitHubAPIEnricher{BaseURL: server.URL}).Enrich(context.Background(), &section, fixedCredentials("canary-token"))
	if len(section.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want the JOB_STATE disagreement", section.Conflicts)
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("enriched section invalid: %v", err)
	}
}

// §9.3 / 5.12 / 5.36: one canary planted in every secret-bearing place the
// provider can reach on a runner host must not appear anywhere in the
// frozen section or its interpretation, at either privacy level.
func TestAuditCanaryNeverLeavesTheHost(t *testing.T) {
	const canary = "ghp_CANARYc4n4ry0000000000000000000000"
	host, root, base := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs",
		"[2026-10-28 12:00:01Z INFO JobDispatcher] Job request 1 for plan "+canary+" job j received.",
		"[2026-10-28 12:00:02Z INFO Terminal] Running job: "+canary,
		"[2026-10-28 12:00:02Z INFO HttpClient] GET https://api.github.com/x?token="+canary+" Authorization: Bearer "+canary,
		"[2026-10-28 12:00:03Z INFO Terminal] Job "+canary+" completed with result: Succeeded",
	)
	for name, content := range map[string]string{
		".credentials":           `{"scheme":"OAuth","data":{"token":"` + canary + `"}}`,
		".credentials_rsaparams": canary,
		".env":                   "GITHUB_TOKEN=" + canary + "\n",
		".runner": "\xef\xbb\xbf" + `{"agentId":1,"agentName":"r1","serverUrl":"https://x.invalid/` + canary +
			`","gitHubUrl":"https://github.com/acme/` + canary + `","workFolder":"_work"}`,
		"_diag/Worker_20261028-120002-utc.log": "[2026-10-28 12:00:02Z INFO JobRunner] env GITHUB_TOKEN=" + canary + "\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DEPREHENDO_GITHUB_TOKEN", canary)
	for _, level := range []evidence.PrivacyLevel{evidence.PrivacyIdentifiers, evidence.PrivacyConservative} {
		s, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{Privacy: level})
		if err != nil {
			t.Fatal(err)
		}
		s.Observe(context.Background(), snapshotAt(host, base, 10))
		s.Observe(context.Background(), snapshotAt(host, base.Add(3*time.Second), 0, procWorker, procJobRoot))
		section := freezeAll(t, s, base)
		interp, err := GitHubProvider{}.Interpret(section, nil)
		if err != nil {
			t.Fatal(err)
		}
		dump, _ := json.Marshal(struct {
			S evidence.Section
			I provider.Interpretation
		}{section, interp})
		for _, needle := range []string{"CANARY", "c4n4ry", root, "acme", "x.invalid"} {
			if strings.Contains(string(dump), needle) {
				t.Fatalf("privacy %s: %q left the host: %s", level, needle, dump)
			}
		}
		if level == evidence.PrivacyIdentifiers && (len(section.Runners) != 1 || section.Runners[0].Name.Value != "r1") {
			t.Fatalf("identifiers level lost the allowlisted runner name: %+v", section.Runners)
		}
	}
}
