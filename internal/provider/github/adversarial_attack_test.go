package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// adversarial adversarial pass (phase 5 items 5.7, 5.12, 5.36). each test tries to
// make the provider say something the runner did not say, or let a secret
// out. A failing test is a defect; the expected behaviour is the one the
// architecture (§6 C6–C7, §9) requires.

// 5.7: a worker-scope intent phrase in the listener log is not a fact. the
// listener scope must stay closed to worker-only patterns.
func TestAdversarialAttackWorkerPhraseInListenerLogIsIgnored(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:00Z INFO Terminal] Job was cancelled",
		"[2026-09-03 18:34:01Z INFO Terminal] The job running on runner r1 has exceeded the maximum execution time of 1 minutes.",
	)
	if len(events) != 0 {
		t.Fatalf("worker-only phrases produced listener facts: %+v", events)
	}
}

// 5.7: "running jobs ..." is not "running job: <name>". the accepted-job
// pattern must not match a longer word.
func TestAdversarialAttackRunningJobsIsNotAcceptance(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:10Z INFO Terminal] Running jobs in parallel is not supported by this runner",
		"[2026-09-03 18:34:11Z INFO Terminal] Running jobsite maintenance window",
	)
	for _, ev := range events {
		if ev.Type == EventJobAccepted {
			t.Fatalf("a line about other jobs was read as job acceptance: %+v", ev)
		}
	}
}

// 5.7: a record still being written has no newline yet. it must not be
// consumed, and it must be reported exactly once when it completes.
func TestAdversarialAttackPartialTrailingRecordWaitsForNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Runner_20260903-183400-utc.log")
	const full = "[2026-09-03 18:34:29Z INFO Terminal] Job build completed with result: Succeeded"
	if err := os.WriteFile(path, []byte(full[:40]), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := newLogTail(dir)
	if events, _, _ := tail.readPass(1 << 20); len(events) != 0 {
		t.Fatalf("partial record produced events: %+v", events)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(full[40:] + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	events, _, _ := tail.readPass(1 << 20)
	if len(events) != 1 || events[0].Type != EventJobCompleted || events[0].Outcome != evidence.OutcomeSucceeded {
		t.Fatalf("completed record = %+v", events)
	}
	if again, _, _ := tail.readPass(1 << 20); len(again) != 0 {
		t.Fatalf("record reported twice: %+v", again)
	}
}

// 5.7: CRLF line endings (written by some Windows-hosted tooling and copied
// into shared log folders) must not change the result.
func TestAdversarialAttackCRLFRecordParsesLikeLF(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:29Z INFO Terminal] Job build completed with result: Succeeded\r")
	if len(events) != 1 || events[0].Outcome != evidence.OutcomeSucceeded {
		t.Fatalf("CRLF record = %+v", events)
	}
}

// 5.7 (bounded memory, tailing): one enormous line must not blind the reader
// for the rest of the run. the reader reads at most one budget per pass and
// must eventually move past a line longer than the budget.
func TestAdversarialAttackOversizedLineDoesNotStallTheTail(t *testing.T) {
	dir := t.TempDir()
	huge := strings.Repeat("A", 2<<20)
	writeDiag(t, dir, "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:00Z INFO Terminal] "+huge+"\n"+
			"[2026-09-03 18:34:31Z INFO Terminal] Job build completed with result: Succeeded\n")
	tail := newLogTail(dir)
	var got []logEvent
	for pass := 0; pass < 16; pass++ {
		events, _, _ := tail.readPass(1 << 20)
		got = append(got, events...)
	}
	if len(got) != 1 || got[0].Type != EventJobCompleted {
		t.Fatalf("after an oversized line the reader produced %+v; the record after it was lost", got)
	}
}

// 5.12 / 5.36: the runner name is operator text, not a secret, but a token
// pasted into it must not reach the bundle at the identifiers level either.
func TestAdversarialAttackTokenInRunnerNameIsWithheld(t *testing.T) {
	const canary = "ghp_AUDITcanary0000000000000000000000000"
	host, root, base := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs")
	if err := os.WriteFile(filepath.Join(root, ".runner"),
		[]byte(`{"agentId":1,"agentName":"`+canary+`","workFolder":"_work"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []evidence.PrivacyLevel{evidence.PrivacyIdentifiers, evidence.PrivacyConservative} {
		s, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{Privacy: level})
		if err != nil {
			t.Fatal(err)
		}
		s.Observe(context.Background(), snapshotAt(host, base, 0))
		section := freezeAll(t, s, base)
		dump, _ := json.Marshal(section)
		if strings.Contains(string(dump), "AUDITcanary") {
			t.Fatalf("privacy %s: token in runner name left the host: %s", level, dump)
		}
	}
}

// 5.12: a workFolder value carrying a token-shaped string (or a signed URL)
// is an allowlisted key, but the value is operator text. it must not appear
// in the bundle at either level.
func TestAdversarialAttackTokenInWorkFolderIsWithheld(t *testing.T) {
	const canary = "ghp_AUDITwork0000000000000000000000000000"
	host, root, base := fakeRunner(t, "[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs")
	if err := os.WriteFile(filepath.Join(root, ".runner"),
		[]byte(`{"agentId":1,"agentName":"r1","workFolder":"_work/`+canary+`?sig=abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []evidence.PrivacyLevel{evidence.PrivacyIdentifiers, evidence.PrivacyConservative} {
		s, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{Privacy: level})
		if err != nil {
			t.Fatal(err)
		}
		s.Observe(context.Background(), snapshotAt(host, base, 0))
		dump, _ := json.Marshal(freezeAll(t, s, base))
		for _, needle := range []string{"AUDITwork", "sig=abc", "_work/"} {
			if strings.Contains(string(dump), needle) {
				t.Fatalf("privacy %s: %q from workFolder left the host: %s", level, needle, dump)
			}
		}
	}
}

// 5.40 (healthy look-alike): a healthy job whose worker log contains an
// ordinary "job" sentence must not become a failure or intent fact.
func TestAdversarialAttackHealthyJobSentencesStayQuiet(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Worker_20260903-183435-utc.log",
		"[2026-09-03 18:35:00Z INFO JobRunner] Job step timeout is unset; using the default",
		"[2026-09-03 18:35:01Z INFO JobRunner] Job cancellation is not requested for this job",
	)
	for _, ev := range events {
		if ev.Type == EventJobCancellation || ev.Type == EventJobTimeout {
			t.Fatalf("negated or unrelated job sentence became intent: %+v", ev)
		}
	}
}

// 5.37: the remaining required API failure modes. A GitHub outage (503) and
// an unreachable network must both be degraded provider health, never a
// capture failure, and neither may leak the credential.
func TestAdversarialAttackAPIOutageAndNetworkLossAreHealth(t *testing.T) {
	const credential = "canary-token-adversarial"
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, "outage "+credential)
	}))
	defer unavailable.Close()
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedurl := closed.URL
	closed.Close()

	for name, baseURL := range map[string]string{"github outage": unavailable.URL, "network unavailable": closedurl} {
		t.Run(name, func(t *testing.T) {
			section := apiTestSection()
			health := (GitHubAPIEnricher{BaseURL: baseURL}).Enrich(context.Background(), &section, fixedCredentials(credential))
			if health.State != evidence.HealthDegraded {
				t.Fatalf("health = %+v, want degraded", health)
			}
			if err := section.Validate(); err != nil {
				t.Fatalf("section invalid after %s: %v", name, err)
			}
			if strings.Contains(fmt.Sprint(health, section), credential) {
				t.Fatal("credential leaked into health or evidence")
			}
		})
	}
}

// 5.2 / C2 (adversarial adversarial pass): a process merely named Runner.Listener
// that runs from outside the runner installation must not be classified as
// the runner's supervisor. C2 needs two facts (basename and install layout).
func TestAdversarialAttackImpostorListenerIsNotASupervisor(t *testing.T) {
	host, _, base := fakeRunner(t, "[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs")
	host.exe[procListener] = "/tmp/impostor/bin/Runner.Listener"
	s := attachSession(t, host)
	s.Observe(context.Background(), snapshotAt(host, base, 0))
	section := freezeAll(t, s, base)
	for _, role := range section.ProcessRoles {
		if role.Process.PID == procListener && role.Role == evidence.RoleSupervisor {
			t.Fatalf("impostor listener classified as supervisor: %+v", role)
		}
	}
	for _, runner := range section.Runners {
		for _, sup := range runner.Supervisors {
			if sup.PID == procListener {
				t.Fatalf("impostor listener attached to runner %+v", runner)
			}
		}
	}
}

// 5.5 / C1 (adversarial adversarial pass): a PID reused by a new Runner.Worker
// (different start time) is a different incarnation. the session must record
// two worker identities, never fold the new one into the old.
func TestAdversarialAttackReusedWorkerPIDIsANewIncarnation(t *testing.T) {
	host, _, base := fakeRunner(t,
		"[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs",
		"[2026-10-28 12:00:02Z INFO JobDispatcher] Job request 1 for plan 6f1c job 0d2e received.")
	s := attachSession(t, host)
	s.Observe(context.Background(), snapshotAt(host, base, 0))
	s.Observe(context.Background(), snapshotAt(host, base.Add(time.Second), 0))
	// the worker exits; a different process takes PID procWorker.
	for i := range host.table {
		if host.table[i].PID == procWorker {
			host.table[i].StartTicks = ticksWorker + 1000
		}
	}
	s.Observe(context.Background(), snapshotAt(host, base.Add(2*time.Second), 0))
	section := freezeAll(t, s, base)
	starts := map[int64]bool{}
	for _, role := range section.ProcessRoles {
		if role.Role == evidence.RoleWorker && role.Process.PID == procWorker {
			starts[role.Process.StartTicks] = true
		}
	}
	if len(starts) < 2 {
		t.Fatalf("reused PID %d folded into one incarnation: roles=%+v", procWorker, section.ProcessRoles)
	}
}
