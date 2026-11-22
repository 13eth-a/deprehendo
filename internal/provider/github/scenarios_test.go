package github

// scenario fixtures (phase 5 items 5.39/5.40). every directory under
// testdata/github/ is driven through the real provider session: a real runner
// installation layout on disk, the real diagnostic-log tail, and the real
// correlation code. nothing here stubs the provider.
//
// the healthy fixtures are the load-bearing half: an idle runner, a running
// job, a normal worker exit and a normal ephemeral shutdown must not produce a
// failure-shaped fact. the failure fixtures assert only facts the current
// implementation can prove; they must not claim a provider diagnosis that the
// diagnosis engine does not yet implement (docs/github/signatures.md).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"runopsy/internal/incident"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github/fixtures"
)

const fixtureRoot = "../../../testdata/github"

func TestGitHubScenarios(t *testing.T) {
	cases, err := fixtures.LoadAll(fixtureRoot)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no GitHub fixtures found")
	}
	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) { runScenario(t, fixture) })
	}
}

// runScenario observes every snapshot with a real session and then asserts the
// scenario contract.
func runScenario(t *testing.T, fixture *fixtures.Fixture) {
	t.Helper()
	host, err := fixture.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := (GitHubProvider{}).Attach(ctx, host, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers,
		Budget:  provider.DefaultBudget(),
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer session.Close()

	for i := 0; i < host.Count(); i++ {
		if err := host.SetSnapshot(i); err != nil {
			t.Fatal(err)
		}
		session.Observe(ctx, host.CollectorSnapshot(i))
	}
	from, to := host.Window()
	section, err := session.Freeze(ctx, from, to)
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}

	assertHeader(t, section, fixture.Expected)
	assertRunners(t, section, fixture.Expected)
	assertWorkersAndJobs(t, section, fixture.Expected)
	assertEvents(t, section, fixture.Expected)
	assertSockets(t, section, fixture.Expected)
	assertConflicts(t, section, fixture.Expected)
	assertNoLeak(t, section, host.Roots())
	assertInterpretable(t, section)
	assertSignatures(t, fixture.Name, section, to)
}

// wantSignatures is the reported signature label set per scenario, judged at
// the capture window end. healthy scenarios must report none.
var wantSignatures = map[string][]string{
	"healthy-idle":          nil,
	"healthy-job":           nil,
	"normal-ephemeral-exit": nil,
	"tree-empty-clean-exit": nil,
	"finalization-stall":    {SignatureJobFinalizationStall},
	"runner-self-kill":      {SignatureRunnerSelfTermination},
	// one finding per surviving job-tree member (bash and make, §10A.4).
	"orphan-job": {SignatureOrphanedJobProcess, SignatureOrphanedJobProcess},
}

// assertSignatures runs the report-side interpretation at the window end and
// checks the labels, so the offline path is exercised as the report uses it.
func assertSignatures(t *testing.T, name string, section evidence.Section, windowEnd time.Time) {
	t.Helper()
	want, ok := wantSignatures[name]
	if !ok {
		return
	}
	interp, err := (GitHubProvider{}).Interpret(section, &incident.Incident{CaptureEnd: windowEnd})
	if err != nil {
		t.Fatalf("interpret: %v", err)
	}
	var got []string
	for _, sig := range interp.Signatures {
		got = append(got, sig.Label)
	}
	if len(got) != len(want) || (len(want) == 1 && got[0] != want[0]) {
		t.Fatalf("signatures = %v, want %v", got, want)
	}
}

func assertHeader(t *testing.T, section evidence.Section, want fixtures.Expected) {
	t.Helper()
	if section.Provider != Name || section.SchemaVersion != evidence.SchemaVersion {
		t.Fatalf("section header = %s/%d", section.Provider, section.SchemaVersion)
	}
	if want.Health != "" && string(section.Health.State) != want.Health {
		t.Fatalf("health = %s (%v), want %s", section.Health.State, section.Health.Reasons, want.Health)
	}
}

func assertRunners(t *testing.T, section evidence.Section, want fixtures.Expected) {
	t.Helper()
	if want.Runners != nil && len(section.Runners) != *want.Runners {
		t.Fatalf("runners = %d, want %d", len(section.Runners), *want.Runners)
	}
	if len(section.Runners) == 0 {
		return
	}
	runner := section.Runners[0]
	if want.RunnerName != "" {
		if runner.Name.State != evidence.Known || runner.Name.Value != want.RunnerName {
			t.Errorf("runner name = %+v, want %q", runner.Name, want.RunnerName)
		}
	}
	if want.RunnerVersion != "" {
		if runner.Version.State != evidence.Known || runner.Version.Value != want.RunnerVersion {
			t.Errorf("runner version = %+v, want %q", runner.Version, want.RunnerVersion)
		}
	}
	if want.Lifecycle != "" && string(runner.Lifecycle) != want.Lifecycle {
		t.Errorf("lifecycle = %s, want %s", runner.Lifecycle, want.Lifecycle)
	}
	if len(runner.Supervisors) == 0 {
		t.Error("runner has no supervisor incarnation")
	}
}

func assertWorkersAndJobs(t *testing.T, section evidence.Section, want fixtures.Expected) {
	t.Helper()
	if want.Workers != nil && len(section.Workers) != *want.Workers {
		t.Fatalf("workers = %d, want %d", len(section.Workers), *want.Workers)
	}
	if want.Jobs != nil && len(section.Jobs) != *want.Jobs {
		t.Fatalf("jobs = %d, want %d", len(section.Jobs), *want.Jobs)
	}
	for _, worker := range section.Workers {
		if worker.Runner == "" {
			t.Errorf("worker %s has no runner", worker.Ref)
		}
	}
	for _, job := range section.Jobs {
		if job.Runner == "" {
			t.Errorf("job %s has no runner", job.Ref)
		}
		if len(want.JobOutcomes) > 0 && !containsString(want.JobOutcomes, string(job.Outcome)) {
			t.Errorf("job %s outcome = %s, allowed %v", job.Ref, job.Outcome, want.JobOutcomes)
		}
	}
	if len(want.JobRoles) > 0 {
		got := map[string]int{}
		for _, role := range section.ProcessRoles {
			got[string(role.Role)]++
		}
		for role, count := range want.JobRoles {
			if got[role] != count {
				t.Errorf("%s role count = %d, want %d (roles: %v)", role, got[role], count, got)
			}
		}
	}
	// A worker/listener attribution pin for multi-runner fixtures.
	if len(want.WorkerListener) > 0 {
		bysupervisor := map[int]evidence.Ref{}
		for _, runner := range section.Runners {
			for _, supervisor := range runner.Supervisors {
				bysupervisor[supervisor.PID] = runner.Ref
			}
		}
		for pidtext, listener := range want.WorkerListener {
			pid := atoi(t, pidtext)
			var got evidence.Ref
			for _, worker := range section.Workers {
				if worker.Process.PID == pid {
					got = worker.Runner
				}
			}
			if wantref := bysupervisor[listener]; got == "" || got != wantref {
				t.Errorf("worker %d bound to %q, want listener %d's runner %q", pid, got, listener, wantref)
			}
		}
	}
}

func assertEvents(t *testing.T, section evidence.Section, want fixtures.Expected) {
	t.Helper()
	present := map[string]bool{}
	for _, event := range section.Events {
		present[event.Type] = true
	}
	for _, eventtype := range want.Events {
		if !present[eventtype] {
			t.Errorf("missing event %s (have %v)", eventtype, fixtures.EventTypes(section))
		}
	}
	for _, eventtype := range want.AbsentEvents {
		if present[eventtype] {
			t.Errorf("unexpected event %s", eventtype)
		}
	}
}

func assertSockets(t *testing.T, section evidence.Section, want fixtures.Expected) {
	t.Helper()
	roles := map[string]int{}
	for _, role := range section.SocketRoles {
		roles[role.Role]++
	}
	for _, role := range want.SocketRoles {
		if roles[role] == 0 {
			t.Errorf("missing socket role %s (have %v)", role, roles)
		}
	}
	for _, role := range want.AbsentSocketRoles {
		if roles[role] > 0 {
			t.Errorf("unexpected socket role %s", role)
		}
	}
}

func assertConflicts(t *testing.T, section evidence.Section, want fixtures.Expected) {
	t.Helper()
	topics := map[string]int{}
	for _, conflict := range section.Conflicts {
		topics[conflict.Question]++
	}
	for _, topic := range want.ConflictTopics {
		if topics[topic] == 0 {
			t.Errorf("missing conflict %s", topic)
		}
	}
	for _, topic := range want.AbsentConflictTopic {
		if topics[topic] > 0 {
			t.Errorf("unexpected conflict %s", topic)
		}
	}
}

// assertNoLeak is the fixture analogue of the §11.4 canary: no installation
// path or raw log text may appear in the frozen section (5.36).
func assertNoLeak(t *testing.T, section evidence.Section, roots []string) {
	t.Helper()
	raw, err := json.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, root := range roots {
		if strings.Contains(text, root) {
			t.Fatalf("section leaks installation path %q", root)
		}
	}
	for _, needle := range []string{"Listening for Jobs", "Received job message", "Running job", "bin/Runner"} {
		if strings.Contains(text, needle) {
			t.Fatalf("section leaks raw log text %q", needle)
		}
	}
}

// assertInterpretable proves the offline half works on every stored section:
// the bundle alone is enough to translate, which is 5.38's contract.
func assertInterpretable(t *testing.T, section evidence.Section) {
	t.Helper()
	interp, err := (GitHubProvider{}).Interpret(section, nil)
	if err != nil {
		t.Fatalf("interpret: %v", err)
	}
	if len(interp.Generic) == 0 {
		t.Error("interpretation produced no generic events")
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("stored section invalid: %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func atoi(t *testing.T, text string) int {
	t.Helper()
	value := 0
	for _, r := range text {
		if r < '0' || r > '9' {
			t.Fatalf("not a number: %q", text)
		}
		value = value*10 + int(r-'0')
	}
	return value
}

// TestAssignmentStallKeepsAssignmentUnbound is the precise 5.20-adjacent
// contract the current provider can prove: the assignment is recorded, but
// with no worker in the window it must stay unbound rather than guessed.
func TestAssignmentStallKeepsAssignmentUnbound(t *testing.T) {
	fixture, err := fixtures.Load(fixtureRoot + "/job-assignment-stall")
	if err != nil {
		t.Fatal(err)
	}
	host, err := fixture.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := (GitHubProvider{}).Attach(ctx, host, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers, Budget: provider.DefaultBudget(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for i := 0; i < host.Count(); i++ {
		if err := host.SetSnapshot(i); err != nil {
			t.Fatal(err)
		}
		session.Observe(ctx, host.CollectorSnapshot(i))
	}
	from, to := host.Window()
	section, err := session.Freeze(ctx, from, to)
	if err != nil {
		t.Fatal(err)
	}
	assigned := 0
	for _, event := range section.Events {
		if event.Type != EventJobAssigned {
			continue
		}
		assigned++
		if event.Worker != "" || event.Job != "" {
			t.Errorf("assignment guessed a worker/job: worker=%q job=%q", event.Worker, event.Job)
		}
		if event.Source != evidence.SourceRunnerLog {
			t.Errorf("assignment source = %s, want RUNNER_LOG", event.Source)
		}
	}
	if assigned == 0 {
		t.Fatal("assignment record missing")
	}
	if len(section.Workers) != 0 || len(section.Jobs) != 0 {
		t.Fatalf("workers/jobs invented without a process: %d/%d", len(section.Workers), len(section.Jobs))
	}
}

// TestHealthyScenariosCarryNoFailureFacts restates the 5.40 acceptance rule in
// one place: none of the healthy fixtures may contain a stall, exit or
// termination-intent fact that a signature could turn into a false diagnosis.
func TestHealthyScenariosCarryNoFailureFacts(t *testing.T) {
	for _, name := range []string{"healthy-idle", "healthy-job", "normal-ephemeral-exit"} {
		t.Run(name, func(t *testing.T) {
			fixture, err := fixtures.Load(fixtureRoot + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			host, err := fixture.Materialize(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			session, err := (GitHubProvider{}).Attach(ctx, host, provider.AttachOptions{
				Privacy: evidence.PrivacyIdentifiers, Budget: provider.DefaultBudget(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			for i := 0; i < host.Count(); i++ {
				if err := host.SetSnapshot(i); err != nil {
					t.Fatal(err)
				}
				session.Observe(ctx, host.CollectorSnapshot(i))
			}
			from, to := host.Window()
			section, err := session.Freeze(ctx, from, to)
			if err != nil {
				t.Fatal(err)
			}
			for _, banned := range []string{
				EventJobProgressStopped,
				EventCommunicationStalled,
				EventJobCancellation,
				EventJobTimeout,
			} {
				if fixtures.HasEvent(section, banned) {
					t.Errorf("healthy scenario produced %s", banned)
				}
			}
			for _, conflict := range section.Conflicts {
				if conflict.Question == ConflictTopicTermination {
					t.Errorf("healthy scenario produced a termination-intent conflict")
				}
			}
		})
	}
}
