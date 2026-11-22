package github

// session tests against a fake-runner harness (5.41): a generated runner
// installation (bin/, .runner, config.sh, _diag/) plus a fixed process
// table and snapshot feed. these drive the live correlation invariants
// C2 (supervisor), C3 (worker), C4 (job tree), C6 (job binding), and end
// with the conformance kit for the frozen fixture.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/platform"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/providertest"
)

// TestMain registers the provider once so section validation can resolve
// the vocabulary table (the compiled binaries do this in their init).
func TestMain(m *testing.M) {
	if err := provider.Default.Register(GitHubProvider{}); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// buildFakeRunner creates one runner installation on disk and returns its
// root (5.41). diary lines are written to the listener log exactly as the
// runner would have written them.
func buildFakeRunner(t *testing.T, diary ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "_diag"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"bin/Runner.Listener": "#!/fake-runner\n",
		"bin/Runner.Worker":   "#!/fake-runner\n",
		"config.sh":           "#!/bin/sh\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".runner"),
		[]byte(`{"agentId":7,"agentName":"fake-1","ephemeral":false,"workFolder":"_work"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(diary) > 0 {
		var log strings.Builder
		for _, line := range diary {
			log.WriteString(line + "\n")
		}
		if err := os.WriteFile(filepath.Join(root, "_diag", "Runner_20261028-1200.log"), []byte(log.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fakeHost is a fixed provider.HostView: a constant process table, resolved
// executables for the runner binaries, a fixed salt and clock.
type fakeHost struct {
	table []platform.Process
	exe   map[int]string
	salt  []byte
	now   time.Time
	// starts maps a PID to its wall-clock start (see StartTime).
	starts map[int]time.Time
}

func (h *fakeHost) Processes(context.Context) ([]platform.Process, error) { return h.table, nil }

func (h *fakeHost) Inspect(_ context.Context, ref evidence.ProcessRef) (provider.ProcessDetail, error) {
	exe, ok := h.exe[ref.PID]
	if !ok || ref.StartTicks != h.startTicks(ref.PID) {
		return provider.ProcessDetail{}, errors.New("fake: incarnation gone")
	}
	return provider.ProcessDetail{Executable: exe}, nil
}

func (h *fakeHost) startTicks(pid int) int64 {
	for _, proc := range h.table {
		if proc.PID == pid {
			return proc.StartTicks
		}
	}
	return -1
}

func (h *fakeHost) Now() time.Time { return h.now }

// StartTime reports the wall-clock start a test set for a PID. unset PIDs
// report false, so the other fixtures keep the sample-time fallback.
func (h *fakeHost) StartTime(p platform.Process) (time.Time, bool) {
	at, ok := h.starts[p.PID]
	return at, ok
}
func (h *fakeHost) Salt() []byte { return h.salt }

const (
	procListener  = 100
	procWorker    = 200
	procJobRoot   = 300
	ticksListener = 10
	ticksWorker   = 20
	ticksJobRoot  = 30
)

// fakeRunner feeds the fixture process table:
//
//	listener(100) ← worker(200) ← jobroot(300)
func fakeRunner(t *testing.T, diary ...string) (*fakeHost, string, time.Time) {
	t.Helper()
	base := time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC)
	root := buildFakeRunner(t, diary...)
	host := &fakeHost{
		table: []platform.Process{
			{PID: procListener, PPID: 1, StartTicks: ticksListener, Name: "Runner.Listener", State: "S"},
			{PID: procWorker, PPID: procListener, StartTicks: ticksWorker, Name: "Runner.Worker", State: "S"},
			{PID: procJobRoot, PPID: procWorker, StartTicks: ticksJobRoot, Name: "bash", State: "S"},
		},
		exe: map[int]string{
			procListener: filepath.Join(root, "bin", "Runner.Listener"),
			procWorker:   filepath.Join(root, "bin", "Runner.Worker"),
		},
		salt: []byte("0123456789abcdef0123456789abcdef"),
		now:  base,
	}
	return host, root, base
}

func snapshotAt(host *fakeHost, at time.Time, jobCPUPercent float64, drop ...int) collector.Snapshot {
	dropped := map[int]bool{}
	for _, pid := range drop {
		dropped[pid] = true
	}
	snap := collector.Snapshot{Timestamp: at}
	for _, proc := range host.table {
		if dropped[proc.PID] {
			continue
		}
		cpu := 0.0
		if proc.PID == procJobRoot {
			cpu = jobCPUPercent
		}
		snap.Processes = append(snap.Processes, collector.ProcessSnapshot{Process: proc, CPUPercent: cpu})
	}
	return snap
}

func attachSession(t *testing.T, host *fakeHost) provider.Session {
	t.Helper()
	s, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{
		// identifiers level: the tests assert KNOWN text (runner name). the
		// conservative canary is covered by the conformance kit's redaction
		// comparison and the no-path checks.
		Privacy: evidence.PrivacyIdentifiers,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSessionClassifies verifies C2, C3, C4 and the worker lifecycle on the
// fake-runner feed, then the §11.4 canary: no host path or log text can be
// read from the frozen section.
func TestSessionClassifies(t *testing.T) {
	// job message at +1 s: within C6's ±2 s of the worker's start.
	host, root, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	s := attachSession(t, host)

	s.Observe(context.Background(), snapshotAt(host, base, 0))
	s.Observe(context.Background(), snapshotAt(host, base.Add(time.Second), 12))
	atexit := base.Add(2 * time.Second)
	s.Observe(context.Background(), snapshotAt(host, atexit, 0, procWorker, procJobRoot))

	section, err := s.Freeze(context.Background(), base.Add(-time.Second), atexit.Add(time.Second))
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if section.Provider != Name || section.Health.State != evidence.HealthAvailable {
		t.Fatalf("unexpected section header: provider=%s health=%s", section.Provider, section.Health.State)
	}
	if len(section.Runners) != 1 {
		t.Fatalf("runners = %d, want 1", len(section.Runners))
	}
	runner := section.Runners[0]
	if runner.Name.Value != "fake-1" || runner.Lifecycle != evidence.LifecyclePersistent {
		t.Fatalf("runner record off: %+v", runner)
	}
	if len(runner.Supervisors) != 1 || runner.Supervisors[0].PID != procListener {
		t.Fatalf("supervisors = %+v", runner.Supervisors)
	}
	if len(section.Workers) != 1 {
		t.Fatalf("workers = %d, want 1", len(section.Workers))
	}
	worker := section.Workers[0]
	if worker.Process.PID != procWorker || worker.Process.StartTicks != ticksWorker {
		t.Fatalf("worker identity broken (PID + start ticks): %+v", worker.Process)
	}
	if worker.Job == "" {
		t.Fatal("job ref not bound although exactly one worker started within ±2 s (C6)")
	}
	if len(section.Jobs) != 1 || section.Jobs[0].Ref != worker.Job {
		t.Fatalf("jobs = %+v", section.Jobs)
	}

	roles := map[int]evidence.ProcessRole{}
	for _, role := range section.ProcessRoles {
		roles[role.Process.PID] = role
	}
	sup, ok := roles[procListener]
	if !ok || sup.Role != evidence.RoleSupervisor {
		t.Fatalf("supervisor role missing: %+v", sup)
	}
	if sup.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("supervisor confidence = %s, want HIGH with exe + layout (C2)", sup.Confidence)
	}
	wr, ok := roles[procWorker]
	if !ok || wr.Role != evidence.RoleWorker {
		t.Fatalf("worker role missing: %+v", wr)
	}
	if wr.Confidence != evidence.ConfidenceHigh || !hasCode(wr.Evidence, EvidenceParentIsSupervisor) {
		t.Fatalf("worker evidence = %+v, want HIGH at PARENT_IS_SUPERVISOR (C3)", wr)
	}
	jr, ok := roles[procJobRoot]
	if !ok || jr.Role != evidence.RoleJobRoot || jr.Worker != worker.Ref {
		t.Fatalf("job root = %+v", jr)
	}

	// events: assigned (bound), worker started, worker exited.
	want := map[string]bool{EventJobAssigned: true, EventWorkerStarted: true, EventWorkerExited: true}
	for _, ev := range section.Events {
		delete(want, ev.Type)
	}
	if len(want) != 0 {
		t.Fatalf("missing events %v", want)
	}

	// canary: the frozen section carries no host path and no log text.
	raw, _ := json.Marshal(section)
	for _, banned := range []string{root, "Listening", "job message", "bin/Runner"} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("section leaks %q: %s", banned, raw)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestSessionJobBindingConflict: two workers inside the ±2 s window can
// never bind; a JOB_BINDING conflict records both candidates and each
// worker's job stays UNKNOWN (C6: never pick the nearest).
func TestSessionJobBindingConflict(t *testing.T) {
	host, root, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	host.table = append(host.table,
		platform.Process{PID: 201, PPID: procListener, StartTicks: 21, Name: "Runner.Worker", State: "S"})
	host.exe[201] = filepath.Join(root, "bin", "Runner.Worker")
	s := attachSession(t, host)

	s.Observe(context.Background(), snapshotAt(host, base, 0))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(section.Workers) != 2 {
		t.Fatalf("workers = %d, want 2", len(section.Workers))
	}
	for _, worker := range section.Workers {
		if worker.Job != "" {
			t.Fatal("bound a job with two candidates in the binding window")
		}
	}
	bindingconflicts := 0
	for _, conflict := range section.Conflicts {
		if conflict.Question == ConflictTopicJobBinding {
			bindingconflicts++
			if len(conflict.Claims) != 2 {
				t.Fatalf("conflict claims = %d, want the two worker candidates", len(conflict.Claims))
			}
		}
	}
	if bindingconflicts != 1 {
		t.Fatalf("JOB_BINDING conflicts = %d, want 1", bindingconflicts)
	}
	_ = s.Close()
}

// TestSessionControlChannel: C12's long-lived ESTABLISHED:443 supervisor
// socket with a log-timing discriminator becomes CONTROL_CHANNEL at HIGH;
// without a discriminator it is a CONTROL_CHANNEL_CANDIDATE.
func TestSessionControlChannel(t *testing.T) {
	channel := collector.ConnectionSnapshot{
		LocalAddr: "10.0.0.7", LocalPort: 52000, RemoteAddr: "140.82.121.3",
		RemotePort: 443, State: "ESTABLISHED", Inode: 9,
		PID: procListener, StartTicks: ticksListener, FD: 5,
	}

	// with the log-timing discriminator.
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:01.600 +00:00 [RUNNER 1] Reconnected to the message queue")
	s := attachSession(t, host)
	for step := 0; step < 3; step++ {
		snap := snapshotAt(host, base.Add(time.Duration(step)*time.Second), 0)
		snap.Connections = []collector.ConnectionSnapshot{channel}
		s.Observe(context.Background(), snap)
	}
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(section.SocketRoles) != 1 {
		t.Fatalf("socket roles = %d, want 1", len(section.SocketRoles))
	}
	role := section.SocketRoles[0]
	if role.Role != SocketRoleControlChannel || role.Inode != 9 || role.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("discriminated socket = %+v, want HIGH %s", role, SocketRoleControlChannel)
	}
	if !hasCode(role.Evidence, EvidenceLogTimingMatch) {
		t.Fatalf("socket evidence = %v, want the log timing discriminator", role.Evidence)
	}
	_ = s.Close()

	// two qualifying sockets and no discriminator: neither is "the only"
	// socket (C12.4b) and neither has log timing, so both stay candidates.
	host2, _, _ := fakeRunner(t, "2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs")
	s2 := attachSession(t, host2)
	second := channel
	second.Inode = 10
	for step := 0; step < 3; step++ {
		snap := snapshotAt(host2, base.Add(time.Duration(step)*time.Second), 0)
		snap.Connections = []collector.ConnectionSnapshot{channel, second}
		s2.Observe(context.Background(), snap)
	}
	section2, err := s2.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(section2.SocketRoles) != 2 {
		t.Fatalf("socket roles = %d, want 2", len(section2.SocketRoles))
	}
	for _, got := range section2.SocketRoles {
		if got.Role != SocketRoleControlChannelCandidate {
			t.Fatalf("undiscriminated socket %d = %s, want %s", got.Inode, got.Role, SocketRoleControlChannelCandidate)
		}
	}
	_ = s2.Close()
}

// TestWorkerReparentStaysBound: the C4 tag is sticky. after the worker
// exits and its job process is reparented, the job-process role remains.
func TestWorkerReparentStaysBound(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs")
	s := attachSession(t, host)

	s.Observe(context.Background(), snapshotAt(host, base, 0))
	// worker gone; the job process survives (reparented in the table).
	host.table = filterTable(host.table, procWorker)
	s.Observe(context.Background(), snapshotAt(host, base.Add(time.Second), 0))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, role := range section.ProcessRoles {
		if role.Process.PID == procJobRoot {
			found = true
			if role.Role != evidence.RoleJobRoot {
				t.Fatalf("job root became %s after the worker exit (C4 sticky)", role.Role)
			}
		}
	}
	if !found {
		t.Fatal("job process lost its sticky membership tag")
	}
	_ = s.Close()
}

func filterTable(table []platform.Process, gone int) []platform.Process {
	out := table[:0]
	for _, proc := range table {
		if proc.PID != gone {
			out = append(out, proc)
		}
	}
	return out
}

// containerCgroupPath builds one docker-created container scope path (64
// lowercase hex is the rule's shape for 5.33).
var containerCgroupPath = "/system.slice/docker-" + strings.Repeat("a", 64) + ".scope"

// addTable appends processes to a fake host so tests can grow the table
// without renumbering the fixture constants.
func addTable(host *fakeHost, refs ...platform.Process) []platform.Process {
	host.table = append(host.table, refs...)
	return host.table
}

// snapWithCgroup returns a snapshot of the host table plus hand-set cgroup
// identities per PID (5.33). PIDs without an entry are passed through with
// no cgroup telemetry.
func snapWithCgroup(host *fakeHost, at time.Time, cgroups map[int]string) collector.Snapshot {
	snap := snapshotAt(host, at, 0)
	for i := range snap.Processes {
		if path, ok := cgroups[snap.Processes[i].PID]; ok {
			snap.Processes[i].Cgroup = &platform.CgroupSnapshot{Path: path}
		}
	}
	return snap
}

// TestContainerStepLinkedThroughCgroup (5.33 / C5): a verified docker client
// in the job tree plus a process living in a docker-created container cgroup
// links the container step into that job at MEDIUM. the watcher (container's
// unrelated parent) must not be dragged into the job tree.
func TestContainerStepLinkedThroughCgroup(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	addTable(host,
		platform.Process{PID: 301, PPID: procJobRoot, StartTicks: 31, Name: "docker", State: "S"},
		platform.Process{PID: 500, PPID: 1, StartTicks: 50, Name: "containerd", State: "S"},
		platform.Process{PID: 600, PPID: 500, StartTicks: 60, Name: "node", State: "S"},
	)
	host.exe[301] = filepath.Join("/fake", "docker")
	s := attachSession(t, host)

	cgroups := map[int]string{600: containerCgroupPath}
	s.Observe(context.Background(), snapWithCgroup(host, base, cgroups))
	s.Observe(context.Background(), snapWithCgroup(host, base.Add(time.Second), cgroups))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	if len(section.Workers) != 1 || section.Workers[0].Job == "" {
		t.Fatalf("worker not bindable in the fixture: %+v", section.Workers)
	}
	workerref := section.Workers[0].Ref
	var step *evidence.ProcessRole
	for i := range section.ProcessRoles {
		if section.ProcessRoles[i].Process.PID == 600 {
			step = &section.ProcessRoles[i]
		}
	}
	if step == nil {
		t.Fatalf("container step untagged: roles = %+v", section.ProcessRoles)
	}
	if step.Role != evidence.RoleJobProcess || step.Worker != workerref {
		t.Fatalf("container step role off: %+v", step)
	}
	if step.Confidence != evidence.ConfidenceMedium || !hasCode(step.Evidence, EvidenceContainerCgroupLinkage) {
		t.Fatalf("container step evidence off: %+v", step)
	}
	for _, role := range section.ProcessRoles {
		if role.Process.PID == 500 {
			t.Fatalf("containerd was tagged into a job tree: %+v", role)
		}
	}
	if len(section.Jobs) != 1 {
		t.Fatalf("jobs = %+v", section.Jobs)
	}
	if !hasCode(section.Jobs[0].Evidence, EvidenceContainerCgroupLinkage) ||
		hasCode(section.Jobs[0].Evidence, EvidenceContainerLinkageUnavailable) {
		t.Fatalf("job evidence = %v, want the positive linkage, not the marker", section.Jobs[0].Evidence)
	}
}

// TestContainerMembershipNeverGuessed (5.33): when two live jobs each run
// their own docker client, a container cgroup matches both witness sets and
// the step stays untagged. with cgroup telemetry present but no container
// step, neither job claims a positive linkage nor carries the
// unavailable marker (the check was possible).
func TestContainerMembershipNeverGuessed(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	host.table = append(host.table,
		platform.Process{PID: 201, PPID: procListener, StartTicks: 21, Name: "Runner.Worker", State: "S"},
		platform.Process{PID: 302, PPID: procJobRoot, StartTicks: 32, Name: "docker", State: "S"},
		platform.Process{PID: 303, PPID: 201, StartTicks: 33, Name: "docker", State: "S"},
		platform.Process{PID: 500, PPID: 1, StartTicks: 50, Name: "containerd", State: "S"},
		platform.Process{PID: 600, PPID: 500, StartTicks: 60, Name: "node", State: "S"},
	)
	host.exe[201] = filepath.Join("/fake2", "bin", "Runner.Worker")
	host.exe[302] = filepath.Join("/fake", "bin", "docker")
	host.exe[303] = filepath.Join("/fake2", "bin", "docker")
	s := attachSession(t, host)

	cgroups := map[int]string{600: containerCgroupPath}
	s.Observe(context.Background(), snapWithCgroup(host, base, cgroups))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	for _, role := range section.ProcessRoles {
		if role.Process.PID == 600 {
			t.Fatalf("container step tagged under ambiguity: %+v", role)
		}
	}
	// both workers live across one docker-capable host; the two unbound jobs
	// (C6 conflict) never reach jobRecord, so the role above is the verdict
	// surface for this case. the bound-job verdicts for the two positive and
	// negative 5.33 outcomes are pinned in
	// TestContainerStepLinkedThroughCgroup, TestCgroupTelemetryWithoutSteps
	// and TestJobNotesContainerLinkageUnavailable.
}

// TestCgroupTelemetryWithoutSteps pins the third 5.33 outcome: with cgroup
// identity recorded and no container step, a job neither claims the positive
// linkage nor carries the unavailable marker. the check was possible and
// found nothing.
func TestCgroupTelemetryWithoutSteps(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	s := attachSession(t, host)
	cgroups := map[int]string{procJobRoot: "/system.slice/user.slice/session-1.scope"}
	s.Observe(context.Background(), snapWithCgroup(host, base, cgroups))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if len(section.Jobs) != 1 || len(section.Jobs[0].Evidence) != 0 {
		t.Fatalf("job evidence = %+v, want none", section.Jobs)
	}
}

// TestJobNotesContainerLinkageUnavailable pins the honest half of 5.33: on
// a feed whose samples carry no cgroup identity at all (e.g. macOS, or a
// collector without the feature), a bound job states that its container
// membership could not be verified.
func TestJobNotesContainerLinkageUnavailable(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	s := attachSession(t, host)
	s.Observe(context.Background(), snapshotAt(host, base, 0))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if len(section.Jobs) != 1 {
		t.Fatalf("jobs = %+v", section.Jobs)
	}
	if len(section.Jobs[0].Evidence) != 1 || section.Jobs[0].Evidence[0] != EvidenceContainerLinkageUnavailable {
		t.Fatalf("job evidence = %v, want [%s]", section.Jobs[0].Evidence, EvidenceContainerLinkageUnavailable)
	}
}

// TestProviderConformance runs the conformance kit against the frozen
// fake-runner fixture (§10, 5.41): contract, determinism, references and
// privacy independence.
// TestAuditG4StallWindowIsConfigurable pins the phase 5 gap G4 fix: the
// C11 progress window is a configuration knob, not a fixed 2-minute constant
// (a sleep-heavy step cannot be told apart from a stall at any one fixed
// window). the session reads RUNOPSY_GITHUB_STALL_WINDOW, and an override
// that does not parse as a positive duration keeps the default: a
// misconfigured environment can change the knob's value but must never
// disable progress detection.
func TestAuditG4StallWindowIsConfigurable(t *testing.T) {
	documented := defaultStallWindow

	// no override configured: the documented default reaches the session.
	previous, had := os.LookupEnv(stallWindowEnvironment)
	os.Unsetenv(stallWindowEnvironment)
	defer func() {
		if had {
			os.Setenv(stallWindowEnvironment, previous)
		}
	}()
	host, _, _ := fakeRunner(t)
	attached, err := GitHubProvider{}.Attach(context.Background(), host, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := attached.(*session); !ok || s.stallWindow != documented {
		t.Fatalf("default window not in effect: want %s, got %v", documented, attached)
	}
	attached.Close()

	// A stated override reaches the session unclamped.
	t.Setenv(stallWindowEnvironment, "45s")
	host2, _, _ := fakeRunner(t)
	attached2, err := GitHubProvider{}.Attach(context.Background(), host2, provider.AttachOptions{
		Privacy: evidence.PrivacyIdentifiers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := attached2.(*session); !ok || s.stallWindow != 45*time.Second {
		t.Fatalf("45s override not in effect: got %v", attached2)
	}
	attached2.Close()

	// helper negatives: unparseable, non-positive and empty overrides keep
	// the default.
	for _, raw := range []string{"nonsense", "-5s", "0s", "", "   "} {
		t.Setenv(stallWindowEnvironment, raw)
		if got := stallWindowFromEnv(); got != documented {
			t.Errorf("override %q: stall window = %s, want the documented default", raw, got)
		}
	}
}

func TestRunnerDiscoveryMultipleRunnersAndStableInstallIdentity(t *testing.T) {
	// create two distinct installations and two listener incarnations, then
	// rediscover one installation with a new PID to prove identity is not PID.
	roota := buildFakeRunner(t)
	rootb := buildFakeRunner(t)
	host := &fakeHost{
		table: []platform.Process{
			{PID: 501, PPID: 1, StartTicks: 10, Name: listenerName},
			{PID: 502, PPID: 1, StartTicks: 20, Name: listenerName},
		},
		exe: map[int]string{
			501: filepath.Join(roota, "bin", listenerName),
			502: filepath.Join(rootb, "bin", listenerName),
		},
		salt: []byte("0123456789abcdef0123456789abcdef"),
		now:  time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
	}
	discovered, err := Discover(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered) != 2 || discovered[0].Ref == discovered[1].Ref {
		t.Fatalf("multiple installs not distinguished: %+v", discovered)
	}
	stableref := discovered[0].Ref
	stableroot := host.exe[discovered[0].Supervisor.PID]
	stableroot = installRootFromExe(stableroot)
	host.table[0] = platform.Process{PID: 601, PPID: 1, StartTicks: 30, Name: listenerName}
	host.exe[601] = filepath.Join(stableroot, "bin", listenerName)
	host.table = host.table[:1]
	discovered, err = Discover(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered) != 1 || discovered[0].Ref != stableref || discovered[0].Supervisor.PID != 601 {
		t.Fatalf("runner identity changed across listener restart: %+v; prior ref=%s", discovered, stableref)
	}
}

func TestRunnerVersionUsesNumericOrdering(t *testing.T) {
	root := t.TempDir()
	for _, version := range []string{"2.99.0", "2.100.0", "2.09.12"} {
		if err := os.Mkdir(filepath.Join(root, version), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, source, err := runnerVersion(root)
	if err != nil {
		t.Fatal(err)
	}
	if source != evidence.SourceRunnerConfig {
		t.Fatalf("version source = %s, want RUNNER_CONFIG", source)
	}
	if got != "2.100.0" {
		t.Fatalf("runnerVersion = %q, want highest numeric version 2.100.0", got)
	}
}

func TestRunnerVersionLogFallbackPreservesSource(t *testing.T) {
	root := buildFakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Runner.Listener version 2.321.4")
	version, source, err := runnerVersion(root)
	if err != nil {
		t.Fatal(err)
	}
	if version != "2.321.4" || source != evidence.SourceRunnerLog {
		t.Fatalf("version/source = %q/%s, want 2.321.4/RUNNER_LOG", version, source)
	}
}

func TestProviderConformance(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	s := attachSession(t, host)
	s.Observe(context.Background(), snapshotAt(host, base, 0))
	s.Observe(context.Background(), snapshotAt(host, base.Add(time.Second), 5))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	providertest.Run(t, GitHubProvider{}, []providertest.Fixture{
		{Name: "fake-runner", Section: section, Incident: nil},
	})
}

func hasCode(codes []string, want string) bool {
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}

var _ = strconv.Itoa

// TestSessionAssignmentOnBoundWorkerKeepsWorkerRef: a second assignment that
// lands in an already-bound worker's window must reuse the worker ref and job
// ref, never store the job ref as the worker.
func TestSessionAssignmentOnBoundWorkerKeepsWorkerRef(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message",
		"2026-10-28 12:00:02.200 +00:00 [RUNNER 1] Received job message")
	s := attachSession(t, host)

	s.Observe(context.Background(), snapshotAt(host, base, 0))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var bound evidence.Worker
	for _, worker := range section.Workers {
		if worker.Job != "" {
			bound = worker
		}
	}
	if bound.Ref == "" || bound.Job == "" {
		t.Fatalf("no bound worker in section: %+v", section.Workers)
	}
	if bound.Job == bound.Ref {
		t.Fatal("job ref stored as worker ref")
	}
	for _, event := range section.Events {
		if event.Type == EventJobAssigned && event.Worker != "" && event.Worker == event.Job {
			t.Fatalf("assigned event carries job ref as worker: %+v", event)
		}
	}
	_ = s.Close()
}

// TestSessionAssignmentBindsWhenWorkerSampledLate: on a real runner the worker
// starts about a second after the "job request … received" record, but the
// first sample that sees it can land several seconds later. the worker must
// bind on its real start time, not on the sample time, or the assignment stays
// unbound (GITHUB_JOB_ASSIGNED worker="" on a healthy job).
func TestSessionAssignmentBindsWhenWorkerSampledLate(t *testing.T) {
	host, root, base := fakeRunner(t,
		"[2026-10-28 12:00:02Z INFO JobDispatcher] Job request 0 for plan 484b job eeb5 received.")
	host.table = append(host.table,
		platform.Process{PID: 201, PPID: procListener, StartTicks: 21, Name: "Runner.Worker", State: "S"})
	host.exe[201] = filepath.Join(root, "bin", "Runner.Worker")
	host.starts = map[int]time.Time{201: base.Add(2 * time.Second)}
	s := attachSession(t, host)

	// the worker started at 12:00:03 (1 s after the record) but is first
	// sampled at 12:00:07.
	s.Observe(context.Background(), snapshotAt(host, base.Add(6*time.Second), 0))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var bound bool
	for _, event := range section.Events {
		if event.Type == EventJobAssigned && event.Worker != "" && event.Job != "" {
			bound = true
		}
	}
	if !bound {
		t.Fatalf("assignment unbound although the worker started 1 s after the record: %+v", section.Events)
	}
	_ = s.Close()
}

// TestSessionControlChannelRequiresConsecutiveSamples: C12.3 needs three
// consecutive samples. A socket absent from one sample must restart the count,
// so a gapped socket is not reported as long-lived.
func TestSessionControlChannelRequiresConsecutiveSamples(t *testing.T) {
	channel := collector.ConnectionSnapshot{
		LocalAddr: "10.0.0.7", LocalPort: 52000, RemoteAddr: "140.82.121.3",
		RemotePort: 443, State: "ESTABLISHED", Inode: 9,
		PID: procListener, StartTicks: ticksListener, FD: 5,
	}
	host, _, base := fakeRunner(t, "2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs")
	s := attachSession(t, host)
	// present in samples 0, 1 and 3; absent in sample 2.
	for step, present := range []bool{true, true, false, true} {
		snap := snapshotAt(host, base.Add(time.Duration(step)*time.Second), 0)
		if present {
			snap.Connections = []collector.ConnectionSnapshot{channel}
		}
		s.Observe(context.Background(), snap)
	}
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range section.SocketRoles {
		if role.Role == SocketRoleControlChannel {
			t.Fatalf("gapped socket classified as long-lived control channel: %+v", role)
		}
	}
	_ = s.Close()
}
