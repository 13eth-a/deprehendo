// the live github session: one session tracks runner, supervisor, worker and
// job-tree state across recorder snapshots and freezes it into an evidence
// section. the correlation invariants live in docs/providers/architecture.md
// §6 (C1–C12); each function below names the invariants it implements.
package github

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
)

// GitHubProvider implements provider.Provider for GitHub actions runners.
type GitHubProvider struct{}

// name implements provider.Provider.
func (GitHubProvider) Name() string { return Name }

// vocabulary implements provider.Provider.
func (GitHubProvider) Vocabulary() evidence.Vocabulary { return Vocabulary() }

// detect implements provider.Provider.
func (p GitHubProvider) Detect(ctx context.Context, host provider.HostView) (provider.Detection, error) {
	return Detect(ctx, host)
}

// discover implements provider.Provider.
func (p GitHubProvider) Discover(ctx context.Context, host provider.HostView) ([]provider.RunnerInstance, error) {
	return Discover(ctx, host)
}

// attach implements provider.Provider.
func (p GitHubProvider) Attach(ctx context.Context, host provider.HostView, opts provider.AttachOptions) (provider.Session, error) {
	return newSession(ctx, host, opts)
}

// interpret implements provider.Provider (interpret.go).
func (p GitHubProvider) Interpret(section evidence.Section, inc *incident.Incident) (provider.Interpretation, error) {
	return interpret(section, inc)
}

// stallWindow is the default C11 / 5.18 progress-stall window: a worker
// with no job-tree progress and no runner-side job activity for this long
// is stalled. A single-process compile is never stalled: CPU deltas are
// progress. it is a default, not a constant (phase 5 gap G4): a long-
// lasting sleep-heavy step cannot be told apart from a stall at any one
// fixed window, so the session reads DEPREHENDO_GITHUB_STALL_WINDOW (a go
// duration, e.g. 45s); 5.18 must not be enabled by default before this
// knob exists.
const defaultStallWindow = 2 * time.Minute

// stallWindowEnvironment names the G4 override of the C11 progress window.
const stallWindowEnvironment = "DEPREHENDO_GITHUB_STALL_WINDOW"

// minStallWindow is the smallest accepted override (audit F3): a window of a
// few samples turns every quiet sample into a C11 progress stall. A shorter
// value keeps the default.
const minStallWindow = 10 * time.Second

// stallWindowFromEnv returns the configured C11 progress-stall window: the
// DEPREHENDO_GITHUB_STALL_WINDOW override when it parses as a positive go
// duration, the default otherwise. an unparseable or non-positive override
// keeps the default, so a misconfigured environment can change the knob's
// value but never disable progress detection (the audit's G4: a fixed
// window cannot separate a sleep-heavy step from a stall).
func stallWindowFromEnv() time.Duration {
	raw, ok := os.LookupEnv(stallWindowEnvironment)
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultStallWindow
	}
	if d, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil && d >= minStallWindow {
		return d
	}
	return defaultStallWindow
}

// jobBindingTolerance is the ±2 s window of C6.
const jobBindingTolerance = 2 * time.Second

type runnerState struct {
	ref         evidence.Ref
	instance    provider.RunnerInstance
	install     *githubInstall
	supervisors []evidence.ProcessRef // incarnations, oldest first (C9)
}

type workerState struct {
	proc      evidence.ProcessRef // the incarnation (C1): PID + start ticks
	ppid      int
	ref       evidence.Ref // worker identity, salt-derived (C1)
	runner    evidence.Ref // empty: candidate not yet bound (C3)
	job       evidence.Ref // bound job (C6); empty = unknown/unbound
	jobKnown  bool
	viaParent bool // the C3 (b) parent-is-supervisor fact, recorded once
	started   time.Time
	exited    bool
	exitedAt  time.Time // first sample the incarnation was absent (R10)
}

type jobTreeEntry struct {
	worker    evidence.ProcessRef // owning worker incarnation
	role      evidence.Role       // JOB_ROOT or JOB_PROCESS
	firstSeen time.Time
	// container (5.33): membership was established through the cgroup
	// linkage rule, not the PPID lineage; witness is the in-tree docker
	// client that pins the container step to this job.
	container bool
	witness   evidence.ProcessRef
}

type sampleProvenance struct {
	at    time.Time
	index int
}

// pendingBinding is an assignment record that had no worker to bind when it
// was read. the runner logs the assignment milliseconds before Runner.Worker
// exists, so a sample can see the log first and the worker in the next one;
// the binding is retried while the C6 window still allows it (never guessed).
type pendingBinding struct {
	runner   evidence.Ref
	received time.Time
	file     int
	offset   int64
}

// session implements provider.Session. the supervisor calls Observe/Freeze/
// close from a single goroutine, so those need no locking. questions to the
// host are cheap and answered once per process incarnation.
type session struct {
	host        provider.HostView
	opts        provider.AttachOptions
	budget      provider.Budget
	stallWindow time.Duration // C11 progress window; default 2 min, G4 env override

	runners     map[evidence.Ref]*runnerState
	roots       map[string]evidence.Ref              // install root → runner ref
	supervisors map[evidence.ProcessRef]evidence.Ref // incarnation → runner ref
	// overrideOnly marks supervisors tagged through --github-runner-pids whose
	// executable/layout could not be verified: C2 MEDIUM, USER_OVERRIDE.
	overrideOnly map[evidence.ProcessRef]bool
	workers      map[evidence.ProcessRef]*workerState
	jobTree      map[evidence.ProcessRef]*jobTreeEntry // sticky membership (C4)
	// orphanNoted: job-tree members already reported as surviving their
	// worker (5.24), so each survivor yields one event.
	orphanNoted map[evidence.ProcessRef]bool

	inspectCache map[evidence.ProcessRef]*provider.ProcessDetail
	// container linkage (5.33): docker client incarnations recorded as the
	// witness of container membership, client → owning worker incarnation,
	// plus whether any sample ever carried a cgroup identity for its
	// process list at all.
	dockerClients map[evidence.ProcessRef]evidence.ProcessRef
	// containerUnverified: workers alive when a docker container step was
	// seen that could not be attributed to one job (audit F2). their jobs'
	// process lists may be incomplete and say so.
	containerUnverified map[evidence.ProcessRef]bool
	cgroupSeen          bool

	// Control-channel tracking (C12): per-inode socket state, plus the
	// per-runner facts the communication-stall rule needs (a channel once
	// qualified; the stall episode already reported).
	channels       map[uint64]*channelTrack
	channelRunners map[evidence.Ref]bool
	noteStalled    map[evidence.Ref]bool
	// stallEpisodes: onset and end of each communication-stall episode, so
	// a capture window that starts mid-episode keeps its onset (commstall.go).
	stallEpisodes []stallEpisode

	events    []evidence.Event
	conflicts []evidence.Conflict
	pending   []pendingBinding

	// C11 progress clocks: last process-side job-tree progress per worker
	// ref, last runner-side job activity per runner ref, and the previous
	// alive job-tree member count per worker incarnation.
	lastProgress map[evidence.Ref]time.Time
	lastSide     map[evidence.Ref]time.Time
	prevAlive    map[evidence.ProcessRef]int
	stalled      map[evidence.Ref]bool // one emission per stall episode

	tails map[evidence.Ref]*logTail // per runner install root

	rotated   bool
	logBroken bool
	dropped   int

	prev    map[evidence.ProcessRef]collector.ProcessSnapshot
	samples []sampleProvenance
	at      time.Time
}

func newSession(ctx context.Context, host provider.HostView, opts provider.AttachOptions) (*session, error) {
	s := &session{
		host: host, opts: opts,
		budget:              opts.Budget,
		runners:             map[evidence.Ref]*runnerState{},
		roots:               map[string]evidence.Ref{},
		supervisors:         map[evidence.ProcessRef]evidence.Ref{},
		overrideOnly:        map[evidence.ProcessRef]bool{},
		workers:             map[evidence.ProcessRef]*workerState{},
		jobTree:             map[evidence.ProcessRef]*jobTreeEntry{},
		orphanNoted:         map[evidence.ProcessRef]bool{},
		inspectCache:        map[evidence.ProcessRef]*provider.ProcessDetail{},
		dockerClients:       map[evidence.ProcessRef]evidence.ProcessRef{},
		containerUnverified: map[evidence.ProcessRef]bool{},
		channels:            map[uint64]*channelTrack{},
		channelRunners:      map[evidence.Ref]bool{},
		noteStalled:         map[evidence.Ref]bool{},
		lastProgress:        map[evidence.Ref]time.Time{},
		lastSide:            map[evidence.Ref]time.Time{},
		prevAlive:           map[evidence.ProcessRef]int{},
		stalled:             map[evidence.Ref]bool{},
		tails:               map[evidence.Ref]*logTail{},
		prev:                map[evidence.ProcessRef]collector.ProcessSnapshot{},
		stallWindow:         stallWindowFromEnv(),
	}
	if s.budget.MaxLogBytesPerSecond <= 0 || s.budget.MaxTrackedProcesses <= 0 || s.budget.MaxRetainedLogBytes <= 0 {
		s.budget = provider.DefaultBudget()
	}
	runners := opts.Runners
	if len(runners) == 0 {
		discovered, err := Discover(ctx, host)
		if err == nil {
			runners = discovered
		}
		// A discovery failure is not fatal: overrides and any supervisor
		// observed later still classify through Observe.
	}
	for _, inst := range runners {
		s.enroll(inst)
	}
	s.applyOverrides(ctx, opts.SupervisorPIDs)
	return s, nil
}

// enroll adds a runner and opens its diagnostic-log tail. identity is ref,
// never a PID (C1).
func (s *session) enroll(inst provider.RunnerInstance) {
	if inst.Ref == "" || s.runners[inst.Ref] != nil {
		return
	}
	st := &runnerState{ref: inst.Ref, instance: inst}
	if install, ok := inst.Private.(*githubInstall); ok && install != nil {
		st.install = install
		s.roots[install.root] = inst.Ref
		if install.root != "" {
			s.tails[inst.Ref] = newLogTail(filepath.Join(install.root, runnerDiagDir))
		}
	}
	s.runners[inst.Ref] = st
}

// runForInstall resolves the runner for an install root, enrolling an
// install nobody discovered yet (e.g. a supervisor observed after attach).
// name may be UNKNOWN; the root alone is identity (5.3, C10).
func (s *session) runForInstall(root string) evidence.Ref {
	if root == "" {
		return ""
	}
	if ref, ok := s.roots[root]; ok {
		return ref
	}
	install := githubInstall{root: root}
	if cfg, err := readRunnerConfig(root); err == nil {
		install.cfg = cfg
		install.ConfigGood = true
	}
	if version, source, err := runnerVersion(root); err == nil {
		install.version, install.versionSource = version, source
	}
	ref, err := evidence.NewRef("rnr", s.host.Salt(), filepath.Clean(root), install.cfg.AgentName)
	if err != nil || ref == "" {
		return ""
	}
	name := evidence.UnknownText(evidence.ClassRunnerName)
	if install.cfg.AgentName != "" {
		name = evidence.KnownText(evidence.ClassRunnerName, install.cfg.AgentName, evidence.SourceRunnerConfig)
	}
	version := evidence.UnknownText(evidence.ClassVersion)
	if install.version != "" {
		version = evidence.KnownText(evidence.ClassVersion, install.version, install.versionSource)
	}
	lifecycle := evidence.LifecycleUnknown
	switch {
	case install.ConfigGood && install.cfg.Ephemeral:
		lifecycle = evidence.LifecycleEphemeral
	case install.ConfigGood:
		lifecycle = evidence.LifecyclePersistent
	}
	inst := provider.RunnerInstance{Provider: Name, Ref: ref, Name: name, Version: version, Lifecycle: lifecycle}
	s.roots[root] = ref
	s.tails[ref] = newLogTail(filepath.Join(root, runnerDiagDir))
	s.runners[ref] = &runnerState{ref: ref, instance: inst, install: &install}
	return ref
}

// applyOverrides implements the manual override (5.2, C2 alternative): a
// listener comm match plus the flag tags RUNNER_SUPERVISOR at MEDIUM with
// USER_OVERRIDE evidence. without the name match the override does nothing:
// it never creates a supervisor out of a non-listener.
func (s *session) applyOverrides(ctx context.Context, pids []int) {
	for _, pid := range pids {
		procs, err := s.host.Processes(ctx)
		if err != nil {
			return
		}
		for _, proc := range procs {
			if proc.PID != pid || !procNameIs(proc.Name, listenerName) {
				continue
			}
			ref := evidence.ProcessRef{PID: proc.PID, StartTicks: proc.StartTicks}
			if _, tagged := s.supervisors[ref]; tagged {
				break
			}
			// resolve the install before tagging so the RUNNER_STARTED event
			// carries the identity it was tagged with; an unresolvable install
			// stays empty rather than being invented.
			var runner evidence.Ref
			verified := false
			if detail, err := s.host.Inspect(ctx, ref); err == nil {
				root := installRootFromExe(detail.Executable)
				runner = s.runForInstall(root)
				_, layout := installLayout(root)
				verified = runner != "" && layout &&
					strings.EqualFold(exeBasename(detail.Executable), listenerName)
			}
			if runner == "" {
				// no install root, so no runner identity (C1: never a PID).
				// tagging it would name a runner the section cannot hold
				// (audit R12b: that invalidated the whole section).
				break
			}
			if verified {
				// the override named a process that also passes C2's two
				// facts: it is tagged exactly as discovery would tag it.
				s.tagSupervisor(ref, runner, evidence.SourceLocalProcess,
					EvidenceExeBaseNameMatch, EvidenceInstallLayoutMatch)
				break
			}
			s.overrideOnly[ref] = true
			s.tagSupervisor(ref, runner, evidence.SourceUserOverride, EvidenceUserOverride)
			break
		}
	}
}

// observe consumes one recorder snapshot (provider.Session).
func (s *session) Observe(ctx context.Context, snap collector.Snapshot) {
	at := snap.Timestamp
	if at.IsZero() {
		at = s.host.Now()
	}
	if s.at.IsZero() || at.After(s.at) {
		s.at = at
	}
	if snap.CaptureIndex > 0 {
		s.samples = append(s.samples, sampleProvenance{at: at, index: snap.CaptureIndex})
	}
	current := mapSample(snap.Processes)

	// 5.33 bookkeeping: a sample that carried at least one cgroup identity
	// proves container membership was checkable in principle for that
	// sample's population; a capture without any such identity never
	// verified it.
	for i := range snap.Processes {
		if path := cgroupPathOf(snap.Processes[i]); path != "" {
			s.cgroupSeen = true
			break
		}
	}

	s.observeSupervisors(ctx, current, at)
	workersbefore := len(s.workers)
	s.observeWorkers(ctx, current, at)
	if len(s.workers) > workersbefore {
		// A new worker is the only thing that can resolve an assignment that
		// arrived before its worker did.
		s.resolvePendingBindings(at)
	}
	s.observeJobTree(ctx, current, at)
	s.observeSockets(snap.Connections, at)
	s.observeLogs(at)
	s.observeProgress(current, at)
	s.observeExits(current, at)
	s.observeOrphans(current, at)

	s.observeCommunication(current, at)
	s.prev = current
}

func mapSample(procs []collector.ProcessSnapshot) map[evidence.ProcessRef]collector.ProcessSnapshot {
	out := make(map[evidence.ProcessRef]collector.ProcessSnapshot, len(procs))
	for _, proc := range procs {
		ref := evidence.ProcessRef{PID: proc.PID, StartTicks: proc.StartTicks}
		out[ref] = proc
	}
	return out
}

// observeSupervisors: C2 verification and C9 restart bookkeeping. only new
// incarnations reach the two-fact path; supervision is rare by design.
func (s *session) observeSupervisors(ctx context.Context, current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	procs, err := s.host.Processes(ctx)
	if err != nil {
		return // the sample stands alone; supervisor state is unchanged
	}
	for _, proc := range procs {
		if !procNameIs(proc.Name, listenerName) {
			continue
		}
		ref := evidence.ProcessRef{PID: proc.PID, StartTicks: proc.StartTicks}
		if _, tagged := s.supervisors[ref]; tagged {
			continue
		}
		detail, ok := s.inspect(ctx, ref)
		if !ok {
			continue // incarnation died mid-check: not reportable
		}
		root := installRootFromExe(detail.Executable)
		exeok := strings.EqualFold(exeBasename(detail.Executable), listenerName)
		_, layout := installLayout(root)
		if !exeok || root == "" || !layout {
			continue // name-only candidate: discover reported it; never tagged (C2)
		}
		runner := s.runForInstall(root)
		if runner == "" {
			continue // cannot derive identity without the salt (§3.2)
		}
		// C9: a new incarnation of a known runner is appended to the same
		// runner's supervisors; tagSupervisor records its single
		// RUNNER_STARTED (the earlier incarnation's exit is the matching
		// RUNNER_STOPPED). audit R11: this used to emit a second start.
		s.tagSupervisor(ref, runner, evidence.SourceLocalProcess,
			EvidenceExeBaseNameMatch, EvidenceInstallLayoutMatch)
	}
}

// tagSupervisor enroll an incarnation and records its start.
func (s *session) tagSupervisor(ref evidence.ProcessRef, runner evidence.Ref, src evidence.Source, codes ...string) {
	s.supervisors[ref] = runner
	if st := s.runners[runner]; st != nil && !containsRef(st.supervisors, ref) {
		st.supervisors = append(st.supervisors, ref)
	}
	s.events = append(s.events, evidence.Event{
		Timestamp: s.now(), Type: EventRunnerStarted, Runner: runner,
		Process: refPtr(ref), Source: src,
	})
}

// observeWorkers: C3 classification. executable basename must verify; the
// parent decides confidence and binding.
func (s *session) observeWorkers(ctx context.Context, current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	for ref, proc := range current {
		if !procNameIs(proc.Name, workerName) {
			continue
		}
		if _, known := s.workers[ref]; known {
			continue
		}
		detail, ok := s.inspect(ctx, ref)
		if !ok || !strings.EqualFold(exeBasename(detail.Executable), workerName) {
			continue // comm-only worker: a candidate, never tagged (C2 logic)
		}
		if len(s.workers) >= s.budget.MaxTrackedProcesses {
			s.dropped++
			return
		}
		st := &workerState{proc: ref, ppid: proc.PPID, started: at}
		if start, ok := workerStartTime(s.host, proc.Process); ok {
			// the real start, not the first sample: a worker is often first
			// seen seconds after it started, and binding must not drift with
			// the sampling cadence.
			st.started = start
		}
		if parentref, ok := s.lookupParent(current, proc.PPID); ok {
			if runnerref, issupervisor := s.supervisors[parentref]; issupervisor && parentref.StartTicks <= ref.StartTicks {
				// C3 (b): parent is a tagged supervisor incarnation.
				st.runner = runnerref
				st.viaParent = true
			}
		}
		if st.runner == "" {
			// reparented before first observation (or parent unknown):
			// C3 binds through the install root of the executable.
			st.runner = s.runForInstall(installRootFromExe(detail.Executable))
		}
		if st.runner == "" {
			continue // runner identity needs the salt (§3.2)
		}
		refid, err := evidence.NewRef("wkr", s.host.Salt(), workerRefKey(st.runner, ref))
		if err != nil || refid == "" {
			s.dropped++
			continue
		}
		st.ref = refid
		s.workers[ref] = st
		s.prevAlive[ref] = 0
		s.lastProgress[st.ref] = at
		s.events = append(s.events, evidence.Event{
			Timestamp: at, Type: EventWorkerStarted, Runner: st.runner, Worker: st.ref,
			Process: refPtr(ref), Source: evidence.SourceLocalProcess,
		})
	}
}

// observeJobTree: C4 sticky, first-observation membership. session and PGID
// equality are never consulted; only the PPID lineage recorded in this very
// sample is, with every ancestor verified by its incarnation record.
func (s *session) observeJobTree(ctx context.Context, current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	for ref, proc := range current {
		if _, known := s.jobTree[ref]; known {
			continue
		}
		if _, isworker := s.workers[ref]; isworker {
			continue
		}
		if _, issup := s.supervisors[ref]; issup {
			continue
		}
		walk := ref
		for depth := 0; depth < 32; depth++ {
			parentref, ok := s.lookupParent(current, current[walk].PPID)
			if !ok {
				break // lineage unverifiable where it is not recorded
			}
			if _, parentisworker := s.workers[parentref]; parentisworker {
				if len(s.jobTree) >= s.budget.MaxTrackedProcesses {
					s.dropped++
					return
				}
				role := evidence.RoleJobProcess
				if !s.workerHasChild(parentref) {
					role = evidence.RoleJobRoot
				}
				s.jobTree[ref] = &jobTreeEntry{worker: parentref, role: role, firstSeen: at}
				s.touchProgress(parentref, at)
				break
			}
			walk = parentref
		}
		_ = proc
	}
	s.observeContainerMembership(ctx, current, at)
}

// observeContainerMembership implements C5 / 5.33. two facts together tag a
// container step into a worker's job tree:
//
//  1. a docker client (executable basename verified, like every role) is a
//     PPID-lineage member of that worker's job tree. the job drives docker;
//  2. a sampled process lives in a docker-created container cgroup
//     (docker-<64 hex>.scope or docker/<64 hex>), whose process table does
//     not carry the job tree's PPID lineage (containers are children of
//     dockerd/containerd, not the worker).
//
// with exactly one live witnessed client the container step is that job's;
// several candidate jobs and the step stays untagged (never guessed). the
// worker must still be alive: membership inside a job tree is a fact about
// the worker's lifetime. unlinked membership stays unclaimed, and every
// job whose container relationship was not positively verified carries the
// CONTAINER_LINKAGE_UNAVAILABLE marker (jobRecord).
func (s *session) observeContainerMembership(ctx context.Context, current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	// pass 1: record verified docker clients already tagged as job-tree
	// members (C2 logic: the basename alone is a candidate, never the
	// witness).
	for ref, proc := range current {
		entry, known := s.jobTree[ref]
		if !known || entry.container {
			continue
		}
		if _, noted := s.dockerClients[ref]; noted {
			continue
		}
		if !procNameIs(proc.Name, dockerClientName) {
			continue
		}
		detail, ok := s.inspect(ctx, ref)
		if !ok || !strings.EqualFold(exeBasename(detail.Executable), dockerClientName) {
			continue
		}
		s.dockerClients[ref] = entry.worker
	}
	// pass 2: link cgroup-identified container processes to the one job
	// their witnessed client pins. deterministic order: never choose from
	// map iteration.
	for _, ref := range sortedSnapshots(current) {
		proc := current[ref]
		if _, known := s.jobTree[ref]; known {
			continue
		}
		if _, isworker := s.workers[ref]; isworker {
			continue
		}
		if _, issup := s.supervisors[ref]; issup {
			continue
		}
		if !dockerContainerCgroup(cgroupPathOf(proc)) {
			continue
		}
		witness, worker := s.containerWitness(ref, at)
		if witness.PID == 0 {
			// zero or several candidate jobs: membership is not guessed, but
			// every job that could own this step must say its process list
			// may be incomplete (audit F2: it used to be silent whenever the
			// host had cgroup identity at all).
			for wref, st := range s.workers {
				if !st.exited {
					s.containerUnverified[wref] = true
				}
			}
			continue
		}
		if len(s.jobTree) >= s.budget.MaxTrackedProcesses {
			s.dropped++
			return
		}
		s.jobTree[ref] = &jobTreeEntry{
			worker: worker, role: evidence.RoleJobProcess,
			firstSeen: at, container: true, witness: witness,
		}
		s.touchProgress(worker, at)
	}
}

// containerWitness resolves the unique live witnessed client whose job the
// container step belongs to. zero value means the linkage is undecided:
// either no verified client is alive in a job tree, or several jobs are
// candidates and the membership is never guessed.
func (s *session) containerWitness(container evidence.ProcessRef, at time.Time) (evidence.ProcessRef, evidence.ProcessRef) {
	var found, worker evidence.ProcessRef
	picked := false
	for _, client := range sortRefs(dockerClientRefs(s.dockerClients)) {
		w, owns := s.dockerClients[client]
		if !owns {
			continue
		}
		if st := s.workers[w]; st == nil || st.exited {
			continue // membership is a fact about a live worker's lifetime
		}
		entry := s.jobTree[client]
		if entry == nil || at.Before(entry.firstSeen) {
			continue // the client was not yet observed when the step appeared
		}
		if picked && found != client && worker != w {
			return evidence.ProcessRef{}, evidence.ProcessRef{} // two candidate jobs
		}
		found, worker, picked = client, w, true
	}
	if !picked {
		return evidence.ProcessRef{}, evidence.ProcessRef{}
	}
	return found, worker
}

func dockerClientRefs(in map[evidence.ProcessRef]evidence.ProcessRef) []evidence.ProcessRef {
	out := make([]evidence.ProcessRef, 0, len(in))
	for ref := range in {
		out = append(out, ref)
	}
	return sortRefs(out)
}

// sortRefs orders process incarnations deterministically (PID, then start
// ticks), the same key stableRoles uses.
func sortRefs(refs []evidence.ProcessRef) []evidence.ProcessRef {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].PID != refs[j].PID {
			return refs[i].PID < refs[j].PID
		}
		return refs[i].StartTicks < refs[j].StartTicks
	})
	return refs
}

// dockerClientName is the verified-basename witness for container linkage
// (5.33): the job that drives docker runs the docker client in its tree.
const dockerClientName = "docker"

// dockerContainerCgroup reports whether a cgroup path was created by docker
// for one container: a docker-<64 hex>.scope unit (systemd) or a docker/<64
// hex> leaf (cgroupfs driver). anything else is not claimed as container
// membership.
var dockerContainerCgroupRe = regexp.MustCompile(`(^|/)docker[-/][0-9a-f]{64}(\.scope)?$`)

func dockerContainerCgroup(path string) bool {
	if path == "" {
		return false
	}
	return dockerContainerCgroupRe.MatchString(path)
}

// cgroupPathOf is the recorded cgroup identity of one sampled process;
// empty when the sample carried none (the platform does not provide cgroup
// telemetry, or the collector omitted it).
func cgroupPathOf(proc collector.ProcessSnapshot) string {
	if proc.Cgroup == nil {
		return ""
	}
	return proc.Cgroup.Path
}

func sortedSnapshots(in map[evidence.ProcessRef]collector.ProcessSnapshot) []evidence.ProcessRef {
	out := make([]evidence.ProcessRef, 0, len(in))
	for ref := range in {
		out = append(out, ref)
	}
	sortWorkers(out)
	return out
}

func (s *session) workerHasChild(worker evidence.ProcessRef) bool {
	for _, entry := range s.jobTree {
		if entry.worker == worker {
			return true
		}
	}
	return false
}

// lookupParent resolves a PPID to an incarnation record present in this
// sample (the incarnation key carries the parent's own start ticks, so a
// reused PID never fakes a link).
func (s *session) lookupParent(current map[evidence.ProcessRef]collector.ProcessSnapshot, ppid int) (evidence.ProcessRef, bool) {
	if ppid <= 0 {
		return evidence.ProcessRef{}, false
	}
	for ref, proc := range current {
		if proc.PID == ppid {
			return ref, true
		}
	}
	return evidence.ProcessRef{}, false
}

// ---- runner logs -----------------------------------------------------------

func (s *session) observeLogs(at time.Time) {
	for _, st := range sortedRunners(s.runners) {
		tail, ok := s.tails[st.ref]
		if !ok {
			continue
		}
		events, truncated, readable := tail.readPass(s.budget.MaxLogBytesPerSecond)
		if !readable {
			s.logBroken = true
			continue
		}
		if truncated {
			s.rotated = true
		}
		for _, ev := range events {
			s.ingestLogEvent(at, st.ref, ev)
		}
	}
}

func sortedRunners(in map[evidence.Ref]*runnerState) []*runnerState {
	out := make([]*runnerState, 0, len(in))
	for _, st := range in {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ref < out[j].ref })
	return out
}

// ingestLogEvent turns one parsed log record into a section event and, for
// job records, into C6 binding decisions. the text is long gone: only the
// type, timestamp and provenance survive parseLine (§9.1).
func (s *session) ingestLogEvent(at time.Time, runner evidence.Ref, ev logEvent) {
	timestamp := ev.Timestamp
	if timestamp.IsZero() {
		timestamp = at
	}
	record := evidence.Event{
		Timestamp: timestamp, Type: ev.Type, Runner: runner,
		Source: evidence.SourceRunnerLog, Provenance: ev.provenance(),
	}
	switch ev.Type {
	case EventJobAssigned:
		// C6 binds here, on the record itself, so the bundle carries one
		// assigned event with the worker and job it resolved to.
		record.Worker, record.Job = s.bindJob(runner, timestamp)
		if record.Worker == "" {
			provenance := ev.provenance()
			s.pending = append(s.pending, pendingBinding{
				runner: runner, received: timestamp,
				file: provenance.File, offset: provenance.Offset,
			})
		}
		s.noteSide(runner, timestamp)
	case EventJobAccepted, EventJobCompleted, EventJobCancellation, EventJobTimeout:
		// audit R6: a job-scoped record names its worker (and that worker's
		// job) when exactly one worker of this runner was alive at the
		// record's time. otherwise it stays runner-scoped: never guessed.
		if worker := s.workerAt(runner, timestamp); worker != nil {
			record.Worker = worker.ref
			if worker.jobKnown {
				record.Job = worker.job
			}
		}
		record.Outcome = ev.Outcome
		s.noteSide(runner, timestamp)
	}
	s.events = append(s.events, record)
	if len(s.events) > maxStoredEvents {
		s.events = s.events[len(s.events)-maxStoredEvents:]
	}
}

// workerAt returns the unique worker of runner whose lifetime covers t
// (±jobBindingTolerance, C7's ≥ 1 s attribution), or nil when none or
// several do.
func (s *session) workerAt(runner evidence.Ref, t time.Time) *workerState {
	var found *workerState
	for _, st := range s.workers {
		if st.runner != runner || st.started.IsZero() {
			continue
		}
		if st.started.After(t.Add(jobBindingTolerance)) {
			continue
		}
		if st.exited && st.exitedAt.Before(t.Add(-jobBindingTolerance)) {
			continue
		}
		if found != nil {
			return nil
		}
		found = st
	}
	return found
}

// noteSide advances C11's runner-side progress clock for a runner.
func (s *session) noteSide(runner evidence.Ref, at time.Time) {
	s.lastSide[runner] = at
}

// bindJob: C6. the job binds only when exactly one worker started within
// ±2 s of the received record; otherwise a JOB_BINDING conflict lists the
// candidates and the worker keeps no job ref. never pick the nearest.
// returns the bound worker and job refs (both empty when unbound).
func (s *session) bindJob(runner evidence.Ref, received time.Time) (evidence.Ref, evidence.Ref) {
	var matches []evidence.ProcessRef
	for ref, st := range s.workers {
		if st.runner != "" && st.runner != runner {
			continue
		}
		if st.started.IsZero() {
			continue
		}
		delta := st.started.Sub(received)
		if delta < -jobBindingTolerance || delta > jobBindingTolerance {
			continue
		}
		matches = append(matches, ref)
	}
	if len(matches) == 0 {
		return "", "" // no worker yet in the window: cannot bind (never guess)
	}
	if len(matches) > 1 {
		sortWorkers(matches)
		claims := make([]evidence.Claim, 0, len(matches))
		for range matches {
			claims = append(claims, evidence.Claim{
				Source: evidence.SourceDerived, Value: "ASSIGNED", ObservedAt: received,
			})
		}
		s.conflicts = append(s.conflicts, evidence.Conflict{
			Question: ConflictTopicJobBinding, Runner: runner, Claims: claims,
		})
		return "", ""
	}
	worker := s.workers[matches[0]]
	if worker.jobKnown {
		return worker.ref, worker.job
	}
	jobref, err := evidence.NewRef("job", s.host.Salt(), string(worker.ref))
	if err != nil || jobref == "" {
		return "", ""
	}
	worker.job, worker.jobKnown = jobref, true
	return worker.ref, jobref
}

// resolvePendingBindings retries assignments whose worker had not appeared
// yet. the window is C6's: once a new worker's first observation cannot fall
// inside ±2 s of the record, the assignment stays unbound for good.
func (s *session) resolvePendingBindings(at time.Time) {
	if len(s.pending) == 0 {
		return
	}
	kept := s.pending[:0]
	for _, pending := range s.pending {
		workerref, jobref := s.bindJob(pending.runner, pending.received)
		if workerref != "" {
			s.attachBinding(pending, workerref, jobref)
			continue
		}
		if at.Sub(pending.received) <= jobBindingTolerance {
			kept = append(kept, pending)
		}
	}
	s.pending = kept
}

// attachBinding writes a late-resolved binding into the stored assignment.
// the record is matched by its provenance, not by index: events are bounded
// and the oldest are dropped.
func (s *session) attachBinding(pending pendingBinding, workerRef, jobRef evidence.Ref) {
	for i := range s.events {
		event := &s.events[i]
		if event.Type != EventJobAssigned || event.Runner != pending.runner {
			continue
		}
		if event.Provenance.File != pending.file || event.Provenance.Offset != pending.offset {
			continue
		}
		event.Worker, event.Job = workerRef, jobRef
		return
	}
}

// ---- progress (C11 / 5.18) --------------------------------------------------

// observeProgress maintains per-worker progress clocks: any job-tree member
// with CPU progress, or a change in the alive job-tree member count, is
// process-side progress. Runner-side progress is job-related log activity.
func (s *session) observeProgress(current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	alive := make(map[evidence.ProcessRef]int, len(s.workers))
	for ref := range s.workers {
		alive[ref] = 0
	}
	for ref, entry := range s.jobTree {
		if _, present := current[ref]; present {
			alive[entry.worker]++
		}
	}
	for ref := range s.workers {
		progress := false
		for jref, entry := range s.jobTree {
			if entry.worker != ref {
				continue
			}
			if proc, ok := current[jref]; ok && proc.CPUPercent > 0 {
				progress = true
				break
			}
		}
		if alive[ref] != s.prevAlive[ref] {
			progress = true
		}
		if progress {
			s.touchProgress(ref, at)
		}
		if s.prevAlive[ref] > 0 && alive[ref] == 0 {
			if st := s.workers[ref]; st != nil && !st.exited {
				s.events = append(s.events, evidence.Event{
					Timestamp: at, Type: EventJobTreeEmptied, Runner: st.runner, Worker: st.ref,
					Job: st.job, Process: refPtr(ref), Source: evidence.SourceDerived,
				})
			}
		}
		s.prevAlive[ref] = alive[ref]
	}
	// emit at most one event per stall episode, and only when *both*
	// conditions hold over the same window (C11: one alone is LOW and is
	// not emitted).
	for ref, st := range s.workers {
		if st.exited || s.stalled[st.ref] {
			continue
		}
		lastproc, ok := s.lastProgress[st.ref]
		if !ok || at.Sub(lastproc) < s.stallWindow {
			continue
		}
		if st.runner != "" {
			if lastlog, ok := s.lastSide[st.runner]; ok && at.Sub(lastlog) < s.stallWindow {
				continue
			}
		}
		s.stalled[st.ref] = true
		s.events = append(s.events, evidence.Event{
			Timestamp: at, Type: EventJobProgressStopped, Runner: st.runner, Worker: st.ref,
			Process: refPtr(ref), Source: evidence.SourceDerived,
		})
	}
}

func (s *session) touchProgress(worker evidence.ProcessRef, at time.Time) {
	st := s.workers[worker]
	if st == nil {
		return
	}
	s.lastProgress[st.ref] = at
}

// ---- lifecycle transitions --------------------------------------------------

// observeExits turns presence→absence transitions into lifecycle events.
// an observation gap is the only exit evidence available to v1; the window
// edges may hide real exits, which freeze reports as outside its range.
func (s *session) observeExits(current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	for ref := range s.prev {
		if _, alive := current[ref]; alive {
			continue
		}
		if runnerref, issupervisor := s.supervisors[ref]; issupervisor {
			s.supervisorExited(runnerref, ref, at)
			continue
		}
		st, isworker := s.workers[ref]
		if !isworker || st.exited {
			continue
		}
		st.exited = true
		st.exitedAt = at
		s.events = append(s.events, evidence.Event{
			Timestamp: at, Type: EventWorkerExited, Runner: st.runner, Worker: st.ref,
			Process: refPtr(ref), Source: evidence.SourceLocalProcess,
		})
	}
}

// orphanGrace: how long a job-tree member may outlive its worker's exit
// before it is reported as orphaned (10.4 of architecture §10A.4).
const orphanGrace = 10 * time.Second

// observeOrphans records GITHUB_JOB_ORPHANED (5.24): a sticky job-tree member
// still alive at least orphanGrace after its worker incarnation exited. the
// survivor is named by refs only, never by command line or name.
func (s *session) observeOrphans(current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	for ref, entry := range s.jobTree {
		if s.orphanNoted[ref] {
			continue
		}
		if _, alive := current[ref]; !alive {
			continue
		}
		worker, ok := s.workers[entry.worker]
		if !ok || !worker.exited || at.Sub(worker.exitedAt) < orphanGrace {
			continue
		}
		s.orphanNoted[ref] = true
		s.events = append(s.events, evidence.Event{
			Timestamp: at, Type: EventJobOrphaned, Runner: worker.runner, Worker: worker.ref,
			Job: worker.job, Process: refPtr(ref), Source: evidence.SourceLocalProcess,
		})
	}
}

// supervisorExited records the runner's stopped event and, for an
// ephemeral runner whose job completed first, the EPHEMERAL_COMPLETE
// intended-termination fact (5.44: intent is never inferred from the exit
// itself. it requires the configured lifecycle plus a completed job).
func (s *session) supervisorExited(runner evidence.Ref, supervisor evidence.ProcessRef, at time.Time) {
	s.events = append(s.events, evidence.Event{
		Timestamp: at, Type: EventRunnerStopped, Runner: runner,
		Process: refPtr(supervisor), Source: evidence.SourceLocalProcess,
	})
	st := s.runners[runner]
	if st == nil || st.instance.Lifecycle != evidence.LifecycleEphemeral {
		return
	}
	// T1: configured EPHEMERAL, a job whose result was stated (any terminal
	// result: an ephemeral runner leaves after one job however it ended),
	// and the supervisor exit after that statement.
	for _, ref := range sortedWorkerStates(s.workers) {
		worker := s.workers[ref]
		if worker.runner != runner {
			continue
		}
		stated, at2 := s.statedOutcome(worker)
		if stated == evidence.OutcomeUnknown || stated == evidence.OutcomeRunning || at2.After(at) {
			continue
		}
		event := evidence.Event{
			Timestamp: at, Type: EventRunnerEphemeralComplete, Runner: runner, Worker: worker.ref,
			Source: evidence.SourceDerived,
		}
		if worker.jobKnown {
			event.Job = worker.job
		}
		s.events = append(s.events, event)
		return
	}
}

// observeCommunication emits GITHUB_COMMUNICATION_STALLED (5.20) once per
// episode: a runner whose control channel had qualified, whose supervisor is
// alive in this very sample, and which has held no supervisor-owned 443
// connection for longer than the re-establish window. the episode ends when
// a connection returns.
func (s *session) observeCommunication(current map[evidence.ProcessRef]collector.ProcessSnapshot, at time.Time) {
	alive := map[evidence.Ref]bool{}
	for ref, runner := range s.supervisors {
		if _, ok := current[ref]; ok && runner != "" {
			alive[runner] = true
		}
	}
	for _, runner := range s.communicationStalled(at, alive) {
		if s.noteStalled[runner] {
			continue
		}
		s.noteStalled[runner] = true
		s.openStallEpisode(runner, at)
		s.events = append(s.events, evidence.Event{
			Timestamp: at, Type: EventCommunicationStalled, Runner: runner,
			Source: evidence.SourceDerived,
		})
	}
}

// ---- live helpers ------------------------------------------------------------

// startTimer is an optional host capability: a host that can convert a
// process's start ticks to wall-clock time implements it. hosts without it
// (fixtures) fall back to the sample time.
type startTimer interface {
	StartTime(p platform.Process) (time.Time, bool)
}

func workerStartTime(host provider.HostView, proc platform.Process) (time.Time, bool) {
	if st, ok := host.(startTimer); ok {
		return st.StartTime(proc)
	}
	return time.Time{}, false
}

func (s *session) now() time.Time {
	if !s.at.IsZero() {
		return s.at
	}
	return s.host.Now()
}

// inspect resolves live process details once per incarnation. the cache is
// keyed by incarnation: a different start-ticks PID resolves again.
func (s *session) inspect(ctx context.Context, ref evidence.ProcessRef) (provider.ProcessDetail, bool) {
	if d, ok := s.inspectCache[ref]; ok {
		return *d, true
	}
	detail, err := s.host.Inspect(ctx, ref)
	if err != nil || detail.Executable == "" {
		return provider.ProcessDetail{}, false
	}
	s.inspectCache[ref] = &detail
	return detail, true
}

// ---- freeze -----------------------------------------------------------------

// freeze returns the section for the capture window (provider.Session).
// the section validates against the provider's vocabulary before it leaves.
func (s *session) Freeze(_ context.Context, from, to time.Time) (evidence.Section, error) {
	sec := evidence.Section{
		Provider: Name, SchemaVersion: evidence.SchemaVersion,
		Privacy: s.opts.Privacy, Health: s.health(),
		// F4: the C11 window in force, so a reader knows which window
		// produced a progress-stall event.
		StallWindowSeconds: int64(s.stallWindow / time.Second),
	}
	for _, st := range sortedRunners(s.runners) {
		sec.Runners = append(sec.Runners, s.runnerRecord(st))
	}
	sec.Workers, sec.Jobs = s.workerRecords()
	sec.ProcessRoles = s.processRoles()
	sec.SocketRoles = s.socketRoles(from, to)
	sec.Events = s.sectionEvents(from, to)
	for index := range sec.Events {
		if sec.Events[index].Source != evidence.SourceDerived || sec.Events[index].Provenance.Sample != 0 {
			continue
		}
		if sample := s.sampleFor(sec.Events[index].Timestamp); sample > 0 {
			sec.Events[index].Provenance.Sample = sample
		}
	}
	s.detectConflicts()
	sec.Conflicts = s.conflicts
	// the section leaves the session already redacted to the requested
	// privacy level (idempotent with the supervisor's later redact), so
	// validation checks what will actually be embedded.
	sec.Redact(s.opts.Privacy)
	sortSection(&sec)
	if err := sec.Validate(); err != nil {
		return sec, err
	}
	return sec, nil
}

func (s *session) health() evidence.Health {
	state := evidence.HealthAvailable
	var reasons []evidence.Reason
	if s.dropped > 0 {
		state = evidence.HealthDegraded
		reasons = append(reasons, evidence.ReasonBackpressure)
	}
	if s.logBroken {
		state = evidence.HealthDegraded
		reasons = append(reasons, evidence.ReasonLogUnreadable)
	}
	if s.rotated {
		state = evidence.HealthDegraded
		reasons = append(reasons, evidence.ReasonLogRotated)
	}
	if len(s.runners) == 0 && len(s.workers) == 0 && len(s.supervisors) == 0 {
		state = evidence.HealthUnavailable
		reasons = append(reasons, evidence.ReasonNotDetected)
	}
	return evidence.Health{State: state, Reasons: dedupeReasons(reasons), Dropped: s.dropped}
}

func dedupeReasons(in []evidence.Reason) []evidence.Reason {
	seen := map[evidence.Reason]bool{}
	out := make([]evidence.Reason, 0, len(in))
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func (s *session) runnerRecord(st *runnerState) evidence.Runner {
	return evidence.Runner{
		Ref:           st.ref,
		Name:          st.instance.Name,
		Version:       st.instance.Version,
		Labels:        evidence.UnknownText(evidence.ClassLabels),
		Lifecycle:     st.instance.Lifecycle,
		Containerized: st.instance.Containerized,
		Supervisors:   st.supervisors,
	}
}

func (s *session) workerRecords() ([]evidence.Worker, []evidence.Job) {
	refs := make([]evidence.Ref, 0, len(s.workers))
	byref := make(map[evidence.Ref]*workerState, len(s.workers))
	for _, st := range s.workers {
		refs = append(refs, st.ref)
		byref[st.ref] = st
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
	workers := make([]evidence.Worker, 0, len(refs))
	jobs := make([]evidence.Job, 0, len(refs))
	for _, ref := range refs {
		st := byref[ref]
		worker := evidence.Worker{
			Ref: ref, Runner: st.runner, Process: st.proc, Job: st.job, Started: st.started,
		}
		if st.exited {
			// audit R10: the observed exit, not the freeze time.
			worker.Exited = st.exitedAt
		}
		workers = append(workers, worker)
		if st.jobKnown {
			jobs = append(jobs, s.jobRecord(st))
		}
	}
	return workers, jobs
}

func (s *session) jobRecord(st *workerState) evidence.Job {
	job := evidence.Job{
		Ref:        st.job,
		Runner:     st.runner,
		Repository: evidence.UnknownText(evidence.ClassRepository),
		Workflow:   evidence.UnknownText(evidence.ClassWorkflow),
		Name:       evidence.UnknownText(evidence.ClassJobName),
		RunID:      evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID},
		JobID:      evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID},
		Attempt:    evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt},
		Outcome:    s.jobOutcome(st),
	}
	for _, ev := range s.events {
		if ev.Worker != st.ref || ev.Source == evidence.SourceDerived {
			continue
		}
		if ev.Type == EventJobCancellation || ev.Type == EventJobTimeout || ev.Type == EventJobCompleted {
			if ev.Timestamp.After(job.OutcomeObservedAt) {
				job.OutcomeSource, job.OutcomeObservedAt = ev.Source, ev.Timestamp
			}
		}
	}
	if job.Outcome == evidence.OutcomeUnknown {
		job.OutcomeSource, job.OutcomeObservedAt = "", time.Time{}
	}
	// 5.33 / C5: container membership is not fully verifiable. A job whose
	// process list was linked through cgroups states that; every other job
	// states honestly that its process list may be incomplete. container
	// membership could not be verified (this includes platforms with no
	// cgroup telemetry at all).
	linked, unverified := s.containerSteps(st.proc) > 0, !s.cgroupSeen || s.containerUnverified[st.proc]
	switch {
	case linked && unverified:
		job.Evidence = []string{EvidenceContainerCgroupLinkage, EvidenceContainerLinkageUnavailable}
	case linked:
		job.Evidence = []string{EvidenceContainerCgroupLinkage}
	case unverified:
		job.Evidence = []string{EvidenceContainerLinkageUnavailable}
	}
	return job
}

// containerSteps counts the container-linked members of one worker's job
// tree, the positive 5.33 verification behind CONTAINER_CGROUP_LINKAGE.
func (s *session) containerSteps(worker evidence.ProcessRef) int {
	n := 0
	for _, entry := range s.jobTree {
		if entry.container && entry.worker == worker {
			n++
		}
	}
	return n
}

// jobOutcome: 5.44–5.46. an evidence-checked record states the outcome;
// otherwise an exited worker leaves its job UNKNOWN; otherwise RUNNING.
func (s *session) jobOutcome(st *workerState) evidence.Outcome {
	if stated, _ := s.statedOutcome(st); stated != evidence.OutcomeUnknown {
		return stated
	}
	if st.exited {
		return evidence.OutcomeUnknown
	}
	return evidence.OutcomeRunning
}

// statedOutcome is the outcome a runner record states for the worker's job,
// with the time of the deciding record. A stated timeout outranks a stated
// cancellation (a timeout is carried out by cancelling), which outranks a
// plain result; UNKNOWN when nothing was stated.
func (s *session) statedOutcome(st *workerState) (evidence.Outcome, time.Time) {
	outcome, at, rank := evidence.OutcomeUnknown, time.Time{}, 0
	for _, ev := range s.events {
		if ev.Worker != st.ref {
			continue
		}
		candidate, candidaterank := evidence.OutcomeUnknown, 0
		switch ev.Type {
		case EventJobTimeout:
			candidate, candidaterank = evidence.OutcomeTimedOut, 3
		case EventJobCancellation:
			candidate, candidaterank = evidence.OutcomeCancelled, 2
		case EventJobCompleted:
			if ev.Outcome == evidence.OutcomeSucceeded || ev.Outcome == evidence.OutcomeFailed {
				candidate, candidaterank = ev.Outcome, 1
			}
		}
		if candidaterank > rank || (candidaterank == rank && candidaterank > 0 && ev.Timestamp.After(at)) {
			outcome, at, rank = candidate, ev.Timestamp, candidaterank
		}
	}
	return outcome, at
}

func sortedWorkerStates(in map[evidence.ProcessRef]*workerState) []evidence.ProcessRef {
	out := make([]evidence.ProcessRef, 0, len(in))
	for ref := range in {
		out = append(out, ref)
	}
	sortWorkers(out)
	return out
}

// processRoles renders every tagged incarnation, bounded and deterministic.
func (s *session) processRoles() []evidence.ProcessRole {
	out := make([]evidence.ProcessRole, 0, len(s.supervisors)+len(s.workers)+len(s.jobTree))
	for ref, runner := range s.supervisors {
		role := evidence.ProcessRole{
			Process: ref, Role: evidence.RoleSupervisor, Runner: runner,
			Confidence: evidence.ConfidenceHigh,
			Sources:    []evidence.Source{evidence.SourceLocalProcess},
			Evidence:   []string{EvidenceExeBaseNameMatch, EvidenceInstallLayoutMatch},
		}
		if s.overrideOnly[ref] {
			// C2 alternative: the user's word plus a name match is MEDIUM
			// (audit R12: it used to be reported as a verified HIGH).
			role.Confidence = evidence.ConfidenceMedium
			role.Sources = []evidence.Source{evidence.SourceUserOverride}
			role.Evidence = []string{EvidenceUserOverride}
		}
		out = append(out, role)
	}
	for ref, st := range s.workers {
		role := evidence.ProcessRole{
			Process: ref, Role: evidence.RoleWorker, Runner: st.runner, Worker: st.ref,
			Sources: []evidence.Source{evidence.SourceLocalProcess},
		}
		role.Evidence, role.Confidence = s.workerEvidence(st)
		out = append(out, role)
	}
	for ref, entry := range s.jobTree {
		role := evidence.ProcessRole{
			Process: ref, Role: entry.role,
			Runner:  s.workerRunner(entry.worker),
			Worker:  s.jobTreeWorkerRef(entry.worker),
			Sources: []evidence.Source{evidence.SourceLocalProcess},
		}
		if entry.container {
			// 5.33: membership through the cgroup-linkage rule, not PPID
			// lineage. MEDIUM: identity is typed (cgroup path + incarnation)
			// but the job tie rests on the witnessed docker client.
			role.Confidence = evidence.ConfidenceMedium
			role.Evidence = []string{EvidenceContainerCgroupLinkage}
		} else {
			role.Confidence = evidence.ConfidenceMedium
			role.Evidence = []string{EvidenceDescendantAtFirstSeen}
		}
		out = append(out, role)
	}
	stableRoles(out)
	if len(out) > s.budget.MaxTrackedProcesses {
		out = out[:s.budget.MaxTrackedProcesses]
	}
	return out
}

// workerEvidence keeps the C3 verdict recorded at classification time: a
// supervisor parent made it HIGH at PARENT_IS_SUPERVISOR, a missing parent
// left it MEDIUM at PARENT_GONE.
func (s *session) workerEvidence(st *workerState) ([]string, evidence.Confidence) {
	if st.viaParent {
		return []string{EvidenceExeBaseNameMatch, EvidenceParentIsSupervisor}, evidence.ConfidenceHigh
	}
	return []string{EvidenceExeBaseNameMatch, EvidenceParentGone}, evidence.ConfidenceMedium
}

func (s *session) workerRunner(worker evidence.ProcessRef) evidence.Ref {
	if st, ok := s.workers[worker]; ok {
		return st.runner
	}
	return ""
}

func (s *session) jobTreeWorkerRef(worker evidence.ProcessRef) evidence.Ref {
	if st, ok := s.workers[worker]; ok {
		return st.ref
	}
	return ""
}

func stableRoles(in []evidence.ProcessRole) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Process.PID != in[j].Process.PID {
			return in[i].Process.PID < in[j].Process.PID
		}
		return in[i].Process.StartTicks < in[j].Process.StartTicks
	})
}

func (s *session) sampleFor(at time.Time) int {
	var index int
	for _, sample := range s.samples {
		if !sample.at.After(at) && sample.index > index {
			index = sample.index
		}
	}
	return index
}

func (s *session) sectionEvents(from, to time.Time) []evidence.Event {
	out := make([]evidence.Event, 0, len(s.events))
	for _, event := range s.events {
		if event.Timestamp.IsZero() || event.Timestamp.After(to) {
			continue
		}
		// A communication-stall episode that began before the window and
		// was still open at its start keeps its onset (S10).
		if event.Timestamp.Before(from) && !(event.Type == EventCommunicationStalled && s.stallEpisodeReaches(event.Runner, event.Timestamp, from)) {
			continue
		}
		out = append(out, event)
	}
	stableEvents(out)
	if len(out) > maxStoredEvents {
		out = out[len(out)-maxStoredEvents:]
	}
	return out
}

// maxStoredEvents bounds the in-memory event backlog (5.49). the cap keeps
// the freshest side: an incident window is recent by construction.
const maxStoredEvents = 5000

func stableEvents(in []evidence.Event) {
	sort.Slice(in, func(i, j int) bool {
		if !in[i].Timestamp.Equal(in[j].Timestamp) {
			return in[i].Timestamp.Before(in[j].Timestamp)
		}
		if in[i].Type != in[j].Type {
			return in[i].Type < in[j].Type
		}
		return in[i].Provenance.Offset < in[j].Provenance.Offset
	})
}

// sortSection orders every list deterministically; output equality must not
// depend on map iteration order.
func sortSection(sec *evidence.Section) {
	sort.Slice(sec.Runners, func(i, j int) bool { return sec.Runners[i].Ref < sec.Runners[j].Ref })
	sort.Slice(sec.Workers, func(i, j int) bool { return sec.Workers[i].Ref < sec.Workers[j].Ref })
	sort.Slice(sec.Jobs, func(i, j int) bool { return sec.Jobs[i].Ref < sec.Jobs[j].Ref })
	stableRoles(sec.ProcessRoles)
	sort.Slice(sec.SocketRoles, func(i, j int) bool { return sec.SocketRoles[i].Inode < sec.SocketRoles[j].Inode })
	stableEvents(sec.Events)
	sort.Slice(sec.Conflicts, func(i, j int) bool {
		if sec.Conflicts[i].Question != sec.Conflicts[j].Question {
			return sec.Conflicts[i].Question < sec.Conflicts[j].Question
		}
		return sec.Conflicts[i].Runner < sec.Conflicts[j].Runner
	})
}

// close releases log tails (provider.Session).
func (s *session) Close() error {
	for _, tail := range s.tails {
		tail.close()
	}
	s.tails = map[evidence.Ref]*logTail{}
	return nil
}

// ---- deterministic helpers --------------------------------------------------

func refPtr(ref evidence.ProcessRef) *evidence.ProcessRef { return &ref }

func workerRefKey(runner evidence.Ref, proc evidence.ProcessRef) string {
	return string(runner) + "|" + strconv.Itoa(proc.PID) + "|" + strconv.FormatInt(proc.StartTicks, 10)
}

func sortWorkers(refs []evidence.ProcessRef) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].StartTicks < refs[j].StartTicks })
}

func containsRef(refs []evidence.ProcessRef, ref evidence.ProcessRef) bool {
	for _, r := range refs {
		if r == ref {
			return true
		}
	}
	return false
}
