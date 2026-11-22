package diagnosis

import (
	"math"
	"sort"
	"strconv"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// CoverageField names one recorder section whose availability the context
// tracks. missing sections must be reported as UNKNOWN by signatures, never
// FALSE; use coverage to keep that honest.
type CoverageField string

const (
	CoverProcesses   CoverageField = "processes"
	CoverConnections CoverageField = "connections"
	CoverSystem      CoverageField = "system"
	CoverPressure    CoverageField = "pressure"
	CoverCgroups     CoverageField = "cgroups"
)

// heavyCoverageLoss is the fraction of samples after which a section is
// considered unreliable: rules must weaken or refuse conclusions that depend
// on a section the recorder could not consistently provide (3.36).
const heavyCoverageLoss = 0.4

// PSI avg10 values are percentages of stalled wall-clock time (0..100), not
// 0..1 fractions. these are the v1 "meaningful contention" boundaries used
// for yes/no resource-stress context; individual signatures declare their own
// evidentiary thresholds on the same scale.
const (
	pressureSomeStressed = 10.0
	pressureFullStressed = 5.0
)

// identity is PID + start ticks. PID alone is never a process identity; the
// kernel can hand a recycled PID to a fresh process.
type identity struct {
	PID        int
	StartTicks int64
}

func (i identity) less(o identity) bool {
	if i.PID != o.PID {
		return i.PID < o.PID
	}
	return i.StartTicks < o.StartTicks
}

func isStoppedState(state string) bool {
	return len(state) > 0 && (state[0] == 'T' || state[0] == 't')
}

func isAliveState(state string) bool {
	return len(state) > 0 && state[0] != 'X' && state[0] != 'Z' && !isStoppedState(state)
}

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// CollectorCoverage describes how consistently a section was captured.
type CollectorCoverage struct {
	Samples      int     `json:"samples"`
	Available    int     `json:"available"`
	FractionLost float64 `json:"fraction_lost"` // 0..1; 0 with no samples
}

// HeavyLoss reports whether the section was missing for enough samples that
// conclusions depending on it must be weakened or refused.
func (c CollectorCoverage) HeavyLoss() bool {
	return c.Samples > 0 && c.FractionLost >= heavyCoverageLoss
}

// sample is one normalized snapshot plus which sections were usable.
type sample struct {
	At          time.Time
	System      *collector.SystemSnapshot
	Pressure    map[platform.Resource]platform.PressureSnapshot
	Processes   []collector.ProcessSnapshot
	Connections []collector.ConnectionSnapshot
	Available   map[CoverageField]bool
}

// sectionOK applies the same conservative rule as the incident differ: an
// error report from the collector overrides optimistic presence, and a
// metrics entry flagged as an error counts as failed.
func sectionOK(s collector.Snapshot, name string) bool {
	seen := false
	for _, m := range s.Metrics {
		if m.Name == name {
			seen = true
			if m.Error {
				return false
			}
		}
	}
	for _, e := range s.Errors {
		if e.Collector == name {
			return false
		}
	}
	if seen {
		return true
	}
	// legacy bundles may not include per-cycle metrics. A populated section
	// can prove the collector ran; an empty absent section cannot.
	switch name {
	case "system":
		return s.System != nil
	case "processes":
		return len(s.Processes) > 0 || (s.System != nil && s.System.ProcessCountAvailable)
	case "connections":
		return len(s.Connections) > 0
	case "pressure":
		return len(s.Pressure) > 0
	case "cgroups":
		if s.Cgroup != nil {
			return true
		}
		for _, p := range s.Processes {
			if p.Cgroup != nil {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func newSample(s collector.Snapshot) sample {
	sm := sample{
		At:          s.Timestamp,
		System:      s.System,
		Pressure:    s.Pressure,
		Processes:   s.Processes,
		Connections: s.Connections,
		Available:   map[CoverageField]bool{},
	}
	if sectionOK(s, "system") && s.System != nil {
		sm.Available[CoverSystem] = true
	}
	if sectionOK(s, "processes") {
		sm.Available[CoverProcesses] = true
	}
	if sectionOK(s, "connections") {
		sm.Available[CoverConnections] = true
	}
	if sectionOK(s, "pressure") {
		sm.Available[CoverPressure] = true
	}
	if sectionOK(s, "cgroups") {
		sm.Available[CoverCgroups] = true
	}
	return sm
}

type memorySample struct {
	index   int
	At      time.Time
	Percent float64 // host memory used, percent of total
}

type diskSample struct {
	index     int
	At        time.Time
	Percent   float64 // percent free
	InodeFree float64 // free inode fraction 0..1; -1 when unavailable
}

type pressureSample struct {
	At               time.Time
	Some, Full       float64 // avg10 values
	SomeHas, FullHas bool
}

func pressValue(s pressureSample, full bool) float64 {
	if full {
		return s.Full
	}
	return s.Some
}

func pressHas(s pressureSample, full bool) bool {
	if full {
		return s.FullHas
	}
	return s.SomeHas
}

// processGap is one observed absence across adjacent usable process
// sections. factual only: no cause, no expected/unexpected distinction.
type processGap struct {
	From         time.Time // first sample where the identity was absent
	NextObserved time.Time // zero while the identity stayed absent
	Identity     identity
}

// end reports the exclusive end of the gap: the closer of the reappearance
// and the capture end. absences without a reappearance end at the last
// capture sample.
func (g processGap) End(end time.Time) time.Time {
	if !g.NextObserved.IsZero() && g.NextObserved.Before(end) {
		return g.NextObserved
	}
	return end
}

func (g processGap) Closed() bool { return !g.NextObserved.IsZero() }

type stateChange struct {
	At       time.Time
	From, To string
}

type processStoppedEpisode struct {
	From, To time.Time
	// StillStopped is true when the identity was observed in a stopped state
	// at the last sample containing it.
	StillStopped bool
	Resumed      bool
}

// span reports the observed stopped span, extending an open episode to the
// capture end.
func (e processStoppedEpisode) Span(end time.Time) time.Duration {
	if e.To.Before(e.From) {
		return 0
	}
	return e.To.Sub(e.From)
}

// ProcessLifetime is every observation of one process identity, in capture
// order (3.4/3.5): lifetime bounds, state transitions, parent changes, CPU
// and RSS series. all conclusions stay factual; signatures interpret.
type ProcessLifetime struct {
	Identity      identity
	FirstSeen     time.Time
	LastSeen      time.Time
	InitialParent int
	Parent        int // last observed PPID
	Group         int // last observed PGID
	Name          string

	States        []stateChange
	ParentChanges []stateChange
	Stopped       []processStoppedEpisode
	Gaps          []processGap

	CPU           []float64
	RSS           []uint64
	SeenAt        []time.Time
	SampleIndices []int
	CPUAvailable  []bool
	FDs           []int
	Threads       []int

	// CgroupPeakMemoryFraction is the identity's highest observed
	// cgroup memory.current/memory.max, -1 when no limit was ever observed.
	CgroupPeakMemoryFraction float64
	// CgroupPeakAt anchors the peak fraction to its sampled time.
	CgroupPeakAt time.Time

	// cgroupPath is the identity's last identity-consistent cgroup path.
	// it keys the kernel oom_kill counter series and never leaves the
	// analysis (a runner's unit name can embed its repository).
	cgroupPath string
}

// oomCounterSample is one sampled reading of a cgroup's cumulative
// memory.events oom_kill counter.
type oomCounterSample struct {
	At    time.Time
	Kills uint64
}

// oomCounterWindow bounds how late the first counter reading after a
// departure may be and still explain it: the same 5 s bound as the causal
// rule CGROUP_OOM_KILLS_MEMBER@1.
const oomCounterWindow = 5 * time.Second

// kernelOOMRise reports a rise of the kernel's oom_kill counter in life's own
// cgroup across the interval in which the identity vanished.
//
// the baseline is the last reading taken strictly before the victim's final
// sample. A sample reads the process table before the cgroup counters, so the
// sample in which the victim was last seen can already carry the kernel's
// count for its own kill (real-runner S11: the counter went 2 -> 3 in the very
// sample that last listed the OOM-killed job process). measuring only from
// the reading after LastSeen therefore missed the kill whenever the two landed
// in one sample. the final sample's own reading and later ones up to
// oomCounterWindow are candidates; an earlier rise is already part of the
// baseline and is never attributed.
func (c *AnalysisContext) kernelOOMRise(life *ProcessLifetime) (uint64, time.Time, bool) {
	if life == nil || life.cgroupPath == "" {
		return 0, time.Time{}, false
	}
	series := c.cgroupOOM[life.cgroupPath]
	before := -1
	for i, reading := range series {
		if !reading.At.Before(life.LastSeen) {
			break
		}
		before = i
	}
	if before < 0 {
		return 0, time.Time{}, false
	}
	baseline := series[before]
	if c.cgroupMemberDepartedBefore(life, baseline.At) {
		// another member of this cgroup vanished after the baseline and
		// before this process's final sample, so the final-sample reading may
		// hold that member's kill (principal review of L2). it joins the baseline:
		// only a later rise can be this process's.
		for i := before + 1; i < len(series) && !series[i].At.After(life.LastSeen); i++ {
			before = i
		}
		baseline = series[before]
	}
	for i := before + 1; i < len(series); i++ {
		reading := series[i]
		if reading.At.Sub(life.LastSeen) > oomCounterWindow {
			break
		}
		if reading.Kills > baseline.Kills {
			return reading.Kills - baseline.Kills, reading.At, true
		}
	}
	return 0, time.Time{}, false
}

// cgroupMemberDepartedBefore reports whether another process of life's cgroup
// was last seen at or after since but before life's own final sample.
// kernelOOMVictim reports the tracer's direct oom:mark_victim record for this
// exact identity, when the bundle carries one.
func (c *AnalysisContext) kernelOOMVictim(life *ProcessLifetime) (time.Time, bool) {
	if life == nil {
		return time.Time{}, false
	}
	at, ok := c.kernelOOM[life.Identity]
	return at, ok
}

func (c *AnalysisContext) cgroupMemberDepartedBefore(life *ProcessLifetime, since time.Time) bool {
	for _, other := range c.Process {
		if other == life || other.cgroupPath != life.cgroupPath {
			continue
		}
		if !other.LastSeen.Before(since) && other.LastSeen.Before(life.LastSeen) {
			return true
		}
	}
	return false
}

// AliveAtEnd reports whether the identity was present at the last sample.
func (life *ProcessLifetime) AliveAtEnd(end time.Time) bool {
	if life == nil || !life.LastSeen.Equal(end) || len(life.States) == 0 {
		return false
	}
	state := life.States[len(life.States)-1].To
	return len(state) > 0 && state[0] != 'Z' && state[0] != 'X' && state[0] != 'x'
}

// WasStoppedBetween reports whether the identity was observed in a stopped
// state at any sample in [from, to]. the caller is responsible for refusing
// the question when process coverage was too thin to ask it.
func (life *ProcessLifetime) WasStoppedBetween(from, to time.Time) bool {
	if life == nil {
		return false
	}
	for _, ep := range life.Stopped {
		end := ep.To
		if end.IsZero() || end.Before(ep.From) {
			end = ep.From
		}
		if ep.StillStopped && life.LastSeen.After(end) {
			end = life.LastSeen
		}
		if !end.Before(from) && !ep.From.After(to) {
			return true
		}
	}
	return false
}

// WasReparented reports whether the identity's PPID ever changed to the
// given PPID, returning the first such change.
func (life *ProcessLifetime) WasReparented(toPPID int) (stateChange, bool) {
	for _, c := range life.ParentChanges {
		if c.To == itoa(toPPID) {
			return c, true
		}
	}
	return stateChange{}, false
}

// SpawnedChildren reports whether any other identity ever held a PPID equal
// to this identity's PID (a child spawn observed by the differ).
func (ctx *AnalysisContext) SpawnedChildren(parent *ProcessLifetime) []identity {
	var out []identity
	for _, life := range ctx.orderedProcesses() {
		if life.Identity == parent.Identity {
			continue
		}
		if life.InitialParent == parent.Identity.PID && !life.FirstSeen.Before(parent.FirstSeen) && !life.FirstSeen.After(parent.LastSeen) {
			out = append(out, life.Identity)
			continue
		}
		for _, c := range life.ParentChanges {
			if c.To == itoa(parent.Identity.PID) && !c.At.Before(parent.FirstSeen) && !c.At.After(parent.LastSeen) {
				out = append(out, life.Identity)
				break
			}
		}
	}
	return out
}

// connKey identifies one socket across samples: tuple plus inode. phase 1
// records no byte counters, so RX/TX progress is structurally UNKNOWN.
type connKey struct {
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	Inode      uint64
}

// ConnectionLifetime tracks one socket identity across the capture (3.7).
// byte counters are not part of the v1 format, so no progress feature can be
// derived; signatures must treat RX/TX progress as UNKNOWN.
type ConnectionLifetime struct {
	Key              connKey
	FirstSeen        time.Time
	LastSeen         time.Time
	Owner            identity
	OwnerKnown       bool
	States           []stateChange
	Established      bool // state at last observation
	EstablishedSince time.Time
	Continuous       bool // observed without a missing/failed network sample
	lastSample       int
}

func (life *ConnectionLifetime) leftEstablishedMidCapture() (stateChange, bool) {
	for _, c := range life.States {
		if c.From == "ESTABLISHED" && c.To != "ESTABLISHED" {
			return c, true
		}
	}
	// state change records carry the previous state in from only when a
	// transition happened inside the capture; an initial non-Established
	// state says nothing about a mid-capture disconnect.
	return stateChange{}, false
}

// AnalysisContext holds incident features computed once per analyzer run
// (3.3). signatures never rescan raw snapshots. A context is read-only once
// built, and deterministic: ordered lists back every map the rules use.
type AnalysisContext struct {
	Incident   *incident.Incident
	Start, End time.Time
	Samples    []sample

	Memory     []memorySample
	MemoryPeak float64 // percent of host memory used; -1 with no samples

	Disk        []diskSample
	DiskMinFree float64 // percent free; -1 with no samples

	Pressure map[platform.Resource][]pressureSample

	Process     map[identity]*ProcessLifetime
	Connections map[connKey]*ConnectionLifetime
	Groups      map[int][]identity

	Events []incident.Event

	// SocketByteCounters records whether any RX/TX accounting could be
	// derived. the v1 format has no byte counters, so it is always false;
	// broker-stall reasoning must treat RX progress as UNKNOWN.
	SocketByteCounters bool

	coverage map[CoverageField]CollectorCoverage

	// covers are provider intents that explain exits in their window (T2).
	covers []IntentCover

	// cgroupOOM is the sampled memory.events oom_kill series per cgroup
	// path, in capture order (one reading per sample and path).
	cgroupOOM map[string][]oomCounterSample

	// kernelOOM is the phase 6 tracer's direct oom:mark_victim record per
	// exact process identity. unlike cgroupOOM it names the victim, so it
	// needs no window or cgroup inference: the kernel said it killed this
	// incarnation. A PID without its start time is never recorded (PID
	// reuse would bind another process's death to this one).
	kernelOOM map[identity]time.Time
}

// explainedByIntent reports whether a process exit at ts with identity id falls
// inside a cover's window and names that process.
func (c *AnalysisContext) explainedByIntent(id identity, ts time.Time) bool {
	for _, cover := range c.covers {
		if ts.Before(cover.From) || ts.After(cover.Until) {
			continue
		}
		for _, p := range cover.Processes {
			if p.PID == id.PID && (p.StartTicks == 0 || id.StartTicks == 0 || p.StartTicks == id.StartTicks) {
				return true
			}
		}
	}
	return false
}

// runnerTreeIntentCovers reports whether the exit at ts is inside a cover that
// ends the runner's whole tree (service stop, self-update, ephemeral
// completion), not just a cancellation of one job.
func (c *AnalysisContext) runnerTreeIntentCovers(id identity, ts time.Time) bool {
	for _, cover := range c.covers {
		if !cover.RunnerTree || ts.Before(cover.From) || ts.After(cover.Until) {
			continue
		}
		for _, p := range cover.Processes {
			if p.PID == id.PID && (p.StartTicks == 0 || id.StartTicks == 0 || p.StartTicks == id.StartTicks) {
				return true
			}
		}
	}
	return false
}

// jobTreeIntentCovers reports whether a stated job outcome at ts covers this
// exit because the process belongs to the job's own tree.
//
// Real-runner regression (2026-11-04, selfhosted-e2e run 41950041166): a job
// GitHub reports SUCCEEDED spawned a test process tree of its own, and the
// runner SIGKILLed the leftovers when the job ended. those processes sat in
// their own process group, so nothing survived to trip groupMemberSurvived,
// and their traced exits are signal:9, so the normal-exit rule could not cover
// them either: PROCESS_GROUP_TERMINATION reported the cleanup at 0.80
// CRITICAL. the job's own stated completion is the authority for the tree it
// started, so the covered set is widened from the role-tagged processes the
// provider names to their observed descendants.
func (c *AnalysisContext) jobTreeIntentCovers(id identity, ts time.Time) bool {
	for _, cover := range c.covers {
		if !cover.JobTree || ts.Before(cover.From) || ts.After(cover.Until) {
			continue
		}
		if c.descendsFrom(id, cover.Processes) {
			return true
		}
	}
	return false
}

// descendsFrom reports whether id is one of roots or a descendant of one,
// following only the parentage this capture observed. the provider section can
// tag the job's role-bearing processes; everything the job started below them
// is resolved here, including after an intermediate process exited normally.
func (c *AnalysisContext) descendsFrom(id identity, roots []ProcessIdentity) bool {
	if len(roots) == 0 {
		return false
	}
	var queue []*ProcessLifetime
	for key, life := range c.Process {
		for _, root := range roots {
			if key.PID == root.PID && (root.StartTicks == 0 || key.StartTicks == 0 || root.StartTicks == key.StartTicks) {
				queue = append(queue, life)
				break
			}
		}
	}
	seen := make(map[identity]bool, len(queue))
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur.Identity] {
			continue
		}
		seen[cur.Identity] = true
		if cur.Identity == id {
			return true
		}
		for _, child := range c.SpawnedChildren(cur) {
			if life := c.Process[child]; life != nil {
				queue = append(queue, life)
			}
		}
	}
	return false
}

// coverage reports capture consistency for one section.
func (c *AnalysisContext) Coverage(field CoverageField) CollectorCoverage {
	return c.coverage[field]
}

// orderedProcesses returns process lifetimes sorted by identity so rule
// candidate selection is deterministic regardless of map order.
func (c *AnalysisContext) orderedProcesses() []*ProcessLifetime {
	out := make([]*ProcessLifetime, 0, len(c.Process))
	for _, life := range c.Process {
		out = append(out, life)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Identity.less(out[b].Identity) })
	return out
}

// orderedGroups returns process groups sorted by PGID with members sorted by
// identity.
func (c *AnalysisContext) orderedGroups() []int {
	out := make([]int, 0, len(c.Groups))
	for pgid := range c.Groups {
		out = append(out, pgid)
	}
	sort.Ints(out)
	return out
}

func (c *AnalysisContext) groupMembers(pgid int) []identity {
	members := make([]identity, 0, len(c.Groups[pgid]))
	for _, id := range c.Groups[pgid] {
		if life := c.Process[id]; life != nil && life.Group == pgid {
			members = append(members, id)
		}
	}
	sort.Slice(members, func(a, b int) bool { return members[a].less(members[b]) })
	return members
}

// orderedConnections returns connection lifetimes sorted by key.
func (c *AnalysisContext) orderedConnections() []*ConnectionLifetime {
	out := make([]*ConnectionLifetime, 0, len(c.Connections))
	for _, life := range c.Connections {
		out = append(out, life)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Key.Inode != out[b].Key.Inode {
			return out[a].Key.Inode < out[b].Key.Inode
		}
		if out[a].Key.LocalPort != out[b].Key.LocalPort {
			return out[a].Key.LocalPort < out[b].Key.LocalPort
		}
		if out[a].Key.RemotePort != out[b].Key.RemotePort {
			return out[a].Key.RemotePort < out[b].Key.RemotePort
		}
		if out[a].Key.LocalAddr != out[b].Key.LocalAddr {
			return out[a].Key.LocalAddr < out[b].Key.LocalAddr
		}
		if out[a].Key.RemoteAddr != out[b].Key.RemoteAddr {
			return out[a].Key.RemoteAddr < out[b].Key.RemoteAddr
		}
		return out[a].FirstSeen.Before(out[b].FirstSeen)
	})
	return out
}

func (c *AnalysisContext) coverageOK(field CoverageField) bool {
	coverage := c.Coverage(field)
	return coverage.Available > 0 && !coverage.HeavyLoss()
}

func (c *AnalysisContext) fractionLost(field CoverageField) float64 {
	return c.Coverage(field).FractionLost
}

// MemoryOverDuration returns the longest continuous span with host memory
// used at or above percent. resolution is bounded by sampling. the scan is
// linear so large captures do not pay quadratic time per signature.
func (c *AnalysisContext) MemoryOverDuration(percent float64) time.Duration {
	best := time.Duration(0)
	var runStart time.Time
	for index, m := range c.Memory {
		if index > 0 && m.index != c.Memory[index-1].index+1 {
			runStart = time.Time{}
		}
		if m.Percent < percent {
			runStart = time.Time{}
			continue
		}
		if runStart.IsZero() {
			runStart = m.At
		}
		if span := m.At.Sub(runStart); span > best {
			best = span
		}
	}
	return best
}

// DiskUnderDuration returns the longest continuous span with disk free space
// at or below percent. resolution is bounded by sampling.
func (c *AnalysisContext) DiskUnderDuration(percent float64) time.Duration {
	best := time.Duration(0)
	var runStart time.Time
	for index, d := range c.Disk {
		if index > 0 && d.index != c.Disk[index-1].index+1 {
			runStart = time.Time{}
		}
		if d.Percent > percent {
			runStart = time.Time{}
			continue
		}
		if runStart.IsZero() {
			runStart = d.At
		}
		if span := d.At.Sub(runStart); span > best {
			best = span
		}
	}
	return best
}

// PressureAverage is the mean of available avg10 values for one resource.
func (c *AnalysisContext) PressureAverage(resource platform.Resource, full bool) (float64, bool) {
	var sum float64
	n := 0
	for _, s := range c.Pressure[resource] {
		if !pressHas(s, full) {
			continue
		}
		sum += pressValue(s, full)
		n++
	}
	if n == 0 {
		return 0, false
	}
	return sum / float64(n), true
}

// PressurePeak is the peak observed avg10 value for one resource metric.
func (c *AnalysisContext) PressurePeak(resource platform.Resource, full bool) (float64, bool) {
	peak := 0.0
	has := false
	for _, s := range c.Pressure[resource] {
		if !pressHas(s, full) {
			continue
		}
		has = true
		if v := pressValue(s, full); v > peak {
			peak = v
		}
	}
	return peak, has
}

// PressureSustained returns the longest continuous span with the resource's
// some/full avg10 (a percentage, 0..100) at or above threshold. an
// unavailable reading breaks the run, matching the tri-state rule.
func (c *AnalysisContext) PressureSustained(resource platform.Resource, full bool, threshold float64) time.Duration {
	best := time.Duration(0)
	var runStart time.Time
	for _, s := range c.Pressure[resource] {
		if !pressHas(s, full) || pressValue(s, full) < threshold {
			runStart = time.Time{}
			continue
		}
		if runStart.IsZero() {
			runStart = s.At
		}
		if span := s.At.Sub(runStart); span > best {
			best = span
		}
	}
	return best
}

// TimeOfPressure returns the earliest sample witnessing an at-or-above
// reading. zero time when absent, meaning the caller has no anchor.
func (c *AnalysisContext) TimeOfPressure(resource platform.Resource, value float64) time.Time {
	for _, s := range c.Pressure[resource] {
		if s.SomeHas && s.Some >= value {
			return s.At
		}
		if s.FullHas && s.Full >= value {
			return s.At
		}
	}
	return time.Time{}
}

func (c *AnalysisContext) timeOfMemory(percent float64) time.Time {
	for _, m := range c.Memory {
		if m.Percent >= percent {
			return m.At
		}
	}
	return time.Time{}
}

func (c *AnalysisContext) timeOfDisk(percent float64) time.Time {
	for _, d := range c.Disk {
		if d.Percent <= percent {
			return d.At
		}
	}
	return time.Time{}
}

// memoryAtOrAbove returns the highest memory reading within window of t, or
// -1 when the sensor gave no reading near t (the UNKNOWN case).
func (c *AnalysisContext) memoryAtOrAbove(t time.Time, window time.Duration) float64 {
	best := -1.0
	for _, m := range c.Memory {
		if !Within(m.At, t, window) {
			continue
		}
		if m.Percent > best {
			best = m.Percent
		}
	}
	return best
}

// totalMemoryBytes returns host total memory from snapshot sensor data;
// metadata totals are ignored when sensors disagree, but used as a fallback.
func (c *AnalysisContext) totalMemoryBytes() uint64 {
	for _, sm := range c.Samples {
		if sm.Available[CoverSystem] && sm.System != nil && sm.System.MemoryStatsAvailable && sm.System.MemoryTotal > 0 {
			return sm.System.MemoryTotal
		}
	}
	if c.Incident != nil && c.Incident.Metadata.Host.MemoryTotal > 0 {
		return c.Incident.Metadata.Host.MemoryTotal
	}
	return 0
}

// identityPeakRSSFraction returns the candidate's peak RSS as a fraction of
// host memory. 0 when memory totals are unknown.
func (c *AnalysisContext) identityPeakRSSFraction(life *ProcessLifetime) float64 {
	total := c.totalMemoryBytes()
	if total <= 0 || life == nil {
		return 0
	}
	peak := uint64(0)
	for _, rss := range life.RSS {
		if rss > peak {
			peak = rss
		}
	}
	return float64(peak) / float64(total)
}

// identityCgroupNearLimit reports whether the identity was ever observed
// with a cgroup memory limit and usage at or above fraction of it (3.11's
// cgroup awareness). false means either never observed or no limit; the
// caller must treat a missing sensor as its own answer, not as evidence of
// headroom.
func (c *AnalysisContext) identityCgroupNearLimit(life *ProcessLifetime, fraction float64) bool {
	return life != nil && life.CgroupPeakMemoryFraction >= fraction
}

// cpuSmoothingWindow is the trailing window used to classify sustained CPU.
// kernel CPU accounting is quantized to 10 ms ticks, so at a 100 ms sampling
// interval a fully busy core legitimately reads anywhere from ~90% to ~128%
// depending on sample jitter. requiring every single sample to stay above the
// threshold would let one 89.6% sample break an otherwise hour-long spin.
const cpuSmoothingWindow = 5 * time.Second

// identitySustainedCPU returns the longest run where the trailing-window mean
// CPUPercent stays at or above threshold. sampling gaps bound the resolution.
// the scan is linear because every signature calls it over every lifetime.
func (c *AnalysisContext) identitySustainedCPU(life *ProcessLifetime, threshold float64) time.Duration {
	if life == nil {
		return 0
	}
	samples := len(life.CPU)
	if len(life.SeenAt) < samples {
		samples = len(life.SeenAt)
	}
	best := time.Duration(0)
	var runStart time.Time
	var sum float64
	windowstart := 0
	for index := 0; index < samples; index++ {
		if (index > 0 && len(life.SampleIndices) > index && life.SampleIndices[index] != life.SampleIndices[index-1]+1) || (len(life.CPUAvailable) > index && !life.CPUAvailable[index]) || math.IsNaN(life.CPU[index]) || math.IsInf(life.CPU[index], 0) || life.CPU[index] < 0 {
			sum = 0
			windowstart = index
			runStart = time.Time{}
			if len(life.CPUAvailable) > index && !life.CPUAvailable[index] || math.IsNaN(life.CPU[index]) || math.IsInf(life.CPU[index], 0) || life.CPU[index] < 0 {
				windowstart = index + 1
				continue
			}
		}
		sum += life.CPU[index]
		for windowstart < index && life.SeenAt[index].Sub(life.SeenAt[windowstart]) > cpuSmoothingWindow {
			sum -= life.CPU[windowstart]
			windowstart++
		}
		mean := sum / float64(index-windowstart+1)
		if mean < threshold {
			runStart = time.Time{}
			continue
		}
		if runStart.IsZero() {
			runStart = life.SeenAt[index]
		}
		if span := life.SeenAt[index].Sub(runStart); span > best {
			best = span
		}
	}
	return best
}

// identityCPUIdle reports whether every CPU reading for the identity is
// under the low-water mark.
func (c *AnalysisContext) identityCPUIdle(life *ProcessLifetime) bool {
	if life == nil {
		return false
	}
	for index, v := range life.CPU {
		if len(life.CPUAvailable) > index && !life.CPUAvailable[index] || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 5 {
			return false
		}
	}
	return len(life.CPU) > 0
}

// identitySpawnedChildrenDuring reports whether any child appeared under
// this identity after since. it covers both an observed PPID change to the
// parent and a new identity first seen already parented to it: a short-lived
// child can appear and disappear entirely between two samples.
func (c *AnalysisContext) identitySpawnedChildrenDuring(parent *ProcessLifetime, since time.Time) bool {
	for _, life := range c.orderedProcesses() {
		if life.Identity == parent.Identity {
			continue
		}
		if life.InitialParent == parent.Identity.PID && After(life.FirstSeen, since) && !life.FirstSeen.Before(parent.FirstSeen) && !life.FirstSeen.After(parent.LastSeen) {
			return true
		}
		for _, change := range life.ParentChanges {
			if change.To == itoa(parent.Identity.PID) && After(change.At, since) && !change.At.Before(parent.FirstSeen) && !change.At.After(parent.LastSeen) {
				return true
			}
		}
	}
	return false
}

// resourcesStressed reports whether any pressure or sensor saw trouble
// anywhere in the capture; facts for the resource-starvation gate.
func (c *AnalysisContext) resourcesStressed() bool {
	for _, resource := range []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO} {
		// PSI avg10 is a percentage of stalled wall time, not a fraction.
		if peak, ok := c.PressurePeak(resource, false); ok && peak >= pressureSomeStressed {
			return true
		}
		if peak, ok := c.PressurePeak(resource, true); ok && peak >= pressureFullStressed {
			return true
		}
	}
	if c.MemoryPeak >= oomMemoryNear {
		return true
	}
	if c.DiskMinFree >= 0 && c.DiskMinFree <= diskNearFull {
		return true
	}
	return false
}

// isWatchedIdentity reports whether the lifetime is the identity the
// incident trigger named, as far as the trigger metadata allows.
func isWatchedIdentity(ctx *AnalysisContext, life *ProcessLifetime) bool {
	t := ctx.Incident.Trigger
	if t.PID == life.Identity.PID && t.StartTicks == life.Identity.StartTicks {
		return true
	}
	if t.PID == life.Identity.PID && t.StartTicks == 0 && life.Identity.StartTicks >= 0 {
		return t.StartTicks == 0
	}
	return false
}

// buildContext normalizes one incident (3.3-3.7). the context takes no
// ownership of incident data and never mutates it.
func buildContext(i *incident.Incident) *AnalysisContext {
	ctx := &AnalysisContext{
		Incident:    i,
		Process:     map[identity]*ProcessLifetime{},
		Connections: map[connKey]*ConnectionLifetime{},
		Groups:      map[int][]identity{},
		Pressure:    map[platform.Resource][]pressureSample{},
		MemoryPeak:  -1,
		DiskMinFree: -1,
		coverage:    map[CoverageField]CollectorCoverage{},
		cgroupOOM:   map[string][]oomCounterSample{},
		kernelOOM:   map[identity]time.Time{},
	}
	// direct kernel OOM evidence (phase 6): the tracer's oom:mark_victim
	// record names the victim incarnation. last observation wins when a
	// bundle carries more than one, so the newest kill is the one reported.
	for _, ev := range i.Events {
		if ev.Type != incident.TraceOomKill || ev.PID <= 0 || ev.StartTicks <= 0 {
			continue
		}
		id := identity{ev.PID, ev.StartTicks}
		if prev, ok := ctx.kernelOOM[id]; !ok || ev.Timestamp.After(prev) {
			ctx.kernelOOM[id] = ev.Timestamp
		}
	}
	totals := map[CoverageField]int{}
	available := map[CoverageField]int{}
	fields := []CoverageField{CoverProcesses, CoverConnections, CoverSystem, CoverPressure, CoverCgroups}

	prevpresent := map[identity]time.Time{} // identity -> last sample it was seen in
	for sampleindex, ss := range i.Snapshots {
		sm := newSample(ss)
		ctx.Samples = append(ctx.Samples, sm)
		for _, field := range fields {
			totals[field]++
			if sm.Available[field] {
				available[field]++
			}
		}

		if sm.Available[CoverSystem] && sm.System.MemoryStatsAvailable && sm.System.MemoryTotal > 0 && sm.System.MemoryUsed <= sm.System.MemoryTotal {
			percent := float64(sm.System.MemoryUsed) * 100 / float64(sm.System.MemoryTotal)
			ctx.Memory = append(ctx.Memory, memorySample{At: sm.At, Percent: percent, index: sampleindex})
			if percent > ctx.MemoryPeak {
				ctx.MemoryPeak = percent
			}
		}
		if sm.Available[CoverSystem] && sm.System.DiskStatsAvailable && sm.System.DiskTotal > 0 && sm.System.DiskFree <= sm.System.DiskTotal {
			ds := diskSample{
				index:     sampleindex,
				At:        sm.At,
				Percent:   float64(sm.System.DiskFree) * 100 / float64(sm.System.DiskTotal),
				InodeFree: -1,
			}
			if sm.System.DiskTotalInodes > 0 {
				ds.InodeFree = float64(sm.System.DiskFreeInodes) / float64(sm.System.DiskTotalInodes)
				if ds.InodeFree > 1 {
					ds.InodeFree = 1
				}
			}
			ctx.Disk = append(ctx.Disk, ds)
		}
		for _, resource := range []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO} {
			value, ok := sm.Pressure[resource]
			valid := ok && sm.Available[CoverPressure]
			reading := pressureSample{At: sm.At}
			if valid {
				reading.Some, reading.Full = value.Some.Avg10, value.Full.Avg10
				reading.SomeHas = value.HasSome && validPercent(value.Some.Avg10)
				reading.FullHas = value.HasFull && validPercent(value.Full.Avg10)
			}
			ctx.Pressure[resource] = append(ctx.Pressure[resource], reading)
		}

		if !sm.Available[CoverProcesses] {
			for key := range prevpresent {
				endStopped(ctx.Process[key], false)
			}
			prevpresent = nil
			continue // gaps are never inferred across unknown intervals
		}

		present := map[identity]*collector.ProcessSnapshot{}
		for index := range sm.Processes {
			p := &sm.Processes[index]
			present[identity{p.PID, p.StartTicks}] = p
		}
		// identities seen at the previous usable sample but absent now open a
		// gap; identities present now close their open gap.
		for key := range prevpresent {
			if _, ok := present[key]; ok {
				continue
			}
			life := ctx.Process[key]
			if life == nil {
				continue
			}
			endStopped(life, false)
			if n := len(life.Gaps); n == 0 || life.Gaps[n-1].Closed() {
				life.Gaps = append(life.Gaps, processGap{From: sm.At, Identity: key})
			}
		}
		for key := range present {
			if life := ctx.Process[key]; life != nil {
				if n := len(life.Gaps); n > 0 && !life.Gaps[n-1].Closed() {
					life.Gaps[n-1].NextObserved = sm.At
				}
			}
		}
		// fold this sample's observations into the lifetimes.
		for _, p := range orderedProcessSnapshots(sm.Processes) {
			key := identity{p.PID, p.StartTicks}
			life := ctx.Process[key]
			if life == nil {
				life = &ProcessLifetime{Identity: key, FirstSeen: sm.At, InitialParent: p.PPID, Parent: p.PPID, Group: p.PGID, Name: p.Name, CgroupPeakMemoryFraction: -1}
				ctx.Process[key] = life
			}
			if p.Cgroup != nil && p.Cgroup.Path != "" && (p.Cgroup.PID == 0 || p.Cgroup.PID == p.PID && p.Cgroup.StartTicks == p.StartTicks) && !sectionFailed(ss, "process-cgroups") {
				life.cgroupPath = p.Cgroup.Path
				if p.Cgroup.OOMEventsAvailable {
					series := ctx.cgroupOOM[p.Cgroup.Path]
					if n := len(series); n == 0 || !series[n-1].At.Equal(sm.At) {
						ctx.cgroupOOM[p.Cgroup.Path] = append(series, oomCounterSample{At: sm.At, Kills: p.Cgroup.OOMKills})
					}
				}
			}
			if p.Cgroup != nil && (p.Cgroup.PID == 0 || p.Cgroup.PID == p.PID && p.Cgroup.StartTicks == p.StartTicks) && !sectionFailed(ss, "process-cgroups") && p.Cgroup.MemoryMaxAvailable && p.Cgroup.MemoryCurrentAvailable && p.Cgroup.MemoryMax > 0 {
				fraction := float64(p.Cgroup.MemoryCurrent) / float64(p.Cgroup.MemoryMax)
				if fraction > life.CgroupPeakMemoryFraction {
					life.CgroupPeakMemoryFraction = fraction
					life.CgroupPeakAt = sm.At
				}
			}
			life.LastSeen = sm.At
			life.SeenAt = append(life.SeenAt, sm.At)
			life.CPU = append(life.CPU, p.CPUPercent)
			life.SampleIndices = append(life.SampleIndices, sampleindex)
			life.CPUAvailable = append(life.CPUAvailable, sm.System != nil && sm.System.CPUPercentAvailable || p.CPUTicks > 0)
			life.FDs = append(life.FDs, p.OpenFDs)
			life.Threads = append(life.Threads, p.Threads)
			life.RSS = append(life.RSS, p.RSSBytes)
			if p.PPID != life.Parent {
				life.ParentChanges = append(life.ParentChanges, stateChange{At: sm.At, From: itoa(life.Parent), To: itoa(p.PPID)})
				life.Parent = p.PPID
			}
			if p.PGID != life.Group {
				life.Group = p.PGID
			}
			ctx.Groups[p.PGID] = appendIdentityIfMissing(ctx.Groups[p.PGID], key)
			if isStoppedState(p.State) {
				if n := len(life.Stopped); n > 0 && life.Stopped[n-1].StillStopped {
					life.Stopped[n-1].To = sm.At
				} else {
					life.Stopped = append(life.Stopped, processStoppedEpisode{From: sm.At, To: sm.At, StillStopped: true})
				}
			} else {
				endStopped(life, isAliveState(p.State))
			}
			if n := len(life.States); n == 0 || life.States[n-1].To != p.State {
				from := ""
				if n > 0 {
					from = life.States[n-1].To
				}
				life.States = append(life.States, stateChange{At: sm.At, From: from, To: p.State})
			}
		}
		// prevPresent becomes the identities in this usable sample.
		prevpresent = make(map[identity]time.Time, len(present))
		for key := range present {
			prevpresent[key] = sm.At
		}
	}

	if n := len(ctx.Samples); n > 0 {
		ctx.Start = ctx.Samples[0].At
		ctx.End = ctx.Samples[n-1].At
	}
	if len(ctx.Disk) > 0 {
		ctx.DiskMinFree = 100
		for _, d := range ctx.Disk {
			if d.Percent < ctx.DiskMinFree {
				ctx.DiskMinFree = d.Percent
			}
		}
	} else {
		ctx.DiskMinFree = -1
	}
	for _, field := range fields {
		ctx.coverage[field] = CollectorCoverage{
			Samples:      totals[field],
			Available:    available[field],
			FractionLost: coverageLost(totals[field], available[field]),
		}
	}
	for _, e := range i.Events {
		ctx.Events = append(ctx.Events, e)
	}
	buildConnections(ctx)
	return ctx
}

func buildConnections(ctx *AnalysisContext) {
	for sampleindex, sm := range ctx.Samples {
		if !sm.Available[CoverConnections] {
			continue
		}
		for _, cs := range orderedConnectionSnapshots(sm.Connections) {
			key := connKey{cs.LocalAddr, cs.LocalPort, cs.RemoteAddr, cs.RemotePort, cs.Inode}
			life := ctx.Connections[key]
			if life == nil {
				life = &ConnectionLifetime{Key: key, FirstSeen: sm.At, Continuous: true, lastSample: sampleindex}
				ctx.Connections[key] = life
			}
			gap := sampleindex > life.lastSample+1
			if gap {
				life.Continuous = false
				life.Established = false
				life.EstablishedSince = time.Time{}
			}
			life.lastSample = sampleindex
			life.LastSeen = sm.At
			owner, known := identity{}, false
			if cs.PID > 0 && sm.Available[CoverProcesses] {
				for _, p := range sm.Processes {
					if p.PID == cs.PID {
						if known {
							known = false
							break
						}
						owner = identity{p.PID, p.StartTicks}
						known = true
					}
				}
			}
			if !known || life.OwnerKnown && life.Owner != owner {
				life.Continuous = false
			}
			life.Owner, life.OwnerKnown = owner, known

			if gap || len(life.States) == 0 || life.States[len(life.States)-1].To != cs.State {
				from := ""
				if !gap && len(life.States) > 0 {
					from = life.States[len(life.States)-1].To
				}
				life.States = append(life.States, stateChange{At: sm.At, From: from, To: cs.State})
			}
			if cs.State == "ESTABLISHED" {
				if !life.Established {
					life.EstablishedSince = sm.At
				}
			} else {
				life.EstablishedSince = time.Time{}
			}
			life.Established = cs.State == "ESTABLISHED"
		}
	}
}

func coverageLost(total, available int) float64 {
	if total == 0 || available >= total {
		return 0
	}
	return float64(total-available) / float64(total)
}

// deterministic interleavings: snapshots arrive in capture order, but the
// differ produces them unsorted inside one sample; sort by identity first so
// lifetime details never depend on scan order.
func orderedProcessSnapshots(list []collector.ProcessSnapshot) []collector.ProcessSnapshot {
	out := append([]collector.ProcessSnapshot(nil), list...)
	sort.SliceStable(out, func(a, b int) bool {
		return identity{out[a].PID, out[a].StartTicks}.less(identity{out[b].PID, out[b].StartTicks})
	})
	return out
}

func orderedConnectionSnapshots(list []collector.ConnectionSnapshot) []collector.ConnectionSnapshot {
	out := append([]collector.ConnectionSnapshot(nil), list...)
	sort.SliceStable(out, func(a, b int) bool {
		return lessConn(out[a], out[b])
	})
	return out
}

func lessConn(a, b collector.ConnectionSnapshot) bool {
	return a.Inode < b.Inode || (a.Inode == b.Inode &&
		(a.LocalPort < b.LocalPort || (a.LocalPort == b.LocalPort &&
			(a.RemotePort < b.RemotePort || (a.RemotePort == b.RemotePort &&
				(a.LocalAddr < b.LocalAddr || (a.LocalAddr == b.LocalAddr && a.RemoteAddr < b.RemoteAddr)))))))
}

func appendIdentityIfMissing(list []identity, key identity) []identity {
	for _, existing := range list {
		if existing == key {
			return list
		}
	}
	return append(list, key)
}

func endStopped(life *ProcessLifetime, resumed bool) {
	if life == nil {
		return
	}
	if n := len(life.Stopped); n > 0 && life.Stopped[n-1].StillStopped {
		life.Stopped[n-1].StillStopped = false
		life.Stopped[n-1].Resumed = resumed
	}
}
func validPercent(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 100 }
func sectionFailed(s collector.Snapshot, name string) bool {
	for _, m := range s.Metrics {
		if m.Name == name && m.Error {
			return true
		}
	}
	for _, e := range s.Errors {
		if e.Collector == name {
			return true
		}
	}
	return false
}

// healthy is positive evidence, not the absence of a stress observation.
func (c *AnalysisContext) resourcesKnownHealthy() bool {
	if len(c.Samples) == 0 || len(c.Memory) != len(c.Samples) || len(c.Disk) != len(c.Samples) || c.resourcesStressed() {
		return false
	}
	for _, resource := range []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO} {
		if len(c.Pressure[resource]) != len(c.Samples) {
			return false
		}
		for _, p := range c.Pressure[resource] {
			if !p.SomeHas {
				return false
			}
		}
	}
	return true
}
