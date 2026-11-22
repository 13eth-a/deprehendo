package diagnosis

import (
	"fmt"
	"sort"
	"time"

	"runopsy/internal/platform"
)

// the bundled v1 rules. all weights are declared constants so a stored
// diagnosis can be recomputed byte-for-byte against the same signature
// version. confidence sums declared supporting weights, applies recorded
// contradicting evidence, and is capped by rule-specific inference limits:
// the v1 bundle cannot observe kernel OOM events, exit signals, or socket
// byte counters, so no rule may score as if it had. nothing here is a
// statistical model; the tracker observes, and rules refuse conclusions
// their evidence cannot carry (3.9/3.10/3.35).

type confidenceContext struct {
	supporting        []Evidence
	contradicting     []Evidence
	missing           []string
	attributes        map[string]string
	processIdentities []ProcessIdentity
	processGroupID    int
}

func newConfidence() *confidenceContext {
	return &confidenceContext{attributes: map[string]string{}}
}

func (cc *confidenceContext) support(ev Evidence) { cc.supporting = append(cc.supporting, ev) }
func (cc *confidenceContext) reject(ev Evidence)  { cc.contradicting = append(cc.contradicting, ev) }
func (cc *confidenceContext) unknown(code string) { cc.missing = append(cc.missing, code) }

func supportHealthyResources(cc *confidenceContext, ctx *AnalysisContext, weight float64, at time.Time) {
	if ctx.resourcesKnownHealthy() {
		cc.support(Evidence{Code: CodePressureHealthy, Source: SourcePressure, At: at, Weight: weight, Observed: true})
	} else if !ctx.resourcesStressed() {
		cc.unknown("RESOURCE_HEALTH_TELEMETRY")
	}
}

func (cc *confidenceContext) attr(key, value string) {
	if cc.attributes == nil {
		cc.attributes = map[string]string{}
	}
	cc.attributes[key] = value
}

func (cc *confidenceContext) process(pid int, startTicks int64) {
	identity := ProcessIdentity{PID: pid, StartTicks: startTicks}
	for _, existing := range cc.processIdentities {
		if existing == identity {
			return
		}
	}
	cc.processIdentities = append(cc.processIdentities, identity)
}

func (cc *confidenceContext) processGroup(pgid int) {
	cc.processGroupID = pgid
}

func (cc *confidenceContext) scope(match SignatureMatch) SignatureMatch {
	match.ProcessIdentities = append([]ProcessIdentity(nil), cc.processIdentities...)
	match.ProcessGroupID = cc.processGroupID
	return match
}

// score sums declared weights, subtracts contradicting weights, clamps to
// [0, cap], and returns the evidence sorted deterministically: supporting
// and contradicting lists are rendered in weight-then-code order so the
// same evidence always renders the same report.
func (cc *confidenceContext) score(cap float64) (float64, []Evidence, []Evidence) {
	total := 0.0
	for _, ev := range cc.supporting {
		total += ev.Weight
	}
	for _, ev := range cc.contradicting {
		total -= ev.Weight
	}
	sortEvidence(cc.supporting)
	sortEvidence(cc.contradicting)
	if total > cap {
		total = cap
	}
	if total < 0 {
		total = 0
	}
	return total, cc.supporting, cc.contradicting
}

func sortEvidence(list []Evidence) {
	sort.SliceStable(list, func(i, j int) bool { return lessEvidence(list[i], list[j]) })
}

func lessEvidence(a, b Evidence) bool {
	if a.Weight != b.Weight {
		return a.Weight > b.Weight
	}
	if a.Code != b.Code {
		return a.Code < b.Code
	}
	return a.Source < b.Source
}

// notMatched marks a signature as evaluated and rejected, with the reason
// that --explain will render.
func notMatched(id SignatureID, reason string) SignatureMatch {
	return SignatureMatch{SignatureID: id, Rejected: reason}
}

// collectorLossReject returns contradicting evidence when a required
// section was unavailable for much of the capture (3.36).
func collectorLossReject(field CoverageField, fraction float64) Evidence {
	return Evidence{
		Code:      CodeCollectorHeavyLoss,
		Source:    SourceCollectorReliability,
		Weight:    0.25,
		Observed:  fraction,
		Threshold: heavyCoverageLoss,
	}
}

// ---------------------------------------------------------------------------
// OOM_KILL
// ---------------------------------------------------------------------------

// OOM weights: the host/cgroup memory condition is required; the departure,
// footprint, and pressure readings support it. without kernel evidence the
// score caps at .50, below the report threshold: memory pressure plus a
// disappearance cannot tell an OOM kill from a clean exit. the kernel
// evidence is the sampled memory.events oom_kill counter of the victim's own
// cgroup rising across its departure (OOM_KILL@3); it carries the largest
// weight and lifts the cap.
const (
	oomMemoryNear         = 92.0
	oomCgroupNearFraction = 0.95
	oomDepartureWindow    = 90 * time.Second
	wOOMMemory            = 0.20
	wOOMCgroupMemory      = 0.20
	wOOMDeparture         = 0.15
	wOOMRSS               = 0.05
	wOOMPressure          = 0.10
	oomPressureSupport    = 20.0 // percent of stalled wall time (avg10)
	oOMCap                = 0.50
	wOOMKernelCounter     = 0.40
	oomKernelCap          = 0.85
	// the tracer's victim-naming record outranks the sampled counter: the
	// kernel states which incarnation it killed, so there is no kill window
	// or cgroup-membership inference left to cap.
	wOOMKernelVictim = 0.60
	oomDirectCap     = 0.95
)

// OOMKillSignature diagnoses a process vanishing while memory was at or near
// exhaustion (3.11). Tri-state: memory below the boundary is FALSE and ends
// the rule; memory telemetry unavailable is UNKNOWN and also ends the rule,
// without claiming the event did not happen.
type OOMKillSignature struct{}

func (OOMKillSignature) ID() SignatureID { return SignatureOOMKill }
func (OOMKillSignature) Description() string {
	return "detects processes vanishing while host or cgroup memory was at or near exhaustion"
}

func (s OOMKillSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("EXIT_SIGNAL_DETAILS")

	// required memory condition, host or cgroup. established once; every
	// later step reads the recorded tri-state rather than re-asking.
	memorycondition := s.memoryCondition(ctx)
	switch memorycondition.State {
	case False:
		return notMatched(SignatureOOMKill, "host and cgroup memory never approached the exhaustion boundary")
	case Unknown:
		return notMatched(SignatureOOMKill, "memory telemetry was unavailable for most of the capture")
	}
	memoryat := memorycondition.ObservedAt
	cgrouponly := !(ctx.coverageOK(CoverSystem) && ctx.MemoryPeak >= oomMemoryNear)
	candidate, _ := ctx.departureNearMemoryPeak(memoryat, oomDepartureWindow, cgrouponly)
	if candidate == nil {
		return notMatched(SignatureOOMKill, "no process disappeared while its applicable memory boundary was approached")
	}
	if !cgrouponly {
		cc.support(Evidence{Code: CodeHostMemoryNearLimit, Source: SourceHost, At: memoryat, Weight: wOOMMemory,
			Observed: memorycondition.Value, Threshold: oomMemoryNear})
		cc.attr("memory_peak_percent", fmt.Sprintf("%.1f", memorycondition.Value))
	} else {
		memoryat = candidate.CgroupPeakAt
		cc.support(Evidence{Code: CodeCgroupMemoryNearLimit, Source: SourceCgroup, At: memoryat, Weight: wOOMCgroupMemory,
			Observed: candidate.CgroupPeakMemoryFraction, Threshold: oomCgroupNearFraction})
	}
	cc.support(Evidence{Code: CodeProcessDepartureNearPeak, Source: SourceProcess, At: candidate.Gaps[len(candidate.Gaps)-1].From, Weight: wOOMDeparture,
		Observed:  map[string]any{"pid": candidate.Identity.PID, "start_ticks": candidate.Identity.StartTicks},
		Threshold: oomDepartureWindow})
	cc.process(candidate.Identity.PID, candidate.Identity.StartTicks)
	cc.attr("pid", itoa(candidate.Identity.PID))
	cc.attr("start_ticks", itoa64(candidate.Identity.StartTicks))

	// kernel evidence: the victim's own cgroup counted an OOM kill across
	// the interval in which it vanished. the path stays out of the output.
	cap, rejected := oOMCap, "kernel OOM event and exit cause are unavailable; memory pressure plus disappearance cannot distinguish OOM from a clean exit"
	if at, ok := ctx.kernelOOMVictim(candidate); ok {
		// direct evidence: the kernel named this exact incarnation as its
		// victim, so neither the cgroup counter nor a kill window is needed.
		cc.support(Evidence{Code: CodeKernelOOMVictim, Source: SourceProcess, At: at, Weight: wOOMKernelVictim,
			Observed: map[string]any{"pid": candidate.Identity.PID, "start_ticks": candidate.Identity.StartTicks}})
		cap = oomDirectCap
		rejected = ""
	} else if delta, at, ok := ctx.kernelOOMRise(candidate); ok {
		cc.support(Evidence{Code: CodeKernelOOMCounter, Source: SourceCgroup, At: at, Weight: wOOMKernelCounter,
			Observed: map[string]any{"oom_kill_delta": delta}})
		cap = oomKernelCap
		rejected = "" // the counter rise is the kernel's own record of the kill; the score decides
	} else {
		cc.unknown("KERNEL_OOM_EVENT")
	}

	// optional corroboration.
	if share := ctx.identityPeakRSSFraction(candidate); share >= 0.30 {
		cc.support(Evidence{Code: CodeCandidateRSSLarge, Source: SourceProcess, At: candidate.LastSeen, Weight: wOOMRSS,
			Observed: share, Threshold: 0.30})
		cc.attr("rss_share_percent", fmt.Sprintf("%.1f", share*100))
	}
	// PSI avg10 is a percentage of stalled wall time; 20% sustained memory
	// contention is strong corroboration, not a rounding-level reading.
	if avg, ok := ctx.PressureAverage(platform.PressureMemory, false); ok && avg >= oomPressureSupport {
		cc.support(Evidence{Code: CodeMemoryPressureSpike, Source: SourcePressure, Weight: wOOMPressure,
			Observed: avg, Threshold: oomPressureSupport, At: ctx.TimeOfPressure(platform.PressureMemory, avg)})
	}
	if !ctx.coverageOK(CoverProcesses) {
		cc.reject(collectorLossReject(CoverProcesses, ctx.fractionLost(CoverProcesses)))
	}

	score, sup, contra := cc.score(cap)
	match := SignatureMatch{
		SignatureID: SignatureOOMKill,
		Confidence:  score,
		Summary:     "process vanished while memory was at or near exhaustion",
		Rejected:    rejected,
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

// memoryCondition evaluates the required memory condition as a tri-state.
// TRUE when host memory peaked at or above the boundary or the departing
// candidate's cgroup usage reached its limit; FALSE when memory was
// consistently observed below the boundary; UNKNOWN when memory telemetry
// was too thin to answer.
func (s OOMKillSignature) memoryCondition(ctx *AnalysisContext) Observation[float64] {
	hostknown := ctx.coverageOK(CoverSystem) && ctx.MemoryPeak >= 0
	if hostknown && ctx.MemoryPeak >= oomMemoryNear {
		return observationTrue(ctx.timeOfMemory(oomMemoryNear), ctx.MemoryPeak)
	}
	// Per-process cgroup pressure does not depend on host memory telemetry.
	if ctx.Coverage(CoverProcesses).HeavyLoss() {
		return observationUnknown[float64]()
	}
	peakfraction := 0.0
	var at time.Time
	for _, life := range ctx.orderedProcesses() {
		if life.CgroupPeakMemoryFraction >= oomCgroupNearFraction && life.CgroupPeakMemoryFraction > peakfraction {
			peakfraction = life.CgroupPeakMemoryFraction
			at = life.CgroupPeakAt
		}
	}
	if peakfraction > 0 {
		return observationTrue(at, peakfraction)
	}
	if hostknown {
		return observationFalse[float64]()
	}
	return observationUnknown[float64]()
}

// departureNearMemoryPeak finds the identity whose absence starts near an
// at-or-above-threshold memory reading and never closes, preferring the
// largest peak RSS share; ties break on identity for determinism. adjacency
// is all a sampling tracker can claim: no causal link is recorded.
func (c *AnalysisContext) departureNearMemoryPeak(memoryAt time.Time, window time.Duration, cgroupOnly bool) (*ProcessLifetime, bool) {
	var best *ProcessLifetime
	bestshare := -1.0
	for _, life := range c.orderedProcesses() {
		applicableat := memoryAt
		if cgroupOnly {
			if life.CgroupPeakMemoryFraction < oomCgroupNearFraction {
				continue
			}
			applicableat = life.CgroupPeakAt
		}
		for _, gap := range life.Gaps {
			if gap.Closed() {
				continue // the identity returned: not an OOM-style departure
			}
			if !Within(gap.From, applicableat, window) {
				continue
			}
			if share := c.identityPeakRSSFraction(life); share > bestshare+1e-9 {
				best, bestshare = life, share
			}
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// ---------------------------------------------------------------------------
// FROZEN_PROCESS
// ---------------------------------------------------------------------------

const (
	frozenMinimum   = 5 * time.Second
	wFrozenStopped  = 0.50
	wFrozenRemained = 0.10
	wFrozenResumed  = 0.05
	wFrozenWatched  = 0.15
	wFrozenCPUIdle  = 0.10
	wFrozenHealthy  = 0.05
	frozenCap       = 0.95
)

// FrozenProcessSignature diagnoses a sustained stopped-state episode (3.12).
type FrozenProcessSignature struct{}

func (FrozenProcessSignature) ID() SignatureID { return SignatureFrozenProcess }
func (FrozenProcessSignature) Description() string {
	return "detects processes observed in the stopped state for a sustained span"
}

func (s FrozenProcessSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("SIGSTOP_SIGNAL_CAPTURE")
	if !ctx.coverageOK(CoverProcesses) {
		return notMatched(SignatureFrozenProcess, "process telemetry was unavailable for most of the capture")
	}

	candidate, episode, span := frozenCandidate(ctx)
	if candidate == nil {
		return notMatched(SignatureFrozenProcess, "no sustained stopped-state episode was observed")
	}
	cc.support(Evidence{Code: CodeProcessStopped, Source: SourceProcess, At: episode.From, Weight: wFrozenStopped,
		Observed:  map[string]any{"pid": candidate.Identity.PID, "start_ticks": candidate.Identity.StartTicks, "span_ms": span.Milliseconds()},
		Threshold: frozenMinimum})
	cc.process(candidate.Identity.PID, candidate.Identity.StartTicks)
	cc.attr("pid", itoa(candidate.Identity.PID))
	cc.attr("start_ticks", itoa64(candidate.Identity.StartTicks))
	cc.attr("stopped_span", (span + time.Second/2).Truncate(time.Second).String())

	if episode.StillStopped {
		cc.support(Evidence{Code: CodeProcessRemainedStopped, Source: SourceProcess, At: ctx.End, Weight: wFrozenRemained, Observed: true})
	} else if episode.Resumed {
		cc.support(Evidence{Code: CodeProcessResumed, Source: SourceProcess, At: episode.To, Weight: wFrozenResumed, Observed: true})
	} else {
		cc.unknown("STOP_EPISODE_END")
	}
	if isWatchedIdentity(ctx, candidate) {
		cc.support(Evidence{Code: CodeWatchedIdentity, Source: SourceTrigger, At: ctx.Incident.TriggeredAt, Weight: wFrozenWatched,
			Observed: candidate.Identity.PID})
	}
	if ctx.identityCPUIdle(candidate) {
		cc.support(Evidence{Code: CodeCPUNoProgress, Source: SourceProcess, At: episode.From, Weight: wFrozenCPUIdle, Observed: true})
	}
	supportHealthyResources(cc, ctx, wFrozenHealthy, ctx.End)

	score, sup, contra := cc.score(frozenCap)
	match := SignatureMatch{
		SignatureID: SignatureFrozenProcess,
		Confidence:  score,
		Summary:     "sustained stopped-state episode observed for a process",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

// frozenCandidate selects the longest observed stopped episode; ties break
// on the smaller identity. stopped spans always extend to the capture end
// while the identity remained stopped.
func frozenCandidate(ctx *AnalysisContext) (*ProcessLifetime, processStoppedEpisode, time.Duration) {
	var bestLife *ProcessLifetime
	var bestEpisode processStoppedEpisode
	bestspan := time.Duration(0)
	var keys []identity
	for key := range ctx.Process {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(a, b int) bool { return keys[a].less(keys[b]) })
	for _, key := range keys {
		life := ctx.Process[key]
		for _, ep := range life.Stopped {
			span := ep.Span(ctx.End)
			if span < frozenMinimum {
				continue
			}
			if span > bestspan || (span == bestspan && bestLife != nil && key.less(bestLife.Identity)) || bestLife == nil {
				bestLife, bestEpisode, bestspan = life, ep, span
			}
		}
	}
	return bestLife, bestEpisode, bestspan
}

// ---------------------------------------------------------------------------
// CPU_SPIN
// ---------------------------------------------------------------------------

const (
	spinThreshold   = 90.0
	spinMinimum     = 60 * time.Second
	wSpinCPU        = 0.35
	wSpinNoChildren = 0.05
	wSpinNoStop     = 0.05
	wSpinHealthy    = 0.05
	spinCap         = 0.50
)

// CPUSpinSignature diagnoses a surviving process sustaining near-full core
// CPU without observed child churn (3.13). high CPU alone is not a
// failure: the rule is capped low and refuses vanished processes, which
// belong to OOM or group-termination rules.
type CPUSpinSignature struct{}

func (CPUSpinSignature) ID() SignatureID { return SignatureCPUSpin }
func (CPUSpinSignature) Description() string {
	return "records sustained high CPU; application progress is unavailable in v1"
}

func (s CPUSpinSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("APPLICATION_PROGRESS_TELEMETRY")
	if !ctx.coverageOK(CoverProcesses) {
		return notMatched(SignatureCPUSpin, "process telemetry was unavailable for most of the capture")
	}

	candidate, span := spinCandidate(ctx)
	if candidate == nil {
		return notMatched(SignatureCPUSpin, "no surviving process sustained near-full core CPU for the required span")
	}
	cc.support(Evidence{Code: CodeCPUSustained, Source: SourceProcess, At: ctx.End, Weight: wSpinCPU,
		Observed:  map[string]any{"pid": candidate.Identity.PID, "start_ticks": candidate.Identity.StartTicks, "span_ms": span.Milliseconds()},
		Threshold: spinMinimum})
	cc.process(candidate.Identity.PID, candidate.Identity.StartTicks)
	cc.attr("pid", itoa(candidate.Identity.PID))
	cc.attr("start_ticks", itoa64(candidate.Identity.StartTicks))
	cc.attr("spin_span", (span + time.Second/2).Truncate(time.Second).String())

	// Anti-false-positive gate: a high-CPU process that spawns children is
	// doing ordinary work (compiler drivers, linkers, pipelines). without
	// application progress telemetry this is not distinguishable from a
	// healthy build, so the rule refuses instead of reporting a spin.
	if ctx.identitySpawnedChildrenDuring(candidate, ctx.End.Add(-span)) {
		return SignatureMatch{
			SignatureID: SignatureCPUSpin,
			Rejected:    "sustained CPU came with observed child process churn, which is consistent with legitimate build or pipeline work",
			MissingEvidence: []string{
				"APPLICATION_PROGRESS_TELEMETRY",
			},
			Contradicting:     []Evidence{{Code: CodeCPUNoChildChanges, Source: SourceProcess, At: ctx.End, Weight: wSpinNoChildren, Observed: false}},
			ProcessIdentities: []ProcessIdentity{{PID: candidate.Identity.PID, StartTicks: candidate.Identity.StartTicks}},
		}
	}
	cc.support(Evidence{Code: CodeCPUNoChildChanges, Source: SourceProcess, At: ctx.End, Weight: wSpinNoChildren, Observed: true})
	if !candidate.WasStoppedBetween(ctx.End.Add(-span), ctx.End) {
		cc.support(Evidence{Code: CodeProcessResumed, Source: SourceProcess, At: ctx.End, Weight: wSpinNoStop, Observed: true})
	} else {
		cc.reject(Evidence{Code: CodeProcessStopped, Source: SourceProcess, At: ctx.End, Weight: 0.50,
			Observed: "spin candidate was observed stopped during the spin window"})
	}
	supportHealthyResources(cc, ctx, wSpinHealthy, ctx.End)

	score, sup, contra := cc.score(spinCap)
	match := SignatureMatch{
		SignatureID: SignatureCPUSpin,
		Confidence:  score,
		Summary:     "surviving process sustained near-full core CPU across the incident",
		Rejected:    "application progress is unavailable; productive computation and a CPU spin have indistinguishable recorded evidence",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

// spinCandidate selects the identity with the longest sustained CPU run
// alive at capture end; ties break on the smaller identity.
func spinCandidate(ctx *AnalysisContext) (*ProcessLifetime, time.Duration) {
	var best *ProcessLifetime
	bestspan := time.Duration(0)
	var keys []identity
	for key := range ctx.Process {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(a, b int) bool { return keys[a].less(keys[b]) })
	for _, key := range keys {
		life := ctx.Process[key]
		if !life.AliveAtEnd(ctx.End) {
			continue
		}
		if span := ctx.identitySustainedCPU(life, spinThreshold); span >= spinMinimum && (span > bestspan || best == nil || (span == bestspan && key.less(best.Identity))) {
			best, bestspan = life, span
		}
	}
	return best, bestspan
}
