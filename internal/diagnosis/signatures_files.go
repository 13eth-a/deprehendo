package diagnosis

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// ---------------------------------------------------------------------------
// DISK_EXHAUSTION
// ---------------------------------------------------------------------------

const (
	diskNearFull        = 10.0
	diskMinimum         = 10 * time.Second
	wDiskLowFree        = 0.50
	wDiskPersisted      = 0.10
	wDiskPressure       = 0.15
	wDiskInode          = 0.15
	diskPressureSupport = 20.0 // percent of stalled wall time (avg10)
	diskCap             = 0.90
)

// DiskExhaustionSignature diagnoses filesystem free space remaining near
// zero across the capture (3.14). Write-failure telemetry is not observable
// in v1 bundles, so the rule stays factual about the filesystem and marks
// what it could not see.
type DiskExhaustionSignature struct{}

func (DiskExhaustionSignature) ID() SignatureID { return SignatureDiskExhaustion }
func (DiskExhaustionSignature) Description() string {
	return "detects host filesystem free space remaining near zero across the capture"
}

func (s DiskExhaustionSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("WRITE_FAILURE_TELEMETRY")
	if !ctx.coverageOK(CoverSystem) {
		return notMatched(SignatureDiskExhaustion, "disk telemetry was unavailable for most of the capture")
	}
	if ctx.DiskMinFree < 0 {
		return notMatched(SignatureDiskExhaustion, "no usable disk free-space samples were captured")
	}
	span := ctx.DiskUnderDuration(diskNearFull)
	if span < diskMinimum {
		return notMatched(SignatureDiskExhaustion, fmt.Sprintf("disk free space bottomed at %.1f%% but never stayed near zero for the required span", ctx.DiskMinFree))
	}
	cc.support(Evidence{Code: CodeDiskSustainedLowFree, Source: SourceHost, At: ctx.timeOfDisk(diskNearFull), Weight: wDiskLowFree,
		Observed: ctx.DiskMinFree, Threshold: diskNearFull})
	cc.attr("min_free_percent", fmt.Sprintf("%.1f", ctx.DiskMinFree))
	cc.attr("low_free_span", (span + time.Second/2).Truncate(time.Second).String())

	if ctx.Disk[len(ctx.Disk)-1].At.Equal(ctx.End) && ctx.Disk[len(ctx.Disk)-1].Percent <= diskNearFull {
		cc.support(Evidence{Code: CodeDiskPersistedToAnalysisEnd, Source: SourceHost, At: ctx.End, Weight: wDiskPersisted, Observed: true})
	}
	// inode exhaustion is observable and reported on its own code.
	for _, d := range ctx.Disk {
		if d.InodeFree >= 0 && d.InodeFree <= 0.05 {
			cc.support(Evidence{Code: CodeInodeExhaustion, Source: SourceHost, At: d.At, Weight: wDiskInode,
				Observed: d.InodeFree, Threshold: 0.05})
			break
		}
	}
	// PSI avg10 is a percentage of stalled wall time; 20% sustained IO
	// contention is corroborating, not a rounding-level reading.
	if avg, ok := ctx.PressureAverage(platform.PressureIO, false); ok && avg >= diskPressureSupport {
		cc.support(Evidence{Code: CodeDiskPressure, Source: SourcePressure, Weight: wDiskPressure,
			Observed: avg, Threshold: diskPressureSupport, At: ctx.TimeOfPressure(platform.PressureIO, avg)})
	}
	// Mid-incident recovery contradicts exhaustion-at-analysis-time; the
	// episode may still be real, but the classification weakens.
	if ctx.diskRecoveredAbove(diskNearFull + 20) {
		cc.reject(Evidence{Code: CodeDiskRecoveredMidIncident, Source: SourceHost, At: ctx.End, Weight: 0.30, Observed: true})
	}

	score, sup, contra := cc.score(diskCap)
	return SignatureMatch{
		SignatureID: SignatureDiskExhaustion,
		Confidence:  score,
		Summary:     "filesystem free space stayed near zero across the incident",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
}

// diskRecoveredAbove reports whether free space exceeded the boundary after
// prior low readings.
func (c *AnalysisContext) diskRecoveredAbove(percent float64) bool {
	sawlow := false
	for _, d := range c.Disk {
		if d.Percent <= diskNearFull {
			sawlow = true
			continue
		}
		if sawlow && d.Percent >= percent {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ORPHAN_PROCESS_TREE
// ---------------------------------------------------------------------------

const (
	orphanReparentWindow = 10 * time.Second
	orphanPersistMinimum = 10 * time.Second
	wOrphanReparented    = 0.40
	wOrphanParentGone    = 0.25
	wOrphanPersisted     = 0.05
	wOrphanTrigger       = 0.10
	orphanCap            = 0.85
)

// OrphanProcessTreeSignature diagnoses surviving children whose parent
// disappeared and whose PPID changed to the reaper (3.15). PID 1 is the
// factual kernel adoption target; the rule does not guess reapers it cannot
// observe.
type OrphanProcessTreeSignature struct{}

func (OrphanProcessTreeSignature) ID() SignatureID { return SignatureOrphanProcess }
func (OrphanProcessTreeSignature) Description() string {
	return "detects surviving children whose parent disappeared and whose PPID changed to the reaper"
}

func (s OrphanProcessTreeSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("EXIT_SIGNAL_TELEMETRY")
	if !ctx.coverageOK(CoverProcesses) {
		return notMatched(SignatureOrphanProcess, "process telemetry was unavailable for most of the capture")
	}

	candidate, reparent, parentgap := orphanCandidate(ctx)
	if candidate == nil {
		return notMatched(SignatureOrphanProcess, "no surviving process was observed losing its parent and being reparented")
	}
	cc.support(Evidence{Code: CodeChildReparentedToInit, Source: SourceProcess, At: reparent.At, Weight: wOrphanReparented,
		Observed: map[string]any{"pid": candidate.Identity.PID, "start_ticks": candidate.Identity.StartTicks, "from_ppid": reparent.From}})
	cc.support(Evidence{Code: CodeParentDisappeared, Source: SourceProcess, At: parentgap.From, Weight: wOrphanParentGone,
		Observed: map[string]any{"ppid": reparent.From}})
	cc.process(candidate.Identity.PID, candidate.Identity.StartTicks)
	cc.process(parentgap.Identity.PID, parentgap.Identity.StartTicks)
	cc.attr("pid", itoa(candidate.Identity.PID))
	cc.attr("start_ticks", itoa64(candidate.Identity.StartTicks))
	cc.attr("parent_pid", itoa(parentgap.Identity.PID))
	cc.attr("parent_start_ticks", itoa64(parentgap.Identity.StartTicks))

	// the orphan story requires the child to keep living after adoption.
	if persisted := ctx.End.Sub(reparent.At) >= orphanPersistMinimum && (candidate.AliveAtEnd(ctx.End) || candidate.LastSeen.After(reparent.At.Add(orphanPersistMinimum))); persisted {
		cc.support(Evidence{Code: CodeChildPersisted, Source: SourceProcess, At: candidate.LastSeen, Weight: wOrphanPersisted, Observed: true})
	} else {
		cc.reject(Evidence{Code: CodeChildPersisted, Source: SourceProcess, At: candidate.LastSeen, Weight: wOrphanPersisted,
			Observed: "child did not persist beyond the adoption window"})
	}
	// A trigger naming the deceased parent is consistent with the story; a
	// trigger naming the surviving child is the watched-stop story instead.
	if triggerConsistentWithOrphan(ctx, candidate, reparent) {
		cc.support(Evidence{Code: CodeTriggerConsistent, Source: SourceTrigger, At: ctx.Incident.TriggeredAt, Weight: wOrphanTrigger})
	} else {
		cc.reject(Evidence{Code: CodeTriggerConsistent, Source: SourceTrigger, At: ctx.Incident.TriggeredAt, Weight: wOrphanTrigger,
			Observed: "trigger did not name the departed parent"})
	}

	score, sup, contra := cc.score(orphanCap)
	match := SignatureMatch{
		SignatureID: SignatureOrphanProcess,
		Confidence:  score,
		Summary:     "process survived its parent's disappearance and was adopted",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

// orphanCandidate finds the first (deterministically smallest) identity that
// was reparented to PID 1 while a parent identity with that PPID opened an
// unclosed gap around the change.
func orphanCandidate(ctx *AnalysisContext) (*ProcessLifetime, stateChange, processGap) {
	for _, life := range ctx.orderedProcesses() {
		for _, change := range orderedChanges(life.ParentChanges) {
			if change.To != "1" {
				continue
			}
			parentpid, ok := atoiSafe(change.From)
			if !ok {
				continue
			}
			gap, found := ctx.parentDisappearedNear(parentpid, change)
			if !found {
				continue
			}
			// the adopted child must not itself have returned from a gap
			// afterwards: adoption is about the surviving lineage.
			if !life.AliveAtEnd(ctx.End) {
				continue
			}
			return life, change, gap
		}
	}
	return nil, stateChange{}, processGap{}
}

func orderedChanges(list []stateChange) []stateChange {
	out := append([]stateChange(nil), list...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].At.After(out[j].At); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// parentDisappearedNear reports the parent identity's gap when it opened
// within the window before the reparenting sample.
func (c *AnalysisContext) parentDisappearedNear(parentPID int, reparent stateChange) (processGap, bool) {
	for _, life := range c.orderedProcesses() {
		if life.Identity.PID != parentPID || life.Identity.StartTicks == 0 && life.Identity.PID == 0 {
			continue
		}
		for _, gap := range life.Gaps {
			if gap.Identity.PID != parentPID || gap.Closed() || gap.From.After(reparent.At) {
				continue
			}
			// the gap must have opened no earlier than one sampling window
			// before the reparenting. without kernel timestamps, adjacency
			// is accepted, not causality.
			if gap.From.After(reparent.At.Add(orphanReparentWindow)) {
				continue
			}
			if gap.From.Before(reparent.At.Add(-orphanReparentWindow)) {
				continue
			}
			return gap, true
		}
	}
	return processGap{}, false
}

// triggerConsistentWithOrphan reports whether the incident trigger plausibly
// watched the parent side of the story: manual triggers and process-exit
// triggers on the departed PPID are consistent; a stop trigger on the child
// is the freeze story instead.
func triggerConsistentWithOrphan(ctx *AnalysisContext, child *ProcessLifetime, reparent stateChange) bool {
	trigger := ctx.Incident.Trigger
	switch trigger.Type {
	case "manual":
		return true
	case "process_exit":
		parentpid, ok := atoiSafe(reparent.From)
		return ok && trigger.PID == parentpid
	default:
		// A stop/exit trigger on the child contradicts; other trigger types
		// carry no orphan information and count as neutral-by-absence.
		return trigger.PID != child.Identity.PID
	}
}

func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 0
}

// ---------------------------------------------------------------------------
// PROCESS_GROUP_TERMINATION
// ---------------------------------------------------------------------------

const (
	groupKillMinimum   = 2
	coordinatedWindow  = 5 * time.Second
	wGroupShared       = 0.35
	wGroupCoordinated  = 0.20
	wGroupDidNotReturn = 0.15
	wGroupTrigger      = 0.10
	groupCap           = 0.85
)

// ProcessGroupTerminationSignature diagnoses several processes sharing a
// process group disappearing together (3.16).
type ProcessGroupTerminationSignature struct{}

func (ProcessGroupTerminationSignature) ID() SignatureID { return SignatureGroupKill }
func (ProcessGroupTerminationSignature) Description() string {
	return "detects several processes sharing a process group disappearing together"
}

func (s ProcessGroupTerminationSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("EXIT_SIGNAL_TELEMETRY")
	if !ctx.coverageOK(CoverProcesses) {
		return notMatched(SignatureGroupKill, "process telemetry was unavailable for most of the capture")
	}

	pgid, sites, groupsurvived := groupKillCandidate(ctx)
	if len(sites) < groupKillMinimum {
		if groupsurvived {
			// Real-runner S2: a job's process tree ends while its runner keeps
			// running, so the group lost members but was not terminated.
			return notMatched(SignatureGroupKill, "a process group lost members together but other members of that group kept running")
		}
		return notMatched(SignatureGroupKill, "no process group lost multiple members at the same time")
	}
	cc.support(Evidence{Code: CodeSharedProcessGroup, Source: SourceProcess, At: sites[0].gap.From, Weight: wGroupShared,
		Observed: map[string]any{"pgid": pgid, "vanished": len(sites)}, Threshold: groupKillMinimum})
	cc.support(Evidence{Code: CodeCoordinatedTermination, Source: SourceProcess, At: sites[0].gap.From, Weight: wGroupCoordinated,
		Observed: map[string]any{"window_ms": coordinatedWindow.Milliseconds(), "span_ms": sites[len(sites)-1].gap.From.Sub(sites[0].gap.From).Milliseconds()}})
	cc.processGroup(pgid)
	for _, site := range sites {
		cc.process(site.life.Identity.PID, site.life.Identity.StartTicks)
	}
	cc.attr("pgid", itoa(pgid))
	cc.attr("vanished", itoa(len(sites)))

	if ctx.groupDidNotReturn(pgid, sites) {
		cc.support(Evidence{Code: CodeProcessesDidNotReturn, Source: SourceProcess, At: ctx.End, Weight: wGroupDidNotReturn, Observed: true})
	}
	if triggerInGroup(ctx, pgid) {
		cc.support(Evidence{Code: CodeTriggerInGroup, Source: SourceTrigger, At: ctx.Incident.TriggeredAt, Weight: wGroupTrigger})
	} else {
		cc.reject(Evidence{Code: CodeNoSharedProcessGroup, Source: SourceTrigger, At: ctx.Incident.TriggeredAt, Weight: wGroupTrigger})
	}

	score, sup, contra := cc.score(groupCap)
	match := SignatureMatch{
		SignatureID: SignatureGroupKill,
		Confidence:  score,
		Summary:     "several members of one process group disappeared together",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

type groupDeparture struct {
	life *ProcessLifetime
	gap  processGap
}

// groupKillCandidate scans process groups in PGID order and returns the
// group with the most members whose absence started within the coordinated
// window, listing those members sorted by departure time. A group is only a
// candidate when nothing in it was observed after the last departure: a
// subtree ending inside a live process group (a runner's job tree, whose
// worker inherits the listener's group) is a normal teardown, not a group
// termination. groupSurvived reports that a multi-member departure was seen
// but failed that test.
func groupKillCandidate(ctx *AnalysisContext) (int, []groupDeparture, bool) {
	bestpgid := 0
	var best []groupDeparture
	survived := false
	for _, pgid := range ctx.orderedGroups() {
		var sites []groupDeparture
		for _, key := range ctx.groupMembers(pgid) {
			life := ctx.Process[key]
			for _, gap := range life.Gaps {
				if !gap.Closed() {
					sites = append(sites, groupDeparture{life: life, gap: gap})
					break
				}
			}
		}
		sites = orderGroupDepartures(sites)
		sites = dropIntended(ctx, sites)
		sites = ctx.dropTracedNormalExits(sites)
		left, start, end := 0, 0, 0
		for right := range sites {
			for sites[right].gap.From.Sub(sites[left].gap.From) > coordinatedWindow {
				left++
			}
			if right-left+1 > end-start {
				start, end = left, right+1
			}
		}
		if end-start < groupKillMinimum {
			continue
		}
		if ctx.groupMemberSurvived(pgid, sites[end-1].gap.From) {
			survived = true
			continue
		}
		if end-start > len(best) {
			bestpgid = pgid
			best = append([]groupDeparture(nil), sites[start:end]...)
		}
	}
	return bestpgid, best, survived
}

// groupMemberSurvived reports whether any member of pgid was still observed
// after the last coordinated departure.
func (c *AnalysisContext) groupMemberSurvived(pgid int, last time.Time) bool {
	for _, key := range c.groupMembers(pgid) {
		life := c.Process[key]
		if life == nil {
			continue
		}
		if life.LastSeen.After(last) {
			return true
		}
	}
	return false
}

// dropIntended removes departures a provider intent explains (T2), so a group
// whose members were all cancelled or shut down is not a group kill. an intent
// that ends the runner's tree (service stop, self-update, ephemeral
// completion) explains the whole collapse: the section can only name the
// members that were role-tagged, and on a real runner an update leaves
// untagged job processes behind whose exit would otherwise look like a kill.
func dropIntended(ctx *AnalysisContext, sites []groupDeparture) []groupDeparture {
	kept := sites[:0:0]
	for _, site := range sites {
		if ctx.explainedByIntent(site.life.Identity, site.gap.From) {
			if ctx.runnerTreeIntentCovers(site.life.Identity, site.gap.From) {
				return nil
			}
			continue
		}
		// A stated job outcome covers the job's whole tree, not only the
		// role-tagged processes the provider section names. Real-runner run
		// 41950041166: a SUCCEEDED job's leftover children were SIGKILLed at
		// job end, in their own process group, and this rule is what keeps
		// that cleanup from being reported as a group kill.
		if ctx.jobTreeIntentCovers(site.life.Identity, site.gap.From) {
			continue
		}
		kept = append(kept, site)
	}
	return kept
}

// dropTracedNormalExits removes departures the kernel tracer observed as a
// normal exit of that exact incarnation. A process that called exit() was not
// killed as part of a group, so its disappearance from the snapshot table is
// explained evidence, not an unexplained gap. only normal exits are dropped:
// a signalled exit (or no traced exit at all) stays a candidate, so a group
// killed with SIGKILL is still reported.
//
// Real-runner regression (2026-11-04, selfhosted-e2e run 41935809421): with
// the tracer active and lossless, a job GitHub reports SUCCEEDED produced
// PROCESS_GROUP_TERMINATION, because the job's shell and worker had exited
// normally into a process group of their own and the signature only ever saw
// that the PIDs stopped appearing. the tracer knew the exit cause all along;
// the diagnosis layer simply never read it.
func (c *AnalysisContext) dropTracedNormalExits(sites []groupDeparture) []groupDeparture {
	kept := sites[:0:0]
	for _, site := range sites {
		if c.tracedNormalExit(site.life.Identity) {
			continue
		}
		kept = append(kept, site)
	}
	return kept
}

// tracedNormalExit reports whether a TRACE_PROCESS_EXIT for this identity
// carries an exit code rather than a signal. identity must match exactly when
// both sides know it; a PID-only tracer record is matched on PID alone, since
// it is the record the merge would have paired with this incarnation.
func (c *AnalysisContext) tracedNormalExit(id identity) bool {
	for i := range c.Events {
		e := &c.Events[i]
		if e.Type != incident.TraceProcessExit || e.PID != id.PID {
			continue
		}
		if e.StartTicks != 0 && id.StartTicks != 0 && e.StartTicks != id.StartTicks {
			continue
		}
		if len(e.ExitStatus) <= len("exit:") || e.ExitStatus[:len("exit:")] != "exit:" {
			continue
		}
		if code, err := strconv.Atoi(e.ExitStatus[len("exit:"):]); err == nil && code >= 0 {
			return true
		}
	}
	return false
}

func orderGroupDepartures(sites []groupDeparture) []groupDeparture {
	sort.SliceStable(sites, func(i, j int) bool {
		if !sites[i].gap.From.Equal(sites[j].gap.From) {
			return sites[i].gap.From.Before(sites[j].gap.From)
		}
		return sites[i].life.Identity.less(sites[j].life.Identity)
	})
	return sites
}

// groupDidNotReturn reports whether none of the vanished members came back
// before capture end.
func (c *AnalysisContext) groupDidNotReturn(pgid int, sites []groupDeparture) bool {
	_ = pgid
	for _, site := range sites {
		if site.gap.Closed() {
			return false
		}
	}
	return len(sites) > 0
}

func triggerInGroup(ctx *AnalysisContext, pgid int) bool {
	trigger := ctx.Incident.Trigger
	if trigger.Type == "manual" {
		return true
	}
	for _, key := range ctx.groupMembers(pgid) {
		if key.PID == trigger.PID {
			return true
		}
	}
	return false
}
