package causal

import (
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

// 4.37 counterfactual corpus (docs/reviews/phase4-principal-audit.md, adversarial
// acceptance criteria). each case asserts a CONCLUSION level, not edge
// counts: a removal must change the conclusion in the stated direction and
// must never strengthen it. pairs that need a kernel OOM record are not in
// this corpus: that rule is dormant on v1 bundles (TestV1BundlesCannotSupport
// SignalBoundRules), so such a pair would pass vacuously.

// conclusion summarises what a graph claims about its failures.
type conclusion struct {
	healthy   bool
	anchors   map[EventType]FailureStatus
	chainBand map[EventType]CausalConfidence
}

func summarize(t *testing.T, events []Event, origin time.Time) conclusion {
	t.Helper()
	g := graphFrom(t, events)
	if _, err := NewEngine(Rules(), origin).Apply(g, nil); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("graph invalid: %v", err)
	}
	c := conclusion{
		healthy:   g.Healthy(),
		anchors:   map[EventType]FailureStatus{},
		chainBand: map[EventType]CausalConfidence{},
	}
	for _, analysis := range g.FailureAnalyses() {
		c.anchors[analysis.AnchorType] = analysis.Status
		for _, cand := range analysis.Candidates {
			if ev := g.Get(cand.Event); ev != nil {
				c.chainBand[ev.Type] = cand.Confidence
			}
		}
	}
	return c
}

// rank orders statuses from strongest claim to none, so a counterfactual can
// be checked for never strengthening.
func statusRank(s FailureStatus) int {
	switch s {
	case StatusExplained:
		return 2
	case StatusAmbiguous:
		return 1
	}
	// UNKNOWN makes no causal claim, so it ranks with "no anchor": a removal
	// that surfaces an unexplained failure (e.g. member exits once their
	// group event is gone) does not strengthen anything (re-audit R8).
	return 0
}

func bandWeight(b CausalConfidence) int {
	switch b {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	}
	return 0
}

type cfCase struct {
	name string
	// base and counterfactual are the full event sets; origin is shared.
	base, without []Event
	// wantAnchorGone: the failure anchor of this type must disappear.
	// wantAnchorUnknown: the anchor must remain but be UNKNOWN, not EXPLAINED.
	// wantAnchorExplained: the BASE (with-evidence) case must present this
	// anchor as EXPLAINED, so the pair is never vacuous.
	// wantHealthy: the counterfactual graph must report healthy.
	wantAnchorGone      EventType
	wantAnchorUnknown   EventType
	wantAnchorExplained EventType
	wantHealthy         bool
}

// memoryBase builds pressure → limit on one host episode, followed by a
// process exit, so the limit is the failure anchor with a credible chain.
func memoryBase(base time.Time) []Event {
	host := SubjectRef{SubjectHost, "local"}
	ep := "memory:host:local#1"
	return []Event{
		withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), ep),
		withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, nil), ep),
		baseEvent(EventProcessExited, base.Add(1500*time.Millisecond), processSubject(5842, 100), nil),
	}
}

func without(events []Event, drop EventType) []Event {
	out := make([]Event, 0, len(events))
	for _, e := range events {
		if e.Type != drop {
			out = append(out, e)
		}
	}
	return out
}

// hasRuleEdge reports whether the graph carries an edge from the named rule.
func hasRuleEdge(g *Graph, ruleID string) (CausalConfidence, bool) {
	for _, edge := range g.Edges {
		if edge.RuleID == ruleID {
			return edge.Confidence, true
		}
	}
	return "", false
}

// audit pairs 7, 8 and 13 on the reparent and memory chains.
func TestCounterfactualReparentAndDiscontinuity(t *testing.T) {
	base := baseStart()
	parentexit := baseEvent(EventProcessExited, base.Add(time.Second), processSubject(7, 100), nil)
	parentexit.PID = 7
	parentexit.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("exit", "parent")}}
	childprov := EventProvenance{Sources: []ProvenanceSource{provenance("reparent", "child")}}

	apply := func(events []Event) *Graph {
		t.Helper()
		g := graphFrom(t, events)
		if _, err := NewEngine(Rules(), base).Apply(g, nil); err != nil {
			t.Fatalf("apply rules: %v", err)
		}
		if err := g.Validate(); err != nil {
			t.Fatalf("graph invalid: %v", err)
		}
		return g
	}

	// pair 7: the child is first seen already under PPID 1 (init). its lineage
	// names no exited parent, so no reparent edge may be produced.
	orphaninit := baseEvent(EventProcessReparented, base.Add(2*time.Second), processSubject(8, 200), nil)
	orphaninit.PPID = 1
	orphaninit.PID = 8
	orphaninit.Provenance = childprov
	if _, ok := hasRuleEdge(apply([]Event{parentexit, orphaninit}), "PROCESS_EXIT_CAUSES_REPARENT@2"); ok {
		t.Error("pair 7: reparent under PPID 1 must not link to the parent exit")
	}

	// pair 8 base: the child is reparented from PID 7 after the parent exit.
	linked := baseEvent(EventProcessReparented, base.Add(2*time.Second), processSubject(8, 200), nil)
	linked.PPID = 7
	linked.PID = 8
	linked.Provenance = childprov
	if _, ok := hasRuleEdge(apply([]Event{parentexit, linked}), "PROCESS_EXIT_CAUSES_REPARENT@2"); !ok {
		t.Fatal("pair 8 base: the exit→reparent edge is missing; counterfactual would be vacuous")
	}

	// pair 8: the child was already reparented BEFORE the parent exit. the
	// contradiction veto must remove the edge.
	earlyreparent := baseEvent(EventProcessReparented, base.Add(500*time.Millisecond), processSubject(8, 200), nil)
	earlyreparent.PPID = 7
	earlyreparent.PID = 8
	earlyreparent.Provenance = childprov
	if _, ok := hasRuleEdge(apply([]Event{parentexit, earlyreparent}), "PROCESS_EXIT_CAUSES_REPARENT@2"); ok {
		t.Error("pair 8: reparent observed before the parent exit must veto the edge")
	}

	// pair 13: a clock discontinuity between the endpoints caps the band at LOW.
	host := SubjectRef{SubjectHost, "local"}
	ep := "memory:host:local#1"
	pressure := withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), ep)
	limit := withEpisode(baseEvent(EventMemoryLimitReached, base.Add(2*time.Second), host, nil), ep)
	clean := apply([]Event{pressure, limit})
	if conf, ok := hasRuleEdge(clean, "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1"); !ok || conf == ConfidenceLow {
		t.Fatalf("pair 13 base: escalation edge missing or already LOW (ok=%v conf=%s)", ok, conf)
	}
	step := baseEvent(EventClockDiscontinuity, base.Add(time.Second), host, nil)
	dirty := apply([]Event{pressure, limit, step})
	if conf, ok := hasRuleEdge(dirty, "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1"); ok && conf != ConfidenceLow {
		t.Errorf("pair 13: discontinuity between endpoints left the edge at %s, want LOW", conf)
	}
}

// audit pair 9: two member exits in one PGID derive a group event; removing
// one member must remove the group event (no group claim from one exit).
func TestCounterfactualGroupMemberRemoval(t *testing.T) {
	base := baseStart()
	makeincident := func(members []int) *incident.Incident {
		inc := &incident.Incident{CaptureStart: base}
		for _, pid := range members {
			inc.Metadata.Processes = append(inc.Metadata.Processes, incident.ProcessMetadata{PID: pid, PGID: 7})
			inc.Events = append(inc.Events, incident.Event{
				Type: incident.ProcessExited, Timestamp: base.Add(time.Duration(pid-11) * time.Second),
				PID: pid, StartTicks: int64(pid) * 100,
			})
		}
		return inc
	}
	groupcount := func(members []int) int {
		return countType(BuildTimeline(makeincident(members)), EventProcessGroupTerminated)
	}
	if n := groupcount([]int{11, 12}); n != 1 {
		t.Fatalf("pair 9 base: want 1 group event from two member exits, got %d", n)
	}
	if n := groupcount([]int{11}); n != 0 {
		t.Errorf("pair 9: one member exit alone produced %d group events, want 0", n)
	}
}

// audit pair 14: an UNKNOWN sensor sample inside a memory episode must end
// the episode's recovery claim; no recovery is derived across it.
func TestCounterfactualUnknownSampleInsideEpisode(t *testing.T) {
	base := baseStart()
	total := uint64(1000)
	unknown := memSys(950, total)
	unknown.MemoryStatsAvailable = false
	snaps := []collector.Snapshot{
		snapAt(base, 0, memSys(950, total)),
		snapAt(base, time.Second, unknown),
		snapAt(base, 2*time.Second, memSys(10, total)),
	}
	basesnaps := []collector.Snapshot{
		snapAt(base, 0, memSys(950, total)),
		snapAt(base, time.Second, memSys(10, total)),
	}
	if countType(BuildTimeline(&incident.Incident{Snapshots: basesnaps, CaptureStart: base}), EventMemoryRecovered) != 1 {
		t.Fatal("pair 14 base: recovery missing without the UNKNOWN sample; counterfactual would be vacuous")
	}
	if n := countType(BuildTimeline(&incident.Incident{Snapshots: snaps, CaptureStart: base}), EventMemoryRecovered); n != 0 {
		t.Errorf("pair 14: recovery claimed across an UNKNOWN sample (%d events)", n)
	}
}

func TestCounterfactualCorpus(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	fs := SubjectRef{SubjectFilesystem, "/data"}
	diskep := "disk:/data#1"
	membase := memoryBase(base)

	// pair 12: disk exhausted at capture end; removing the exhaustion sample
	// must turn the disk anchor off. covered in engine_test; repeated here as
	// a corpus entry with the same direction check.
	diskwith := []Event{
		withEpisode(baseEvent(EventDiskPressureStarted, base, fs, nil), diskep),
		withEpisode(baseEvent(EventDiskExhausted, base.Add(time.Second), fs, map[string]any{"free_bytes": 0}), diskep),
	}

	// pair 10: pressure → recovery → pressure → limit, two episodes.
	twoepisodes := []Event{
		withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1"),
		withEpisode(baseEvent(EventMemoryRecovered, base.Add(2*time.Second), host, nil), "memory:host:local#1"),
		withEpisode(baseEvent(EventMemoryPressureStarted, base.Add(4*time.Second), host, nil), "memory:host:local#2"),
		withEpisode(baseEvent(EventMemoryLimitReached, base.Add(5*time.Second), host, nil), "memory:host:local#2"),
	}

	// pair 11: limit recovered before the process exits; the limit anchor
	// must not be presented as a strengthened chain.
	limitrecovered := []Event{
		withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1"),
		withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, nil), "memory:host:local#1"),
		withEpisode(baseEvent(EventMemoryRecovered, base.Add(1200*time.Millisecond), host, nil), "memory:host:local#1"),
		baseEvent(EventProcessExited, base.Add(1500*time.Millisecond), processSubject(5842, 100), nil),
	}

	// 4.37 pairs 3-6: the sampled-counter OOM chain (§3.2), the first OOM
	// chain edge that can fire on v1 recorder evidence.
	counteroom := oomCounterEvents(base, base.Add(300*time.Millisecond), oomCgroup, "signalled")

	cases := []cfCase{
		{
			// pair 1 analogue on v1: remove the limit crossing. the memory
			// anchor goes away; the pressure episode alone is not a failure.
			name:           "remove limit crossing: memory anchor disappears",
			base:           membase,
			without:        without(membase, EventMemoryLimitReached),
			wantAnchorGone: EventMemoryLimitReached,
		},
		{
			// pair 2: remove pressure, keep the limit. the limit anchor stays
			// but must not be EXPLAINED (its upstream onset is not observed).
			name:              "remove pressure onset: limit stays UNKNOWN, never EXPLAINED",
			base:              membase,
			without:           without(membase, EventMemoryPressureStarted),
			wantAnchorUnknown: EventMemoryLimitReached,
		},
		{
			// pair 3/4-style: the process exits normally, so no failure
			// process anchor is produced; the limit is still a severe
			// anchor, so the graph stays unhealthy.
			name:           "process exit removed: process anchor disappears, limit stays",
			base:           membase,
			without:        without(membase, EventProcessExited),
			wantAnchorGone: EventProcessExited,
		},
		{
			// pair 12: exhaustion sample removed; disk anchor disappears.
			name:           "remove disk exhaustion: no disk anchor, healthy",
			base:           diskwith,
			without:        without(diskwith, EventDiskExhausted),
			wantAnchorGone: EventDiskExhausted,
			wantHealthy:    true,
		},
		{
			// pair 10: recovery inserted between pressure and limit. the
			// second episode owns the limit; removing the recovery must not
			// create a cross-episode strengthening.
			name:    "two episodes: removing recovery does not strengthen",
			base:    twoepisodes,
			without: without(twoepisodes, EventMemoryRecovered),
		},
		{
			// pair 11: limit recovered before the exit. removing the recovery
			// must not turn the limit into a stronger chain to the exit.
			name:    "limit recovered before exit: removing recovery does not strengthen",
			base:    limitrecovered,
			without: without(limitrecovered, EventMemoryRecovered),
		},
		{
			// 4.37 pair 3 on the counter path: the counter OOM observation
			// names the kill window; removing it drops the chain into the
			// exit, which stays UNKNOWN (the exit is still a recorded
			// failure, but nothing explains it). removing must never
			// strengthen anything; the base must be EXPLAINED or the pair
			// is vacuous. the window/identity/normal-exit negatives live in
			// TestCounterfactualOomCounterPairs.
			name:                "remove counter OOM observation: exit anchor demotes to UNKNOWN",
			base:                counteroom,
			without:             without(counteroom, EventOOM),
			wantAnchorExplained: EventProcessExited,
			wantAnchorUnknown:   EventProcessExited,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			origin := base
			with := summarize(t, tc.base, origin)
			wo := summarize(t, tc.without, origin)

			if tc.wantAnchorGone != "" {
				if _, present := wo.anchors[tc.wantAnchorGone]; present {
					t.Errorf("removing %s left its anchor: %+v", tc.wantAnchorGone, wo.anchors)
				}
				if _, present := with.anchors[tc.wantAnchorGone]; !present {
					t.Errorf("base case lacks the %s anchor; counterfactual is vacuous", tc.wantAnchorGone)
				}
			}
			if tc.wantAnchorUnknown != "" {
				got, present := wo.anchors[tc.wantAnchorUnknown]
				if !present {
					t.Fatalf("anchor %s vanished; want it kept as UNKNOWN", tc.wantAnchorUnknown)
				}
				if got != StatusUnknown {
					t.Errorf("anchor %s = %s, want UNKNOWN (upstream onset not observed)", tc.wantAnchorUnknown, got)
				}
			}
			if tc.wantAnchorExplained != "" {
				got, present := with.anchors[tc.wantAnchorExplained]
				if !present {
					t.Fatalf("anchor %s vanished; want it present as EXPLAINED", tc.wantAnchorExplained)
				}
				if got != StatusExplained {
					t.Errorf("anchor %s = %s in the base case, want EXPLAINED (the evidence chain must carry it or the pair is vacuous)", tc.wantAnchorExplained, got)
				}
			}
			if tc.wantHealthy && !wo.healthy {
				t.Errorf("counterfactual should be healthy: anchors=%+v", wo.anchors)
			}
			// never strengthens: every anchor's status can only stay or weaken.
			for anchor, wostatus := range wo.anchors {
				if withstatus, ok := with.anchors[anchor]; ok && statusRank(wostatus) > statusRank(withstatus) {
					t.Errorf("removal strengthened %s: %s -> %s", anchor, withstatus, wostatus)
				}
			}
			for cause, woband := range wo.chainBand {
				if withband, ok := with.chainBand[cause]; ok && bandWeight(woband) > bandWeight(withband) {
					t.Errorf("removal strengthened chain band for %s: %s -> %s", cause, withband, woband)
				}
			}
		})
	}
}

// oomCgroup is the killing cgroup path shared by the counter-path pairs.
const oomCgroup = "/system.slice/runner-worker-123"

// oomCounterEvents builds the sampled-counter OOM chain (§3.2) the way the
// extractor emits it: an OOM observation stamped at the open of the kill
// window it names, and a member exit of that cgroup carrying the exit's own
// cgroup stamp in its recorded data.
func oomCounterEvents(base, exitAt time.Time, cgroupStamp, exitState string) []Event {
	cg := SubjectRef{SubjectCgroup, oomCgroup}
	oom := baseEvent(EventOOM, base, cg, map[string]any{
		"oom_kill_delta": int64(1),
		"oom_kill_total": uint64(1),
		"interval_start": base.Format(time.RFC3339Nano),
		"interval_end":   base.Add(500 * time.Millisecond).Format(time.RFC3339Nano),
	})
	oom.Provenance = EventProvenance{RuleID: RuleOOMKillCounter, Sources: []ProvenanceSource{provenance("cgroup_sample", "worker")}}
	exit := baseEvent(EventProcessExited, exitAt, processSubject(5842, 100), map[string]any{
		"cgroup":     cgroupStamp,
		"exit_state": exitState,
	})
	exit.PID = 5842
	return []Event{oom, exit}
}

// TestCounterfactualOomCounterPairs asserts 4.37 pairs 4-6 over the
// sampled-counter OOM telemetry path (pair 3 is a corpus case above): the
// first OOM chain edge that can fire on v1 recorder evidence. each pair
// asserts a CONCLUSION (edge presence and its band), not telemetry presence.
func TestCounterfactualOomCounterPairs(t *testing.T) {
	base := baseStart()
	victim := base.Add(300 * time.Millisecond)

	apply := func(t *testing.T, events []Event) *Graph {
		t.Helper()
		g := graphFrom(t, events)
		if _, err := NewEngine(Rules(), base).Apply(g, nil); err != nil {
			t.Fatalf("apply rules: %v", err)
		}
		if err := g.Validate(); err != nil {
			t.Fatalf("graph invalid: %v", err)
		}
		return g
	}

	// pair 3 base-state check (also asserted by the corpus case): the chain
	// fires on counter telemetry and carries the exit at MEDIUM band.
	withoom := apply(t, oomCounterEvents(base, victim, oomCgroup, "signalled"))
	band, ok := hasRuleEdge(withoom, "CGROUP_OOM_KILLS_MEMBER@1")
	if !ok {
		t.Fatal("counter-path OOM chain did not fire on v1 evidence")
	}
	if band != ConfidenceMedium {
		t.Errorf("counter-path chain band = %s, want MEDIUM (member-level certainty; kernel victim records upgrade later)", band)
	}

	// pair 4: identity negative. the exit's own cgroup stamp names another
	// cgroup, so this counter cannot name this victim; no chain fires.
	mismatch := apply(t, oomCounterEvents(base, victim, "/other/container", "signalled"))
	if _, ok := hasRuleEdge(mismatch, "CGROUP_OOM_KILLS_MEMBER@1"); ok {
		t.Error("fired for an exit whose recorded cgroup is not the killing cgroup")
	}

	// pair 5: window negative. the exit is recorded after the kill window
	// closed, so this rise cannot be that exit's kill; no chain fires.
	late := apply(t, oomCounterEvents(base, base.Add(700*time.Millisecond), oomCgroup, "signalled"))
	if _, ok := hasRuleEdge(late, "CGROUP_OOM_KILLS_MEMBER@1"); ok {
		t.Error("fired for an exit recorded after the kill window closed")
	}

	// pair 6: normal-exit negative. A member exiting normally inside the
	// window is context, not the kernel's victim; no chain fires.
	normal := apply(t, oomCounterEvents(base, victim, oomCgroup, "normal"))
	if _, ok := hasRuleEdge(normal, "CGROUP_OOM_KILLS_MEMBER@1"); ok {
		t.Error("fired for a normally exiting member")
	}
}

// TestCounterfactualNetworkStallChain asserts 4.37 pair 15 over the live
// socket-stall chain (PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1). the
// stall is ClassCondition, never a failure anchor (§5.2), so the chain's
// pair conclusion lives at the edge level: with the recorder's tier B
// telemetry the chain fires at its HIGH ceiling, and removing either the
// stop or the stall shape refuses the edge. Anchor-level counterfactuals
// for this chain arrive with the generic worker-progress event (N2, §7.4).
func TestCounterfactualNetworkStallChain(t *testing.T) {
	base := baseStart()
	stallevents := func(recvQ float64) []Event {
		stop := baseEvent(EventProcessStopped, base, processSubject(42, 900), nil)
		stop.PID, stop.StartTicks = 42, 900
		// distinct provenance sources: two events derived from the same
		// single evidence line cannot propose an edge against each other (P2).
		stop.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("process_sample", "42")}}
		stall := baseEvent(EventNetworkProgressStopped, base.Add(20*time.Second),
			SubjectRef{SubjectSocket, "inode-9"}, map[string]any{"recv_q": recvQ})
		stall.PID, stall.StartTicks = 42, 900
		stall.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("socket_sample", "9")}}
		return []Event{stop, stall}
	}
	apply := func(t *testing.T, events []Event) *Graph {
		t.Helper()
		g := graphFrom(t, events)
		if _, err := NewEngine(Rules(), base).Apply(g, nil); err != nil {
			t.Fatalf("apply rules: %v", err)
		}
		if err := g.Validate(); err != nil {
			t.Fatalf("graph invalid: %v", err)
		}
		return g
	}

	// with the full telemetry the chain fires: the stopped identity owns the
	// socket and the unread receive queue is the LOCAL_NOT_READING shape.
	// the evaluated band is MEDIUM, not the rule's HIGH ceiling: socket
	// ownership rests on sampled state, which carries the D6 demotion (
	// §2.2) that caps the band.
	withstall := apply(t, stallevents(4096))
	band, ok := hasRuleEdge(withstall, "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1")
	if !ok {
		t.Fatal("the socket-stall chain did not fire with its recorded telemetry")
	}
	if band != ConfidenceMedium {
		t.Errorf("stall chain band = %s, want MEDIUM (D6: sampled socket ownership caps the rule's HIGH ceiling)", band)
	}

	// remove the stall event: no shape to bind, no edge. the stop stays
	// context.
	nostall := without(stallevents(4096), EventNetworkProgressStopped)
	if _, ok := hasRuleEdge(apply(t, nostall), "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1"); ok {
		t.Error("stall chain fired without the stall event")
	}

	// remove the stop: the shape alone cannot name a stopped reader, no
	// edge.
	nostop := without(stallevents(4096), EventProcessStopped)
	if _, ok := hasRuleEdge(apply(t, nostop), "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1"); ok {
		t.Error("stall chain fired without the stopped process")
	}

	// shape negative: an empty receive queue says we were reading, so the
	// stopped process is not the mechanism.
	if _, ok := hasRuleEdge(apply(t, stallevents(0)), "PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1"); ok {
		t.Error("stall chain fired on an empty receive queue")
	}
}
