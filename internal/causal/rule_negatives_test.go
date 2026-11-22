package causal

import (
	"testing"
	"time"
)

// 4.39 rule-level negatives. each live rule gets a positive base that must
// produce its edge, then a negative that removes exactly one required
// condition (identity, episode, order, or gap). A negative that passes
// without its base firing would be vacuous, so every case checks the base.

// ruleEdgeCount applies the full rule set and counts edges from one rule.
func ruleEdgeCount(t *testing.T, events []Event, base time.Time, ruleID string) int {
	t.Helper()
	g := graphFrom(t, events)
	if _, err := NewEngine(Rules(), base).Apply(g, nil); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	n := 0
	for _, edge := range g.Edges {
		if edge.RuleID == ruleID {
			n++
		}
	}
	return n
}

// ruleEdgeCountOrRejects is ruleEdgeCount for a base case: on failure it
// reports the engine's rejection reasons so a missing edge is diagnosable.
func ruleEdgeCountOrRejects(t *testing.T, events []Event, base time.Time, ruleID string) int {
	t.Helper()
	g := graphFrom(t, events)
	if _, err := NewEngine(Rules(), base).Apply(g, nil); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	n := 0
	for _, edge := range g.Edges {
		if edge.RuleID == ruleID {
			n++
		}
	}
	if n == 0 {
		t.Logf("rejections: %+v", g.Rejected)
	}
	return n
}

func TestRuleNegativesMemoryEscalation(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	ep := "memory:host:local#1"
	const rule = "MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1"

	positive := []Event{
		withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), ep),
		withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, nil), ep),
	}
	if n := ruleEdgeCount(t, positive, base, rule); n != 1 {
		t.Fatalf("base: want 1 escalation edge, got %d", n)
	}

	t.Run("different episode instance", func(t *testing.T) {
		events := []Event{
			withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), ep),
			withEpisode(baseEvent(EventMemoryLimitReached, base.Add(time.Second), host, nil), "memory:host:local#2"),
		}
		if n := ruleEdgeCount(t, events, base, rule); n != 0 {
			t.Errorf("escalation across two episode instances produced %d edges", n)
		}
	})

	t.Run("limit before onset", func(t *testing.T) {
		events := []Event{
			withEpisode(baseEvent(EventMemoryPressureStarted, base.Add(time.Second), host, nil), ep),
			withEpisode(baseEvent(EventMemoryLimitReached, base, host, nil), ep),
		}
		if n := ruleEdgeCount(t, events, base, rule); n != 0 {
			t.Errorf("reversed order produced %d escalation edges", n)
		}
	})
}

func TestRuleNegativesRecoveryEpisodeLocal(t *testing.T) {
	base := baseStart()
	host := SubjectRef{SubjectHost, "local"}
	const rule = "MEMORY_RECOVERY_FOLLOWS_ONSET@2"

	positive := []Event{
		withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1"),
		withEpisode(baseEvent(EventMemoryRecovered, base.Add(time.Second), host, nil), "memory:host:local#1"),
	}
	if n := ruleEdgeCount(t, positive, base, rule); n != 1 {
		t.Fatalf("base: want 1 recovery edge, got %d", n)
	}

	t.Run("recovery of a different episode", func(t *testing.T) {
		events := []Event{
			withEpisode(baseEvent(EventMemoryPressureStarted, base, host, nil), "memory:host:local#1"),
			withEpisode(baseEvent(EventMemoryRecovered, base.Add(time.Second), host, nil), "memory:host:local#2"),
		}
		if n := ruleEdgeCount(t, events, base, rule); n != 0 {
			t.Errorf("recovery of another episode linked to this onset: %d edges", n)
		}
	})
}

func TestRuleNegativesCPUStopEndsSaturation(t *testing.T) {
	base := baseStart()
	worker := processSubject(9, 1)
	const rule = "PROCESS_STOP_ENDS_CPU_SATURATION@2"

	// the saturation end must be at or after the stop, for the same process.
	stop := baseEvent(EventProcessStopped, base, worker, nil)
	stop.PID, stop.StartTicks = 9, 1
	end := baseEvent(EventCPUSaturationEnded, base.Add(time.Second), worker, nil)
	end.PID, end.StartTicks = 9, 1
	positive := []Event{stop, end}
	if n := ruleEdgeCountOrRejects(t, positive, base, rule); n != 1 {
		t.Fatalf("base: want 1 stop→saturation-end edge, got %d", n)
	}

	t.Run("saturation ended before the stop", func(t *testing.T) {
		earlyend := baseEvent(EventCPUSaturationEnded, base, worker, nil)
		earlyend.PID, earlyend.StartTicks = 9, 1
		latestop := baseEvent(EventProcessStopped, base.Add(time.Second), worker, nil)
		latestop.PID, latestop.StartTicks = 9, 1
		if n := ruleEdgeCount(t, []Event{earlyend, latestop}, base, rule); n != 0 {
			t.Errorf("saturation end before the stop linked: %d edges", n)
		}
	})

	t.Run("different process identity", func(t *testing.T) {
		otherend := baseEvent(EventCPUSaturationEnded, base.Add(time.Second), processSubject(10, 2), nil)
		otherend.PID, otherend.StartTicks = 10, 2
		if n := ruleEdgeCount(t, []Event{stop, otherend}, base, rule); n != 0 {
			t.Errorf("stop of one process linked to another's saturation end: %d edges", n)
		}
	})

	t.Run("saturation end long after the stop", func(t *testing.T) {
		lateend := baseEvent(EventCPUSaturationEnded, base.Add(11*time.Second), worker, nil)
		lateend.PID, lateend.StartTicks = 9, 1
		if n := ruleEdgeCount(t, []Event{stop, lateend}, base, rule); n != 0 {
			t.Errorf("saturation end 10s after the stop linked despite MaxGap: %d edges", n)
		}
	})
}

// TestRuleNegativesReparentIdentity covers PROCESS_EXIT_CAUSES_REPARENT@2.
// the rule declares no MaxGap, so its boundary is identity: the child's typed
// PPID must name the exited parent's PID. audit pairs 7 and 8 cover the
// init-lineage and contradiction cases; this covers the identity mismatch.
func TestRuleNegativesReparentIdentity(t *testing.T) {
	base := baseStart()
	const rule = "PROCESS_EXIT_CAUSES_REPARENT@2"
	parentexit := baseEvent(EventProcessExited, base.Add(time.Second), processSubject(7, 100), nil)
	parentexit.PID = 7
	parentexit.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("exit", "parent")}}
	childprov := EventProvenance{Sources: []ProvenanceSource{provenance("reparent", "child")}}

	reparentfrom := func(ppid int) Event {
		e := baseEvent(EventProcessReparented, base.Add(2*time.Second), processSubject(8, 200), nil)
		e.PPID = ppid
		e.PID = 8
		e.Provenance = childprov
		return e
	}

	if n := ruleEdgeCountOrRejects(t, []Event{parentexit, reparentfrom(7)}, base, rule); n != 1 {
		t.Fatalf("base: want 1 exit→reparent edge, got %d", n)
	}

	t.Run("child names a different parent PID", func(t *testing.T) {
		if n := ruleEdgeCount(t, []Event{parentexit, reparentfrom(9)}, base, rule); n != 0 {
			t.Errorf("reparent from PPID 9 linked to exit of PID 7: %d edges", n)
		}
	})
}

// TestRuleNegativesReparentGap checks the MaxGap bound on
// PROCESS_EXIT_CAUSES_REPARENT@2: a reparent observed well after the exit
// must not link, because the sample does not show when the adoption happened.
func TestRuleNegativesReparentGap(t *testing.T) {
	base := baseStart()
	const rule = "PROCESS_EXIT_CAUSES_REPARENT@2"
	parentexit := baseEvent(EventProcessExited, base.Add(time.Second), processSubject(7, 100), nil)
	parentexit.PID = 7
	parentexit.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("exit", "parent")}}
	late := baseEvent(EventProcessReparented, base.Add(11*time.Second), processSubject(8, 200), nil)
	late.PPID = 7
	late.PID = 8
	late.Provenance = EventProvenance{Sources: []ProvenanceSource{provenance("reparent", "child")}}

	if n := ruleEdgeCount(t, []Event{parentexit, late}, base, rule); n != 0 {
		t.Errorf("reparent 10s after the exit linked despite MaxGap: %d edges", n)
	}
}

// withOOMRecordPresent swaps the two v1-unobservable OOM record checks for
// PRESENT evaluators, so the timing and direction contract of
// OOM_CAUSES_PROCESS_EXIT@2 can be exercised. without this, every pair is
// rejected as unobservable and a boundary test would pass vacuously. the
// registry is restored when the test ends.
func withOOMRecordPresent(t *testing.T) {
	t.Helper()
	present := func(g *Graph, src, tgt *Event) CheckResult {
		return CheckResult{Status: CheckPresent, Detail: "test-only: kernel OOM record assumed present"}
	}
	keys := []string{"OOM_RECORD_IDENTIFIES_VICTIM", "EXIT_NOT_NORMAL"}
	saved := map[string]CheckFunc{}
	for _, k := range keys {
		saved[k] = checkRegistry[k]
		checkRegistry[k] = present
	}
	t.Cleanup(func() {
		for _, k := range keys {
			checkRegistry[k] = saved[k]
		}
	})
}

// TestRuleNegativesOOMTimingBoundary covers the timing and direction contract
// of OOM_CAUSES_PROCESS_EXIT@2 (MaxGap 2 s) with the OOM record checks held
// PRESENT, so only the timing decides the outcome.
func TestRuleNegativesOOMTimingBoundary(t *testing.T) {
	base := baseStart()
	const rule = "OOM_CAUSES_PROCESS_EXIT@2"
	victim := processSubject(9, 1)

	pair := func(gap time.Duration) []Event {
		oom := baseEvent(EventOOM, base, victim, nil)
		exit := baseEvent(EventProcessExited, base.Add(gap), victim, nil)
		return []Event{oom, exit}
	}

	withOOMRecordPresent(t)

	if n := ruleEdgeCount(t, pair(time.Second), base, rule); n != 1 {
		t.Fatalf("base: OOM 1s before exit should link, got %d edges", n)
	}
	t.Run("gap exactly at MaxGap still links", func(t *testing.T) {
		if n := ruleEdgeCount(t, pair(2*time.Second), base, rule); n != 1 {
			t.Errorf("gap = MaxGap should link, got %d edges", n)
		}
	})
	t.Run("gap just past MaxGap does not link", func(t *testing.T) {
		if n := ruleEdgeCount(t, pair(2*time.Second+time.Millisecond), base, rule); n != 0 {
			t.Errorf("gap beyond MaxGap linked: %d edges", n)
		}
	})
	t.Run("gap of 3s does not link", func(t *testing.T) {
		if n := ruleEdgeCount(t, pair(3*time.Second), base, rule); n != 0 {
			t.Errorf("3s gap linked: %d edges", n)
		}
	})
	t.Run("exit before OOM does not link", func(t *testing.T) {
		oom := baseEvent(EventOOM, base.Add(time.Second), victim, nil)
		exit := baseEvent(EventProcessExited, base, victim, nil)
		if n := ruleEdgeCount(t, []Event{oom, exit}, base, rule); n != 0 {
			t.Errorf("exit before OOM linked: %d edges", n)
		}
	})
}

func TestRuleNegativesDiskEscalationIdentity(t *testing.T) {
	base := baseStart()
	fs := SubjectRef{SubjectFilesystem, "/data"}
	const rule = "DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1"

	positive := []Event{
		withEpisode(baseEvent(EventDiskPressureStarted, base, fs, nil), "disk:/data#1"),
		withEpisode(baseEvent(EventDiskExhausted, base.Add(time.Second), fs, nil), "disk:/data#1"),
	}
	if n := ruleEdgeCount(t, positive, base, rule); n != 1 {
		t.Fatalf("base: want 1 disk escalation edge, got %d", n)
	}

	t.Run("exhaustion on a different filesystem", func(t *testing.T) {
		events := []Event{
			withEpisode(baseEvent(EventDiskPressureStarted, base, fs, nil), "disk:/data#1"),
			withEpisode(baseEvent(EventDiskExhausted, base.Add(time.Second), SubjectRef{SubjectFilesystem, "/var"}, nil), "disk:/var#1"),
		}
		if n := ruleEdgeCount(t, events, base, rule); n != 0 {
			t.Errorf("exhaustion of another filesystem linked: %d edges", n)
		}
	})
}
