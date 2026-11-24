package causal

import (
	"encoding/json"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

func baseStart() time.Time {
	return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
}

func snapAt(base time.Time, offset time.Duration, sys *collector.SystemSnapshot) collector.Snapshot {
	s := collector.Snapshot{Timestamp: base.Add(offset), System: sys}
	s.Metrics = nil // sections default OK: no error entries recorded
	return s
}

func memSys(used, total uint64) *collector.SystemSnapshot {
	return &collector.SystemSnapshot{
		MemoryStatsAvailable: true,
		MemoryTotal:          total,
		MemoryUsed:           used,
		DiskStatsAvailable:   false,
	}
}

func eventTypesOf(tl *Timeline) []EventType {
	out := make([]EventType, 0, len(tl.Events))
	for _, e := range tl.Events {
		out = append(out, e.Type)
	}
	return out
}

func countType(tl *Timeline, t EventType) int {
	count := 0
	for _, e := range tl.Events {
		if e.Type == t {
			count++
		}
	}
	return count
}

// TestThresholdCrossesOnce asserts the state machines emit STARTED, LIMIT and
// RECOVERY exactly once per episode, even when the sensor oscillates at the
// boundary (no duplicate emission; hysteresis holds).
func TestThresholdCrossesOnce(t *testing.T) {
	base := baseStart()
	total := uint64(1000)
	// oscillates at 99 (limit), stays inside the hysteresis band on dips.
	values := []float64{80, 92, 99, 99, 94, 99.5, 93, 20}
	snapshots := make([]collector.Snapshot, 0, len(values))
	for i, v := range values {
		used := uint64(v * 10)
		snapshots = append(snapshots, snapAt(base, time.Duration(i)*time.Second, memSys(used, total)))
	}
	inc := &incident.Incident{Snapshots: snapshots, CaptureStart: base}
	tl := BuildTimeline(inc)

	if got := countType(tl, EventMemoryPressureStarted); got != 1 {
		t.Errorf("MEMORY_PRESSURE_STARTED emitted %d times, want 1; events=%v", got, eventTypesOf(tl))
	}
	if got := countType(tl, EventMemoryLimitReached); got != 1 {
		t.Errorf("MEMORY_LIMIT_REACHED emitted %d times, want 1", got)
	}
	if got := countType(tl, EventMemoryRecovered); got != 1 {
		t.Errorf("MEMORY_RECOVERED emitted %d times, want 1", got)
	}
}

// TestConditionActiveAtCaptureStart asserts that a condition already in
// effect at the first available observation is reported as ACTIVE with
// OnsetUnknown - never as an invented start time (4.28).
func TestConditionActiveAtCaptureStart(t *testing.T) {
	base := baseStart()
	// first sample already above the threshold.
	inc := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapAt(base, 0, memSys(950, 1000)),
			snapAt(base, time.Second, memSys(950, 1000)),
		},
	}
	tl := BuildTimeline(inc)
	if countType(tl, EventMemoryPressureStarted) != 0 {
		t.Errorf("STARTED emitted although onset was outside the capture: %v", eventTypesOf(tl))
	}
	var active *Event
	for i := range tl.Events {
		if tl.Events[i].Type == EventMemoryPressureActive {
			active = &tl.Events[i]
		}
	}
	if active == nil {
		t.Fatalf("no MEMORY_PRESSURE_ACTIVE event; events=%v", eventTypesOf(tl))
	}
	if !active.OnsetUnknown {
		t.Errorf("ACTIVE event did not carry OnsetUnknown")
	}
}

// TestSensorGapNeverClaimsRecovery asserts that an unavailable memory section
// between a pressure episode and a low reading never bridges: recovery is not
// claimed across UNKNOWN telemetry.
func TestSensorGapNeverClaimsRecovery(t *testing.T) {
	base := baseStart()
	total := uint64(1000)
	failing := memSys(950, total)
	failing.MemoryStatsAvailable = false

	snapshots := []collector.Snapshot{
		snapAt(base, 0, memSys(950, total)),
		snapAt(base, time.Second, failing), // system section still OK but memory UNKNOWN
		snapAt(base, 2*time.Second, memSys(10, total)),
	}
	inc := &incident.Incident{Snapshots: snapshots, CaptureStart: base}
	tl := BuildTimeline(inc)
	if countType(tl, EventMemoryRecovered) != 0 {
		t.Errorf("recovery claimed across an unavailable sensor: %v", eventTypesOf(tl))
	}
}

// TestClockDiscontinuityDetectsBackwardJump asserts a wall-clock jump emits
// CLOCK_DISCONTINUITY instead of corrupting ordering (4.20).
func TestClockDiscontinuityDetectsBackwardJump(t *testing.T) {
	base := baseStart()
	backward := base.Add(-2 * time.Minute)
	snapshots := []collector.Snapshot{
		snapAt(base, 0, nil),
		snapAt(backward, 0, nil),
	}
	inc := &incident.Incident{Snapshots: snapshots, CaptureStart: base}
	tl := BuildTimeline(inc)
	if countType(tl, EventClockDiscontinuity) != 1 {
		t.Errorf("CLOCK_DISCONTINUITY = %d, want 1: %v", countType(tl, EventClockDiscontinuity), eventTypesOf(tl))
	}
}

// TestGroupTerminationRequiresCoordinatedWindow asserts two member exits are
// derived as one PROCESS_GROUP_TERMINATED only inside the coordinated window.
func TestGroupTerminationRequiresCoordinatedWindow(t *testing.T) {
	base := baseStart()
	makeincident := func(gap time.Duration) *incident.Incident {
		inc := &incident.Incident{CaptureStart: base}
		inc.Metadata.Processes = []incident.ProcessMetadata{
			{PID: 11, PGID: 7},
			{PID: 12, PGID: 7},
		}
		inc.Events = []incident.Event{
			{Type: incident.ProcessExited, Timestamp: base, PID: 11, StartTicks: 100},
			{Type: incident.ProcessExited, Timestamp: base.Add(gap), PID: 12, StartTicks: 200},
		}
		return inc
	}
	near := BuildTimeline(makeincident(2 * time.Second))
	if countType(near, EventProcessGroupTerminated) != 1 {
		t.Errorf("coordinated exits produced %d group events, want 1", countType(near, EventProcessGroupTerminated))
	}
	far := BuildTimeline(makeincident(30 * time.Second))
	if countType(far, EventProcessGroupTerminated) != 0 {
		t.Errorf("uncoordinated exits produced %d group events, want 0", countType(far, EventProcessGroupTerminated))
	}
}

// TestCGroupLimitCrossingOnce asserts one CGROUP_LIMIT_REACHED per episode
// and no event while below the fraction.
func TestCGroupLimitCrossingOnce(t *testing.T) {
	base := baseStart()
	snapshot := func(offset time.Duration, current, max uint64) collector.Snapshot {
		s := collector.Snapshot{Timestamp: base.Add(offset)}
		s.Processes = []collector.ProcessSnapshot{{
			Cgroup: &platform.CgroupSnapshot{
				Path:                   "/runner/w1",
				MemoryCurrentAvailable: true,
				MemoryMaxAvailable:     true,
				MemoryCurrent:          current,
				MemoryMax:              max,
			},
		}}
		return s
	}
	inc := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{snapshot(time.Second, 500, 1000), // below
			snapshot(2*time.Second, 990, 1000), // crossing
			snapshot(3*time.Second, 995, 1000), // stays high: no duplicate
			snapshot(4*time.Second, 500, 1000), // drops below: episode closed
			snapshot(5*time.Second, 992, 1000), // new crossing: new episode
		},
	}
	tl := BuildTimeline(inc)
	if got := countType(tl, EventCgroupLimitReached); got != 2 {
		t.Errorf("CGROUP_LIMIT_REACHED = %d, want 2 (one per episode)", got)
	}
}

// TestCPUSaturationRequiresSustain asserts an instant spike never emits a
// saturation episode; a sustained one does (4.27 transient-vs-persistent).
func TestCPUSaturationRequiresSustain(t *testing.T) {
	base := baseStart()
	proc := func(percent float64, offset time.Duration) collector.ProcessSnapshot {
		return collector.ProcessSnapshot{
			Process:    platform.Process{PID: 3, StartTicks: 5, State: "S", Name: "worker"},
			CPUPercent: percent,
		}
	}
	snapshotat := func(offset time.Duration, percent float64) collector.Snapshot {
		s := collector.Snapshot{Timestamp: base.Add(offset)}
		s.Processes = []collector.ProcessSnapshot{proc(percent, offset)}
		return s
	}
	short := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapshotat(0, 95),
			snapshotat(1e9, 95),
			snapshotat(2e9, 10),
		},
	}
	tlshort := BuildTimeline(short)
	if countType(tlshort, EventCPUSaturationStarted) != 0 {
		t.Errorf("transient spike produced a saturation episode: %v", eventTypesOf(tlshort))
	}

	sustained := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapshotat(0, 10), // unsaturated seed: onset known later
			snapshotat(1e9, 95),
			snapshotat(11e9, 95),
			snapshotat(15e9, 10),
		},
	}
	tlsustained := BuildTimeline(sustained)
	if countType(tlsustained, EventCPUSaturationStarted) != 1 {
		t.Errorf("sustained saturation = %d events, want 1", countType(tlsustained, EventCPUSaturationStarted))
	}
	if got := countType(tlsustained, EventCPUSaturationEnded); got != 1 {
		t.Errorf("saturation ended = %d events, want 1", got)
	}
}

// TestHealthyTimelineEmitsNoFailureEvents asserts a healthy workload produces
// no condition episodes at all.
func TestHealthyTimelineEmitsNoFailureEvents(t *testing.T) {
	base := baseStart()
	total := uint64(1000)
	sys := func(used uint64) *collector.SystemSnapshot {
		return &collector.SystemSnapshot{
			MemoryStatsAvailable: true,
			DiskStatsAvailable:   true,
			MemoryTotal:          total,
			MemoryUsed:           used,
			DiskFree:             500,
			DiskTotal:            1000,
			DiskFilesystem:       "/data",
		}
	}
	snapshots := []collector.Snapshot{
		snapAt(base, 0, sys(200)),
		snapAt(base, time.Second, sys(300)),
		snapAt(base, 2*time.Second, sys(100)),
	}
	tl := BuildTimeline(&incident.Incident{Snapshots: snapshots, CaptureStart: base})
	for _, e := range tl.Events {
		switch e.Type {
		case EventMemoryPressureStarted, EventMemoryPressureActive,
			EventMemoryLimitReached, EventDiskPressureStarted,
			EventDiskLowActive, EventDiskExhausted, EventCPUSaturationStarted:
			t.Errorf("healthy workload emitted failure event %s", e.Type)
		}
	}
}

// TestProcessExitStateFromIncidentEvent checks the exit-state handoff: the
// incident record's opportunistic status (a sampled zombie, platform
// capture) becomes the exit event's exit_state: exit:0 as "normal", every
// other non-empty value as itself, and the ordinary reaped exit stays
// UNKNOWN with no key at all.
func TestProcessExitStateFromIncidentEvent(t *testing.T) {
	base := baseStart()
	inc := &incident.Incident{CaptureStart: base, Events: []incident.Event{
		{Type: incident.ProcessExited, Timestamp: base, PID: 5, StartTicks: 9, ExitStatus: "signal:9"},
		{Type: incident.ProcessExited, Timestamp: base, PID: 6, StartTicks: 10, ExitStatus: "exit:0"},
		{Type: incident.ProcessExited, Timestamp: base, PID: 7, StartTicks: 11},
	}}
	tl := BuildTimeline(inc)
	state := map[int]string{}
	present := map[int]bool{}
	for _, e := range tl.Events {
		if e.Type == EventProcessExited {
			state[e.PID], present[e.PID] = e.Data["exit_state"].(string)
		}
	}
	if !present[5] || state[5] != "signal:9" {
		t.Errorf("signal exit state = %q (present %v), want signal:9", state[5], present[5])
	}
	if !present[6] || state[6] != "normal" {
		t.Errorf("clean exit state = %q (present %v), want normal", state[6], present[6])
	}
	if present[7] || state[7] != "" {
		t.Errorf("unobserved exit recorded state %q; want UNKNOWN (no key)", state[7])
	}
}

// TestTimelineIsDeterministic asserts identical input produces byte-identical
// events (phase 4 contract).
func TestTimelineIsDeterministic(t *testing.T) {
	base := baseStart()
	total := uint64(1000)
	inc := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapAt(base, 0, memSys(950, total)),
			snapAt(base, time.Second, memSys(940, total)),
		},
		Events: []incident.Event{
			{Type: incident.ProcessExited, Timestamp: base.Add(time.Second), PID: 5, StartTicks: 9},
		},
	}
	first := BuildTimeline(inc)
	second := BuildTimeline(inc)
	a, err := json.Marshal(first.Events)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(second.Events)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("identical incident produced different timelines")
	}
}

// TestDerivedEventsCarryRuleProvenance asserts every derived event names its
// versioned rule (4.17/4.18).
func TestDerivedEventsCarryRuleProvenance(t *testing.T) {
	base := baseStart()
	snapshot := func(offset time.Duration, current, max uint64) collector.Snapshot {
		s := collector.Snapshot{Timestamp: base.Add(offset)}
		s.Processes = []collector.ProcessSnapshot{{
			Cgroup: &platform.CgroupSnapshot{
				Path:                   "/runner/w1",
				MemoryCurrentAvailable: true,
				MemoryMaxAvailable:     true,
				MemoryCurrent:          current,
				MemoryMax:              max,
			},
		}}
		return s
	}
	inc := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapshot(0, 500, 1000),
			snapshot(time.Second, 990, 1000),
		},
	}
	tl := BuildTimeline(inc)
	for _, e := range tl.Events {
		if e.Subject.Kind == SubjectCgroup && e.Type == EventCgroupLimitReached {
			if e.Provenance.RuleID != RuleCgroupLimit {
				t.Errorf("cgroup event provenance rule = %q, want %q", e.Provenance.RuleID, RuleCgroupLimit)
			}
			if len(e.Provenance.Sources) == 0 {
				t.Errorf("cgroup event has no provenance sources")
			}
		}
	}
}

// TestCaptureStartingAtLimitKeepsLimitFact asserts a bundle whose first usable
// sample is already at the limit still records the limit fact, marked as an
// onset-unknown observation rather than an invented crossing time (4.28).
func TestCaptureStartingAtLimitKeepsLimitFact(t *testing.T) {
	base := baseStart()
	inc := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapAt(base, 0, memSys(995, 1000)),
			snapAt(base, time.Second, memSys(997, 1000)),
		},
	}
	tl := BuildTimeline(inc)
	if got := countType(tl, EventMemoryPressureStarted); got != 0 {
		t.Errorf("STARTED emitted although the onset predates the capture: %v", eventTypesOf(tl))
	}
	if got := countType(tl, EventMemoryPressureActive); got != 1 {
		t.Errorf("MEMORY_PRESSURE_ACTIVE = %d, want 1; events=%v", got, eventTypesOf(tl))
	}
	if got := countType(tl, EventMemoryLimitReached); got != 1 {
		t.Errorf("MEMORY_LIMIT_REACHED = %d, want 1 (the boundary fact was lost); events=%v", got, eventTypesOf(tl))
	}
	for _, e := range tl.Events {
		if e.Type == EventMemoryLimitReached && !e.OnsetUnknown {
			t.Errorf("limit fact at the first observation claimed an observed onset")
		}
	}
}

// TestCaptureStartingExhaustedKeepsExhaustionFact is the disk equivalent: an
// already-exhausted filesystem at capture start is still reported.
func TestCaptureStartingExhaustedKeepsExhaustionFact(t *testing.T) {
	base := baseStart()
	sys := func(free uint64) *collector.SystemSnapshot {
		return &collector.SystemSnapshot{
			DiskStatsAvailable: true, DiskTotal: 1000, DiskFree: free, DiskFilesystem: "/data",
		}
	}
	inc := &incident.Incident{
		CaptureStart: base,
		Snapshots: []collector.Snapshot{
			snapAt(base, 0, sys(42)),
			snapAt(base, time.Second, sys(30)),
		},
	}
	tl := BuildTimeline(inc)
	if got := countType(tl, EventDiskPressureStarted); got != 0 {
		t.Errorf("DISK_PRESSURE_STARTED emitted although onset predates the capture: %v", eventTypesOf(tl))
	}
	if got := countType(tl, EventDiskLowActive); got != 1 {
		t.Errorf("DISK_LOW_ACTIVE = %d, want 1; events=%v", got, eventTypesOf(tl))
	}
	if got := countType(tl, EventDiskExhausted); got != 1 {
		t.Errorf("DISK_EXHAUSTED = %d, want 1 (the boundary fact was lost); events=%v", got, eventTypesOf(tl))
	}
}

// TestTimelineIgnoresInputArrayOrder asserts that recorded-event array order
// is not evidence: a shuffled event list yields the identical normalized
// timeline (recorded events carry their own timestamps; §10.1 keeps snapshot
// array order as capture order, so snapshots are NOT shuffled here).
func TestTimelineIgnoresInputArrayOrder(t *testing.T) {
	base := baseStart()
	build := func(shuffle bool) *incident.Incident {
		inc := &incident.Incident{
			CaptureStart: base,
			Snapshots: []collector.Snapshot{
				snapAt(base, 0, memSys(500, 1000)),
				snapAt(base, time.Second, memSys(950, 1000)),
				snapAt(base, 2*time.Second, memSys(995, 1000)),
				snapAt(base, 3*time.Second, memSys(950, 1000)),
			},
			Events: []incident.Event{
				{Type: incident.ProcessExited, Timestamp: base.Add(time.Second), PID: 11, StartTicks: 1},
				{Type: incident.ProcessExited, Timestamp: base.Add(1500 * time.Millisecond), PID: 12, StartTicks: 2},
			},
			Metadata: incident.Metadata{Processes: []incident.ProcessMetadata{
				{PID: 11, PGID: 7}, {PID: 12, PGID: 7},
			}},
		}
		if shuffle {
			// recorded events carry their own timestamps, so their array
			// order must change nothing.
			inc.Events[0], inc.Events[1] = inc.Events[1], inc.Events[0]
		}
		return inc
	}
	ordered := BuildTimeline(build(false))
	shuffled := BuildTimeline(build(true))
	if countType(ordered, EventClockDiscontinuity) != 0 {
		t.Fatalf("ordered build invented a clock discontinuity: %v", eventTypesOf(ordered))
	}
	type fact struct {
		Type      EventType
		Timestamp int64
		Subject   SubjectRef
	}
	facts := func(tl *Timeline) []fact {
		out := make([]fact, 0, len(tl.Events))
		for _, e := range tl.Events {
			if e.Type == EventClockDiscontinuity {
				continue
			}
			out = append(out, fact{e.Type, e.Timestamp.UnixNano(), e.Subject})
		}
		return out
	}
	a, b := facts(ordered), facts(shuffled)
	if len(a) != len(b) {
		t.Fatalf("shuffled input changed the event set: %d vs %d events\nordered=%v\nshuffled=%v",
			len(a), len(b), eventTypesOf(ordered), eventTypesOf(shuffled))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("event %d differs by input order: %+v vs %+v", i, a[i], b[i])
		}
	}
	if countType(shuffled, EventMemoryPressureStarted) != 1 || countType(shuffled, EventMemoryLimitReached) != 1 {
		t.Errorf("shuffled input changed episode extraction: %v", eventTypesOf(shuffled))
	}
}
