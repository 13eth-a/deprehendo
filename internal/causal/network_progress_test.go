package causal

import (
	"strings"
	"testing"
	"time"

	"runopsy/internal/collector"
)

func sock(inode uint64, acked, received uint64) collector.ConnectionSnapshot {
	return collector.ConnectionSnapshot{
		State: "ESTABLISHED", Inode: inode, ProgressAvailable: true,
		BytesAcked: acked, BytesReceived: received,
		LocalAddr: "10.0.0.1", LocalPort: 5000, RemoteAddr: "10.0.0.2", RemotePort: 443,
	}
}

// TestSocketOwnedByStoppedIdentityBindsOnIncarnation checks the ownership
// rule: the stall's recorded owner must be the stopped process incarnation.
// A reused PID with a different start time is a different process.
func TestSocketOwnedByStoppedIdentityBindsOnIncarnation(t *testing.T) {
	check := checkRegistry["SOCKET_OWNED_BY_STOPPED_IDENTITY"]
	stop := &Event{Type: EventProcessStopped, PID: 42, StartTicks: 900}

	cases := []struct {
		name string
		tgt  *Event
		want CheckResultStatus
	}{
		{"same incarnation", &Event{PID: 42, StartTicks: 900}, CheckPresent},
		{"reused PID, other start", &Event{PID: 42, StartTicks: 901}, CheckAbsent},
		{"other process", &Event{PID: 7, StartTicks: 900}, CheckAbsent},
		{"owner unresolved", &Event{}, CheckUnknown},
		{"owner pid without start", &Event{PID: 42}, CheckUnknown},
	}
	for _, tc := range cases {
		got := check(nil, stop, tc.tgt)
		if got.Status != tc.want {
			t.Errorf("%s: got %v, want %v (%s)", tc.name, got.Status, tc.want, got.Detail)
		}
	}
}

// TestNetworkStallRecordsOwnerIdentity checks that the STOPPED event carries
// the socket owner's typed identity, so the ownership rule can bind on it.
func TestNetworkStallRecordsOwnerIdentity(t *testing.T) {
	var m networkMachine
	prov := EventProvenance{}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	owned := sock(9, 100, 100)
	owned.PID, owned.StartTicks = 42, 900
	m.observe(t0, []collector.ConnectionSnapshot{owned}, prov, true)
	m.observe(t0.Add(time.Second), []collector.ConnectionSnapshot{withOwner(sock(9, 200, 100), 42, 900)}, prov, true)
	ev := m.observe(t0.Add(40*time.Second), []collector.ConnectionSnapshot{withOwner(sock(9, 200, 100), 42, 900)}, prov, true)
	if len(ev) != 1 || ev[0].PID != 42 || ev[0].StartTicks != 900 {
		t.Fatalf("STOPPED owner = %d@%d, want 42@900 (%v)", ev[0].PID, ev[0].StartTicks, ev)
	}
}

func withOwner(c collector.ConnectionSnapshot, pid int, start int64) collector.ConnectionSnapshot {
	c.PID, c.StartTicks = pid, start
	return c
}

func TestNetworkMachineStopsAfterProgressAndResumes(t *testing.T) {
	var m networkMachine
	prov := EventProvenance{}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// progress is observed, then the counters freeze for longer than the stall threshold.
	if ev := m.observe(t0, []collector.ConnectionSnapshot{sock(7, 100, 100)}, prov, true); len(ev) != 0 {
		t.Fatalf("first sample emitted %v", ev)
	}
	if ev := m.observe(t0.Add(time.Second), []collector.ConnectionSnapshot{sock(7, 200, 100)}, prov, true); len(ev) != 0 {
		t.Fatalf("progress sample emitted %v", ev)
	}
	ev := m.observe(t0.Add(40*time.Second), []collector.ConnectionSnapshot{sock(7, 200, 100)}, prov, true)
	if len(ev) != 1 || ev[0].Type != EventNetworkProgressStopped {
		t.Fatalf("want one STOPPED after a 39s stall, got %v", ev)
	}
	stopepisode := ev[0].Episode
	if stopepisode == "" {
		t.Fatal("STOPPED carries no episode identity")
	}
	if ev[0].Subject != (SubjectRef{SubjectSocket, "inode-7"}) {
		t.Errorf("subject = %v", ev[0].Subject)
	}
	// the stalled state does not re-emit on every later frozen sample.
	if ev := m.observe(t0.Add(50*time.Second), []collector.ConnectionSnapshot{sock(7, 200, 100)}, prov, true); len(ev) != 0 {
		t.Errorf("repeat STOPPED emitted %v", ev)
	}
	ev = m.observe(t0.Add(60*time.Second), []collector.ConnectionSnapshot{sock(7, 300, 100)}, prov, true)
	if len(ev) != 1 || ev[0].Type != EventNetworkProgressResumed || ev[0].Episode != stopepisode {
		t.Fatalf("want one RESUMED, got %v", ev)
	}
}

func TestStallShapeLocalNotReadingReadsRecvQueue(t *testing.T) {
	check := checkRegistry["STALL_SHAPE_LOCAL_NOT_READING"]
	src := &Event{}

	present := check(nil, src, &Event{Data: map[string]any{"recv_q": 4096}})
	if present.Status != CheckPresent {
		t.Errorf("unread receive queue: got %v, want PRESENT", present.Status)
	}
	absent := check(nil, src, &Event{Data: map[string]any{"recv_q": 0}})
	if absent.Status != CheckAbsent {
		t.Errorf("empty receive queue: got %v, want ABSENT", absent.Status)
	}
	unknown := check(nil, src, &Event{Data: map[string]any{}})
	if unknown.Status != CheckUnknown {
		t.Errorf("missing receive queue: got %v, want UNKNOWN (never ABSENT)", unknown.Status)
	}
}

// TestStallShapeStamping (§7.2): the STOPPED event's tier A fields classify
// the stall shape, and RESUMED carries the open episode's latest shape. A
// sample with no tier A reading stamps UNKNOWN_SHAPE and records no queue
// keys. a zero value can always mean "observed empty", never "not captured".
func TestStallShapeStamping(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tiera := func(txq, rxq uint32, timer uint8, retr uint32, avail bool) collector.ConnectionSnapshot {
		c := sock(11, 1000, 1000)
		c.TxQueue, c.RxQueue, c.Timer, c.Retransmits, c.QueuesAvailable = txq, rxq, timer, retr, avail
		return c
	}
	stall := func(m *networkMachine, c collector.ConnectionSnapshot) Event {
		m.observe(t0, []collector.ConnectionSnapshot{sock(11, 1000, 1000)}, EventProvenance{}, true)
		m.observe(t0.Add(time.Second), []collector.ConnectionSnapshot{sock(11, 2000, 2000)}, EventProvenance{}, true)
		m.observe(t0.Add(time.Second), []collector.ConnectionSnapshot{c}, EventProvenance{}, true)
		ev := m.observe(t0.Add(40*time.Second), []collector.ConnectionSnapshot{c}, EventProvenance{}, true)
		if len(ev) != 1 || ev[0].Type != EventNetworkProgressStopped {
			t.Fatalf("want one STOPPED, got %v", ev)
		}
		return ev[0]
	}
	shape := func(ev Event) string { s, _ := ev.Data["stall_shape"].(string); return s }

	cases := []struct {
		name       string
		when       collector.ConnectionSnapshot
		wantShape  string
		wantQueues bool
	}{
		{
			name:       "peer silent: queues observed empty, no timer",
			when:       tiera(0, 0, 0, 0, true),
			wantShape:  StallShapePeerSilent,
			wantQueues: true,
		},
		{
			name:       "path loss: send queue with retransmit timer",
			when:       tiera(4096, 0, 1, 0, true),
			wantShape:  StallShapePathLoss,
			wantQueues: true,
		},
		{
			name:       "path loss: unrecovered RTO without timer",
			when:       tiera(4096, 0, 0, 3, true),
			wantShape:  StallShapePathLoss,
			wantQueues: true,
		},
		{
			name:       "zero window: probe timer armed",
			when:       tiera(2048, 0, 4, 0, true),
			wantShape:  StallShapeZeroWindow,
			wantQueues: true,
		},
		{
			name:       "local not reading: unread receive data wins",
			when:       tiera(0, 1<<20, 1, 0, true),
			wantShape:  StallShapeLocalNotReading,
			wantQueues: true,
		},
		{
			name:       "keepalive timer and queued send data do not discriminate",
			when:       tiera(2048, 0, 2, 0, true),
			wantShape:  StallShapeUnknown,
			wantQueues: true,
		},
		{
			name:       "no Tier A reading: UNKNOWN, no queue keys",
			when:       tiera(31337, 31337, 3, 3, false),
			wantShape:  StallShapeUnknown,
			wantQueues: false,
		},
	}
	for _, tc := range cases {
		var m networkMachine
		stop := stall(&m, tc.when)
		if got := shape(stop); got != tc.wantShape {
			t.Errorf("%s: stall_shape = %q, want %q", tc.name, got, tc.wantShape)
		}
		_, hassend := stop.Data["send_q"]
		if hassend != tc.wantQueues {
			t.Errorf("%s: send_q present = %v, want %v", tc.name, hassend, tc.wantQueues)
		}
	}

	// the open episode's shape is what RESUMED reports: the tier A state may
	// change between STOPPED and RESUMED; the closing stamp is the last
	// stalled sample's classification.
	var m networkMachine
	if stop := stall(&m, tiera(0, 0, 0, 0, true)); shape(stop) != StallShapePeerSilent {
		t.Fatalf("set-up STOPPED shape = %q, want PEER_SILENT", shape(stop))
	}
	// the stall continues and a retransmit timer arms: still stalled, no new event.
	if ev := m.observe(t0.Add(50*time.Second), []collector.ConnectionSnapshot{tiera(1024, 0, 1, 2, true)}, EventProvenance{}, true); len(ev) != 0 {
		t.Fatalf("continuing stall re-emitted %v", ev)
	}
	resumes := m.observe(t0.Add(70*time.Second), []collector.ConnectionSnapshot{sock(11, 3000, 3000)}, EventProvenance{}, true)
	if len(resumes) != 1 || resumes[0].Type != EventNetworkProgressResumed {
		t.Fatalf("want one RESUMED, got %v", resumes)
	}
	if got := shape(resumes[0]); got != StallShapePathLoss {
		t.Errorf("RESUMED stall_shape = %q, want PATH_LOSS (the episode's latest shape)", got)
	}
}

// TestNetworkStallAlternativesCiteShape (§7.3): the alternatives of a stall
// anchored analysis name the BROKER_SOCKET_STALL / NETWORK_PATH_FAILURE pair
// with per-shape support and contradiction, and a shapeless stall (pre-shape
// stamping bundles) renders the UNKNOWN wording.
func TestNetworkStallAlternativesCiteShape(t *testing.T) {
	stallshape := func(ep string, shape string) Event {
		data := map[string]any{"last_progress_at": "x"}
		if shape != "" {
			data["stall_shape"] = shape
		}
		return withEpisode(baseEvent(EventNetworkProgressStopped, baseStart().Add(40*time.Second),
			SubjectRef{SubjectSocket, "inode-7"}, data), ep)
	}
	alternatives := func(t *testing.T, shape string) []string {
		t.Helper()
		g := graphFrom(t, []Event{stallshape("network:inode-7#1", shape)})
		anchors := g.failureAnchors()
		if len(anchors) != 1 || g.Events[anchors[0]].Type != EventNetworkProgressStopped {
			t.Fatalf("want exactly the open stall as anchor, got %v", anchors)
		}
		return g.alternatives(anchors[0])
	}
	assertonce := func(t *testing.T, list []string, frag string) {
		n := 0
		for _, s := range list {
			if strings.Contains(s, frag) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("fragments containing %q: %d, want exactly 1 in %v", frag, n, list)
		}
	}

	cases := []struct {
		shape string
		frag  string
	}{
		{StallShapePeerSilent, "supports BROKER_SOCKET_STALL"},
		{StallShapePeerSilent, "NETWORK_PATH_FAILURE is contradicted"},
		{StallShapePathLoss, "supports NETWORK_PATH_FAILURE"},
		{StallShapeZeroWindow, "peer not reading"},
		{StallShapeUnknown, "cannot be discriminated"},
		{"", "cannot be discriminated"}, // a pre-shape-stamping bundle still cites the pair
	}
	for _, tc := range cases {
		list := alternatives(t, tc.shape)
		assertonce(t, list, tc.frag)
		for _, s := range list {
			// A stall never promotes a hypothesis to a confirmed cause: both
			// hypotheses stay unconfirmed wording (§7.3 caveat).
			if strings.Contains(s, "confirmed") && !strings.Contains(s, "unconf") {
				t.Errorf("shape %q alternative overstates certainty: %q", tc.shape, s)
			}
		}
	}
}

func TestNetworkMachineIdleSocketIsNotStalled(t *testing.T) {
	var m networkMachine
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ev := m.observe(t0.Add(time.Duration(i)*time.Minute), []collector.ConnectionSnapshot{sock(9, 0, 0)}, EventProvenance{}, true)
		if len(ev) != 0 {
			t.Fatalf("idle socket emitted %v at sample %d", ev, i)
		}
	}
}

func TestNetworkMachineIgnoresSocketsWithoutProgressTelemetry(t *testing.T) {
	var m networkMachine
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := sock(3, 100, 100)
	c.ProgressAvailable = false
	m.observe(t0, []collector.ConnectionSnapshot{c}, EventProvenance{}, true)
	if ev := m.observe(t0.Add(time.Hour), []collector.ConnectionSnapshot{c}, EventProvenance{}, true); len(ev) != 0 {
		t.Fatalf("socket without Tier B data emitted %v", ev)
	}
}

func TestNetworkMachineUncertainSampleDecidesNothing(t *testing.T) {
	var m networkMachine
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.observe(t0, []collector.ConnectionSnapshot{sock(5, 100, 100)}, EventProvenance{}, true)
	m.observe(t0.Add(time.Second), []collector.ConnectionSnapshot{sock(5, 150, 100)}, EventProvenance{}, true)
	// A displaced sample must not turn into a stall or a resume.
	if ev := m.observe(t0.Add(2*time.Minute), []collector.ConnectionSnapshot{sock(5, 150, 100)}, EventProvenance{}, false); len(ev) != 0 {
		t.Fatalf("uncertain sample emitted %v", ev)
	}
}
