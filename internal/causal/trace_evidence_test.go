package causal

import (
	"testing"
	"time"

	"runopsy/internal/incident"
)

// phase 6 signal / OOM evidence in the causal graph (contract §3.4 "Y sent
// S"): the tracer's send observation and its victim-naming OOM record are
// kernel facts, so they must reach the rules that explain an exit instead of
// staying bundle-viewport only.

func traceIncident(base time.Time, events ...incident.Event) *incident.Incident {
	return &incident.Incident{
		CaptureStart: base,
		CaptureEnd:   base.Add(time.Minute),
		Metadata: incident.Metadata{Processes: []incident.ProcessMetadata{
			{PID: 4242, PGID: 77, Name: "worker"},
		}},
		Events: events,
	}
}

func traceGraph(t *testing.T, inc *incident.Incident) *Graph {
	t.Helper()
	g := NewGraph(BuildTimeline(inc))
	if _, err := NewEngine(Rules(), inc.CaptureStart).Apply(g, nil); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	return g
}

func signalSent(at time.Time, pid int, ticks int64, signal int, pgid int) incident.Event {
	return incident.Event{
		Type: incident.TraceSignalSent, Timestamp: at, PID: pid, StartTicks: ticks,
		Signal: signal, SignalFact: "SIGNAL_SENT", SenderPID: 4132, TargetPGID: pgid,
		Provenance: incident.ProvenanceTrace,
	}
}

func signalExit(at time.Time, pid int, ticks int64, signal int, fact string) incident.Event {
	return incident.Event{
		Type: incident.TraceProcessExit, Timestamp: at, PID: pid, StartTicks: ticks,
		Signal: signal, SignalFact: fact, ExitStatus: "signal:" + itoa(signal),
		Provenance: incident.ProvenanceTrace,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestSignalSendExplainsExitByThatSignal(t *testing.T) {
	base := baseStart()
	g := traceGraph(t, traceIncident(base,
		signalSent(base.Add(time.Second), 4242, 900, 9, 0),
		signalExit(base.Add(1500*time.Millisecond), 4242, 900, 9, "EXITED_BY_SIGNAL"),
	))
	band, ok := hasRuleEdge(g, "SIGNAL_TERMINATES_PROCESS@1")
	if !ok {
		t.Fatalf("no send-to-exit edge: %+v", g.Edges)
	}
	if band != ConfidenceHigh {
		t.Fatalf("band = %s, want HIGH: the send and the exit's wait status are both kernel facts", band)
	}
}

// TestGroupSendBindsToMemberExitByPGID: a kill(-PGID) send names a group, not
// a process. it may explain the exit of a member of that group, never of
// another group.
func TestGroupSendBindsToMemberExitByPGID(t *testing.T) {
	base := baseStart()
	g := traceGraph(t, traceIncident(base,
		signalSent(base.Add(time.Second), 0, 0, 15, 77),
		signalExit(base.Add(1200*time.Millisecond), 4242, 900, 15, "EXITED_BY_SIGNAL"),
	))
	if _, ok := hasRuleEdge(g, "SIGNAL_TERMINATES_PROCESS@1"); !ok {
		t.Fatalf("group send did not bind to a member exit: %+v", g.Edges)
	}

	other := traceGraph(t, traceIncident(base,
		signalSent(base.Add(time.Second), 0, 0, 15, 78),
		signalExit(base.Add(1200*time.Millisecond), 4242, 900, 15, "EXITED_BY_SIGNAL"),
	))
	if _, ok := hasRuleEdge(other, "SIGNAL_TERMINATES_PROCESS@1"); ok {
		t.Fatal("a send to another process group explained this exit")
	}
}

func TestSignalRuleRefusesMismatchedEvidence(t *testing.T) {
	base := baseStart()
	cases := []struct {
		name string
		ev   []incident.Event
	}{
		{
			name: "different signal number",
			ev: []incident.Event{
				signalSent(base.Add(time.Second), 4242, 900, 15, 0),
				signalExit(base.Add(1500*time.Millisecond), 4242, 900, 9, "EXITED_BY_SIGNAL"),
			},
		},
		{
			name: "normal exit carries no signal fact",
			ev: []incident.Event{
				signalSent(base.Add(time.Second), 4242, 900, 15, 0),
				{Type: incident.TraceProcessExit, Timestamp: base.Add(1500 * time.Millisecond), PID: 4242, StartTicks: 900, ExitStatus: "exit:0", Provenance: incident.ProvenanceTrace},
			},
		},
		{
			name: "another process identity",
			ev: []incident.Event{
				signalSent(base.Add(time.Second), 4243, 901, 15, 0),
				signalExit(base.Add(1500*time.Millisecond), 4242, 900, 15, "EXITED_BY_SIGNAL"),
			},
		},
		{
			name: "send after the exit",
			ev: []incident.Event{
				signalExit(base.Add(time.Second), 4242, 900, 15, "EXITED_BY_SIGNAL"),
				signalSent(base.Add(2*time.Second), 4242, 900, 15, 0),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := hasRuleEdge(traceGraph(t, traceIncident(base, tc.ev...)), "SIGNAL_TERMINATES_PROCESS@1"); ok {
				t.Fatal("rule fired on evidence that does not establish the mechanism")
			}
		})
	}
}

// TestKernelOOMRecordExplainsVictimExit: oom:mark_victim names the victim, so
// OOM_CAUSES_PROCESS_EXIT@2 (dormant in v1 bundles) fires on that record.
func TestKernelOOMRecordExplainsVictimExit(t *testing.T) {
	base := baseStart()
	g := traceGraph(t, traceIncident(base,
		incident.Event{Type: incident.TraceOomKill, Timestamp: base.Add(time.Second), PID: 4242, StartTicks: 900, Provenance: incident.ProvenanceTrace},
		signalExit(base.Add(1200*time.Millisecond), 4242, 900, 9, "EXITED_BY_SIGNAL"),
	))
	band, ok := hasRuleEdge(g, "OOM_CAUSES_PROCESS_EXIT@2")
	if !ok {
		t.Fatalf("kernel OOM record did not explain its victim's exit: %+v", g.Edges)
	}
	if band != ConfidenceHigh {
		t.Fatalf("band = %s, want HIGH", band)
	}

	// A record for another incarnation of the same PID is not this victim.
	other := traceGraph(t, traceIncident(base,
		incident.Event{Type: incident.TraceOomKill, Timestamp: base.Add(time.Second), PID: 4242, StartTicks: 901, Provenance: incident.ProvenanceTrace},
		signalExit(base.Add(1200*time.Millisecond), 4242, 900, 9, "EXITED_BY_SIGNAL"),
	))
	if _, ok := hasRuleEdge(other, "OOM_CAUSES_PROCESS_EXIT@2"); ok {
		t.Fatal("a record naming another incarnation explained this exit")
	}
}

// TestCgroupCounterCannotNameTheVictim: the sampled counter is a real kernel
// OOM record but it names a cgroup, not a victim, so the victim discriminator
// must stay UNKNOWN and leave that path to CGROUP_OOM_KILLS_MEMBER@1.
func TestCgroupCounterCannotNameTheVictim(t *testing.T) {
	check, err := lookupCheck("OOM_RECORD_IDENTIFIES_VICTIM")
	if err != nil {
		t.Fatal(err)
	}
	exit := &Event{Type: EventProcessExited, Subject: processSubject(4242, 900), PID: 4242, StartTicks: 900}
	counter := &Event{
		Type:    EventOOM,
		Subject: SubjectRef{SubjectCgroup, "/system.slice/worker.service"},
		Data:    map[string]any{"oom_kill_delta": int64(1)},
	}
	if got := check.Evaluate(nil, counter, exit); got.Status != CheckUnknown {
		t.Fatalf("cgroup counter answered %s (%s), want UNKNOWN", got.Status, got.Detail)
	}
	direct := &Event{
		Type: EventOOM, Subject: processSubject(4242, 900), PID: 4242, StartTicks: 900,
		Data: map[string]any{"record": "oom_mark_victim"},
	}
	if got := check.Evaluate(nil, direct, exit); got.Status != CheckPresent {
		t.Fatalf("victim-naming record answered %s (%s), want PRESENT", got.Status, got.Detail)
	}
}
