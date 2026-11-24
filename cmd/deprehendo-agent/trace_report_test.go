package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/causal"
	"deprehendo/internal/incident"
)

// TestReportStatesTraceEvidence pins 6.27/6.48/6.62's report contract: the
// report always says whether a kernel trace existed and whether it was
// complete, so "no signal recorded" can never be read as "no signal sent".
func TestReportStatesTraceEvidence(t *testing.T) {
	cases := []struct {
		name    string
		tracing *incident.TraceReliability
		want    []string
	}{
		{
			name:    "no tracer configured",
			tracing: nil,
			want:    []string{"Kernel trace evidence", "not configured (polling only)", "Coverage           none"},
		},
		{
			name:    "active and lossless",
			tracing: &incident.TraceReliability{State: "active", Backend: "proc_connector"},
			want:    []string{"Tracing            active (proc_connector)", "Events lost        0 observed", "complete for the traced event classes"},
		},
		{
			name:    "active with losses",
			tracing: &incident.TraceReliability{State: "active", Backend: "proc_connector", EventsLost: 3},
			want:    []string{"Events lost        at least 3", "Coverage           incomplete"},
		},
		{
			name:    "unavailable with reason",
			tracing: &incident.TraceReliability{State: "unavailable", Reason: "insufficient permission"},
			want:    []string{"Tracing            unavailable", "Reason             insufficient permission", "absence of a signal here is not evidence that none was sent"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inc := timelineTestIncident()
			inc.Tracing = c.tracing
			path := writeTimelineBundle(t, inc)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"timeline", "--report", path}, &stdout, &stderr); code != 0 {
				t.Fatalf("timeline report = %d: %s", code, stderr.String())
			}
			for _, want := range c.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("report missing %q:\n%s", want, stdout.String())
				}
			}
		})
	}
}

// TestReportQualifiesSnapshotOnlyChains: the phase 4 chain in this bundle is
// built from snapshot-derived events, so the report must label it inferred
// rather than presenting it like an observed chain (6.61/6.62).
func TestReportQualifiesSnapshotOnlyChains(t *testing.T) {
	path := writeTimelineBundle(t, timelineTestIncident())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"timeline", "--report", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("timeline report = %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Evidence quality: inferred") {
		t.Fatalf("snapshot-only chain is not labelled inferred:\n%s", out)
	}
	if strings.Contains(out, "Evidence quality: direct") {
		t.Fatalf("snapshot-only bundle claims direct evidence:\n%s", out)
	}
	if !strings.Contains(out, "[snapshot inference]") {
		t.Fatalf("chain links do not name their source class:\n%s", out)
	}
}

// TestReportShowsDirectKernelChain renders the flagship 6.62 shape without a
// kernel: a chain whose anchor cites a kernel-recorded event must render as
// direct, with each link naming the kernel as its source.
func TestReportShowsDirectKernelChain(t *testing.T) {
	base := time.Date(2026, 11, 2, 16, 14, 22, 0, time.UTC)
	inc := timelineTestIncident()
	inc.Events = []incident.Event{
		{
			Timestamp:  base.Add(418 * time.Millisecond),
			Type:       incident.TraceSignalSent,
			Provenance: incident.ProvenanceTrace,
			PID:        8211,
			StartTicks: 200,
			Signal:     15,
			SignalFact: "SIGNAL_SENT",
		},
		{
			Timestamp:  base.Add(423 * time.Millisecond),
			Type:       incident.TraceProcessExit,
			Provenance: incident.ProvenanceTrace,
			PID:        8182,
			StartTicks: 300,
			Signal:     15,
			SignalFact: "EXITED_BY_SIGNAL",
			ExitStatus: "signal:15",
		},
	}
	graph := causal.NewGraph(&causal.Timeline{
		Origin: base,
		Events: []causal.Event{
			{
				ID:         "EV_signal_sent",
				Type:       causal.EventProcessStopped,
				Timestamp:  base.Add(418 * time.Millisecond),
				Subject:    causal.SubjectRef{Kind: causal.SubjectProcess, ID: "8211@200"},
				Class:      causal.ClassContext,
				PID:        8211,
				StartTicks: 200,
				Provenance: causal.EventProvenance{Sources: []causal.ProvenanceSource{{Kind: "event", Ref: "0"}}},
			},
			{
				ID:         "EV_worker_exit",
				Type:       causal.EventProcessExited,
				Timestamp:  base.Add(423 * time.Millisecond),
				Subject:    causal.SubjectRef{Kind: causal.SubjectProcess, ID: "8182@300"},
				Class:      causal.ClassFailure,
				PID:        8182,
				StartTicks: 300,
				Provenance: causal.EventProvenance{Sources: []causal.ProvenanceSource{{Kind: "event", Ref: "1"}}},
			},
		},
	})
	var out bytes.Buffer
	if err := renderCausal(&out, graph, newQualityResolver(inc)); err != nil {
		t.Fatalf("renderCausal: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "Evidence quality: direct") {
		t.Fatalf("kernel-recorded chain is not labelled direct:\n%s", text)
	}
	if !strings.Contains(text, "[kernel trace]") {
		t.Fatalf("chain link does not name the kernel:\n%s", text)
	}
}

// TestReportLeavesUnresolvableLinksUnknown: a graph whose provenance cites an
// event the bundle does not have must not inherit the incident's best class.
func TestReportLeavesUnresolvableLinksUnknown(t *testing.T) {
	inc := timelineTestIncident()
	graph := causal.NewGraph(&causal.Timeline{
		Events: []causal.Event{
			{
				// the bundle's trigger makes the missing-source exit a failure
				// anchor; without context it would be an ordinary exit (R13).
				ID:         "EV_trigger",
				Type:       causal.EventIncidentTriggered,
				Timestamp:  time.Date(2026, 10, 27, 12, 0, 10, 0, time.UTC),
				Subject:    causal.SubjectRef{Kind: causal.SubjectHost, ID: "local"},
				PID:        8,
				StartTicks: 10,
				Provenance: causal.EventProvenance{Sources: []causal.ProvenanceSource{{Kind: "trigger", Ref: "incident"}}},
			},
			{
				ID:         "EV_missing",
				Type:       causal.EventProcessExited,
				Timestamp:  time.Date(2026, 10, 27, 12, 0, 15, 0, time.UTC),
				Subject:    causal.SubjectRef{Kind: causal.SubjectProcess, ID: "8@10"},
				PID:        8,
				StartTicks: 10,
				Provenance: causal.EventProvenance{Sources: []causal.ProvenanceSource{{Kind: "event", Ref: "99"}}},
			},
		},
	})
	var out bytes.Buffer
	if err := renderCausal(&out, graph, newQualityResolver(inc)); err != nil {
		t.Fatalf("renderCausal: %v", err)
	}
	if text := out.String(); !strings.Contains(text, "Evidence quality: unknown") {
		t.Fatalf("unresolvable provenance was given a class:\n%s", text)
	}
}

// TestAnalyzeSharesCausalQuality keeps analyze and timeline in step: both
// read the same bundle and must not disagree about a link's class.
func TestAnalyzeSharesCausalQuality(t *testing.T) {
	path := writeTimelineBundle(t, timelineTestIncident())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"analyze", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyze = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Evidence quality:") {
		t.Fatalf("analyze omitted evidence quality:\n%s", stdout.String())
	}
}
