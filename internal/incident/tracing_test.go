package incident

import (
	"encoding/json"
	"strings"
	"testing"

	"runopsy/internal/trace"
)

func TestTraceReliabilityValidate(t *testing.T) {
	cases := []struct {
		name    string
		report  TraceReliability
		wantErr bool
	}{
		{"active with backend", TraceReliability{State: "active", Backend: "proc_connector"}, false},
		{"degraded with reason", TraceReliability{State: "unavailable", Reason: "runopsy-trace binary not found"}, false},
		{"empty state rejected", TraceReliability{State: ""}, true},
		{"unknown state rejected", TraceReliability{State: "hyper"}, true},
		{"unknown backend rejected", TraceReliability{State: "active", Backend: "perf"}, true},
		{"oversize reason rejected", TraceReliability{State: "stopped", Reason: strings.Repeat("x", 257)}, true},
	}
	for _, c := range cases {
		err := c.report.validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validate = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

func TestTraceReliabilityValidateInIncident(t *testing.T) {
	i := fixture()
	i.Tracing = &TraceReliability{State: "frobnicating"}
	if err := Validate(i); err == nil {
		t.Error("Validate accepted a bundle with an invalid tracing state")
	}
	i.Tracing = &TraceReliability{State: "active", Backend: "proc_connector", EventsLost: 3}
	if err := Validate(i); err != nil {
		t.Errorf("Validate rejected a valid tracing section: %v", err)
	}
}

func TestIncidentTracingOmitted(t *testing.T) {
	i := fixture()
	data, err := json.Marshal(i)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "\"tracing\"") {
		t.Errorf("no-tracer bundle serialized a tracing key: %s", data)
	}
}

func TestTraceReliabilityFromHealth(t *testing.T) {
	h := trace.Health{
		State:  trace.StateRestarting,
		Reason: "connection refused",
		Caps:   trace.Capabilities{Backend: "proc_connector"},
		Lost:   7,
	}
	got := TraceReliabilityFromHealth(h)
	if got.State != "restarting" || got.Backend != "proc_connector" || got.EventsLost != 7 || got.Reason != "connection refused" {
		t.Errorf("from health = %+v", got)
	}
}

func TestRedactIncidentBoundingTraceReason(t *testing.T) {
	i := fixture()
	i.Tracing = &TraceReliability{State: "unavailable", Reason: strings.Repeat("p\xff", 200) + "x"}
	if err := (ConservativeRedactor{}).RedactIncident(i); err != nil {
		t.Fatalf("redact: %v", err)
	}
	got := i.Tracing
	if len(got.Reason) > maxTraceReason {
		t.Errorf("reason not bounded: %d", len(got.Reason))
	}
	for _, r := range got.Reason {
		if r < 0x20 || r == 0x7f {
			t.Errorf("reason keeps control rune %#x", r)
		}
	}
	if got.State != "unavailable" {
		t.Errorf("state mutated: %q", got.State)
	}
}
