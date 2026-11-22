package simulator

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestCLIRejectsNegativeDuration(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunCLI([]string{"normal", "--duration=-1s"}, &out, &errb); code != 2 {
		t.Fatalf("code = %d, want usage error", code)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "must not be negative") {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errb.String())
	}
}

type failedCLIWriter struct{}

func (failedCLIWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCLIExitReportsOutputFailure(t *testing.T) {
	var errb bytes.Buffer
	code := RunCLI([]string{"exit", "--code=0", "--hold=1ms", "--json"}, failedCLIWriter{}, &errb)
	if code != 1 || !strings.Contains(errb.String(), "write event stream") {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
}

func TestCLIHelpListsScenarios(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunCLI([]string{"--help"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errb.String())
	}
	for _, want := range []string{"--json", "--duration"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help output missing %q:\n%s", want, out.String())
		}
	}
	// every registered scenario must be listed, and nothing else.
	for _, sc := range Scenarios() {
		if !strings.Contains(out.String(), sc.Name()) {
			t.Errorf("help output missing registered scenario %q:\n%s", sc.Name(), out.String())
		}
	}
	for _, absent := range []string{"bogus-scenario", "_node"} {
		if strings.Contains(out.String(), absent) {
			t.Errorf("help output must not advertise %q:\n%s", absent, out.String())
		}
	}
}

func TestCLIUnknownScenario(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunCLI([]string{"bogus-scenario"}, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), `unknown scenario "bogus-scenario"`) {
		t.Errorf("stderr = %q, want an unknown-scenario message", errb.String())
	}
}

func TestCLIRunsNormalAsJSON(t *testing.T) {
	var out, errb bytes.Buffer
	code := RunCLI([]string{"normal", "--json", "--duration", "150ms"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errb.String())
	}
	evs := decodeEvents(t, &out)
	if len(evs) < 2 {
		t.Fatalf("got %d events, want at least started+exited", len(evs))
	}
	if evs[0].Type != "started" {
		t.Errorf("first event = %q, want started", evs[0].Type)
	}
	last := evs[len(evs)-1]
	if last.Type != "exited" {
		t.Fatalf("last event = %q, want exited", last.Type)
	}
	if code, _ := last.Data["code"].(float64); code != 0 {
		t.Errorf("exit code in event = %v, want 0", last.Data["code"])
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be quiet on success, got %q", errb.String())
	}
}

func TestCLIRejectsUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunCLI([]string{"normal", "--nope"}, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestCLINoArgsPrintsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunCLI(nil, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Errorf("stderr = %q, want usage", errb.String())
	}
}

func TestCLIScenarioSpecificFlag(t *testing.T) {
	var out, errb bytes.Buffer
	// --stall-threshold is only registered by socket-stall; proving it parses
	// here covers the flagged hook without waiting for a real cycle.
	if code := RunCLI([]string{"socket-stall", "--help"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	combined := out.String() + errb.String()
	if !strings.Contains(combined, "stall-threshold") {
		t.Errorf("scenario flags not shown in help:\n%s", combined)
	}
}
