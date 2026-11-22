package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceCLIUnknownSubcommand(t *testing.T) {
	var out, errOut strings.Builder
	code := runTrace([]string{"frobnicate"}, &out, &errOut)
	if code != 2 {
		t.Errorf("unknown subcommand exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "unknown subcommand") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestTraceCINoSubcommand(t *testing.T) {
	var out, errOut strings.Builder
	if code := runTrace(nil, &out, &errOut); code != 2 {
		t.Errorf("bare trace exit = %d, want 2", code)
	}
}

func TestTraceCLIStatusWithMissingBinary(t *testing.T) {
	if _, err := exec.LookPath("runopsy-trace"); err == nil {
		t.Skip("runopsy-trace installed on this host; the missing-binary path is not exercisable")
	}
	var out, errOut strings.Builder
	code := forwardTrace([]string{"status"}, &out, &errOut)
	if code != 1 {
		t.Errorf("missing binary exit = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "runopsy-trace") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestTraceCLIReplayDecodesFixture(t *testing.T) {
	var out, errOut strings.Builder
	path := filepath.Join("..", "..", "testdata", "trace", "dropped-events.bin")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	code := runTrace([]string{"replay", path}, &out, &errOut)
	if code != 0 {
		t.Fatalf("replay exit = %d, stderr = %q", code, errOut.String())
	}
	combined := out.String() + errOut.String()
	for _, want := range []string{"frames=4", "events=4", "lost=1", "last_sequence=5"} {
		if !strings.Contains(combined, want) {
			t.Errorf("replay output missing %q:\n%s", want, combined)
		}
	}
}
