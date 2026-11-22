package github

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// job display names come from the workflow file, which a contributor
// controls, and the runner echoes them into its own diagnostic lines. the
// classifier must not let a name forge a stated intent (T1).

// A job named to contain a cancellation result must not be read as the
// runner's stated result for that job.
func TestAdversarialJobNameCannotForgeCancellation(t *testing.T) {
	name := "x completed with result: Canceled"
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:35Z INFO Terminal] Job "+name+" completed with result: Failed",
	)
	for _, ev := range events {
		if ev.Intent == intentKindCancelled {
			t.Fatalf("job name forged a cancellation intent: %+v", ev)
		}
	}
}

// A job name that contains a shutdown phrase must not be read as a runner
// shutdown, which would cover a real crash of that runner.
func TestAdversarialJobNameCannotForgeShutdown(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:35Z INFO Terminal] Running job: Stopping runner now",
	)
	for _, ev := range events {
		if ev.Intent == intentKindShutdown {
			t.Fatalf("job name forged a shutdown intent: %+v", ev)
		}
	}
}

// A job name that contains a timeout phrase must not be read as a stated
// timeout on the worker side.
func TestAdversarialJobNameCannotForgeTimeout(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Worker_20260903-183435-utc.log",
		"[2026-09-03 18:35:00Z INFO JobRunner] Running job: job timed out here",
	)
	for _, ev := range events {
		if ev.Intent == intentKindTimedOut {
			t.Fatalf("job name forged a timeout intent: %+v", ev)
		}
	}
}

// A line that merely mentions jobs ("running jobs in parallel") is ordinary
// runner chatter, not the acceptance of a job. only the echo of the runner's
// own "running job: <name>" line is one (T1: intent needs a statement).
func TestAdversarialRunningJobsSentenceIsNotAcceptance(t *testing.T) {
	events := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:35Z INFO CommandSettings] Running jobs in parallel",
	)
	for _, ev := range events {
		if ev.Type == EventJobAccepted {
			t.Fatalf("ordinary sentence read as a job acceptance: %+v", ev)
		}
	}

	// the real acceptance line still fires.
	fine := readOnce(t, t.TempDir(), "Runner_20260903-183400-utc.log",
		"[2026-09-03 18:34:35Z INFO Terminal] Running job: build-and-test (postgresql)",
	)
	accepted := 0
	for _, ev := range fine {
		if ev.Type == EventJobAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("running job: line yields %d acceptance events, want 1", accepted)
	}
}

// one record longer than a read budget must not wedge the tail reader: the
// reader must give up on the oversized record and keep consuming what follows
// it, or every later fact in that file is lost.
func TestAdversarialOverlongLineDoesNotStallReader(t *testing.T) {
	dir := t.TempDir()
	name := "Runner_20260903-183400-utc.log"
	const budget = 4096
	oversize := strings.Repeat("x", 3*budget) // no newline inside
	content := oversize + "\n[2026-09-03 18:34:35Z INFO Terminal] Running job: build-and-test\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := newLogTail(dir)
	var events []logEvent
	for pass := 0; pass < 16; pass++ {
		got, truncated, readable := tail.readPass(budget)
		if !readable {
			t.Fatal("readPass lost the directory")
		}
		events = append(events, got...)
		if !truncated {
			break
		}
	}
	accepted := 0
	for _, ev := range events {
		if ev.Type == EventJobAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("record after the oversized line is unreachable: %d acceptance events after 16 passes", accepted)
	}
}
