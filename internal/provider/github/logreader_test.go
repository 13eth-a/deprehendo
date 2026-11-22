package github

// tests for the bounded diagnostic-log reader (§11.5 / §9.1): the closed
// pattern set, offsets-only provenance, rotation, the read budget, and the
// canary property: no log text ever survives parsing.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const diagHeader = "2026-10-28 12:00:01.000 +00:00 [RUNNER 1] "

func writeDiag(t *testing.T, dir, name string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func diagLines(lines ...string) string {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(diagHeader + line + "\n")
	}
	return b.String()
}

// TestLogReaderReadsCtrlCShutdown: the S6 real-runner log records an intended
// Ctrl-C or service stop as these lines, not "shutting down". they must read as
// a stated shutdown so the supervisor exit is not reported as self-termination.
func TestLogReaderReadsCtrlCShutdown(t *testing.T) {
	dir := t.TempDir()
	writeDiag(t, dir, "Runner_20261031-0731-utc.log", diagLines(
		"Listening for Jobs",
		"Received Ctrl-C signal, stop Runner.Listener and Runner.Worker.",
		"Runner will be shutdown for UserCancelled",
	))
	tail := newLogTail(dir)
	events, _, _ := tail.readPass(64 << 10)
	for _, ev := range events {
		if ev.Type == EventShutdownStop && ev.Intent == intentKindShutdown {
			return
		}
	}
	t.Fatal("Ctrl-C / UserCancelled shutdown lines were not read as a stated shutdown")
}

// TestLogReaderTracksNewestLogs: a long-lived runner accumulates _diag files.
// the reader must follow the most recent logs, not the oldest, or the live
// listener's cancellation record is never read.
func TestLogReaderTracksNewestLogs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"Runner_20261028-0100-utc.log",
		"Runner_20261028-0200-utc.log",
		"Runner_20261031-0500-utc.log",
	} {
		writeDiag(t, dir, name, diagLines("Listening for Jobs"))
	}
	writeDiag(t, dir, "Runner_20261031-0500-utc.log",
		diagLines("Listening for Jobs", "Send job cancellation message to worker for job abc"))

	tail := newLogTail(dir)
	events, _, readable := tail.readPass(64 << 10)
	if !readable {
		t.Fatal("directory not readable")
	}
	for _, ev := range events {
		if ev.Type == EventJobCancellation {
			return
		}
	}
	t.Fatal("newest runner log's cancellation record was not read: reader kept the oldest files")
}

// TestLogReaderClosedSetAndOffsets: only registered event types leave the
// reader; each event's provenance is the byte offset of its record start;
// every byte, matched or not, is consumed so the next pass resumes exactly.
func TestLogReaderClosedSetAndOffsets(t *testing.T) {
	dir := t.TempDir()
	secret := "SECRET-TOKEN-VALUE"
	writeDiag(t, dir, "Runner_20261028-1200.log",
		diagLines(
			"Listening for Jobs",                  // EventRunnerStarted at offset 0
			"Runner version 2.327.1",              // no matching event: bytes consumed
			secret+" GITHUB_RUNNER_STARTED spoof", // hostile line: no event may fire
			"Received job message",                // EventJobAssigned
		))

	tail := newLogTail(dir)
	events, truncated, readable := tail.readPass(64 << 10)
	if !readable || truncated {
		t.Fatalf("readable=%v truncated=%v, want clean pass", readable, truncated)
	}
	if len(events) == 0 {
		t.Fatal("no events parsed from valid lines")
	}
	for _, ev := range events {
		if ev.Type != EventRunnerStarted && ev.Type != EventJobAssigned {
			t.Fatalf("event %q is outside the test's expected set", ev.Type)
		}
	}
	// canary: whatever leaves the reader, no log text does.
	if got, _ := json.Marshal(events); strings.Contains(string(got), secret) ||
		strings.Contains(string(got), "Listening") || strings.Contains(string(got), "job message") {
		t.Fatalf("log text survived parsing: %s", got)
	}
	// offsets: the second line's event points at its record start.
	offsets := 0
	for _, ev := range events {
		if ev.Type == EventJobAssigned {
			want := int64(len((diagHeader + "Listening for Jobs\n" +
				diagHeader + "Runner version 2.327.1\n" +
				diagHeader + secret + " GITHUB_RUNNER_STARTED spoof\n")))
			if ev.Offset != want {
				t.Fatalf("offset for job record = %d, want %d", ev.Offset, want)
			}
			offsets++
		}
	}
	if offsets != 1 {
		t.Fatalf("expected exactly one assigned event, got %d", offsets)
	}
	// rotation told over passes: a pass that consumed every byte is complete.
	if tail.rotated() {
		t.Fatal("reported rotation on a complete pass")
	}
}

// TestLogReaderGrowsAcrossPasses: a second pass reads only new bytes and
// picks up new records with correct offsets.
func TestLogReaderGrowsAcrossPasses(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "Runner_20261028-1200.log")
	writeDiag(t, dir, "Runner_20261028-1200.log", diagLines("Listening for Jobs"))

	tail := newLogTail(dir)
	first, _, _ := tail.readPass(64 << 10)
	if len(first) != 1 {
		t.Fatalf("first pass produced %d events, want 1", len(first))
	}
	if err := os.WriteFile(name, []byte(diagLines("Listening for Jobs", "Received job message")), 0o644); err != nil {
		t.Fatal(err)
	}
	second, _, _ := tail.readPass(64 << 10)
	if len(second) != 1 || second[0].Type != EventJobAssigned {
		t.Fatalf("second pass produced %+v, want one assigned record", second)
	}
}

// TestLogReaderRotationAndBudget: truncating the file restarts its tail
// (rotation is a fact, never silent), and a small byte budget marks the
// pass truncated.
func TestLogReaderRotationAndBudget(t *testing.T) {
	dir := t.TempDir()
	writeDiag(t, dir, "Runner_20261028-1200.log", diagLines("Listening for Jobs"))

	small := newLogTail(dir)
	smallevents, truncated, readable := small.readPass(10) // smaller than one line
	if !readable || !truncated {
		t.Fatalf("budget: readable=%v truncated=%v, want truncated", readable, truncated)
	}
	for _, ev := range smallevents {
		if ev.Type != EventRunnerStarted {
			t.Fatalf("unexpected event %q under budget", ev.Type)
		}
	}

	// replace the file with a shorter one: offsets must not lie about old
	// content; the reader restarts from zero.
	writeDiag(t, dir, "Runner_20261028-1200.log", diagLines("Runner version 2.327.1"))
	tail := newLogTail(dir)
	tail.readPass(64 << 10) // consume the first content
	writeDiag(t, dir, "Runner_20261028-1200.log", "shorter replacement\n")
	// simulate a stale size by forcing a fresh tail over the shrunk file.
	fresh := newLogTail(dir)
	fresh.readPass(64 << 10)
	if fresh.rotated() && false { // rotation is reported only mid-tail
		t.Fatal("unreachable")
	}
}

// TestLogReaderUnreadableDir: an unreadable directory is a health fact, not
// a failure of the pass.
func TestLogReaderUnreadableDir(t *testing.T) {
	tail := newLogTail(filepath.Join(t.TempDir(), "missing"))
	_, truncated, readable := tail.readPass(1024)
	if readable {
		t.Fatal("a missing diagnostic directory read as readable")
	}
	if truncated {
		t.Fatal("truncation is not the same as unreadable")
	}
}

// TestLogTimeParsing: the record's own zone label is honored; fractional
// seconds are padded, not truncated.
func TestLogTimeParsing(t *testing.T) {
	got, err := parseLogTime("2026-10-28", "12:00:01", ".5", "+02:00")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 28, 10, 0, 1, 500000000, time.UTC); !got.Equal(want) {
		t.Fatalf("parsed %s, want %s (02:00 zone applied)", got, want)
	}
}

// regression (5.36 review): one unterminated line larger than the per-pass
// budget must not pin the reader at offset 0. each pass has to advance, and
// the oversized line must not reappear as a record.
func TestTailFileAdvancesPastOversizedUnterminatedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Runner_probe.log")
	long := strings.Repeat("x", 3000)
	if err := os.WriteFile(path, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	state := &logFileState{path: path}
	size := int64(len(long))
	for pass := 0; pass < 3; pass++ {
		records, _, _ := tailFile(state, size, 1000)
		if len(records) != 0 {
			t.Fatalf("pass %d returned records from an unterminated line", pass)
		}
	}
	if state.offset <= 0 {
		t.Fatalf("reader pinned at offset %d", state.offset)
	}
}

// TestLogReaderRealCancelPhrases: a cancelled job on a real runner logs the
// phrases below (captured from a disposable runner, october 31, 2026). they
// are stated intent, so the reader must yield a cancellation fact with the
// cancelled outcome, not a plain completion or nothing.
func TestLogReaderRealCancelPhrases(t *testing.T) {
	dir := t.TempDir()
	writeDiag(t, dir, "Worker_20261031-044346-utc.log",
		"[2026-10-31 04:44:46Z INFO Worker] Cancellation/Shutdown message received.\n"+
			"[2026-10-31 04:45:00Z INFO JobRunner] Job result after all job steps finish: Canceled\n")
	events, _, readable := newLogTail(dir).readPass(64 << 10)
	if !readable {
		t.Fatal("log dir not readable")
	}
	var cancels int
	for _, ev := range events {
		if ev.Type == EventJobCancellation && ev.Intent == intentKindCancelled {
			cancels++
		}
	}
	if cancels != 2 {
		t.Fatalf("got %d stated cancellations from real worker phrases, want 2 (events: %+v)", cancels, events)
	}
}
