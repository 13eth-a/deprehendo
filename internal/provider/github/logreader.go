package github

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"deprehendo/internal/provider/evidence"
)

// log record grammar (closed set, §9.1). two record shapes are accepted:
//
//   - the real GitHub actions runner `_diag` format, as written by
//     Runner.Listener and Runner.Worker trace listeners:
//
//     [2026-09-03 18:34:29Z INFO terminal] job build completed with result: succeeded
//     [2026-09-03 18:34:34Z INFO JobDispatcher] job request 0 for plan 79b6 job 029e received.
//
//   - the fake-runner harness shape used by older fixtures (5.41):
//
//     2026-10-29 12:03:01.123 +00:00 [RUNNER 22] message...
//
// the timestamp carries its own zone (C7: log time is not process time; the
// records are attributed with ≥ 1 s resolution against process observations,
// and the zone label is honored when converting to UTC). A line that does
// not parse is skipped, but its bytes are consumed so offsets stay correct.
// (principal phase 5 audit R1: the reader originally accepted only the harness
// shape, so a real runner's diagnostic logs produced no facts at all.)
var (
	realLogLinePattern = regexp.MustCompile(
		`^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:?\d{2}) +[A-Za-z]{3,8} +[A-Za-z0-9_.]{1,64}\] ?`)
	logLinePattern = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?\s*([+-]\d{2}:?\d{2}|[+-]\d{2}|Z)`)
)

// intentKind is internal to the provider; it surfaces as a GenericEvent
// intent through interpret (§7).
type intentKind string

const (
	intentKindCancelled  intentKind = "CANCELLED"
	intentKindTimedOut   intentKind = "TIMED_OUT"
	intentKindShutdown   intentKind = "SERVICE_SHUTDOWN"
	intentKindSelfUpdate intentKind = "RUNNER_UPDATE"
)

// logPattern is one entry of the closed fact table. whatever it matches is
// reduced to an event type + intent + timestamp + provenance; no matched
// text is ever retained.
type logPattern struct {
	re     *regexp.Regexp
	event  string
	intent intentKind
	// scopes: the pattern only applies in the named file scopes.
	listener bool // Runner_*.log (the listener process)
	worker   bool // Worker_*.log (the job worker process)
}

// the table is ordered: the first matching entry wins. phrases come from the
// runner's own trace and terminal output (see the audit for the sources);
// anything not matched is discarded. two rules shape it (§7 T1, §8 P1):
//
//   - an intended-termination fact needs a record that *states* the intent
//     (a cancellation message, a "canceled" result); a bare word such as
//     "cancel" or "timeout" in an arbitrary trace line is not one;
//   - process exit is a LOCAL_PROCESS fact. A log line that mentions an exit
//     code (every step's "finished process N with exit code 0") never becomes
//     a worker-exit event.
var logPatterns = []logPattern{
	// both scopes: the job result line. "canceled" is a stated cancellation.
	// the worker writes "job result after all job steps finish: <result>",
	// the listener "job <name> completed with result: <result>".
	{re: regexp.MustCompile(`(?:\bcompleted with result|Job result after all job steps finish): ?([A-Za-z]+)`), event: EventJobCompleted, listener: true, worker: true},

	// listener scope (Runner_*.log)
	{re: regexp.MustCompile(`Listening for [Jj]obs`), event: EventRunnerStarted, listener: true},
	{re: regexp.MustCompile(`(?i)\bconnect(?:ion)? error\b|connection (?:error|failed)|Lost [Cc]onnection|disconnected from|Exception in MessagePump|Exception in JobDispatch`), event: EventRunnerDisconnected, listener: true},
	{re: regexp.MustCompile(`(?i)\bre-?connected\b|connection (?:re-?)?established`), event: EventRunnerReconnected, listener: true},
	{re: regexp.MustCompile(`(?i)shutting? ?down|Stopping [Rr]unner|Runner service stopped|Received shutdown request|SIGTERM received|Received Ctrl-C signal|Runner will be shutdown for|stop Runner\.Listener`), event: EventShutdownStop, intent: intentKindShutdown, listener: true},
	{re: regexp.MustCompile(`(?i)software update|self-?update|Downloading the runner|Updating the runner|upgrade to version|Runner update in progress`), event: EventRunnerUpdate, intent: intentKindSelfUpdate, listener: true},
	{re: regexp.MustCompile(`Send job cancellation message to worker`), event: EventJobCancellation, intent: intentKindCancelled, listener: true},
	{re: regexp.MustCompile(`Received job message|Job message received|\bJob request \S+ for plan \S+ job \S+ received`), event: EventJobAssigned, listener: true},
	// matches the runner's own echo only: a word boundary keeps "running
	// jobs in parallel" (ordinary chatter) out of the acceptance fact.
	{re: regexp.MustCompile(`Running [Jj]ob\b:?`), event: EventJobAccepted, listener: true},

	// worker scope (Worker_*.log): only statements of intent.
	{re: regexp.MustCompile(`(?i)\b(?:job|run) (?:was |has been )?cancell?ed\b|\bcancell?ation(?:/shutdown)? (?:request|message) received\b|\breceived (?:a )?(?:job )?cancell?ation\b`), event: EventJobCancellation, intent: intentKindCancelled, worker: true},
	{re: regexp.MustCompile(`(?i)\bjob (?:has )?timed out\b|exceeded the maximum execution time`), event: EventJobTimeout, intent: intentKindTimedOut, worker: true},
}

// logEvent is one parsed fact. it contains no raw text by construction:
// type, caller-local file index, byte offset of the record start, and log
// time (converted to UTC).
type logEvent struct {
	Timestamp time.Time
	Type      string
	File      int
	Offset    int64
	Listener  bool
	Intent    intentKind
	// outcome is set for EventJobCompleted from the stated result.
	Outcome evidence.Outcome
}

func (e logEvent) provenance() evidence.Provenance {
	return evidence.Provenance{File: e.File, Offset: e.Offset}
}

// lineRecord is one buffered line with the byte offset where it starts.
type lineRecord struct {
	offset int64
	text   string
}

// logFileState tracks incremental tail position of one diagnostic file.
type logFileState struct {
	path     string
	inode    uint64
	index    int
	offset   int64
	listener bool
	size     int64
	// complete is true once the tail has consumed the file through EOF with
	// no truncation; a rotation supersedes it before completion.
	complete bool
}

// logTail holds bounded incremental state for one _diag directory. raw
// lines never persist: readPass reduces matches into facts immediately.
type logTail struct {
	dir string

	mu      sync.Mutex
	tracked map[string]*logFileState
	byIndex map[int]*logFileState
	nextIdx int
}

func newLogTail(dir string) *logTail {
	return &logTail{dir: dir, tracked: map[string]*logFileState{}, byIndex: map[int]*logFileState{}}
}

// rotated reports that any tracked file stopped receiving its tail before
// reaching EOF (rotation superseded an incomplete view). offsets never roll
// back silently; the rotation is surfaced as a fact (5.x rotation posture).
func (t *logTail) rotated() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, st := range t.tracked {
		if !st.complete {
			return true
		}
	}
	return false
}

func (t *logTail) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked = map[string]*logFileState{}
	t.byIndex = map[int]*logFileState{}
}

// maxTrackedLogs bounds retained state: the two most recent listener logs
// and the two most recent worker logs.
const maxTrackedLogs = 4

// readPass tails the diagnostic directory once and returns parsed events.
// the second return reports LOG_TRUNCATED for this pass (budget or file
// count), the third whether the directory was readable at all. failures
// become health facts, not text.
func (t *logTail) readPass(budget int64) ([]logEvent, bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	paths, inodes, sizes, err := listDiagLogs(t.dir)
	if err != nil {
		return nil, false, false
	}

	// keep only the most recent files per scope. paths are sorted oldest
	// first, so walk them newest first.
	var keep []string
	seen := map[bool]int{}
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]
		listener := strings.HasPrefix(basename(path), "Runner_")
		seen[listener]++
		if seen[listener] <= 2 {
			keep = append(keep, path)
		}
	}
	// restore oldest-first order so offsets and file indexes stay stable.
	for i, j := 0, len(keep)-1; i < j; i, j = i+1, j-1 {
		keep[i], keep[j] = keep[j], keep[i]
	}

	var events []logEvent
	truncated := false
	for _, path := range keep {
		if budget <= 0 {
			truncated = true
			break
		}
		state := t.tracked[path]
		if state == nil {
			idx := t.nextIdx + 1
			t.nextIdx = idx
			state = &logFileState{
				path: path, inode: inodes[path], index: idx,
				listener: strings.HasPrefix(basename(path), "Runner_"),
			}
			t.tracked[path] = state
			t.byIndex[idx] = state
		}
		fileevents, consumed, done := tailFile(state, sizes[path], budget)
		budget -= consumed
		if !done {
			truncated = true
		}
		for _, lr := range fileevents {
			if ev, ok := reduceLine(state, lr); ok {
				events = append(events, ev)
			}
		}
	}
	// rotation cleanup: forget files that disappeared.
	for path := range t.tracked {
		if _, ok := inodes[path]; !ok {
			delete(t.byIndex, t.tracked[path].index)
			delete(t.tracked, path)
		}
	}
	return events, truncated, true
}

// tailFile reads freshly available bytes up to the budget, returning only
// complete lines. bytes of a trailing partial line stay unread until the
// next pass so offsets remain record-exact.
func tailFile(state *logFileState, size, budget int64) ([]lineRecord, int64, bool) {
	if size < state.offset {
		// truncated or replaced file: restart from 0. history is lost, the
		// fact that it happened is not.
		state.offset = 0
		state.complete = false
	}
	want := size - state.offset
	if want > budget {
		want = budget
	}
	if want <= 0 {
		return nil, 0, true
	}
	data, err := readRange(state.path, state.offset, want)
	if err != nil {
		return nil, 0, false
	}
	consumed := int64(len(data))
	var records []lineRecord
	start := 0
	for pos := 0; pos < len(data); pos++ {
		if data[pos] == '\n' {
			text := strings.TrimSuffix(string(data[start:pos]), "\r")
			records = append(records, lineRecord{offset: state.offset + int64(start), text: text})
			start = pos + 1
		}
	}
	state.offset += consumed
	if start < len(data) {
		if start == 0 && want == budget && state.offset < size {
			// the budget ended inside one line that has no newline yet. rolling
			// back would re-read the same bytes forever, so the oversized line is
			// dropped. its text is unknown text, which the reader discards anyway.
		} else {
			// roll back over the trailing partial line.
			state.offset -= int64(len(data) - start)
		}
	}
	state.complete = state.offset >= size && err == nil
	return records, consumed, state.complete
}

// reduceLine matches one line against the table and reduces it to a fact.
// withoutJobName drops the workflow job display name from the job-echo lines
// the runner writes. that name comes from the workflow file, so anyone who
// can edit a workflow controls it; matching against it would let a name forge
// a stated intent (T1). only the fixed words around the name are kept.
func withoutJobName(message string) string {
	// the reduction applies to the runner's echo only: "running job" alone
	// (after another pattern has reduced it) or "running job: <name>". A
	// sentence such as "running jobs in parallel" is not one, so its
	// remaining words are never normalized into the acceptance phrase.
	if strings.HasPrefix(message, "Running job") &&
		(len(message) == len("Running job") || message[len("Running job")] == ':') {
		return "Running job"
	}
	if strings.HasPrefix(message, "Job ") {
		// the result is the last " completed with result:" in the line, so a
		// name containing that phrase cannot move the match.
		if i := strings.LastIndex(message, " completed with result:"); i >= 0 {
			return "Job" + message[i:]
		}
	}
	return message
}

func reduceLine(state *logFileState, line lineRecord) (logEvent, bool) {
	if line.text == "" {
		return logEvent{}, false
	}
	at, message, ok := splitRecord(line.text)
	if !ok {
		return logEvent{}, false
	}
	message = withoutJobName(message)
	for _, p := range logPatterns {
		if state.listener && !p.listener {
			continue
		}
		if !state.listener && !p.worker {
			continue
		}
		mm := p.re.FindStringSubmatchIndex(message)
		if mm == nil {
			continue
		}
		ev := logEvent{
			Timestamp: at, Type: p.event, File: state.index, Offset: line.offset,
			Listener: state.listener, Intent: p.intent,
		}
		if p.event == EventJobCompleted && len(mm) > 3 && mm[2] >= 0 {
			switch strings.ToLower(message[mm[2]:mm[3]]) {
			case "succeeded", "success":
				ev.Outcome = evidence.OutcomeSucceeded
			case "failed", "failure":
				ev.Outcome = evidence.OutcomeFailed
			case "canceled", "cancelled":
				// A stated cancellation: the intent fact (T1), not a plain
				// completion.
				ev.Type, ev.Intent, ev.Outcome = EventJobCancellation, intentKindCancelled, evidence.OutcomeCancelled
			default:
				ev.Outcome = evidence.OutcomeUnknown
			}
		}
		return ev, true
	}
	return logEvent{}, false
}

// splitRecord recognizes one record header (real runner shape first, then
// the harness shape) and returns the record time in UTC and the message.
func splitRecord(text string) (time.Time, string, bool) {
	for _, pattern := range []*regexp.Regexp{realLogLinePattern, logLinePattern} {
		loc := pattern.FindStringSubmatchIndex(text)
		if loc == nil {
			continue
		}
		frac := ""
		if loc[6] >= 0 {
			frac = text[loc[6]:loc[7]]
		}
		at, err := parseLogTime(text[loc[2]:loc[3]], text[loc[4]:loc[5]], frac, text[loc[8]:loc[9]])
		if err != nil {
			return time.Time{}, "", false
		}
		message := text[loc[1]:]
		if pattern == logLinePattern {
			// harness shape: drop the "[RUNNER n]" / "[WORKER n]" tag.
			message = strings.TrimLeft(message, " ")
			if strings.HasPrefix(message, "[") {
				if end := strings.IndexByte(message, ']'); end > 0 {
					message = message[end+1:]
				}
			}
		}
		return at, message, true
	}
	return time.Time{}, "", false
}

// parseLogTime converts the record's own date/clock/zone label into UTC.
// fractional seconds carry 1–6 digits (logs are written with 3).
func parseLogTime(date, clock, frac, zoneLabel string) (time.Time, error) {
	loc := zoneFromLabel(zoneLabel)
	text := date + " " + clock
	layout := "2006-01-02 15:04:05"
	if frac = strings.TrimPrefix(frac, "."); frac != "" {
		if len(frac) > 6 {
			frac = frac[:6]
		}
		for len(frac) < 3 {
			frac += "0"
		}
		// parsing accepts a fractional second after the seconds field even
		// when the layout omits it, so 1–6 digits all parse.
		text += "." + frac
	}
	parsed, err := time.ParseInLocation(layout, text, loc)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

// zoneFromLabel maps "+00:00", "-05:00", "+0530", "-05" and "Z" onto
// fixed zones. unrecognized labels fall back to UTC (logged time is then
// possibly shifted; the ≥ 1 s attribution tolerance absorbs minutes so the
// label must be a whole-hour class of offsets to be trusted exactly).
func zoneFromLabel(label string) *time.Location {
	label = strings.ReplaceAll(label, ":", "")
	if label == "Z" || label == "" {
		return time.UTC
	}
	sign := 1
	if label[0] == '-' {
		sign = -1
	}
	hours, err := strconv.Atoi(label[1:3])
	if err != nil {
		return time.UTC
	}
	minutes := 0
	if len(label) >= 5 {
		if minutes, err = strconv.Atoi(label[3:5]); err != nil {
			return time.UTC
		}
	}
	return time.FixedZone("", sign*(hours*3600+minutes*60))
}

func basename(path string) string {
	return filepath.Base(path)
}

// listDiagLogs returns tracked runner diagnostic files (Runner_*.log and
// Worker_*.log) sorted oldest first, with inode and size of each path.
func listDiagLogs(dir string) ([]string, map[string]uint64, map[string]int64, error) {
	if dir == "" {
		return nil, nil, nil, fmt.Errorf("diag: no directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	paths := make([]string, 0, len(entries))
	inodes := map[string]uint64{}
	sizes := map[string]int64{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "Runner_") && !strings.HasPrefix(name, "Worker_") {
			continue
		}
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		path := filepath.Join(dir, name)
		inode, size, staterr := statFile(path)
		if staterr != nil {
			continue // unreadable individual file: simply not tracked this pass
		}
		paths = append(paths, path)
		inodes[path] = inode
		sizes[path] = size
	}
	sort.Strings(paths)
	return paths, inodes, sizes, nil
}

// statFile returns (inode, size). inode is 0 on platforms without one.
func statFile(path string) (uint64, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	return fileInode(info), info.Size(), nil
}

// readRange reads up to n bytes at offset. short reads are fine.
func readRange(path string, offset, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, err := f.ReadAt(buf, offset)
	if read > 0 && (err == nil || err == io.EOF) {
		return buf[:read], nil
	}
	if err != nil && read > 0 {
		return buf[:read], nil
	}
	return nil, err
}
