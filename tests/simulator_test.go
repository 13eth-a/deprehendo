package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var simPath string
var agentPath string
var analyzerPath string

func TestMain(m *testing.M) {
	root, err := moduleRoot()
	if err != nil {
		_, _ = os.Stderr.WriteString("find module root: " + err.Error() + "\n")
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "runopsy-acceptance-")
	if err != nil {
		_, _ = os.Stderr.WriteString("create test temp dir: " + err.Error() + "\n")
		os.Exit(1)
	}
	simPath = filepath.Join(dir, "runopsy-sim")
	agentPath = filepath.Join(dir, "runopsy-agent")
	analyzerPath = filepath.Join(dir, "runopsy-analyzer")
	build := exec.Command("go", "build", "-o", dir, "./cmd/runopsy-sim", "./cmd/runopsy-agent", "./cmd/runopsy-analyzer")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		_, _ = os.Stderr.WriteString("build runopsy-sim: " + err.Error() + "\n" + string(out))
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	if err := os.RemoveAll(dir); err != nil {
		_, _ = os.Stderr.WriteString("remove test binary directory: " + err.Error() + "\n")
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod found above " + wd)
		}
	}
}

type event struct {
	Timestamp time.Time      `json:"timestamp"`
	Scenario  string         `json:"scenario"`
	Type      string         `json:"type"`
	Data      map[string]any `json:"data"`
}

type runResult struct {
	stdout []byte
	stderr []byte
	err    error
}

func runJSON(t *testing.T, timeout time.Duration, args ...string) runResult {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("integration scenarios require Linux or macOS, got %s", runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args = append(args, "--json")
	cmd := exec.CommandContext(ctx, simPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("runopsy-sim %v timed out after %s\nstderr: %s\nstdout: %s", args, timeout, stderr.String(), stdout.String())
	}
	return runResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), err: err}
}

func decodeEvents(t *testing.T, raw []byte) []event {
	t.Helper()
	var events []event
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid JSON event: %v\nline: %s", err, line)
		}
		if ev.Scenario == "" || ev.Type == "" || ev.Timestamp.IsZero() {
			t.Fatalf("event missing timestamp/scenario/type: %s", line)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read event stream: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("empty JSON event stream; raw=%s", raw)
	}
	return events
}

func requireSuccess(t *testing.T, res runResult) {
	t.Helper()
	if res.err != nil {
		t.Fatalf("scenario returned error: %v\nstderr: %s\nstdout: %s", res.err, res.stderr, res.stdout)
	}
	if len(res.stderr) != 0 {
		t.Errorf("stderr on success = %q", res.stderr)
	}
}

func eventTypes(events []event) map[string]bool {
	types := make(map[string]bool, len(events))
	for _, ev := range events {
		types[ev.Type] = true
	}
	return types
}

func requireTypes(t *testing.T, events []event, wants ...string) {
	t.Helper()
	got := eventTypes(events)
	for _, want := range wants {
		if !got[want] {
			t.Errorf("event stream missing %q; got %v", want, got)
		}
	}
}

func TestScenarioAcceptanceJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("runs full end-to-end scenario matrix")
	}
	cases := []struct {
		name    string
		timeout time.Duration
		args    []string
		want    []string
	}{
		{name: "normal", timeout: 5 * time.Second, args: []string{"normal", "--duration", "120ms"}, want: []string{"started", "exited"}},
		{name: "cpu-spin", timeout: 5 * time.Second, args: []string{"cpu-spin", "--workers", "2", "--duration", "300ms"}, want: []string{"started", "work_report", "exited"}},
		{name: "memory-pressure", timeout: 5 * time.Second, args: []string{"memory-pressure", "--rate", "1MB", "--interval", "10ms", "--limit", "2MB"}, want: []string{"started", "memory_allocated", "exited"}},
		{name: "frozen-worker", timeout: 12 * time.Second, args: []string{"frozen-worker", "--freeze-after", "150ms", "--freeze-for", "150ms", "--grace", "150ms"}, want: []string{"started", "worker_spawned", "worker_frozen", "worker_resumed", "worker_killed", "exited"}},
		{name: "orphan-process", timeout: 12 * time.Second, args: []string{"orphan-process", "--tasks", "1", "--grace", "50ms"}, want: []string{"started", "tree_recorded", "worker_killed", "orphan_report", "tree_cleaned", "exited"}},
		{name: "process-tree", timeout: 12 * time.Second, args: []string{"process-tree", "--settle", "150ms", "--between", "50ms"}, want: []string{"started", "tree_recorded", "branch_killed", "branch_survey", "tree_cleaned", "exited"}},
		{name: "socket-stall", timeout: 8 * time.Second, args: []string{"socket-stall", "--ping-interval", "20ms", "--stall-threshold", "80ms", "--stall-duration", "120ms", "--stall-after", "1"}, want: []string{"started", "stall_detected", "recovered", "exited"}},
		{name: "exit", timeout: 5 * time.Second, args: []string{"exit", "--code", "0"}, want: []string{"started", "exited"}},
		{name: "signal", timeout: 5 * time.Second, args: []string{"signal", "--signal", "CONT", "--hold", "50ms"}, want: []string{"started", "signal_sent", "exited"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runJSON(t, tc.timeout, tc.args...)
			requireSuccess(t, res)
			evs := decodeEvents(t, res.stdout)
			for _, ev := range evs {
				if ev.Scenario != tc.name {
					t.Errorf("event scenario = %q, want %q", ev.Scenario, tc.name)
				}
			}
			requireTypes(t, evs, tc.want...)
			if evs[0].Type != "started" {
				t.Errorf("first event = %q, want started", evs[0].Type)
			}
			if evs[len(evs)-1].Type != "exited" {
				t.Errorf("last event = %q, want exited", evs[len(evs)-1].Type)
			}
		})
	}
}

func TestSignalAndExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real signal-target processes")
	}
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"chosen exit code", []string{"exit", "--code", "7"}, 7},
		{"TERM", []string{"signal", "--signal", "TERM", "--hold", "30ms"}, 143},
		{"INT", []string{"signal", "--signal", "INT", "--hold", "30ms"}, 130},
		{"KILL", []string{"signal", "--signal", "KILL", "--hold", "30ms"}, 137},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runJSON(t, 3*time.Second, tc.args...)
			var exitErr *exec.ExitError
			gotcode := -1
			if errors.As(res.err, &exitErr) {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					if status.Signaled() {
						gotcode = 128 + int(status.Signal())
					} else if status.Exited() {
						gotcode = status.ExitStatus()
					}
				}
			}
			if gotcode != tc.code {
				t.Fatalf("err=%v, got status %d, want %d; stdout=%s stderr=%s", res.err, gotcode, tc.code, res.stdout, res.stderr)
			}
			evs := decodeEvents(t, res.stdout)
			requireTypes(t, evs, "started")
			if tc.args[0] == "signal" {
				requireTypes(t, evs, "signal_sent")
				if eventTypes(evs)["exited"] {
					t.Fatal("fatal signal stream must not claim its own exit")
				}
			}
		})
	}
}

func TestSignalStopResumes(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns signal watcher")
	}
	res := runJSON(t, 3*time.Second, "signal", "--signal", "STOP", "--hold", "30ms", "--resume-after", "100ms")
	requireSuccess(t, res)
	evs := decodeEvents(t, res.stdout)
	requireTypes(t, evs, "watcher_spawned", "signal_sent", "resumed", "exited")
}

func TestProcessScenariosRespectShortDurationAndCleanChildren(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real process trees")
	}
	cases := [][]string{
		{"frozen-worker", "--duration", "250ms", "--freeze-after", "10s"},
		{"orphan-process", "--duration", "250ms"},
		{"process-tree", "--duration", "250ms"},
	}
	for _, args := range cases {
		t.Run(args[0], func(t *testing.T) {
			res := runJSON(t, 8*time.Second, args...)
			if res.err != nil {
				t.Fatalf("run: %v\nstdout=%s\nstderr=%s", res.err, res.stdout, res.stderr)
			}
			evs := decodeEvents(t, res.stdout)
			seen := make(map[int]bool)
			for _, ev := range evs {
				collectPIDs(ev.Data, seen)
			}
			for pid := range seen {
				waitPIDNotRunning(t, pid, 3*time.Second)
			}
		})
	}
}

func collectPIDs(value any, seen map[int]bool) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			// `tasks` is a PID list in tree_recorded but a plain count in started.
			_, islist := child.([]any)
			if strings.HasSuffix(key, "_pid") || strings.HasSuffix(key, "_pids") || key == "targeted" || (key == "tasks" && islist) {
				collectPIDValues(child, seen)
			} else {
				collectPIDs(child, seen)
			}
		}
	case []any:
		for _, child := range v {
			collectPIDs(child, seen)
		}
	}
}

func collectPIDValues(value any, seen map[int]bool) {
	switch v := value.(type) {
	case float64:
		if v > 0 {
			seen[int(v)] = true
		}
	case []any:
		for _, child := range v {
			collectPIDValues(child, seen)
		}
	}
}

func waitPIDNotRunning(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		// `kill -0` regards zombies as alive, so prefer `ps` and inspect state.
		out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
		if err != nil || strings.TrimSpace(string(out)) == "" || strings.HasPrefix(strings.TrimSpace(string(out)), "Z") {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("pid %d still running after scenario cleanup", pid)
}

func TestCLIHelpAndUnknownScenario(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	helpcmd := exec.CommandContext(ctx, simPath, "--help")
	helpout, err := helpcmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v output=%s", err, helpout)
	}
	for _, want := range []string{"cpu-spin", "memory-pressure", "frozen-worker", "orphan-process", "process-tree", "socket-stall", "--json"} {
		if !strings.Contains(string(helpout), want) {
			t.Errorf("help missing %q: %s", want, helpout)
		}
	}
	cmd := exec.CommandContext(ctx, simPath, "definitely-unknown")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("unknown scenario status: err=%v output=%s; want exit 2", err, out)
	}
	if !strings.Contains(string(out), "unknown scenario") {
		t.Errorf("unknown scenario output missing message: %s", out)
	}
}
