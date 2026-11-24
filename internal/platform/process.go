// package platform is deprehendo's OS boundary: process identity snapshots,
// signals, process groups, TCP tables, PSI and cgroup reads. linux specifics
// (/proc, /sys/fs/cgroup) only appear in the linux < collects funcs; portable
// parsers live beside them so fixture-based tests run on any OS.
package platform

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// process is one observed process. state is the ps-style stat string ("S",
// "T+", "Z", ...); compare with strings.HasPrefix(p.State, "T") for stopped.
//
// SID is the kernel session id. RSSBytes is the resident set size. CPUTicks
// and StartTicks are raw clock ticks from /proc/<pid>/stat (linux); on
// platforms that do not expose them they are zero. StartTicks is valid only
// within one boot: identity never crosses a restart.
//
// ExitStatus is the observed terminal state, when the kernel exposes one:
// "exit:<code>" for a normal exit, "signal:<number>" for a signal death,
// and "" (never a zero value of another kind) when the platform does not
// expose this process's exit status. it is opportunistic: the status exists
// in /proc only while the zombie waits between samples (see parseLinuxStat).
type Process struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	PGID       int    `json:"pgid"`
	SID        int    `json:"sid"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Threads    int    `json:"threads,omitempty"`
	RSSBytes   uint64 `json:"rss_bytes,omitempty"`
	CPUTicks   uint64 `json:"cpu_ticks,omitempty"`
	StartTicks int64  `json:"start_ticks,omitempty"`
	ExitStatus string `json:"exit_status,omitempty"`
}

// processes snapshots all visible processes on the machine. it is cheap and
// inherently racy: answers are correct for "right now" only. processes that
// vanish mid-scan, or whose records cannot be read by this user, are skipped
// rather than failing the whole snapshot.
func Processes() ([]Process, error) { return ProcessesContext(context.Background()) }

// ProcessesContext bounds command-backed scans and checks cancellation between proc entries.
func ProcessesContext(ctx context.Context) ([]Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "linux":
		return ProcessesAt(ctx, "/proc")
	case "darwin":
		return darwinProcessesContext(ctx)
	default:
		return nil, fmt.Errorf("platform: process snapshot not implemented on %s", runtime.GOOS)
	}
}

// find returns the process for pid, or ok=false when it is gone.
func Find(pid int) (Process, bool, error) {
	if pid <= 0 {
		return Process{}, false, fmt.Errorf("platform: pid must be positive")
	}
	if runtime.GOOS == "linux" {
		p, err := ReadProcessAt("/proc", pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return Process{}, false, nil
		}
		return p, err == nil, err
	}
	var all []Process
	var err error
	if runtime.GOOS == "darwin" {
		all, err = darwinProcessRows(context.Background(), pid)
	} else {
		all, err = Processes()
	}
	if err != nil {
		return Process{}, false, err
	}
	for _, p := range all {
		if p.PID == pid {
			return p, true, nil
		}
	}
	return Process{}, false, nil
}

// alive reports whether pid is still on the machine (possibly as a zombie).
func Alive(pid int) bool {
	_, ok, err := Find(pid)
	return err == nil && ok
}

// children returns the live processes whose parent is pid, sorted by pid.
func Children(parent int) ([]Process, error) {
	var all []Process
	var err error
	if runtime.GOOS == "darwin" {
		all, err = darwinProcessRows(context.Background(), 0)
	} else {
		all, err = Processes()
	}
	if err != nil {
		return nil, err
	}
	var kids []Process
	for _, p := range all {
		if p.PPID == parent {
			kids = append(kids, p)
		}
	}
	sort.Slice(kids, func(i, j int) bool { return kids[i].PID < kids[j].PID })
	return kids, nil
}

// SignalProcess sends sig to a single process. A vanished pid is not an error:
// callers use this in cleanup paths where "already gone" is success.
func SignalProcess(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return fmt.Errorf("signal process: pid must be positive, got %d", pid)
	}
	if err := syscall.Kill(pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	return nil
}

// KillGroup sends sig to a process group. A vanished group is not an error.
// it kills every process in the group: never call it on the runner's own
// process group.
func KillGroup(pgid int, sig syscall.Signal) error {
	if pgid <= 0 {
		return fmt.Errorf("signal group: pgid must be positive, got %d", pgid)
	}
	if err := syscall.Kill(-pgid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal group %d: %w", pgid, err)
	}
	return nil
}

// linuxProcesses reads /proc/<pid>/stat. field layout after "(comm)":
// state, ppid, pgrp, session, ..., utime, stime, ..., threads, ..., starttime,
// vsize, rss: see parseLinuxStat for indices.
func linuxProcesses() ([]Process, error) { return ProcessesAt(context.Background(), "/proc") }

// ReadProcessAt reads one linux identity record without scanning unrelated PIDs.
func ReadProcessAt(root string, pid int) (Process, error) {
	if pid <= 0 {
		return Process{}, fmt.Errorf("platform: pid must be positive")
	}
	raw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return Process{}, fmt.Errorf("platform: read pid %d stat: %w", pid, err)
	}
	return parseLinuxStat(pid, raw)
}

// ProcessesAt scans a proc filesystem, returning usable rows alongside a
// summary error when records are inaccessible or malformed. exit races are normal.
func ProcessesAt(ctx context.Context, root string) ([]Process, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("platform: read proc: %w", err)
	}
	out := make([]Process, 0)
	failed := 0
	var first error
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		p, err := ReadProcessAt(root, pid)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			failed++
			if first == nil {
				first = err
			}
			continue
		}
		out = append(out, p)
	}
	if failed > 0 {
		return out, fmt.Errorf("platform: %d process records unavailable: %w", failed, first)
	}
	return out, nil
}

// parseLinuxStat parses the identity and accounting fields from one
// /proc/<pid>/stat record. the comm field is parenthesized but may itself
// contain spaces and ')', so find its final delimiter before splitting fields.
//
// field indices here are relative to the fields after comm (0-based): the
// kernel's man/proc numbering counts pid, comm and state before ppid, so the
// after-comm index is the kernel field number minus three. the kernel fields
// used are: state(0) ppid(1) pgrp(2) session(3) utime(11) stime(12)
// num_threads(17) starttime(19) vsize(20) rss(21) exit_code(49).
//
// exit_code (kernel field 52, after-comm 49, linux ≥ 4.5) is the terminal
// wait status, and the kernel exports it non-zero only while the process is
// a zombie: a parent that never reaped, or one that has not reaped yet at
// sample time. A live process's value is kernel bookkeeping and is never
// reported as a terminal state; older kernels (or a reaped zombie whose PID
// is gone) yield no stat row at all, which the differ already records as
// "exit observed, status not captured".
func parseLinuxStat(pid int, raw []byte) (Process, error) {
	end := lastParen(raw) - 1
	start := strings.IndexByte(string(raw), '(')
	if start < 0 || end <= start {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat command name", pid)
	}
	recordpid, err := strconv.Atoi(strings.TrimSpace(string(raw[:start])))
	if err != nil || recordpid != pid || pid <= 0 {
		return Process{}, fmt.Errorf("platform: mismatched stat pid %d", pid)
	}
	name := string(raw[start+1 : end])
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) <= 21 {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat: got %d fields after comm", pid, len(fields))
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat parent pid: %w", pid, err)
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat process group: %w", pid, err)
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat session id: %w", pid, err)
	}
	threads, err := strconv.Atoi(fields[17])
	if err != nil || threads < 0 {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat thread count %q", pid, fields[17])
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat utime %q", pid, fields[11])
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat stime %q", pid, fields[12])
	}
	startTicks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || startTicks < 0 {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat starttime %q", pid, fields[19])
	}
	rsspages, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return Process{}, fmt.Errorf("platform: malformed /proc/%d/stat rss %q", pid, fields[21])
	}
	if len(fields[0]) != 1 || !strings.Contains("RSDZTtXxKWPI", fields[0]) || ppid < 0 || pgid < 0 || sid < 0 {
		return Process{}, fmt.Errorf("platform: invalid process identity fields for pid %d", pid)
	}
	if utime > math.MaxUint64-stime || rsspages > math.MaxUint64/uint64(os.Getpagesize()) {
		return Process{}, fmt.Errorf("platform: accounting overflow for pid %d", pid)
	}
	exitStatus := ""
	if fields[0] == "Z" && len(fields) > 49 {
		code, err := strconv.ParseUint(fields[49], 10, 32)
		if err != nil || code > math.MaxUint16 {
			// A malformed kernel bookkeeping value is unavailable, not fatal:
			// the process's identity is still valid without it.
			return Process{
				PID: pid, PPID: ppid, PGID: pgid, SID: sid, Name: name, State: fields[0],
				Threads:    threads,
				CPUTicks:   utime + stime,
				StartTicks: startTicks,
				RSSBytes:   rsspages * uint64(os.Getpagesize()),
			}, nil
		}
		s := uint16(code)
		if s&0x7f > 0 {
			// killed by signal: the low 7 bits name it (WIFSIGNALED).
			exitStatus = fmt.Sprintf("signal:%d", s&0x7f)
		} else {
			// exited: the high byte is the code passed to _exit (WEXITSTATUS).
			exitStatus = fmt.Sprintf("exit:%d", s>>8)
		}
	}
	return Process{
		PID:        pid,
		PPID:       ppid,
		PGID:       pgid,
		SID:        sid,
		Name:       name,
		State:      fields[0],
		Threads:    threads,
		RSSBytes:   rsspages * uint64(os.Getpagesize()),
		CPUTicks:   utime + stime,
		StartTicks: startTicks,
		ExitStatus: exitStatus,
	}, nil
}

// parseDarwinThreadCounts interprets `ps -M` continuation rows, which start
// with a PID followed by the thread CPU percentage. process summary rows start
// with a username and are excluded. it is shared with tests on non-Darwin OSes
// so fixture coverage does not depend on the host platform.
func parseDarwinThreadCounts(out []byte) map[int]int {
	counts := make(map[int]int)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if _, err := strconv.ParseFloat(fields[1], 64); err != nil {
			continue
		}
		counts[pid]++
	}
	return counts
}

func lastParen(raw []byte) int {
	i := -1
	for j, b := range raw {
		if b == ')' {
			i = j
		}
	}
	if i < 0 {
		return 0
	}
	return i + 1
}

func darwinProcesses() ([]Process, error) { return darwinProcessesContext(context.Background()) }

func darwinProcessesContext(ctx context.Context) ([]Process, error) {
	// ps -M enumerates every thread and can take seconds on developer hosts.
	// macOS lacks a cheap thread-count column; zero means unavailable here.
	return darwinProcessRows(ctx, 0)
}

// Identity/cleanup queries avoid enumerating every system thread.
func darwinProcessRows(ctx context.Context, pid int) ([]Process, error) {
	args := []string{"-axo", "pid=,ppid=,pgid=,sess=,state=,rss=,comm="}
	if pid > 0 {
		args = []string{"-p", strconv.Itoa(pid), "-o", "pid=,ppid=,pgid=,sess=,state=,rss=,comm="}
	}
	out, err := exec.CommandContext(ctx, "/bin/ps", args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if pid > 0 && errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(out) == 0 && ctx.Err() == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("platform: ps: %w", err)
	}
	var procs []Process
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		pgid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		sid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		rsskb, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			continue
		}
		// `ps rss=` is in kilobytes on macOS; linux parses stat's rss pages.
		// macOS ps does not expose clock ticks here, so CPUTicks stays zero.
		procs = append(procs, Process{
			PID: pid, PPID: ppid, PGID: pgid, SID: sid,
			Name: strings.Join(fields[6:], " "), State: fields[4],
			RSSBytes: rsskb * 1024,
		})
	}
	return procs, nil
}
