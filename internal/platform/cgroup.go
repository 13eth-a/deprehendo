// cgroup identification and limit reads. the cgroup file parser and the stats
// loader are filesystem-layout based and testable with fixture trees; the
// default paths are Linux-only so no other package imports /proc or
// /sys/fs/cgroup layout.
package platform

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// CgroupSnapshot describes the unified (cgroup v2) cgroup a process lives in.
// MemoryMaxSet is true when memory.max is literally "max" (unbounded);
// MemoryMax is then meaningless. path is the v2 cgroup path and "", with all
// limits zeroed, on cgroup v1 systems where the unified hierarchy is absent.
type CgroupSnapshot struct {
	PID                    int    `json:"pid,omitempty"`
	StartTicks             int64  `json:"start_ticks,omitempty"`
	MemoryCurrentAvailable bool   `json:"memory_current_available"`
	MemoryMaxAvailable     bool   `json:"memory_max_available"`
	CPUAvailable           bool   `json:"cpu_available"`
	Path                   string `json:"path,omitempty"`
	MemoryCurrent          uint64 `json:"memory_current,omitempty"`
	MemoryMax              uint64 `json:"memory_max,omitempty"`
	MemoryMaxSet           bool   `json:"memory_max_set,omitempty"`
	CPUMax                 string `json:"cpu_max,omitempty"`

	// cumulative kernel counters from memory.events (cgroup v2). the
	// oom_kill counter is the sampled OOM evidence of causal-semantics §3.2;
	// it rises when the kernel killed a member of this cgroup. available is
	// false when the controller does not expose the file: zero values then
	// mean "not captured", never "no OOM kill".
	OOMKills           uint64 `json:"oom_kills,omitempty"`
	OOMGroupKills      uint64 `json:"oom_group_kills,omitempty"`
	OOMEventsAvailable bool   `json:"oom_events_available,omitempty"`
}

// DefaultProcRoot and DefaultCgroupRoot are the linux mounted locations used
// by SelfCgroup; tests pass their own roots instead.
const (
	DefaultProcRoot   = "/proc"
	DefaultCgroupRoot = "/sys/fs/cgroup"
)

// SelfCgroup inspects this agent's own cgroup. that is the phase 1 answer to
// "does the recording host run under a constrained cgroup": the agent's
// container/cgroup limits bound the agent just as they bound any runner.
// other platforms return an explicit not-implemented error.
func SelfCgroup() (CgroupSnapshot, error) {
	return ProcessCgroup(os.Getpid())
}

// ProcessCgroup reads a watched process's cgroup and validates its identity
// across the read. unsupported platforms and v1 layouts are explicit errors.
func ProcessCgroup(pid int) (CgroupSnapshot, error) {
	if runtime.GOOS != "linux" {
		return CgroupSnapshot{}, fmt.Errorf("platform: cgroups not implemented on %s", runtime.GOOS)
	}
	return processCgroupAt(pid, DefaultProcRoot, DefaultCgroupRoot)
}

func processCgroupAt(pid int, procRoot, cgroupRoot string) (CgroupSnapshot, error) {
	before, err := ReadProcessAt(procRoot, pid)
	if err != nil {
		return CgroupSnapshot{}, err
	}
	snapshot, readerr := CgroupFor(pid, procRoot, cgroupRoot)
	after, err := ReadProcessAt(procRoot, pid)
	if err != nil {
		return CgroupSnapshot{}, errors.Join(readerr, err)
	}
	if before.StartTicks != after.StartTicks {
		return CgroupSnapshot{}, fmt.Errorf("platform: pid %d changed identity during cgroup read", pid)
	}
	snapshot.PID, snapshot.StartTicks = pid, before.StartTicks
	if snapshot.Path == "" && readerr == nil {
		readerr = fmt.Errorf("platform: pid %d has no cgroup v2 membership", pid)
	}
	return snapshot, readerr
}

// CgroupFor resolves and reads the cgroup of one pid under the given /proc and
// cgroup roots (injected for tests). A process without a unified cgroup line
// reports a zero-valued snapshot without error, and snapshot.Path is empty in
// that case.
func CgroupFor(pid int, procRoot, cgroupRoot string) (CgroupSnapshot, error) {
	if pid <= 0 {
		return CgroupSnapshot{}, fmt.Errorf("platform: cgroup pid must be positive")
	}
	membership := filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")
	readpath := func() (string, error) {
		f, err := os.Open(membership)
		if err != nil {
			return "", fmt.Errorf("platform: open cgroup %d: %w", pid, err)
		}
		defer f.Close()
		return ParseCgroupFile(f)
	}
	path, err := readpath()
	if err != nil || path == "" {
		return CgroupSnapshot{}, err
	}
	relative := path
	// A cgroup2 mount can expose a subtree of the hierarchy. resolve the
	// membership relative to that mount's root, not the host hierarchy root.
	mountinfo, err := os.ReadFile(filepath.Join(procRoot, "self", "mountinfo"))
	if err == nil {
		mountroot, found := cgroupMountRoot(string(mountinfo), cgroupRoot)
		if !found {
			return CgroupSnapshot{Path: path}, fmt.Errorf("platform: no cgroup2 mount at %s", cgroupRoot)
		}
		if mountroot != "/" {
			if path == mountroot {
				relative = "/"
			} else if strings.HasPrefix(path, mountroot+"/") {
				relative = strings.TrimPrefix(path, mountroot)
			} else {
				return CgroupSnapshot{Path: path}, fmt.Errorf("platform: cgroup %s outside mounted hierarchy %s", path, mountroot)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return CgroupSnapshot{Path: path}, err
	}
	snapshot, readerr := LoadCgroupStats(cgroupRoot, relative)
	snapshot.Path = path
	after, err := readpath()
	if err != nil {
		return CgroupSnapshot{}, errors.Join(readerr, err)
	}
	if after != path {
		return CgroupSnapshot{}, fmt.Errorf("platform: pid %d changed cgroup during read", pid)
	}
	return snapshot, readerr
}

func cgroupMountRoot(raw, mountpoint string) (string, bool) {
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(raw, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields, fs := strings.Fields(left), strings.Fields(right)
		if len(fields) < 5 || len(fs) < 1 || fs[0] != "cgroup2" {
			continue
		}
		if filepath.Clean(unescape.Replace(fields[4])) == filepath.Clean(mountpoint) {
			return unescape.Replace(fields[3]), true
		}
	}
	return "", false
}

// ParseCgroupFile returns the unified ("0::<path>") cgroup path from one
// /proc/<pid>/cgroup, or "" for cgroup v1 layouts that have no unified line.
func ParseCgroupFile(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	path := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("platform: malformed cgroup line %q", line)
		}
		if parts[0] == "0" && parts[1] == "" {
			if path != "" {
				return "", fmt.Errorf("platform: duplicate unified cgroup membership")
			}
			if err := validateCgroupPath(parts[2]); err != nil {
				return "", err
			}
			path = parts[2]
		}
	}
	return path, scanner.Err()
}

// LoadCgroupStats reads memory.current, memory.max and cpu.max for one cgroup
// path below cgroupRoot. missing controller files degrade to zero values
// rather than errors: controllers may be legitimately unmounted for a valid
// cgroup. Present-but-garbled files are errors.
func validateCgroupPath(path string) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
		return fmt.Errorf("platform: invalid cgroup path %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("platform: cgroup path escapes visible hierarchy: %q", path)
		}
	}
	return nil
}

// the memory.events file of one cgroup: one "key value" pair per line.
// parseMemoryEvents extracts the OOM counters (causal-semantics §3.2);
// unknown future keys and the oom (deferral) counter are ignored, so the
// kernel extending the file is not an error.
func parseMemoryEvents(raw string) (oomKill, oomGroupKill uint64, err error) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			return 0, 0, fmt.Errorf("platform: malformed memory.events line %q", line)
		}
		count, cerr := strconv.ParseUint(value, 10, 64)
		if cerr != nil {
			return 0, 0, fmt.Errorf("platform: memory.events %s: %w", key, cerr)
		}
		switch key {
		case "oom_kill":
			oomKill = count
		case "oom_group_kill":
			oomGroupKill = count
		}
	}
	return oomKill, oomGroupKill, nil
}

func LoadCgroupStats(cgroupRoot, path string) (CgroupSnapshot, error) {
	snapshot := CgroupSnapshot{Path: path}
	if err := validateCgroupPath(path); err != nil {
		return snapshot, err
	}
	dir := filepath.Join(cgroupRoot, path)
	if st, err := os.Stat(dir); err != nil {
		return snapshot, err
	} else if !st.IsDir() {
		return snapshot, fmt.Errorf("platform: cgroup path is not a directory")
	}
	var problems error
	read := func(name string) (string, bool) {
		raw, ok, err := readOptionalCgroupFile(filepath.Join(dir, name))
		problems = errors.Join(problems, err)
		return strings.TrimSpace(raw), ok
	}
	if raw, ok := read("memory.current"); ok {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			problems = errors.Join(problems, fmt.Errorf("platform: memory.current: %w", err))
		} else {
			snapshot.MemoryCurrent = value
			snapshot.MemoryCurrentAvailable = true
		}
	}
	if raw, ok := read("memory.max"); ok {
		if raw == "max" {
			snapshot.MemoryMaxSet = true
			snapshot.MemoryMaxAvailable = true
		} else {
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				problems = errors.Join(problems, fmt.Errorf("platform: memory.max: %w", err))
			} else {
				snapshot.MemoryMax = value
				snapshot.MemoryMaxAvailable = true
			}
		}
	}
	if raw, ok := read("memory.events"); ok {
		// memory.events is the sampled kernel OOM evidence (§3.2): the
		// cumulative oom_kill counter. A missing or unread value is reported
		// as a problem; the snapshot keeps "not captured" for the counter.
		oomkill, oomgroupkill, err := parseMemoryEvents(raw)
		if err != nil {
			problems = errors.Join(problems, err)
		} else {
			snapshot.OOMKills = oomkill
			snapshot.OOMGroupKills = oomgroupkill
			snapshot.OOMEventsAvailable = true
		}
	}
	if raw, ok := read("cpu.max"); ok {
		fields := strings.Fields(raw)
		valid := len(fields) == 2
		if valid {
			period, err := strconv.ParseUint(fields[1], 10, 64)
			valid = err == nil && period > 0
			if fields[0] != "max" {
				quota, err := strconv.ParseUint(fields[0], 10, 64)
				valid = valid && err == nil && quota > 0
			}
		}
		if !valid {
			problems = errors.Join(problems, fmt.Errorf("platform: malformed cpu.max %q", raw))
		} else {
			snapshot.CPUMax = raw
			snapshot.CPUAvailable = true
		}
	}
	return snapshot, problems
}

// readOptionalCgroupUint64 reads a file whose absence means "controller not
// mounted" and reports zero. other read failures or garbage content error out.
func readOptionalCgroupUint64(path string) (uint64, error) {
	raw, ok, err := readOptionalCgroupFile(path)
	if err != nil || !ok {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("platform: parse %s: %w", path, err)
	}
	return value, nil
}

// readOptionalCgroupString returns "" for a missing file, with ok=false.
func readOptionalCgroupString(path string) (string, error) {
	raw, ok, err := readOptionalCgroupFile(path)
	if err != nil || !ok {
		return "", err
	}
	return strings.TrimSpace(raw), nil
}

func readOptionalCgroupFile(path string) (string, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("platform: read %s: %w", path, err)
	}
	return string(raw), true, nil
}
