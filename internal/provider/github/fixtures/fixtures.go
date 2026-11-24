// package fixtures loads the committed GitHub provider scenarios (phase 5
// item 5.39/5.40, testdata/github/*) and materializes them as a live host a
// real provider session can observe.
//
// A fixture is declarative: one JSON manifest per scenario names the runner
// installation(s), a sequence of recorder snapshots (process table + TCP
// table, with the runner diagnostic lines that become visible at that
// snapshot), and the provider facts the scenario must produce. materialize
// writes a real runner installation layout (bin/Runner.Listener,
// bin/Runner.Worker, .runner, config.sh, _diag/) so the provider's
// installation checks and log tail run against files, not mocks.
//
// nothing here contains production data: installation names, versions and log
// fragments are synthetic, and the manifests hold no paths, tokens or URLs.
package fixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/platform"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
)

// fixture is one committed scenario.
type Fixture struct {
	Name    string    `json:"name"`
	Notes   string    `json:"notes,omitempty"`
	Install []Install `json:"install"`
	// snapshots are recorder samples in capture order; times must increase.
	Snapshots []Snapshot `json:"snapshots"`
	// expected lists the provider facts this scenario must produce.
	Expected Expected `json:"expected"`
}

// install is one runner installation. key names it inside the manifest (the
// process "install" field selects it); the rest is the safe metadata the
// provider is allowed to read.
type Install struct {
	Key       string   `json:"key,omitempty"`
	Name      string   `json:"name,omitempty"`
	Version   string   `json:"version,omitempty"`
	Ephemeral bool     `json:"ephemeral,omitempty"`
	RunnerLog []string `json:"runner_log,omitempty"`
	WorkerLog []string `json:"worker_log,omitempty"`
}

// snapshot is one recorder sample. log lines listed here are appended to the
// installation's diagnostic files immediately before this sample is observed,
// which is what makes incremental tailing observable in a fixture.
type Snapshot struct {
	At          time.Time    `json:"at"`
	Processes   []Process    `json:"processes,omitempty"`
	Connections []Connection `json:"connections,omitempty"`
	RunnerLog   []string     `json:"runner_log,omitempty"`
	WorkerLog   []string     `json:"worker_log,omitempty"`
}

// process is one process-table row. install selects which installation's
// binaries this process resolves to (default: the first installation).
type Process struct {
	PID        int     `json:"pid"`
	PPID       int     `json:"ppid"`
	PGID       int     `json:"pgid,omitempty"`
	StartTicks int64   `json:"start_ticks"`
	Name       string  `json:"name"`
	State      string  `json:"state,omitempty"`
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	RSSBytes   uint64  `json:"rss_bytes,omitempty"`
	Install    string  `json:"install,omitempty"`
}

// connection is one TCP socket row.
type Connection struct {
	LocalAddr  string `json:"local_addr,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
	Inode      uint64 `json:"inode,omitempty"`
	PID        int    `json:"pid,omitempty"`
	StartTicks int64  `json:"start_ticks,omitempty"`
	FD         int    `json:"fd,omitempty"`
}

// expected is the scenario's contract. empty fields are not asserted; the
// pointer fields distinguish "must be zero" from "not asserted".
type Expected struct {
	Runners       *int   `json:"runners,omitempty"`
	RunnerName    string `json:"runner_name,omitempty"`
	RunnerVersion string `json:"runner_version,omitempty"`
	Lifecycle     string `json:"lifecycle,omitempty"`
	Health        string `json:"health,omitempty"`

	Events       []string `json:"events,omitempty"`
	AbsentEvents []string `json:"absent_events,omitempty"`

	Workers *int `json:"workers,omitempty"`
	Jobs    *int `json:"jobs,omitempty"`
	// JobRoles counts tagged job-tree members by role.
	JobRoles map[string]int `json:"job_roles,omitempty"`
	// JobOutcomes is the allowed outcome set (empty: not asserted).
	JobOutcomes []string `json:"job_outcomes,omitempty"`

	// WorkerListener pins worker PID → listener PID so a multi-runner
	// fixture can prove attribution across installations (5.31).
	WorkerListener map[string]int `json:"worker_listener,omitempty"`

	SocketRoles         []string `json:"socket_roles,omitempty"`
	AbsentSocketRoles   []string `json:"absent_socket_roles,omitempty"`
	ConflictTopics      []string `json:"conflict_topics,omitempty"`
	AbsentConflictTopic []string `json:"absent_conflict_topics,omitempty"`
}

// load reads and validates one fixture directory (it must contain
// fixture.json).
func Load(dir string) (*Fixture, error) {
	data, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f Fixture
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, "fixture.json"), err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return &f, nil
}

// LoadAll loads every fixture directory under root, sorted by name.
func LoadAll(root string) ([]*Fixture, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []*Fixture
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		if _, err := os.Stat(filepath.Join(dir, "fixture.json")); err != nil {
			continue
		}
		fixture, err := Load(dir)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fixture) validate() error {
	if strings.TrimSpace(f.Name) == "" {
		return fmt.Errorf("fixture needs a name")
	}
	if len(f.Install) == 0 {
		return fmt.Errorf("fixture needs at least one installation")
	}
	seen := map[string]bool{}
	for i, inst := range f.Install {
		key := inst.Key
		if key == "" {
			key = fmt.Sprintf("i%d", i)
			f.Install[i].Key = key
		}
		if seen[key] {
			return fmt.Errorf("duplicate installation key %q", key)
		}
		seen[key] = true
	}
	if len(f.Snapshots) == 0 {
		return fmt.Errorf("fixture needs at least one snapshot")
	}
	var previous time.Time
	for i, snap := range f.Snapshots {
		if snap.At.IsZero() {
			return fmt.Errorf("snapshot %d has no timestamp", i)
		}
		if !previous.IsZero() && !snap.At.After(previous) {
			return fmt.Errorf("snapshot %d does not advance the clock", i)
		}
		previous = snap.At
		for _, proc := range snap.Processes {
			if proc.PID <= 0 || proc.Name == "" {
				return fmt.Errorf("snapshot %d has a process without pid or name", i)
			}
			if proc.Install != "" && !seen[proc.Install] {
				return fmt.Errorf("snapshot %d process %d names unknown installation %q", i, proc.PID, proc.Install)
			}
		}
	}
	return nil
}

// hostSalt is the fixture's installation salt. it is fixed so fixture
// assertions can reference the same opaque refs deterministically; it is
// not a real agent salt.
var hostSalt = []byte("fixture-salt-0123456789abcdef00")

// host is a materialized fixture: real installation directories plus the
// snapshot the session must currently see.
type Host struct {
	fixture  *Fixture
	dir      string
	installs map[string]*installState
	order    []string
	current  int
	appended int
}

type installState struct {
	key       string
	root      string
	listener  string
	worker    string
	runnerLog string
	workerLog string
}

// materialize writes every installation under base and returns the host.
// base should be an empty temporary directory.
func (f *Fixture) Materialize(base string) (*Host, error) {
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, err
	}
	h := &Host{fixture: f, dir: base, installs: map[string]*installState{}, appended: -1}
	for _, inst := range f.Install {
		root := filepath.Join(base, "runner-"+inst.Key)
		state := &installState{
			key:       inst.Key,
			root:      root,
			listener:  filepath.Join(root, "bin", "Runner.Listener"),
			worker:    filepath.Join(root, "bin", "Runner.Worker"),
			runnerLog: filepath.Join(root, "_diag", "Runner_20261028-120000-utc.log"),
			workerLog: filepath.Join(root, "_diag", "Worker_20261028-120000-utc.log"),
		}
		dirs := []string{filepath.Join(root, "bin"), filepath.Join(root, "_diag")}
		if inst.Version != "" {
			// the runner keeps its version as a directory next to bin/; the
			// provider reads only the version string from its name.
			dirs = append(dirs, filepath.Join(root, inst.Version))
		}
		for _, dir := range dirs {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
		}
		for _, file := range []struct {
			path    string
			content string
			mode    os.FileMode
		}{
			{state.listener, "#!/fixture-runner\n", 0o755},
			{state.worker, "#!/fixture-runner\n", 0o755},
			{filepath.Join(root, "config.sh"), "#!/bin/sh\n", 0o755},
			{filepath.Join(root, ".runner"), runnerConfigJSON(inst), 0o600},
		} {
			if err := os.WriteFile(file.path, []byte(file.content), file.mode); err != nil {
				return nil, err
			}
		}
		if err := writeLines(state.runnerLog, inst.RunnerLog); err != nil {
			return nil, err
		}
		if err := writeLines(state.workerLog, inst.WorkerLog); err != nil {
			return nil, err
		}
		h.installs[inst.Key] = state
		h.order = append(h.order, inst.Key)
	}
	if len(h.order) > 0 {
		h.current = 0
	}
	return h, nil
}

// runnerConfigJSON writes only the allowlisted .runner keys. the provider
// refuses any unexpected key, so a fixture cannot smuggle one in.
func runnerConfigJSON(inst Install) string {
	cfg := map[string]any{"agentId": 7, "workFolder": "_work"}
	if inst.Name != "" {
		cfg["agentName"] = inst.Name
	}
	if inst.Ephemeral {
		cfg["ephemeral"] = true
	}
	data, _ := json.Marshal(cfg)
	return string(data) + "\n"
}

func writeLines(path string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func appendLines(path string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	_, err = file.WriteString(b.String())
	return err
}

// dir is the materialized base directory.
func (h *Host) Dir() string { return h.dir }

// roots returns the installation roots (for leak assertions).
func (h *Host) Roots() []string {
	out := make([]string, 0, len(h.order))
	for _, key := range h.order {
		out = append(out, h.installs[key].root)
	}
	return out
}

// count is the number of snapshots.
func (h *Host) Count() int { return len(h.fixture.Snapshots) }

// SetSnapshot makes snapshot i the current host state and appends that
// snapshot's diagnostic lines. it must be called before the session observes
// the snapshot.
func (h *Host) SetSnapshot(i int) error {
	if i < 0 || i >= len(h.fixture.Snapshots) {
		return fmt.Errorf("fixtures: snapshot %d out of range", i)
	}
	if i <= h.appended {
		return fmt.Errorf("fixtures: snapshot %d already applied", i)
	}
	snap := h.fixture.Snapshots[i]
	keys := append([]string(nil), h.order...)
	if len(keys) > 1 {
		// incremental lines belong to the first installation. Multi-runner
		// fixtures use static logs instead, so an ambiguous append is a
		// fixture bug rather than something to guess at.
		for _, key := range keys[1:] {
			if inst := h.fixture.install(key); inst != nil && (len(snap.RunnerLog) > 0 || len(snap.WorkerLog) > 0) {
				return fmt.Errorf("fixtures: snapshot %d adds log lines with multiple installations", i)
			}
		}
	}
	state := h.installs[keys[0]]
	if err := appendLines(state.runnerLog, snap.RunnerLog); err != nil {
		return err
	}
	if err := appendLines(state.workerLog, snap.WorkerLog); err != nil {
		return err
	}
	h.current = i
	h.appended = i
	return nil
}

func (f *Fixture) install(key string) *Install {
	for i := range f.Install {
		if f.Install[i].Key == key {
			return &f.Install[i]
		}
	}
	return nil
}

// processes implements provider.HostView: the current snapshot's table.
func (h *Host) Processes(_ context.Context) ([]platform.Process, error) {
	return h.table(h.current), nil
}

func (h *Host) table(index int) []platform.Process {
	snap := h.fixture.Snapshots[index]
	out := make([]platform.Process, 0, len(snap.Processes))
	for _, proc := range snap.Processes {
		out = append(out, platform.Process{
			PID: proc.PID, PPID: proc.PPID, PGID: proc.PGID, Name: proc.Name,
			State: proc.State, StartTicks: proc.StartTicks, RSSBytes: proc.RSSBytes,
		})
	}
	return out
}

// inspect implements provider.HostView with an incarnation check: a PID whose
// start ticks differ is a different process.
func (h *Host) Inspect(_ context.Context, ref evidence.ProcessRef) (provider.ProcessDetail, error) {
	snap := h.fixture.Snapshots[h.current]
	for _, proc := range snap.Processes {
		if proc.PID != ref.PID || proc.StartTicks != ref.StartTicks {
			continue
		}
		key := proc.Install
		if key == "" {
			key = h.order[0]
		}
		state := h.installs[key]
		if state == nil {
			return provider.ProcessDetail{}, fmt.Errorf("fixtures: no installation %q", key)
		}
		switch strings.ToLower(proc.Name) {
		case "runner.listener":
			return provider.ProcessDetail{Executable: state.listener, WorkingDir: state.root}, nil
		case "runner.worker":
			return provider.ProcessDetail{Executable: state.worker, WorkingDir: state.root}, nil
		default:
			// A non-runner process has no installation executable. the
			// provider only inspects runner binaries, so this is not a gap.
			return provider.ProcessDetail{}, fmt.Errorf("fixtures: %s has no resolved executable", proc.Name)
		}
	}
	return provider.ProcessDetail{}, fmt.Errorf("fixtures: incarnation %d@%d is not in the current sample", ref.PID, ref.StartTicks)
}

// now implements provider.HostView.
func (h *Host) Now() time.Time { return h.fixture.Snapshots[h.current].At }

// salt implements provider.HostView.
func (h *Host) Salt() []byte { return hostSalt }

// CollectorSnapshot converts snapshot i into the recorder snapshot a session
// observes.
func (h *Host) CollectorSnapshot(i int) collector.Snapshot {
	snap := h.fixture.Snapshots[i]
	out := collector.Snapshot{Timestamp: snap.At, CaptureIndex: i + 1}
	for _, proc := range snap.Processes {
		out.Processes = append(out.Processes, collector.ProcessSnapshot{
			Process: platform.Process{
				PID: proc.PID, PPID: proc.PPID, PGID: proc.PGID, Name: proc.Name,
				State: proc.State, StartTicks: proc.StartTicks, RSSBytes: proc.RSSBytes,
			},
			CPUPercent: proc.CPUPercent,
		})
	}
	for _, conn := range snap.Connections {
		out.Connections = append(out.Connections, collector.ConnectionSnapshot{
			LocalAddr: conn.LocalAddr, LocalPort: conn.LocalPort,
			RemoteAddr: conn.RemoteAddr, RemotePort: conn.RemotePort,
			State: conn.State, Inode: conn.Inode, PID: conn.PID,
			StartTicks: conn.StartTicks, FD: conn.FD,
		})
	}
	return out
}

// window returns the freeze window for the whole fixture: one second either
// side of the observed samples.
func (h *Host) Window() (time.Time, time.Time) {
	snaps := h.fixture.Snapshots
	return snaps[0].At.Add(-time.Second), snaps[len(snaps)-1].At.Add(time.Second)
}

// EventTypes returns the sorted unique event types in a section.
func EventTypes(section evidence.Section) []string {
	seen := map[string]bool{}
	var out []string
	for _, event := range section.Events {
		if !seen[event.Type] {
			seen[event.Type] = true
			out = append(out, event.Type)
		}
	}
	sort.Strings(out)
	return out
}

// HasEvent reports whether the section contains the event type.
func HasEvent(section evidence.Section, eventType string) bool {
	for _, event := range section.Events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}
