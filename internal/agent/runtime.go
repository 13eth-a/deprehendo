// package agent hosts the foreground phase 1 executable's runtime: it wires
// the platform collectors into the collector scheduler (which owns the ring
// buffer and partial-failure semantics) and exposes status, uptime, and JSON
// dumps for the CLI.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// status summarizes the current foreground recorder process.
type Status struct {
	LastSuccessfulSample time.Time                            `json:"last_successful_sample,omitempty"`
	DroppedSnapshots     uint64                               `json:"dropped_snapshots"`
	BufferBytes          int64                                `json:"buffer_bytes"`
	BufferByteCap        int64                                `json:"buffer_byte_cap"`
	StartedAt            time.Time                            `json:"started_at"`
	Uptime               time.Duration                        `json:"uptime"`
	LastSample           time.Time                            `json:"last_sample,omitempty"`
	LastDuration         time.Duration                        `json:"last_duration"`
	Samples              uint64                               `json:"samples"`
	ProcessCount         int                                  `json:"process_count"`
	ConnectionCount      int                                  `json:"connection_count"`
	CollectorMetrics     map[string]collector.CollectorMetric `json:"collectors"`
	CollectorErrors      uint64                               `json:"collector_errors"`
	MissedSamples        uint64                               `json:"missed_samples"`
	BufferUsed           int                                  `json:"buffer_used"`
	BufferCapacity       int                                  `json:"buffer_capacity"`
	LastError            string                               `json:"last_error,omitempty"`
}

// runtime records snapshots into the collector scheduler's bounded rolling
// buffer. run samples the process table immediately and then at each tick
// until the context is cancelled; collection is synchronous, so cycles cannot
// overlap or accumulate backlog.
type Runtime struct {
	sched   *collector.Scheduler
	capture *incident.Capture
}

// maxRecordedSnapshots bounds the buffer the agent is willing to allocate,
// so a grotesque --window/--interval combination fails at configuration time
// instead of materializing a giant ring buffer.
const maxRecordedSnapshots = 1 << 20

// options configures the foreground recorder.
type Options struct {
	Interval         time.Duration
	Window           time.Duration
	MaxHistoryBytes  int64
	Capacity         int
	DisableProcesses bool
	DisableNetwork   bool
	DisablePressure  bool
	DisableCgroups   bool
	// OnSnapshot feeds completed samples to an optional incident capture.
	// callbacks must be quick and must not reenter collection.
	OnSnapshot func(collector.Snapshot)
	// filter selects watched processes; the zero value records everything.
	Filter collector.Filter
	// WatchFS is the filesystem whose disk capacity is sampled (default "/").
	WatchFS string
	// capture optionally exposes manual triggers and incident status over the
	// control socket. the runtime does not feed it; OnSnapshot does.
	Capture *incident.Capture
}

// new creates a foreground runtime with a retention capacity of capacity
// snapshots at the given sampling interval.
func New(options Options) (*Runtime, error) {
	if options.Capacity <= 0 || options.Capacity > maxRecordedSnapshots {
		return nil, fmt.Errorf("agent: snapshot capacity %d out of supported range (1..%d)", options.Capacity, maxRecordedSnapshots)
	}
	sources := collector.Sources{
		OnSnapshot:      options.OnSnapshot,
		System:          collector.NewHostSystemCollector(options.WatchFS),
		Retention:       options.Window,
		MaxHistoryBytes: options.MaxHistoryBytes,
		ProcessCgroup:   processCgroupSource{},
		Process:         processSource{},
		Network:         networkSource{},
		Pressure:        pressureSource{},
		Cgroup:          cgroupSource{},
		Owners:          ownerSource{},
		Filter:          options.Filter,
	}
	if options.DisableProcesses {
		sources.Process = nil
		sources.ProcessCgroup = nil
	}
	if options.DisableNetwork {
		sources.Network = nil
		sources.Owners = nil
	}
	if options.DisablePressure {
		sources.Pressure = nil
	}
	if options.DisableCgroups {
		sources.Cgroup = nil
		sources.ProcessCgroup = nil
	}
	sched, err := collector.NewScheduler(options.Interval, options.Capacity, sources)
	if err != nil {
		return nil, fmt.Errorf("agent: initialize recorder: %w", err)
	}
	return &Runtime{sched: sched, capture: options.Capture}, nil
}

// run records until ctx is cancelled.
func (r *Runtime) Run(ctx context.Context) error {
	return r.sched.Run(ctx)
}

// SampleOnce performs one synchronous collection cycle without a loop. it
// backs the standalone dump command.
func (r *Runtime) SampleOnce() {
	r.sched.Collect(context.Background())
}

// history returns the retained snapshots oldest-first.
func (r *Runtime) History() []collector.Snapshot {
	return r.sched.History()
}

// status returns a copy of the current runtime health counters.
func (r *Runtime) Status() Status {
	schedstatus := r.sched.Status()
	status := Status{
		StartedAt:            schedstatus.StartedAt,
		LastSuccessfulSample: schedstatus.LastSuccessfulSample,
		BufferBytes:          schedstatus.BufferBytes,
		DroppedSnapshots:     schedstatus.DroppedSnapshots,
		BufferByteCap:        schedstatus.BufferByteCap,
		Uptime:               uptimeSince(schedstatus.StartedAt),
		LastSample:           schedstatus.LastSnapshot,
		LastDuration:         schedstatus.LastDuration,
		Samples:              schedstatus.Samples,
		CollectorErrors:      schedstatus.CollectorErr,
		MissedSamples:        schedstatus.MissedSamples,
		BufferUsed:           schedstatus.BufferUsed,
		BufferCapacity:       schedstatus.BufferCap,
		CollectorMetrics:     schedstatus.Collectors,
	}
	if status.StartedAt.IsZero() {
		status.Uptime = r.Uptime()
	}
	if latest, ok := r.sched.Latest(); ok {
		status.ProcessCount = len(latest.Processes)
		status.ConnectionCount = len(latest.Connections)
		if len(latest.Errors) > 0 {
			status.LastError = latest.Errors[0].Err
		}
	}
	return status
}

// uptime reports elapsed time since run (or the runtime construction) began.
func (r *Runtime) Uptime() time.Duration {
	return uptimeSince(r.sched.Status().StartedAt)
}

func uptimeSince(started time.Time) time.Duration {
	if started.IsZero() {
		return 0
	}
	return time.Since(started)
}

// dump writes the latest snapshot as JSON, including partial-failure records.
// it returns an error until the first collection cycle has stored a snapshot.
func (r *Runtime) Dump(w io.Writer) error {
	latest, ok := r.sched.Latest()
	if !ok {
		return fmt.Errorf("agent: no snapshot recorded yet")
	}
	return json.NewEncoder(w).Encode(latest)
}

// processSource adapts the platform process-table snapshot to the collector
// interface. Skip-races live inside the platform layer.
type processSource struct{}

func (processSource) CollectProcesses() ([]platform.Process, error) {
	return platform.Processes()
}

// networkSource adapts the host TCP table. Non-Linux platforms report an
// explicit not-implemented error, which the scheduler records as a partial
// failure rather than losing the snapshot.
type networkSource struct{}

func (networkSource) CollectConnections() ([]platform.TCPRecord, error) {
	return platform.Connections()
}

// pressureSource collects the PSI resources that exist on this host.
type pressureSource struct{}

func (pressureSource) CollectPressure() (map[platform.Resource]platform.PressureSnapshot, error) {
	out := make(map[platform.Resource]platform.PressureSnapshot, 3)
	var firstErr error
	for _, resource := range []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO} {
		snapshot, err := platform.ReadPressure(resource)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out[resource] = snapshot
	}
	return out, firstErr
}

// cgroupSource reports the cgroup the agent itself lives in.
type cgroupSource struct{}

func (cgroupSource) CollectCgroup() (platform.CgroupSnapshot, error) {
	return platform.SelfCgroup()
}

// ownerSource maps socket inodes to holding processes. it simply reports its
// not-implemented status on non-Linux hosts, which the scheduler tolerates.
type ownerSource struct{}

func (ownerSource) CollectSocketOwners() (map[uint64]platform.SocketOwner, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("platform: socket ownership not implemented on %s", runtime.GOOS)
	}
	return platform.SocketOwners(platform.DefaultProcRoot)
}

// processCgroupSource records the constraints of the observed process rather
// than assuming that every target shares the agent's cgroup.
type processCgroupSource struct{}

func (processCgroupSource) CollectProcessCgroup(pid int) (platform.CgroupSnapshot, error) {
	return platform.ProcessCgroup(pid)
}

func (processSource) CollectProcessesContext(ctx context.Context) ([]platform.Process, error) {
	return platform.ProcessesContext(ctx)
}
func (networkSource) CollectConnectionsContext(ctx context.Context) ([]platform.TCPRecord, error) {
	return platform.ConnectionsContext(ctx)
}

// CollectSocketProgressContext reads tier B tcp_info counters. it is Linux-only;
// other platforms return no table and no error, so progress stays absent there.
func (networkSource) CollectSocketProgressContext(ctx context.Context) (map[uint64]platform.SocketInfo, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	return platform.SocketInfos(ctx)
}
func (ownerSource) CollectSocketOwnersContext(ctx context.Context) (map[uint64]platform.SocketOwner, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("platform: socket ownership not implemented on %s", runtime.GOOS)
	}
	return platform.SocketOwnersContext(ctx, platform.DefaultProcRoot)
}

func (ownerSource) CollectSocketOwnersForContext(ctx context.Context, processes []platform.Process) (map[uint64]platform.SocketOwner, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("platform: socket ownership not implemented on %s", runtime.GOOS)
	}
	return platform.SocketOwnersForContext(ctx, platform.DefaultProcRoot, processes)
}
