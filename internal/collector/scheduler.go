package collector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"runopsy/internal/platform"
)

// OwnerIndexer produces the inode→owner table used to attribute TCP sockets
// to processes. implementations are best-effort: an error means connections
// keep flowing but without ownership attribution.
type OwnerIndexer interface {
	CollectSocketOwners() (map[uint64]platform.SocketOwner, error)
}

// sources bundles the concrete collectors the scheduler polls. any field may
// be nil; nil collectors are skipped without being counted as errors. filter
// (if active) selects which sampled processes enter each snapshot; the whole
// process table is still read first so descendant expansion is possible.
type ProcessCgroupProducer interface {
	CollectProcessCgroup(pid int) (platform.CgroupSnapshot, error)
}

type Sources struct {
	// OnSnapshot receives a detached completed sample outside the history lock.
	// it must return promptly; capture persistence must happen asynchronously.
	OnSnapshot func(Snapshot)
	// retention expires samples by age, including when sampling is paused.
	// zero defaults to interval*capacity. MaxHistoryBytes defaults to 64 MiB
	// and bounds estimated retained go payload, including ring slots.
	Retention       time.Duration
	MaxHistoryBytes int64
	ProcessCgroup   ProcessCgroupProducer
	System          SystemCollector
	Process         ProcessCollector
	Network         NetworkProducer
	Pressure        PressureProducer
	Cgroup          CgroupProducer
	Owners          OwnerIndexer
	Filter          Filter
}

// scheduler runs one collection cycle at a time: cycles never overlap, so a
// slow collector cannot create backlog. late ticks are counted as missed
// samples instead. each collector's failure becomes a CollectionError inside
// the snapshot (partial-failure semantics), never a lost snapshot, and
// per-collector duration telemetry is kept for self-monitoring.
type Scheduler struct {
	onSnapshot      func(Snapshot)
	interval        time.Duration
	retention       time.Duration
	maxHistoryBytes int64
	historyBytes    int64
	dropped         uint64
	cycle           chan struct{}
	running         bool
	captureIndex    int
	processCgroup   ProcessCgroupProducer
	ring            *Ring[Snapshot]

	system   SystemCollector
	process  ProcessCollector
	network  NetworkProducer
	pressure PressureProducer
	cgroup   CgroupProducer
	owners   OwnerIndexer
	filter   Filter
	// selection applies filter across cycles, retaining reparented
	// descendants (see TreeSelection).
	selection TreeSelection
	cpu       CPUTracker

	mu           sync.RWMutex
	started      time.Time
	lastSuccess  time.Time
	lastTick     time.Time
	lastDuration time.Duration
	samples      uint64
	missed       uint64
	metrics      map[string]*CollectorMetric
}

// CollectorMetric is timing/failure telemetry for one collector name.
type CollectorMetric struct {
	LastSuccess time.Time     `json:"last_success,omitempty"`
	Cycles      uint64        `json:"cycles"`
	Errors      uint64        `json:"errors"`
	Last        time.Duration `json:"last"`
	Average     time.Duration `json:"average"`
	Total       time.Duration `json:"total"`
}

// SchedulerStatus is the agent's self-monitoring view: uptime, samples,
// missed ticks, buffer utilization, aggregate collector errors, and
// per-collector timing. the struct is a detached copy; updating it cannot
// mutate the scheduler's counters.
type SchedulerStatus struct {
	// LastSuccessfulSample is the last cycle with at least one successful collector.
	LastSuccessfulSample time.Time                  `json:"last_successful_sample,omitempty"`
	BufferBytes          int64                      `json:"buffer_bytes"`
	BufferByteCap        int64                      `json:"buffer_byte_capacity"`
	DroppedSnapshots     uint64                     `json:"dropped_snapshots"`
	StartedAt            time.Time                  `json:"started_at"`
	LastSnapshot         time.Time                  `json:"last_snapshot,omitempty"`
	LastDuration         time.Duration              `json:"last_duration"`
	Samples              uint64                     `json:"samples"`
	MissedSamples        uint64                     `json:"missed_samples"`
	BufferUsed           int                        `json:"buffer_used"`
	BufferCap            int                        `json:"buffer_capacity"`
	CollectorErr         uint64                     `json:"collector_errors"`
	Collectors           map[string]CollectorMetric `json:"collectors"`
}

// NewScheduler validates the cadence and capacity and prepares the ring.
func NewScheduler(interval time.Duration, capacity int, sources Sources) (*Scheduler, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("collector: sampling interval must be positive")
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("collector: snapshot capacity must be positive")
	}
	retention := sources.Retention
	if retention < 0 || (retention == 0 && int64(capacity) > int64(^uint64(0)>>1)/int64(interval)) {
		return nil, fmt.Errorf("collector: invalid retention duration")
	}
	if retention == 0 {
		retention = interval * time.Duration(capacity)
	}
	bytecap := sources.MaxHistoryBytes
	if bytecap == 0 {
		bytecap = 64 << 20
	}
	if bytecap < 0 || int64(capacity) > bytecap/int64(unsafe.Sizeof(Snapshot{})) {
		return nil, fmt.Errorf("collector: ring slots exceed history byte budget")
	}
	filter := sources.Filter
	filter.PIDs = append([]int(nil), filter.PIDs...)
	return &Scheduler{
		onSnapshot:      sources.OnSnapshot,
		interval:        interval,
		retention:       retention,
		maxHistoryBytes: bytecap,
		historyBytes:    int64(capacity) * int64(unsafe.Sizeof(Snapshot{})),
		cycle:           make(chan struct{}, 1),
		processCgroup:   sources.ProcessCgroup,
		ring:            NewRing[Snapshot](capacity),
		system:          sources.System,
		process:         sources.Process,
		network:         sources.Network,
		pressure:        sources.Pressure,
		cgroup:          sources.Cgroup,
		owners:          sources.Owners,
		filter:          filter,
		selection:       TreeSelection{Filter: filter},
		metrics:         make(map[string]*CollectorMetric),
	}, nil
}

// run samples immediately and then on each tick until cancellation.
func (s *Scheduler) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("collector: scheduler already running")
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	next := time.Now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		s.Collect(ctx)
		next = next.Add(s.interval)
		if late := time.Since(next); late >= 0 {
			missed := uint64(late/s.interval) + 1
			s.mu.Lock()
			s.missed += missed
			s.mu.Unlock()
			next = next.Add(time.Duration(missed) * s.interval)
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// latest returns a detached copy without cloning the entire history.
func (s *Scheduler) Latest() (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now())
	snapshot, ok := s.ring.latest()
	return cloneSnapshot(snapshot), ok
}

// history returns detached snapshots oldest-first, expiring aged samples even
// when recording has stopped.
func (s *Scheduler) History() []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now())
	items := s.ring.Items()
	for i := range items {
		items[i] = cloneSnapshot(items[i])
	}
	return items
}

func (s *Scheduler) expireLocked(now time.Time) {
	cutoff := now.Add(-s.retention)
	s.ring.evictWhile(func(item Snapshot) bool {
		if !item.Timestamp.Before(cutoff) {
			return false
		}
		s.historyBytes -= snapshotPayloadBytes(item)
		return true
	})
}

// status returns a copy of the self-monitoring counters.
func (s *Scheduler) Status() SchedulerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now())
	status := SchedulerStatus{
		LastSuccessfulSample: s.lastSuccess,
		BufferBytes:          s.historyBytes,
		BufferByteCap:        s.maxHistoryBytes,
		DroppedSnapshots:     s.dropped,
		StartedAt:            s.started,
		LastSnapshot:         s.lastTick,
		LastDuration:         s.lastDuration,
		Samples:              s.samples,
		MissedSamples:        s.missed,
		BufferUsed:           s.ring.Len(),
		BufferCap:            s.ring.Capacity(),
		Collectors:           make(map[string]CollectorMetric, len(s.metrics)),
	}
	var collectorErrs uint64
	for name, m := range s.metrics {
		status.Collectors[name] = *m
		collectorErrs += m.Errors
	}
	status.CollectorErr = collectorErrs
	return status
}

// collect runs one synchronous cycle and stores the snapshot in the ring.
// regardless of individual collector failures the returned snapshot contains
// whatever did succeed.
func (s *Scheduler) Collect(ctx context.Context) Snapshot {
	if ctx.Err() != nil {
		return Snapshot{}
	}
	select {
	case s.cycle <- struct{}{}:
	case <-ctx.Done():
		return Snapshot{}
	}
	defer func() { <-s.cycle }()
	if ctx.Err() != nil {
		return Snapshot{}
	}
	now := time.Now().UTC()
	snapshot := s.sample(ctx, now)
	if ctx.Err() != nil {
		return Snapshot{}
	}
	// stamp per-capture order before storing or exporting. Wall-clock steps do
	// not reorder samples during offline causal reconstruction.
	s.mu.Lock()
	s.captureIndex++
	snapshot.CaptureIndex = s.captureIndex
	s.mu.Unlock()
	// store only independent payloads. neither a producer reusing its output
	// map nor a caller editing Collect/History may corrupt retained history.
	stored := cloneSnapshot(snapshot)
	weight := snapshotPayloadBytes(stored)
	if s.onSnapshot != nil {
		defer func() { s.onSnapshot(cloneSnapshot(snapshot)) }()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now())
	// make room before add so overwritten payloads are accounted and cleared.
	canfit := weight <= s.maxHistoryBytes-int64(s.ring.Capacity())*int64(unsafe.Sizeof(Snapshot{}))
	needslot := s.ring.Len() == s.ring.Capacity()
	s.ring.evictWhile(func(item Snapshot) bool {
		if !canfit || (!needslot && s.historyBytes+weight <= s.maxHistoryBytes) {
			return false
		}
		s.historyBytes -= snapshotPayloadBytes(item)
		needslot = false
		return true
	})
	if s.historyBytes+weight <= s.maxHistoryBytes && !stored.Timestamp.Before(time.Now().Add(-s.retention)) {
		s.ring.Add(stored)
		s.historyBytes += weight
	} else {
		s.dropped++
	}
	if s.started.IsZero() {
		s.started = now
	}
	s.samples++
	s.lastTick = now
	for _, metric := range snapshot.Metrics {
		if !metric.Error {
			s.lastSuccess = now
			break
		}
	}
	return cloneSnapshot(snapshot)
}

// sample runs each configured collector, timing it individually, and folds
// partial results into one snapshot. failed collectors land in Errors.
func (s *Scheduler) sample(ctx context.Context, now time.Time) Snapshot {
	begantotal := time.Now()
	monostart := platform.MonotonicNs()
	snapshot := Snapshot{Timestamp: now}

	var records []platform.TCPRecord
	var progress map[uint64]platform.SocketInfo
	var owners map[uint64]platform.SocketOwner
	var cycleMetrics []CollectorTiming
	timed := func(name string, run func() error) error {
		begin := time.Now()
		err := s.timed(name, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return run()
		})
		cycleMetrics = append(cycleMetrics, CollectorTiming{
			Name: name, Duration: time.Since(begin), Error: err != nil,
		})
		return err
	}

	if s.system != nil {
		if err := timed("system", func() error {
			system, err := s.system.CollectSystem()
			snapshot.System = &system
			return err
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "system", Err: err.Error()})
		}
	}
	processtotal := 0
	processavailable := false
	identities := make(map[int]int64)
	if s.process != nil {
		if err := timed("processes", func() error {
			var raw []platform.Process
			var err error
			if source, ok := s.process.(interface {
				CollectProcessesContext(context.Context) ([]platform.Process, error)
			}); ok {
				raw, err = source.CollectProcessesContext(ctx)
			} else {
				raw, err = s.process.CollectProcesses()
			}
			var observed []ProcessSnapshot
			if raw != nil || err == nil {
				processavailable = true
				observed = s.cpu.Observe(raw, time.Now())
			}
			for _, p := range raw {
				identities[p.PID] = p.StartTicks
			}
			processtotal = len(observed)
			if s.filter.Active() {
				observed = s.selection.Select(observed)
			}
			snapshot.Processes = observed
			return err
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "processes", Err: err.Error()})
		}
	}
	if s.filter.Active() && len(snapshot.Processes) > 0 && runtime.GOOS == "linux" {
		if err := timed("open-fds", func() error {
			var failures []error
			for i := range snapshot.Processes {
				if err := ctx.Err(); err != nil {
					return err
				}
				p := &snapshot.Processes[i]
				count, err := platform.CountOpenFDsFor(p.Process)
				if err != nil {
					failures = append(failures, fmt.Errorf("pid %d: %w", p.PID, err))
					continue
				}
				p.OpenFDs = count
			}
			return errors.Join(failures...)
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "open-fds", Err: err.Error()})
		}
	}
	if s.filter.Active() && s.processCgroup != nil && len(snapshot.Processes) > 0 {
		if err := timed("process-cgroups", func() error {
			var failures []error
			for i := range snapshot.Processes {
				if err := ctx.Err(); err != nil {
					return err
				}
				p := &snapshot.Processes[i]
				cg, err := s.processCgroup.CollectProcessCgroup(p.PID)
				if cg.PID != p.PID || cg.StartTicks != p.StartTicks {
					failures = append(failures, fmt.Errorf("pid %d: cgroup identity unavailable or changed", p.PID))
					continue
				}
				if cg.Path != "" {
					p.Cgroup = &cg
				}
				if err != nil {
					failures = append(failures, fmt.Errorf("pid %d: %w", p.PID, err))
				}
			}
			return errors.Join(failures...)
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "process-cgroups", Err: err.Error()})
		}
	}

	if s.network != nil {
		if err := timed("connections", func() error {
			var rows []platform.TCPRecord
			var inner error
			if source, ok := s.network.(interface {
				CollectConnectionsContext(context.Context) ([]platform.TCPRecord, error)
			}); ok {
				rows, inner = source.CollectConnectionsContext(ctx)
			} else {
				rows, inner = s.network.CollectConnections()
			}
			records = rows
			return inner
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "connections", Err: err.Error()})
		}
		if source, ok := s.network.(interface {
			CollectSocketProgressContext(context.Context) (map[uint64]platform.SocketInfo, error)
		}); ok {
			if err := timed("socket-progress", func() error {
				var inner error
				progress, inner = source.CollectSocketProgressContext(ctx)
				return inner
			}); err != nil {
				snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "socket-progress", Err: err.Error()})
			}
		}
	}
	if s.network != nil && s.owners != nil {
		if err := timed("socket-owners", func() error {
			var table map[uint64]platform.SocketOwner
			var inner error
			if source, ok := s.owners.(interface {
				CollectSocketOwnersForContext(context.Context, []platform.Process) (map[uint64]platform.SocketOwner, error)
			}); ok && s.filter.Active() {
				selected := make([]platform.Process, len(snapshot.Processes))
				for i, p := range snapshot.Processes {
					selected[i] = p.Process
				}
				table, inner = source.CollectSocketOwnersForContext(ctx, selected)
			} else if source, ok := s.owners.(interface {
				CollectSocketOwnersContext(context.Context) (map[uint64]platform.SocketOwner, error)
			}); ok {
				table, inner = source.CollectSocketOwnersContext(ctx)
			} else {
				table, inner = s.owners.CollectSocketOwners()
			}
			owners = table
			return inner
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "socket-owners", Err: err.Error()})
		}
	}
	if s.pressure != nil {
		if err := timed("pressure", func() error {
			pressure, err := s.pressure.CollectPressure()
			snapshot.Pressure = pressure
			return err
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "pressure", Err: err.Error()})
		}
	}
	if s.cgroup != nil {
		if err := timed("cgroups", func() error {
			cg, err := s.cgroup.CollectCgroup()
			if err == nil && cg.Path == "" {
				// no unified cgroup line on this host (cgroup v1 or a
				// platform without cgroups): omit the section entirely.
				snapshot.Cgroup = nil
				return nil
			}
			snapshot.Cgroup = &cg
			return err
		}); err != nil {
			snapshot.Errors = append(snapshot.Errors, CollectionError{Collector: "cgroups", Err: err.Error()})
		}
	}

	// attribution must refer to the same PID incarnation as the process
	// table, rather than a replacement process encountered by the fd scan.
	if s.process != nil {
		checked := make(map[uint64]platform.SocketOwner, len(owners))
		for inode, owner := range owners {
			if start, ok := identities[owner.PID]; ok && start == owner.StartTicks {
				checked[inode] = owner
			}
		}
		owners = checked
	}
	snapshot.Connections = connectSnapshots(records, owners, progress)
	snapshot.Metrics = cycleMetrics
	if s.process != nil {
		// ProcessCount is the host total sampled this cycle, not the number
		// retained after filtering. values provided by a system collector
		// (memory, disk, load) must survive this fill.
		if snapshot.System == nil {
			snapshot.System = &SystemSnapshot{CPUCount: runtime.NumCPU()}
		}
		snapshot.System.ProcessCount = processtotal
		snapshot.System.ProcessCountAvailable = processavailable
	}
	if monostart > 0 {
		// bracket the whole read cycle with CLOCK_MONOTONIC (§8): the trace
		// merge correlates a tracer event to this snapshot only when the
		// event's monotonic stamp falls inside this window, so a wall-clock
		// step mid-read can never invent or destroy a match.
		if mononow := platform.MonotonicNs(); mononow >= monostart {
			snapshot.MonotonicStart = monostart
			snapshot.MonotonicEnd = mononow
		}
	}

	s.mu.Lock()
	s.lastDuration = time.Since(begantotal)
	s.mu.Unlock()

	if len(snapshot.Errors) == 0 {
		snapshot.Errors = nil
	}
	return snapshot
}

// connectSnapshots converts raw TCP rows into owned connection snapshots.
// ownership is best-effort attribution by socket inode.
func connectSnapshots(records []platform.TCPRecord, owners map[uint64]platform.SocketOwner, progress map[uint64]platform.SocketInfo) []ConnectionSnapshot {
	out := make([]ConnectionSnapshot, 0, len(records))
	for _, r := range records {
		conn := ConnectionSnapshot{
			LocalAddr:  printAddr(r.LocalAddr),
			LocalPort:  r.LocalPort,
			RemoteAddr: printAddr(r.RemoteAddr),
			RemotePort: r.RemotePort,
			State:      r.State,
			Inode:      r.Inode,
			FD:         -1,

			QueuesAvailable: r.QueuesAvailable,
			TxQueue:         r.TxQueue,
			RxQueue:         r.RxQueue,
			Timer:           r.Timer,
			Retransmits:     r.Retransmits,
		}
		if info, ok := progress[r.Inode]; ok && r.Inode != 0 {
			conn.ProgressAvailable = true
			conn.BytesAcked = info.BytesAcked
			conn.BytesReceived = info.BytesReceived
			conn.LastDataRecvMs = info.LastDataRecvMs
		}
		if owner, ok := owners[r.Inode]; ok {
			conn.PID = owner.PID
			conn.StartTicks = owner.StartTicks
			conn.FD = owner.FD
		}
		out = append(out, conn)
	}
	return out
}

// timed measures one collector call and merges duration/error into telemetry.
func (s *Scheduler) timed(name string, run func() error) error {
	begin := time.Now()
	err := run()
	duration := time.Since(begin)
	// shutdown cancellation is not a sensor failure or a completed cycle.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	metric := s.metrics[name]
	if metric == nil {
		metric = &CollectorMetric{}
		s.metrics[name] = metric
	}
	metric.Cycles++
	metric.Last = duration
	metric.Total += duration
	metric.Average = time.Duration(int64(metric.Total) / int64(metric.Cycles))
	if err != nil {
		metric.Errors++
	} else {
		metric.LastSuccess = time.Now().UTC()
	}
	return err
}

func printAddr(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
