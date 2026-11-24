// package collector defines the phase 1 flight-recorder core: the snapshot
// model, small specialized collector interfaces, the bounded rolling ring
// buffer, process-tree reconstruction, per-process CPU deltas keyed on
// PID+start-time identity, and the sampling scheduler with partial-failure
// semantics and self-monitoring counters.
package collector

import (
	"fmt"
	"time"

	"deprehendo/internal/platform"
)

// snapshot is one sample of the machine at Timestamp. every section is
// optional: System/Pressure/Cgroup are nil when their collector is absent or
// failed this round, processes and connections are simply shorter or empty.
// errors records failed or incomplete collectors; usable partial results are
// retained, so a failed network collector never destroys a good process sample.
type Snapshot struct {
	Timestamp time.Time `json:"timestamp"`
	// CaptureIndex is the recorder's per-capture sample counter (phase 1
	// contract): causal analysis processes samples in capture order, not wall
	// order, so a clock step cannot re-sort history (audit A7). zero in v1
	// bundles; test-built bundles set it explicitly.
	CaptureIndex int
	System       *SystemSnapshot                                 `json:"system,omitempty"`
	Pressure     map[platform.Resource]platform.PressureSnapshot `json:"pressure,omitempty"`
	Cgroup       *platform.CgroupSnapshot                        `json:"cgroup,omitempty"`
	Processes    []ProcessSnapshot                               `json:"processes,omitempty"`
	Connections  []ConnectionSnapshot                            `json:"connections,omitempty"`
	// MonotonicStart/MonotonicEnd bracket every read in this sample with
	// CLOCK_MONOTONIC readings (§8 / 6.28). the trace merge (§9.1) only
	// correlates tracer events against a snapshot whose clock window covers
	// the tracer's monotonic stamp; a wall-clock step inside the window can
	// then never invent a match. zero (clock read failed) disables matching
	// for the snapshot; both zero values fall back to wall ordering.
	MonotonicStart int64             `json:"monotonic_start,omitempty"`
	MonotonicEnd   int64             `json:"monotonic_end,omitempty"`
	Metrics        []CollectorTiming `json:"metrics,omitempty"`
	Errors         []CollectionError `json:"errors,omitempty"`
}

// CollectorTiming records the duration and outcome of one collector in this
// specific sample cycle. cumulative timing counters live in SchedulerStatus.
type CollectorTiming struct {
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration"`
	Error    bool          `json:"error"`
}

// SystemSnapshot is host-level CPU/load, memory, and disk state. values whose
// sensor is unavailable on this host stay zero; the system collector reports
// those gaps as an error on the snapshot rather than failing the sample.
type SystemSnapshot struct {
	LoadAvailable         bool    `json:"load_available"`
	CPUAvailable          bool    `json:"cpu_available"`
	CPUPercentAvailable   bool    `json:"cpu_percent_available"`
	MemoryStatsAvailable  bool    `json:"memory_stats_available"`
	DiskStatsAvailable    bool    `json:"disk_stats_available"`
	ProcessCountAvailable bool    `json:"process_count_available"`
	LoadAverage           float64 `json:"load_average"`
	CPUCount              int     `json:"cpu_count"`
	CPUPercent            float64 `json:"cpu_percent"`
	MemoryTotal           uint64  `json:"memory_total"`
	MemoryUsed            uint64  `json:"memory_used"`
	MemoryFree            uint64  `json:"memory_free"`
	MemoryBuffers         uint64  `json:"memory_buffers"`
	MemoryCached          uint64  `json:"memory_cached"`
	SwapTotal             uint64  `json:"swap_total"`
	SwapFree              uint64  `json:"swap_free"`
	DiskFilesystem        string  `json:"disk_filesystem"`
	DiskAvailable         uint64  `json:"disk_available"`
	DiskTotalInodes       uint64  `json:"disk_total_inodes"`
	DiskFreeInodes        uint64  `json:"disk_free_inodes"`
	MemoryAvailable       uint64  `json:"memory_available,omitempty"`
	DiskTotal             uint64  `json:"disk_total"`
	DiskFree              uint64  `json:"disk_free"`
	DiskUsed              uint64  `json:"disk_used"`
	ProcessCount          int     `json:"process_count"`
}

// ProcessSnapshot is one process in one sample. process carries the platform
// identity fields (pid, ppid, pgid, session, name, state, RSS, thread count,
// and linux clock-tick accounting). CPUPercent is derived between consecutive
// samples; the first sample of a process reports 0.
type ProcessSnapshot struct {
	platform.Process
	CPUPercent float64 `json:"cpu_percent"`
	// OpenFDs is the watched process descriptor count; -1 means unavailable.
	OpenFDs int                      `json:"open_fds"`
	Cgroup  *platform.CgroupSnapshot `json:"cgroup,omitempty"`
}

// ConnectionSnapshot is one TCP socket with, when it could be resolved, the
// owning process. PID 0 means ownership is unknown (net ns shared, or fd
// unreadable); FD is -1 in that case.
type ConnectionSnapshot struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	State      string `json:"state"`
	Inode      uint64 `json:"inode,omitempty"`
	PID        int    `json:"pid,omitempty"`
	// StartTicks is the owner's process start time. it names the PID
	// incarnation, so a reused PID is not mistaken for the original owner.
	StartTicks int64 `json:"start_ticks,omitempty"`
	FD         int   `json:"fd"`

	// tier A socket facts (§7.1); zero values with QueuesAvailable false
	// mean "not captured", never "empty queue".
	QueuesAvailable bool   `json:"queues_available,omitempty"`
	TxQueue         uint32 `json:"tx_queue,omitempty"`
	RxQueue         uint32 `json:"rx_queue,omitempty"`
	Timer           uint8  `json:"timer,omitempty"`
	Retransmits     uint32 `json:"retransmits,omitempty"`

	// tier B progress counters (§7.1), from NETLINK_SOCK_DIAG tcp_info. present
	// only when ProgressAvailable is true; zero never means "no progress".
	ProgressAvailable bool   `json:"progress_available,omitempty"`
	BytesAcked        uint64 `json:"bytes_acked,omitempty"`
	BytesReceived     uint64 `json:"bytes_received,omitempty"`
	LastDataRecvMs    uint32 `json:"last_data_recv_ms,omitempty"`
}

// CollectionError records that one named collector failed or returned partial
// data. errors are data in the snapshot, not a failure of the snapshot.
type CollectionError struct {
	Collector string `json:"collector"`
	Err       string `json:"error"`
}

func (e CollectionError) Error() string {
	return fmt.Sprintf("collector %s: %s", e.Collector, e.Err)
}

// SystemCollector produces host-level load/memory samples.
type SystemCollector interface {
	CollectSystem() (SystemSnapshot, error)
}

// ProcessCollector produces the raw process-table sample.
type ProcessCollector interface {
	CollectProcesses() ([]platform.Process, error)
}

// NetworkProducer produces the raw TCP table sample.
type NetworkProducer interface {
	CollectConnections() ([]platform.TCPRecord, error)
}

// PressureProducer produces one PSI reading per available resource.
type PressureProducer interface {
	CollectPressure() (map[platform.Resource]platform.PressureSnapshot, error)
}

// CgroupProducer produces one cgroup-limit reading.
type CgroupProducer interface {
	CollectCgroup() (platform.CgroupSnapshot, error)
}
