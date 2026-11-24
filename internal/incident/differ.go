package incident

import (
	"cmp"
	"sort"
	"strings"
	"time"

	"deprehendo/internal/collector"
)

type identity struct {
	pid   int
	start int64
}

// availability evidence must agree: an optimistic host count cannot override
// failed collector telemetry. duplicate metrics are treated conservatively.
func sectionOK(s collector.Snapshot, name string, available bool) bool {
	for _, m := range s.Metrics {
		if m.Name == name {
			if m.Error {
				return false
			}
			available = true
		}
	}
	for _, e := range s.Errors {
		if e.Collector == name {
			return false
		}
	}
	return available
}
func processOK(s collector.Snapshot) bool {
	return sectionOK(s, "processes", s.System != nil && s.System.ProcessCountAvailable)
}
func networkOK(s collector.Snapshot) bool { return sectionOK(s, "connections", false) }

// differ preserves baselines across unavailable sections. no start/exit is
// fabricated on the first observation; PID reuse is exit+start, not mutation.
type connectionIdentity struct {
	local, remote         string
	localPort, remotePort uint16
	inode                 uint64
}

type Differ struct {
	processes   map[identity]collector.ProcessSnapshot
	connections map[connectionIdentity]collector.ConnectionSnapshot
	last        time.Time
}

func (d *Differ) Observe(s collector.Snapshot) []Event {
	if s.Timestamp.IsZero() || (!d.last.IsZero() && !s.Timestamp.After(d.last)) {
		return nil
	}
	d.last = s.Timestamp
	var out []Event
	if processOK(s) {
		next := make(map[identity]collector.ProcessSnapshot, len(s.Processes))
		for _, p := range s.Processes {
			key := identity{p.PID, p.StartTicks}
			next[key] = p
			if old, ok := d.processes[key]; ok {
				if old.State != p.State {
					out = append(out, Event{Timestamp: s.Timestamp, Type: ProcessStateChanged, PID: p.PID, StartTicks: p.StartTicks, From: old.State, To: p.State})
				}
			} else if d.processes != nil {
				out = append(out, Event{Timestamp: s.Timestamp, Type: ProcessStarted, PID: p.PID, StartTicks: p.StartTicks})
			}
		}
		for key := range d.processes {
			if _, ok := next[key]; !ok {
				event := Event{Timestamp: s.Timestamp, Type: ProcessExited, PID: key.pid, StartTicks: key.start}
				// the kernel exposes a terminal wait status only while the
				// zombie still occupies its PID (linux, platform capture): a
				// last-seen zombie row is the one sample that can still name
				// how this process ended. A reaped, vanished PID carries no
				// status and the field stays empty.
				if last, ok := d.processes[key]; ok && strings.HasPrefix(last.State, "Z") {
					event.ExitStatus = last.ExitStatus
				}
				out = append(out, event)
			}
		}
		d.processes = next
	}
	if networkOK(s) {
		next := make(map[connectionIdentity]collector.ConnectionSnapshot, len(s.Connections))
		for _, c := range s.Connections {
			// ownership and state may change without a new socket. inode+tuple is
			// best effort within the recording namespace, not a global socket ID.
			key := connectionIdentity{c.LocalAddr, c.RemoteAddr, c.LocalPort, c.RemotePort, c.Inode}
			next[key] = c
			if _, ok := d.connections[key]; !ok && d.connections != nil {
				v := c
				out = append(out, Event{Timestamp: s.Timestamp, Type: ConnectionOpened, PID: c.PID, Connection: &v})
			}
		}
		for key, c := range d.connections {
			if _, ok := next[key]; !ok {
				v := c
				out = append(out, Event{Timestamp: s.Timestamp, Type: ConnectionClosed, PID: c.PID, Connection: &v})
			}
		}
		d.connections = next
	}
	failedcollectors := make(map[string]bool)
	for _, e := range s.Errors {
		if !failedcollectors[e.Collector] {
			out = append(out, Event{Timestamp: s.Timestamp, Type: CollectorError, Collector: e.Collector})
			failedcollectors[e.Collector] = true
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return eventLess(out[a], out[b]) })
	return out
}

// ProcessExitRule consumes only successful process sections. it must be fed
// the watched selection (not arbitrary host processes). explicit opt-in is
// required; an unavailable collector never implies process death.
type ProcessExitRule struct {
	Enabled bool
	rule    WatchedProcessExitRule
}

func (r *ProcessExitRule) Observe(s collector.Snapshot) *Trigger {
	r.rule.Enabled = r.Enabled
	return r.rule.Observe(s)
}

// debounce emits once per uninterrupted threshold episode. unavailable or
// below-threshold observations reset duration; stale observations are ignored.
// callers decide the threshold and maximum acceptable sampling gap.
type Debounce struct {
	Duration    time.Duration
	since, last time.Time
	fired       bool
}

func (d *Debounce) Observe(at time.Time, exceeded, available bool) bool {
	if at.IsZero() || (!d.last.IsZero() && !at.After(d.last)) {
		return false
	}
	if !available || !exceeded || d.Duration < 0 {
		d.since = time.Time{}
		d.fired = false
		d.last = at
		return false
	}
	d.last = at
	if d.since.IsZero() {
		d.since = at
	}
	if !d.fired && at.Sub(d.since) >= d.Duration {
		d.fired = true
		return true
	}
	return false
}

// compare typed fields directly: serializing in the sort comparator causes
// O(n log n) allocations for large unattributed connection tables.
func eventLess(a, b Event) bool {
	if c := cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.PID, b.PID), cmp.Compare(a.StartTicks, b.StartTicks), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To), cmp.Compare(a.Collector, b.Collector)); c != 0 {
		return c < 0
	}
	if a.Connection == nil || b.Connection == nil {
		return a.Connection == nil && b.Connection != nil
	}
	x, y := a.Connection, b.Connection
	return cmp.Or(cmp.Compare(x.LocalAddr, y.LocalAddr), cmp.Compare(x.LocalPort, y.LocalPort), cmp.Compare(x.RemoteAddr, y.RemoteAddr), cmp.Compare(x.RemotePort, y.RemotePort), cmp.Compare(x.Inode, y.Inode), cmp.Compare(x.State, y.State), cmp.Compare(x.PID, y.PID), cmp.Compare(x.FD, y.FD)) < 0
}
