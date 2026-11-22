package causal

import (
	"fmt"
	"time"

	"runopsy/internal/collector"
)

// networkStallThreshold is how long a socket that previously made progress
// must show none before NETWORK_PROGRESS_STOPPED is emitted (§7.2).
const networkStallThreshold = 30 * time.Second

// stall shapes (§7.2): the tier A observation one stalled sample's queues
// and timer make possible, stamped on NETWORK_PROGRESS_STOPPED and carried
// by NETWORK_PROGRESS_RESUMED. each shape discriminates between competing
// explanations of the stop condition (§7.3):
//
//	PEER_SILENT          everything we sent is acked, nothing is armed:
//	                     the peer (broker) is not sending. the
//	                     BROKER_SOCKET_STALL side.
//	PATH_LOSS            our data is queued and not acked, retransmit armed:
//	                     the NETWORK_PATH_FAILURE side.
//	ZERO_WINDOW          zero-window probe armed: the peer stopped reading.
//	LOCAL_NOT_READING    unread receive data accumulates: the local process
//	                     is not reading. the stall's arrow reverses (N1),
//	                     so this shape outranks the others.
//	UNKNOWN_SHAPE        tier A queues/timer unavailable: no discrimination.
const (
	StallShapePeerSilent      = "PEER_SILENT"
	StallShapePathLoss        = "PATH_LOSS"
	StallShapeZeroWindow      = "ZERO_WINDOW"
	StallShapeLocalNotReading = "LOCAL_NOT_READING"
	StallShapeUnknown         = "UNKNOWN_SHAPE"
)

// classifyStallShape reads the tier A wire fields of one stalled sample
// (§7.2). only discriminating combinations classify; anything ambiguous is
// UNKNOWN_SHAPE, never a guess. tier A semantics follow /proc/net/tcp:
// timer 1 = retransmit timer armed, 4 = zero-window probe; retransmits is
// the unrecovered RTO count. A missing tier A reading is UNKNOWN, not an
// empty queue.
func classifyStallShape(c collector.ConnectionSnapshot) string {
	if !c.QueuesAvailable {
		return StallShapeUnknown
	}
	if c.RxQueue > 0 {
		// unreceived data accumulates in the receive queue: the local
		// process is not reading through this socket. this shape wins
		// over any send-side state because it alone reverses the arrow.
		return StallShapeLocalNotReading
	}
	if c.Timer == 4 && c.TxQueue > 0 {
		return StallShapeZeroWindow
	}
	if (c.Timer == 1 || c.Retransmits > 0) && c.TxQueue > 0 {
		return StallShapePathLoss
	}
	if c.TxQueue == 0 && c.Timer == 0 && c.Retransmits == 0 {
		return StallShapePeerSilent
	}
	return StallShapeUnknown
}

// tierAData renders the tier A fields of one stalled sample honestly: the
// keys exist only when the sample carried a reading, so a zero value can
// always mean "empty queue, observed", never "not captured".
func tierAData(c collector.ConnectionSnapshot) map[string]any {
	if !c.QueuesAvailable {
		return nil
	}
	return map[string]any{
		"send_q":      int(c.TxQueue),
		"recv_q":      int(c.RxQueue),
		"timer":       int(c.Timer),
		"rto_count":   int(c.Retransmits),
		"stall_shape": classifyStallShape(c),
	}
}

// socketProgress tracks one socket inode across samples. A socket that never
// showed progress in this capture is idle, not stalled, and emits nothing.
type socketProgress struct {
	subject      SubjectRef
	acked        uint64
	received     uint64
	seen         bool
	everProgress bool
	lastProgress time.Time
	stalled      bool
	stallShape   string // shape of the open episode, from the last stalled sample
	episodeN     int
	episode      string
}

// networkMachine evaluates the tier B counters of ESTABLISHED sockets. samples
// must be observed in capture order.
type networkMachine struct {
	sockets map[uint64]*socketProgress
}

// tierA renders the shape of the open stall episode (stall_shape) for the
// closing RESUMED event; keyed so it merges into episodeFinish's map.
func (p *socketProgress) tierA() map[string]any {
	if p.stallShape == "" {
		return nil
	}
	return map[string]any{"stall_shape": p.stallShape}
}

// breakContinuity forgets the previous counters after a clock step or a
// sensor gap, so a stale comparison cannot create or end an episode (P4).
func (m *networkMachine) breakContinuity() {
	for _, p := range m.sockets {
		p.seen = false
	}
}

// observe consumes one sample's connections and returns the derived events.
// progress is a strictly larger cumulative counter than the previous sample.
func (m *networkMachine) observe(at time.Time, conns []collector.ConnectionSnapshot, prov EventProvenance, certain bool) []Event {
	if m.sockets == nil {
		m.sockets = map[uint64]*socketProgress{}
	}
	var out []Event
	for ci := range conns {
		c := &conns[ci]
		if !c.ProgressAvailable || c.Inode == 0 || c.State != "ESTABLISHED" {
			continue
		}
		p := m.sockets[c.Inode]
		if p == nil {
			p = &socketProgress{subject: socketSubject(c)}
			m.sockets[c.Inode] = p
		}
		advanced := p.seen && (c.BytesAcked > p.acked || c.BytesReceived > p.received)
		p.acked, p.received, p.seen = c.BytesAcked, c.BytesReceived, true
		if !certain {
			// unordered sample: counters are recorded, no episode is decided.
			continue
		}
		if advanced {
			if p.stalled {
				data := episodeFinish(at.Sub(p.lastProgress))
				// §7.2: the resumed event names the shape of the episode it
				// closes, judged from the last stalled sample.
				for k, v := range p.tierA() {
					data[k] = v
				}
				out = append(out, Event{
					Type: EventNetworkProgressResumed, Timestamp: at, Subject: p.subject,
					Episode: p.episode,
					Data:    data, Provenance: prov,
				})
				p.stalled = false
				p.stallShape = ""
			}
			p.everProgress = true
			p.lastProgress = at
			continue
		}
		if p.everProgress && !p.stalled && at.Sub(p.lastProgress) >= networkStallThreshold {
			p.stalled = true
			p.episodeN++
			p.episode = fmt.Sprintf("network:%s#%d", p.subject.ID, p.episodeN)
			if data := tierAData(*c); data != nil {
				p.stallShape, _ = data["stall_shape"].(string)
			} else {
				p.stallShape = StallShapeUnknown
			}
			stopped := map[string]any{
				// §7.2: the shape is stamped on every STOPPED. UNKNOWN_SHAPE
				// even when no tier A reading was captured (no discrimination).
				"stall_shape":      p.stallShape,
				"stall_ms":         at.Sub(p.lastProgress).Milliseconds(),
				"last_progress_at": p.lastProgress.Format(time.RFC3339Nano),
			}
			for k, v := range tierAData(*c) {
				stopped[k] = v
			}
			out = append(out, Event{
				Type: EventNetworkProgressStopped, Timestamp: at, Subject: p.subject,
				Episode: p.episode,
				// the owner is typed identity, so the ownership rule can bind on it.
				// zero PID means the owner was not resolved this sample.
				PID: c.PID, StartTicks: c.StartTicks,
				Data:       stopped,
				Provenance: prov,
			})
			continue
		}
		if p.stalled {
			// the stall continues: the shape can change while the episode is
			// open (a retransmit timer arms, the receive queue fills). the
			// event already emitted keeps its onset shape; the open episode's
			// latest shape is what a later RESUMED reports.
			if data := tierAData(*c); data != nil {
				p.stallShape, _ = data["stall_shape"].(string)
			}
		}
	}
	return out
}
