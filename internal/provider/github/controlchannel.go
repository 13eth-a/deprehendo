// Control-channel classification (C12 / 5.15). A socket is CONTROL_CHANNEL
// only when its owner is a tagged supervisor, it is ESTABLISHED to remote
// TCP port 443, it is long-lived (≥ 3 consecutive samples, or
// re-established within 5 s after a previous control channel of the same
// runner closed), and a discriminator holds: runner-log timing within ±2 s
// of a connect record, or it is the only qualifying supervisor socket.
// without a discriminator it stays a CONTROL_CHANNEL_CANDIDATE, which
// signatures may cite as supporting evidence only. remote addresses never
// leave the capture: the decision is made here, live, and only the role is
// stored. worker sockets are never CONTROL_CHANNEL.
package github

import (
	"sort"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/provider/evidence"
)

// reestablishWindow is the long-poll cycle bound (C12.3).
const reestablishWindow = 5 * time.Second

// logTimingTolerance is the ±2 s of the log-timing discriminator.
const logTimingTolerance = 2 * time.Second

const controlChannelPort = 443

const channelMinConsecutive = 3

// channelTrack is the live state of one tracked socket.
type channelTrack struct {
	inode       uint64
	owner       evidence.ProcessRef
	runner      evidence.Ref
	firstSeen   time.Time
	lastSeen    time.Time
	consecutive int  // consecutive samples seen open
	open        bool // present in the latest sample
	closedAt    time.Time
	// reestablished: this socket opened within reestablishWindow of a
	// qualifying channel of the same runner closing (C12.3, the long-poll
	// cycle). A TCP reconnect is a new socket, so this is decided per runner,
	// never by waiting for the same inode to come back (audit R7).
	reestablished bool
	// progress: last byte counters seen, and when they last advanced. A
	// socket that holds queued send data or an armed timer without any
	// advance for reestablishWindow is wedged: its transport is dead while
	// the kernel still reports it ESTABLISHED (S10 network drop).
	acked, received uint64
	progressAt      time.Time
	wedged          bool
}

// observeSockets updates control-channel state from one snapshot's
// connection table. called from observe (single goroutine).
func (s *session) observeSockets(connections []collector.ConnectionSnapshot, at time.Time) {
	type candidate struct {
		inode  uint64
		owner  evidence.ProcessRef
		runner evidence.Ref
	}
	var present []candidate
	seen := make(map[uint64]bool, len(connections))
	for _, conn := range connections {
		if conn.State != "ESTABLISHED" || int(conn.RemotePort) != controlChannelPort {
			continue
		}
		if conn.PID == 0 {
			continue // owner unknown: never a broker fact (C12.1)
		}
		owner := evidence.ProcessRef{PID: conn.PID, StartTicks: conn.StartTicks}
		runner, issupervisor := s.supervisors[owner]
		if !issupervisor {
			continue
		}
		seen[conn.Inode] = true
		present = append(present, candidate{inode: conn.Inode, owner: owner, runner: runner})
	}
	// close first, so a socket that replaces one in this same sample sees
	// its predecessor's close (the long-poll cycle, C12.3).
	for inode, track := range s.channels {
		if !seen[inode] && track.open {
			track.open = false
			track.closedAt = at
		}
	}
	for _, conn := range connections {
		if track := s.channels[conn.Inode]; track != nil && track.open && conn.ProgressAvailable {
			track.observeProgress(conn, at)
		}
	}
	for _, c := range present {
		track := s.channels[c.inode]
		if track != nil && !track.open {
			// reappeared after a gap under the same inode: the run restarts
			// (C12.3 needs consecutive samples).
			track.consecutive = 0
		}
		if track == nil {
			track = &channelTrack{inode: c.inode, owner: c.owner, runner: c.runner, firstSeen: at}
			track.reestablished = s.recentlyClosedChannel(c.runner, at)
			s.channels[c.inode] = track
		}
		track.open = true
		track.owner = c.owner
		track.runner = c.runner
		track.lastSeen = at
		track.consecutive++
	}
	for _, track := range s.channels {
		if track.open && track.qualifying() {
			s.channelRunners[track.runner] = true
			if track.wedged {
				continue // a frozen transport does not end a stall episode
			}
			if _, disconnected := s.statedDisconnectAt(track.runner); disconnected {
				continue // the runner itself still says it is disconnected
			}
			// A live qualifying channel ends any communication-stall episode.
			if s.noteStalled[track.runner] {
				s.closeStallEpisode(track.runner, at)
			}
			delete(s.noteStalled, track.runner)
		}
	}
	// bound the tracked set (5.49): drop sockets dead for over a minute.
	for inode, track := range s.channels {
		if !track.open && at.Sub(track.closedAt) > time.Minute {
			delete(s.channels, inode)
		}
	}
}

// observeProgress advances the byte counters and wedge state of one open
// control socket. advancing counters clear the wedge; a socket with queued
// send data or an armed timer and no advance for reestablishWindow is wedged.
func (t *channelTrack) observeProgress(conn collector.ConnectionSnapshot, at time.Time) {
	advanced := conn.BytesAcked > t.acked || conn.BytesReceived > t.received
	if t.progressAt.IsZero() || advanced {
		t.progressAt = at
		t.wedged = false
	}
	t.acked, t.received = conn.BytesAcked, conn.BytesReceived
	// only unacknowledged send data, the retransmit timer (1) or the
	// zero-window probe (4) mean the transport is stuck. the keepalive timer
	// (2) is armed on every healthy idle long-poll, which carries no data for
	// most of its cycle.
	stuck := conn.TxQueue > 0 || conn.Timer == 1 || conn.Timer == 4
	if conn.QueuesAvailable && stuck && at.Sub(t.progressAt) > reestablishWindow {
		t.wedged = true
	}
}

// qualifying checks C12 items 1–3. item 1 was enforced when the socket was
// first tracked (only owner-verified supervisor sockets are tracked); item
// 3 is the long-lived test.
func (t *channelTrack) qualifying() bool {
	return t.consecutive >= channelMinConsecutive || t.reestablishedQuickly()
}

// reestablishedQuickly: this socket replaced a qualifying channel of the
// same runner within the long-poll window.
func (t *channelTrack) reestablishedQuickly() bool { return t.reestablished }

// recentlyClosedChannel: some qualifying channel of runner closed within
// reestablishWindow before at.
func (s *session) recentlyClosedChannel(runner evidence.Ref, at time.Time) bool {
	if !s.channelRunners[runner] {
		return false
	}
	for _, track := range s.channels {
		if track.runner != runner || track.open || track.closedAt.IsZero() {
			continue
		}
		if at.Sub(track.closedAt) <= reestablishWindow {
			return true
		}
	}
	return false
}

// communicationStalled returns, sorted, the runners that (a) once held a
// qualifying control channel, (b) are alive (a tagged supervisor incarnation
// is in the current sample), and (c) have had no open supervisor-owned 443
// connection for longer than reestablishWindow. A normal long-poll cycle
// replaces the socket within the window and never qualifies; a runner that
// died is a lifecycle fact, not a communication stall (audit R7).
func (s *session) communicationStalled(at time.Time, alive map[evidence.Ref]bool) []evidence.Ref {
	var out []evidence.Ref
	for runner := range s.channelRunners {
		if !alive[runner] {
			continue
		}
		open := false
		var lastClose time.Time
		for _, track := range s.channels {
			if track.runner != runner {
				continue
			}
			if track.open && !track.wedged {
				open = true
				break
			}
			if track.closedAt.After(lastClose) {
				lastClose = track.closedAt
			}
			if track.open && track.wedged && track.progressAt.After(lastClose) {
				// A wedged socket stopped carrying data at progressAt.
				lastClose = track.progressAt
			}
		}
		if open || lastClose.IsZero() || at.Sub(lastClose) <= reestablishWindow {
			continue
		}
		out = append(out, runner)
	}
	// the runner's own statement: an unanswered stated disconnect is a stall
	// even while idle pooled sockets stay ESTABLISHED (commstall.go).
	for runner := range alive {
		if containsRunnerRef(out, runner) {
			continue
		}
		if s.statedStall(runner, at) {
			out = append(out, runner)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// socketRoles renders the C12 decision at freeze time from live state. it
// depends only on facts collected while the host was live: a socket table
// without owner or state information classifies nothing (C12.2 needs
// ESTABLISHED + port 443; C12.1 needs a tagged supervisor owner).
func (s *session) socketRoles(from, to time.Time) []evidence.SocketRole {
	qualifyingtracks := make([]*channelTrack, 0, len(s.channels))
	for _, track := range s.channels {
		if track.qualifying() && windowOverlaps(track, from, to) {
			qualifyingtracks = append(qualifyingtracks, track)
		}
	}
	// C12.4(b) "the only supervisor socket satisfying 1–3" is about
	// sockets open at the same time: a socket that replaced a closed one is
	// still the only one (audit R7b: every past socket in the window used to
	// count, so a single reconnect demoted both to candidates).
	concurrent := func(track *channelTrack) int {
		count := 0
		for _, other := range qualifyingtracks {
			if other.runner != track.runner || other == track {
				continue
			}
			otherend, end := other.lastSeen, track.lastSeen
			if !other.firstSeen.After(end) && !track.firstSeen.After(otherend) {
				count++
			}
		}
		return count
	}
	out := make([]evidence.SocketRole, 0, len(qualifyingtracks))
	for _, track := range qualifyingtracks {
		role := evidence.SocketRole{
			Inode: track.inode, Owner: track.owner, Runner: track.runner,
			Confidence: evidence.ConfidenceMedium,
			Sources:    []evidence.Source{evidence.SourceLocalSocket},
			Evidence:   []string{EvidenceConnectionLongLived},
		}
		if track.reestablished && track.consecutive < channelMinConsecutive {
			role.Evidence = []string{EvidenceReestablishedQuickly}
		}
		logmatch := s.logTimingMatches(track)
		sole := concurrent(track) == 0
		switch {
		case logmatch:
			role.Role = SocketRoleControlChannel
			role.Evidence = append(role.Evidence, EvidenceLogTimingMatch)
			if sole {
				role.Confidence = evidence.ConfidenceHigh
			}
		case sole:
			role.Role = SocketRoleControlChannel
			role.Evidence = append(role.Evidence, EvidenceOnlyControlCandidate)
		default:
			role.Role = SocketRoleControlChannelCandidate
		}
		out = append(out, role)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Inode < out[j].Inode })
	return out
}

// windowOverlaps: the socket was observed within the freeze window.
func windowOverlaps(track *channelTrack, from, to time.Time) bool {
	if track.firstSeen.After(to) {
		return false
	}
	return track.lastSeen.IsZero() || !track.lastSeen.Before(from)
}

// logTimingMatches: the (a) discriminator. the channel's open falls within
// ±2 s of a runner connect record, or a job-received record follows within
// ±2 s of the open (progress burst on a fresh channel).
func (s *session) logTimingMatches(track *channelTrack) bool {
	for _, event := range s.events {
		if event.Runner != track.runner || event.Source != evidence.SourceRunnerLog {
			continue
		}
		switch event.Type {
		case EventRunnerReconnected:
			if absDuration(event.Timestamp.Sub(track.firstSeen)) <= logTimingTolerance {
				return true
			}
		case EventJobAssigned, EventJobAccepted:
			if !event.Timestamp.Before(track.firstSeen) &&
				event.Timestamp.Sub(track.firstSeen) <= logTimingTolerance {
				return true
			}
		}
	}
	return false
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
