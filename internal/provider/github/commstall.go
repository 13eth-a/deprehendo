package github

// Communication-stall episodes (5.16/5.21, real-runner scenario S10).
//
// two sources can open an episode for a live runner:
//
//  1. the socket rule (controlchannel.go): the runner once held a qualifying
//     control channel and now has no open, non-wedged supervisor socket to
//     443 for longer than reestablishWindow;
//  2. the runner's own statement: its log reported a connect error
//     ("runner connect error … retrying until reconnected") and stated no
//     reconnect for longer than logDisconnectGrace. this is what an outbound
//     block looks like when the listener also holds idle pooled HTTPS
//     connections: those stay ESTABLISHED with nothing queued, so the socket
//     rule alone keeps seeing a live channel for the whole outage.
//
// an episode is reported once, at its onset, and stays open until a live
// channel returns and the runner no longer stands disconnected. A capture
// taken during or after a long outage starts after the onset, so the onset
// event is kept in any window that the episode overlaps (S10: a 3-minute
// block captured with a 90 s pre-window used to lose the stall entirely).

import (
	"time"

	"runopsy/internal/provider/evidence"
)

// logDisconnectGrace is how long a stated disconnect may stay unanswered by
// a stated reconnect before it is a stall: long enough to ride out one retry,
// short against an outage.
const logDisconnectGrace = 30 * time.Second

// maxStallEpisodes bounds the episode history (5.49).
const maxStallEpisodes = 256

type stallEpisode struct {
	runner evidence.Ref
	onset  time.Time
	end    time.Time // zero while open
}

// statedDisconnectAt returns the runner's newest stated disconnect that no
// later stated reconnect or restart answers.
func (s *session) statedDisconnectAt(runner evidence.Ref) (time.Time, bool) {
	var disconnect, answered time.Time
	for _, ev := range s.events {
		if ev.Runner != runner || ev.Source != evidence.SourceRunnerLog {
			continue
		}
		switch ev.Type {
		case EventRunnerDisconnected:
			if ev.Timestamp.After(disconnect) {
				disconnect = ev.Timestamp
			}
		case EventRunnerReconnected, EventRunnerStarted:
			if ev.Timestamp.After(answered) {
				answered = ev.Timestamp
			}
		}
	}
	if disconnect.IsZero() || !answered.Before(disconnect) {
		return time.Time{}, false
	}
	return disconnect, true
}

// statedStall reports a live runner whose stated disconnect has gone
// unanswered for longer than logDisconnectGrace at time at.
func (s *session) statedStall(runner evidence.Ref, at time.Time) bool {
	disconnect, ok := s.statedDisconnectAt(runner)
	return ok && at.Sub(disconnect) > logDisconnectGrace
}

func (s *session) openStallEpisode(runner evidence.Ref, at time.Time) {
	s.stallEpisodes = append(s.stallEpisodes, stallEpisode{runner: runner, onset: at})
	if len(s.stallEpisodes) > maxStallEpisodes {
		s.stallEpisodes = s.stallEpisodes[len(s.stallEpisodes)-maxStallEpisodes:]
	}
}

func (s *session) closeStallEpisode(runner evidence.Ref, at time.Time) {
	for i := len(s.stallEpisodes) - 1; i >= 0; i-- {
		if s.stallEpisodes[i].runner == runner && s.stallEpisodes[i].end.IsZero() {
			s.stallEpisodes[i].end = at
			return
		}
	}
}

// stallEpisodeReaches reports whether the episode that began at onset for
// runner was still open at from (or ended at or after it), so its onset event
// belongs in a window starting at from.
func (s *session) stallEpisodeReaches(runner evidence.Ref, onset, from time.Time) bool {
	for _, ep := range s.stallEpisodes {
		if ep.runner == runner && ep.onset.Equal(onset) {
			return ep.end.IsZero() || !ep.end.Before(from)
		}
	}
	return false
}

func containsRunnerRef(list []evidence.Ref, want evidence.Ref) bool {
	for _, ref := range list {
		if ref == want {
			return true
		}
	}
	return false
}
