package simulator

import (
	"fmt"
	"sync"
)

// connState is the state machine the socket-stall scenario drives:
//
//	CONNECTING -> HEALTHY -> STALLED -> RECOVERED -> CLOSED
//
// STALLED means "the TCP connection is still open and no application-level
// progress is being made". RECOVERED means progress resumed on the same
// connection (not a reconnect). every state may close early.
type connState string

const (
	stateConnecting connState = "CONNECTING"
	stateHealthy    connState = "HEALTHY"
	stateStalled    connState = "STALLED"
	stateRecovered  connState = "RECOVERED"
	stateClosed     connState = "CLOSED"
)

// connStateTransitions is the whole legal edge set. recovery loops are
// deliberately absent: a second stall on the same connection is a different
// condition than the one this scenario claims to produce, so the transition is
// rejected rather than silently accepted.
var connStateTransitions = map[connState][]connState{
	stateConnecting: {stateHealthy, stateClosed},
	stateHealthy:    {stateStalled, stateClosed},
	stateStalled:    {stateRecovered, stateClosed},
	stateRecovered:  {stateClosed},
	stateClosed:     {},
}

func (s connState) canTransitionTo(next connState) bool {
	for _, allowed := range connStateTransitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// transitioner guards the current state so concurrent observers cannot move it
// into an impossible state.
type transitioner struct {
	mu  sync.Mutex
	cur connState
}

func newTransitioner(from connState) *transitioner {
	return &transitioner{cur: from}
}

func (t *transitioner) State() connState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur
}

// transition moves to next and reports the previous state. an illegal move
// returns an error and leaves the state untouched.
func (t *transitioner) Transition(next connState) (connState, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.cur.canTransitionTo(next) {
		return t.cur, fmt.Errorf("illegal connection state transition %s -> %s", t.cur, next)
	}
	prev := t.cur
	t.cur = next
	return prev, nil
}
