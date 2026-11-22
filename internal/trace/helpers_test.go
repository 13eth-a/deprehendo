package trace

import (
	"sync"
	"time"
)

// waitSinkDeadline gives the reader goroutine a bounded chance to run. there
// is no lock published for "an event was consumed"; the loop schedules fast.
func (s *Session) waitSinkDeadline() { time.Sleep(2 * time.Millisecond) }

// eventCollector is a race-safe sink for tests.
type eventCollector struct {
	mu   sync.Mutex
	evts []TraceEvent
}

func newEventCollector() *eventCollector { return &eventCollector{} }

func (c *eventCollector) add(e TraceEvent) {
	c.mu.Lock()
	c.evts = append(c.evts, e)
	c.mu.Unlock()
}

func (c *eventCollector) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.evts)
}

func (c *eventCollector) all() []TraceEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]TraceEvent(nil), c.evts...)
}
