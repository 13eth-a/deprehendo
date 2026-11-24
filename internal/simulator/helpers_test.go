package simulator

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"deprehendo/internal/events"
)

func decodeEvents(t *testing.T, b *bytes.Buffer) []events.Event {
	t.Helper()
	var got []events.Event
	dec := json.NewDecoder(b)
	for dec.More() {
		var ev events.Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode event %d: %v\nraw: %s", len(got), err, b.String())
		}
		got = append(got, ev)
	}
	return got
}

func goroutines() int { return runtime.NumGoroutine() }

// checkGoroutines fails if the scenario left goroutines behind. it polls
// briefly because a just-closed socket's reader can take a moment to unwind.
func checkGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := goroutines()
		if n <= baseline {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutine leak: %d running, baseline %d\n%s", n, baseline, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
