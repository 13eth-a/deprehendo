// package events implements the structured event stream shared by every
// deprehendo-sim scenario.
//
// one call to [Emitter.Emit] produces one record. in text mode the record is
// rendered as a compact human line; with --json it becomes one JSON object per
// line on stdout, which is what later phases will consume.
package events

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// event is one machine-readable record.
//
// the field set is part of the phase 0 contract: tests and, later, the
// diagnostic recorder decode these names verbatim. timestamps are always UTC
// and are serialized as RFC 3339 with sub-second precision.
type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Scenario  string         `json:"scenario"`
	Type      string         `json:"type"`
	Data      map[string]any `json:"data,omitempty"`
}

// HumanTimeLayout is the clock format used for human-readable output.
const HumanTimeLayout = "15:04:05.000"

// emitter serializes events from any number of goroutines onto one stream.
//
// in text mode (the default) events are rendered for humans and [Emitter.Say]
// is available for plain narration. in JSON mode only newline-delimited JSON is
// written, so stdout stays machine-parseable even while goroutines narrate.
type Emitter struct {
	scenario string
	jsonMode bool
	out      io.Writer
	human    io.Writer
	now      func() time.Time

	mu       sync.Mutex
	enc      *json.Encoder
	firstErr error
}

// new builds an Emitter. out receives JSON events; human receives text. pass
// nil to drop a stream. jsonMode switches the emitter to JSON-only output.
func New(scenario string, out, human io.Writer, jsonMode bool) *Emitter {
	e := &Emitter{
		scenario: scenario,
		jsonMode: jsonMode,
		out:      out,
		human:    human,
		now:      time.Now,
	}
	if out != nil {
		e.enc = json.NewEncoder(out)
	}
	return e
}

// JSON reports whether the emitter is in JSON mode.
func (e *Emitter) JSON() bool { return e.jsonMode }

// emit records one event. it is safe to call from multiple goroutines; records
// are written atomically and in call order.
//
// write failures are recorded rather than returned so scenarios do not have to
// thread error handling through every observation. call [Emitter.Err] once the
// scenario finishes.
func (e *Emitter) Emit(typ string, data map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ts := e.now().UTC()
	if e.jsonMode {
		if e.enc == nil {
			return
		}
		ev := Event{Timestamp: ts, Scenario: e.scenario, Type: typ, Data: data}
		if err := e.enc.Encode(ev); err != nil && e.firstErr == nil {
			e.firstErr = err
		}
		return
	}

	if e.human == nil {
		return
	}
	if _, err := fmt.Fprintln(e.human, formatText(ts, typ, data)); err != nil && e.firstErr == nil {
		e.firstErr = err
	}
}

// say writes a plain narration line in text mode and discards it in JSON mode.
// use it for context that is not an observation (banners, hints).
func (e *Emitter) Say(msg string) {
	if e.jsonMode {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.human == nil {
		return
	}
	if _, err := fmt.Fprintln(e.human, msg); err != nil && e.firstErr == nil {
		e.firstErr = err
	}
}

// err returns the first write error seen, if any.
func (e *Emitter) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.firstErr
}

// formatText renders one event as "<clock>  <type>  k=v k=v", with data keys
// sorted so repeated runs produce identical output.
func formatText(ts time.Time, typ string, data map[string]any) string {
	var b strings.Builder
	b.WriteString(ts.Format(HumanTimeLayout))
	b.WriteString("  ")
	b.WriteString(fmt.Sprintf("%-20s", typ))
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 0 {
			b.WriteString("  ")
		} else {
			b.WriteString(" ")
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(fmt.Sprint(data[k]))
	}
	return b.String()
}
