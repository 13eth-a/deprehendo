// package simulator holds the fault-injection scenarios and the small runtime
// that runs them.
//
// A scenario creates one kind of machine or process failure and then gets out
// of the way. nothing here observes anything: phase 1 adds the recorder that
// watches these failures happen.
package simulator

import (
	"context"
	"flag"
	"sort"
	"time"

	"runopsy/internal/events"
)

// DefaultDuration is the runtime used by scenarios when the caller does not
// pass --duration and the scenario has no natural end of its own.
const DefaultDuration = 30 * time.Second

// config is everything a scenario needs to run. it is built once by the CLI and
// passed by value.
type Config struct {
	// duration is the overall runtime. zero means "the scenario's own default",
	// which may be a full cycle rather than a fixed window.
	Duration time.Duration
	// verbose enables extra detail in human output and extra events.
	Verbose bool
	// JSON reports whether the event stream is machine-readable.
	JSON bool
	// events is never nil when a scenario is launched through the CLI. the
	// Emit/Say helpers tolerate nil so tests can construct a bare Config.
	Events *events.Emitter
}

// emit records an event, tolerating a nil emitter.
func (c Config) Emit(typ string, data map[string]any) {
	if c.Events != nil {
		c.Events.Emit(typ, data)
	}
}

// say writes narration in text mode and drops it in JSON mode.
func (c Config) Say(msg string) {
	if c.Events != nil {
		c.Events.Say(msg)
	}
}

// scenario is one injectable failure.
//
// event types should be lowercase snake_case past-participle observations
// ("stall_detected", "worker_frozen"), with a single "started" and "exited"
// framing every run so consumers can bracket a scenario.
type Scenario interface {
	Name() string
	Description() string
	// run blocks until the scenario finishes or ctx is canceled. cancellation is
	// a normal outcome: clean up every child, socket, and goroutine, then return
	// nil. returning ctx.Err() is reserved for genuine interruption failures.
	Run(ctx context.Context, cfg Config) error
}

// flagged is an optional interface for scenarios that take their own flags.
//
// the CLI registers the shared flags (--duration, --verbose, --json) before
// asking the scenario to add its own, parses once, and then runs it. keep flag
// names unprefixed and document them in the scenario's Description.
type Flagged interface {
	RegisterFlags(fs *flag.FlagSet)
}

var registry = map[string]Scenario{}

// register adds a scenario to the CLI registry. it panics on a nil or duplicate
// scenario, because both are programming errors that should fail loudly in
// tests rather than at the user's first invocation.
func Register(s Scenario) {
	if s == nil {
		panic("simulator: Register(nil)")
	}
	name := s.Name()
	if name == "" {
		panic("simulator: scenario with empty name")
	}
	if _, dup := registry[name]; dup {
		panic("simulator: duplicate scenario " + name)
	}
	registry[name] = s
}

func init() {
	Register(&Normal{})
	Register(&SocketStall{})
}

// lookup returns the scenario registered under name.
func Lookup(name string) (Scenario, bool) {
	s, ok := registry[name]
	return s, ok
}

// scenarios returns every registered scenario sorted by name.
func Scenarios() []Scenario {
	out := make([]Scenario, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// names returns the registered scenario names sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
