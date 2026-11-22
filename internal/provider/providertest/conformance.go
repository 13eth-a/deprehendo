// package providertest is the conformance kit every concrete provider must
// pass (docs/providers/architecture.md §10). A provider's own test calls run
// with fixtures captured from its fake-runner harness (5.41) and real runners
// (5.42).
package providertest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"runopsy/internal/incident"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// fixture is one recorded provider section with the incident it belongs to.
type Fixture struct {
	Name     string
	Section  evidence.Section
	Incident *incident.Incident // may be nil for section-only fixtures
}

var genericKinds = map[provider.GenericKind]bool{
	provider.GenericRunnerStarted: true, provider.GenericRunnerStopped: true,
	provider.GenericWorkAssigned: true, provider.GenericWorkerStarted: true,
	provider.GenericWorkerExited: true, provider.GenericWorkerProgressStopped: true,
	provider.GenericTerminationIntended: true,
}

var intents = map[provider.Intent]bool{
	provider.IntentCancelled: true, provider.IntentTimedOut: true,
	provider.IntentServiceShutdown: true, provider.IntentEphemeralComplete: true,
	provider.IntentUpdate: true, provider.IntentJobSucceeded: true,
}

// run checks the provider contract against fixtures and fails t for every
// violation check reports.
func Run(t *testing.T, p provider.Provider, fixtures []Fixture) {
	t.Helper()
	for _, v := range Check(p, fixtures) {
		t.Error(v)
	}
}

// check returns every contract violation:
//
//   - the provider registers cleanly and its vocabulary is its own;
//   - every fixture section validates;
//   - interpret is deterministic and does not mutate its input;
//   - every generic event is well formed and references only refs present in
//     the section;
//   - privacy independence: the generic events of a section redacted to the
//     conservative level are identical to those of the same section at the
//     identifiers level. diagnoses may never depend on withheld text.
func Check(p provider.Provider, fixtures []Fixture) (violations []string) {
	fail := func(format string, args ...any) { violations = append(violations, fmt.Sprintf(format, args...)) }
	if err := provider.NewRegistry().Register(p); err != nil {
		fail("register %s: %v", p.Name(), err)
		return violations
	}
	if len(fixtures) == 0 {
		fail("%s: conformance needs at least one fixture", p.Name())
	}
	for _, fx := range fixtures {
		prefix := fx.Name + ": "
		if fx.Section.Provider != p.Name() {
			fail(prefix+"fixture belongs to %q, not %q", fx.Section.Provider, p.Name())
			continue
		}
		if err := fx.Section.Validate(); err != nil {
			fail(prefix+"fixture section invalid: %v", err)
			continue
		}
		before := mustJSON(fx.Section)
		first, err := p.Interpret(fx.Section, fx.Incident)
		if err != nil {
			fail(prefix+"interpret: %v", err)
			continue
		}
		second, err := p.Interpret(fx.Section, fx.Incident)
		if err != nil {
			fail(prefix+"interpret (second call): %v", err)
			continue
		}
		if !reflect.DeepEqual(first.Generic, second.Generic) {
			fail("%sInterpret is not deterministic", prefix)
		}
		if mustJSON(fx.Section) != before {
			fail("%sInterpret mutated its input section", prefix)
		}
		for _, v := range checkGeneric(fx.Section, first.Generic) {
			fail("%s%s", prefix, v)
		}
		identifiers := clone(fx.Section)
		identifiers.Redact(evidence.PrivacyIdentifiers)
		conservative := clone(fx.Section)
		conservative.Redact(evidence.PrivacyConservative)
		if err := conservative.Validate(); err != nil {
			fail(prefix+"conservative redaction produced an invalid section: %v", err)
			continue
		}
		a, erra := p.Interpret(identifiers, fx.Incident)
		b, errb := p.Interpret(conservative, fx.Incident)
		if erra != nil || errb != nil {
			fail(prefix+"interpret after redaction: %v / %v", erra, errb)
			continue
		}
		if !reflect.DeepEqual(a.Generic, b.Generic) {
			fail(prefix+"generic events depend on withheld identifiers: identifiers=%+v conservative=%+v", a.Generic, b.Generic)
		}
	}
	return violations
}

func checkGeneric(section evidence.Section, events []provider.GenericEvent) (out []string) {
	runners, workers, jobs := map[evidence.Ref]bool{}, map[evidence.Ref]bool{}, map[evidence.Ref]bool{}
	for _, r := range section.Runners {
		runners[r.Ref] = true
	}
	for _, w := range section.Workers {
		workers[w.Ref] = true
	}
	for _, j := range section.Jobs {
		jobs[j.Ref] = true
	}
	for i, e := range events {
		if !genericKinds[e.Kind] {
			out = append(out, fmt.Sprintf("generic event %d: unknown kind %q", i, e.Kind))
		}
		if (e.Kind == provider.GenericTerminationIntended) != (e.Intent != "") || (e.Intent != "" && !intents[e.Intent]) {
			out = append(out, fmt.Sprintf("generic event %d: intent %q does not match kind %s", i, e.Intent, e.Kind))
		}
		if e.Timestamp.IsZero() || e.Source == "" || e.Confidence == "" || e.ProviderType == "" {
			out = append(out, fmt.Sprintf("generic event %d: missing timestamp, source, confidence or provider type", i))
		}
		if (e.Runner != "" && !runners[e.Runner]) || (e.Worker != "" && !workers[e.Worker]) || (e.Job != "" && !jobs[e.Job]) {
			out = append(out, fmt.Sprintf("generic event %d references a runner, worker or job absent from the section", i))
		}
		if i > 0 && e.Timestamp.Before(events[i-1].Timestamp) {
			out = append(out, "generic events are not sorted by timestamp")
		}
	}
	return out
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func clone(s evidence.Section) evidence.Section {
	var out evidence.Section
	if err := json.Unmarshal([]byte(mustJSON(s)), &out); err != nil {
		panic(err)
	}
	return out
}
