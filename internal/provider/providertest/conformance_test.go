package providertest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
)

// exampleProvider is the smallest provider that satisfies the contract. it is
// also the template the GitHub provider starts from.
type exampleProvider struct{ leakIdentifiers bool }

func (exampleProvider) Name() string { return "example-ci" }
func (exampleProvider) Vocabulary() evidence.Vocabulary {
	return evidence.Vocabulary{Provider: "example-ci", EventPrefix: "EXAMPLE_", EventTypes: []string{"EXAMPLE_WORKER_STARTED"}}
}
func (exampleProvider) Detect(context.Context, provider.HostView) (provider.Detection, error) {
	return provider.Detection{}, nil
}
func (exampleProvider) Discover(context.Context, provider.HostView) ([]provider.RunnerInstance, error) {
	return nil, nil
}
func (exampleProvider) Attach(context.Context, provider.HostView, provider.AttachOptions) (provider.Session, error) {
	return nil, errors.New("example provider has no live half")
}
func (p exampleProvider) Interpret(s evidence.Section, _ *incident.Incident) (provider.Interpretation, error) {
	out := provider.Interpretation{Provider: p.Name(), Section: s}
	for _, e := range s.Events {
		// A conforming provider decides from enumerations and refs only.
		if p.leakIdentifiers && len(s.Runners) > 0 && s.Runners[0].Name.State != evidence.Known {
			continue
		}
		out.Generic = append(out.Generic, provider.GenericEvent{
			Timestamp: e.Timestamp, Kind: provider.GenericWorkerStarted, Runner: e.Runner,
			Source: e.Source, Confidence: evidence.ConfidenceHigh, ProviderType: e.Type,
		})
	}
	return out, nil
}

func exampleFixture(t *testing.T) Fixture {
	runner, err := evidence.NewRef("rnr", []byte("salt"), "example")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	return Fixture{Name: "worker-started", Section: evidence.Section{
		Provider: "example-ci", SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyIdentifiers,
		Health: evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref: runner, Name: evidence.KnownText(evidence.ClassRunnerName, "runner-1", evidence.SourceRunnerConfig),
			Version: evidence.UnknownText(evidence.ClassVersion), Labels: evidence.UnknownText(evidence.ClassLabels),
			Lifecycle: evidence.LifecycleUnknown,
		}},
		Events: []evidence.Event{{Timestamp: at, Type: "EXAMPLE_WORKER_STARTED", Runner: runner, Source: evidence.SourceRunnerLog}},
	}}
}

func TestExampleProviderConforms(t *testing.T) {
	Run(t, exampleProvider{}, []Fixture{exampleFixture(t)})
}

// the kit must catch a provider whose diagnosis-facing output changes when
// identifiers are withheld.
func TestConformanceCatchesIdentifierDependence(t *testing.T) {
	violations := Check(exampleProvider{leakIdentifiers: true}, []Fixture{exampleFixture(t)})
	found := false
	for _, v := range violations {
		if strings.Contains(v, "depend on withheld identifiers") {
			found = true
		}
	}
	if !found {
		t.Errorf("conformance accepted a provider whose output depends on withheld identifiers: %v", violations)
	}
}

func TestConformanceCatchesBadGenericEvents(t *testing.T) {
	fx := exampleFixture(t)
	bad := badProvider{}
	violations := Check(bad, []Fixture{{Name: fx.Name, Section: relabel(fx.Section, bad.Name())}})
	if len(violations) == 0 {
		t.Errorf("conformance accepted an intent on a non-termination event and a dangling job ref")
	}
}

type badProvider struct{ exampleProvider }

func (badProvider) Name() string { return "bad-example-ci" }
func (badProvider) Vocabulary() evidence.Vocabulary {
	return evidence.Vocabulary{Provider: "bad-example-ci", EventPrefix: "EXAMPLE_", EventTypes: []string{"EXAMPLE_WORKER_STARTED"}}
}
func (p badProvider) Interpret(s evidence.Section, _ *incident.Incident) (provider.Interpretation, error) {
	job, _ := evidence.NewRef("job", []byte("salt"), "not-in-section")
	return provider.Interpretation{Provider: p.Name(), Section: s, Generic: []provider.GenericEvent{{
		Timestamp: s.Events[0].Timestamp, Kind: provider.GenericWorkerStarted, Intent: provider.IntentCancelled,
		Job: job, Source: evidence.SourceRunnerLog, Confidence: evidence.ConfidenceHigh, ProviderType: "EXAMPLE_WORKER_STARTED",
	}}}, nil
}

func relabel(s evidence.Section, name string) evidence.Section {
	s.Provider = name
	return s
}
