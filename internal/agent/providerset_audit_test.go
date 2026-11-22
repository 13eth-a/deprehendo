package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// panickyProvider is detected but panics in Discover.
type panickyProvider struct{}

func (panickyProvider) Name() string { return "audit-panic" }
func (panickyProvider) Vocabulary() evidence.Vocabulary {
	return evidence.Vocabulary{Provider: "audit-panic", EventPrefix: "AUDITP_"}
}
func (panickyProvider) Detect(context.Context, provider.HostView) (provider.Detection, error) {
	return provider.Detection{Present: true}, nil
}
func (panickyProvider) Discover(context.Context, provider.HostView) ([]provider.RunnerInstance, error) {
	panic("discover bug")
}
func (panickyProvider) Attach(context.Context, provider.HostView, provider.AttachOptions) (provider.Session, error) {
	return nopSession{}, nil
}
func (panickyProvider) Interpret(s evidence.Section, _ *incident.Incident) (provider.Interpretation, error) {
	return provider.Interpretation{Provider: s.Provider, Section: s}, nil
}

type nopSession struct{}

func (nopSession) Observe(context.Context, collector.Snapshot) {}
func (nopSession) Freeze(context.Context, time.Time, time.Time) (evidence.Section, error) {
	return evidence.Section{Provider: "audit-panic", SchemaVersion: evidence.SchemaVersion,
		Privacy: evidence.PrivacyConservative, Health: evidence.Health{State: evidence.HealthAvailable}}, nil
}
func (nopSession) Close() error { return nil }

// principal phase 5 audit R15: a provider whose discover panics used to take the
// whole agent down at `start`. discovery is now guarded like Detect.
func TestAuditR15DiscoverPanicDoesNotCrashStart(t *testing.T) {
	registry := provider.NewRegistry()
	if err := registry.Register(panickyProvider{}); err != nil {
		t.Fatal(err)
	}
	set, err := DetectAndStart(context.Background(), ProviderOptions{
		StateDir: t.TempDir(), Registered: registry,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close(time.Second)
	if !set.ProvidersPresent() {
		t.Fatal("a provider with a broken Discover should still be supervised")
	}
}
