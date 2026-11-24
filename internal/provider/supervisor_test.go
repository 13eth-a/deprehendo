package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/provider/evidence"
)

func fastConfig() SupervisorConfig {
	return SupervisorConfig{QueueDepth: 4, AttachTimeout: 200 * time.Millisecond, ObserveTimeout: 200 * time.Millisecond, FreezeTimeout: 200 * time.Millisecond}
}

func registered(t *testing.T, f *fakeProvider) *fakeProvider {
	t.Helper()
	if err := NewRegistry().Register(f); err != nil {
		t.Fatal(err)
	}
	return f
}

func window() (time.Time, time.Time) {
	from := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	return from, from.Add(time.Minute)
}

func mustValid(t *testing.T, s evidence.Section) {
	t.Helper()
	if err := s.Validate(); err != nil {
		t.Fatalf("supervisor returned an invalid section: %v (%+v)", err, s.Health)
	}
}

func hasReason(s evidence.Section, r evidence.Reason) bool {
	for _, got := range s.Health.Reasons {
		if got == r {
			return true
		}
	}
	return false
}

func TestSupervisorHealthyPathIsRedactedAndValid(t *testing.T) {
	f := registered(t, &fakeProvider{name: "fake-ci"})
	s := Start(context.Background(), f, fakeHost{}, AttachOptions{}, fastConfig())
	defer s.Close(time.Second)
	s.Offer(collector.Snapshot{})
	from, to := window()
	section := s.Freeze(context.Background(), from, to)
	mustValid(t, section)
	if section.Health.State != evidence.HealthAvailable {
		t.Errorf("health = %+v, want AVAILABLE", section.Health)
	}
	if section.Privacy != evidence.PrivacyConservative || section.Runners[0].Name.State != evidence.Withheld {
		t.Errorf("default privacy must be conservative and withhold the runner name: %+v", section.Runners[0].Name)
	}
	data, _ := json.Marshal(section)
	if strings.Contains(string(data), "prod-linux-03") {
		t.Errorf("runner name leaked into the conservative section")
	}
}

func TestSupervisorIdentifiersPrivacyStillScrubsSecrets(t *testing.T) {
	f := registered(t, &fakeProvider{name: "fake-ci-secret", freezeSecret: true})
	s := Start(context.Background(), f, fakeHost{}, AttachOptions{Privacy: evidence.PrivacyIdentifiers}, fastConfig())
	defer s.Close(time.Second)
	from, to := window()
	section := s.Freeze(context.Background(), from, to)
	mustValid(t, section)
	if section.Runners[0].Name.State != evidence.Known {
		t.Errorf("opted-in runner name was withheld")
	}
	data, _ := json.Marshal(section)
	if strings.Contains(string(data), "ghp_") || strings.Contains(strings.ToLower(string(data)), "bearer") {
		t.Errorf("credential-looking label reached the section: %s", data)
	}
}

func TestSupervisorOfferNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	f := registered(t, &fakeProvider{name: "fake-ci-slow", observeHang: release})
	cfg := fastConfig()
	cfg.ObserveTimeout = 10 * time.Second // the hang must not be rescued by the timeout
	s := Start(context.Background(), f, fakeHost{}, AttachOptions{}, cfg)
	defer func() { close(release); s.Close(time.Second) }()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			s.Offer(collector.Snapshot{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Offer blocked the recorder")
	}
	if s.dropped.Load() == 0 {
		t.Errorf("a full queue must drop and count")
	}
}

func TestSupervisorFailuresBecomeHealthNotErrors(t *testing.T) {
	cases := []struct {
		name   string
		f      *fakeProvider
		state  evidence.HealthState
		reason evidence.Reason
	}{
		{"attach error", &fakeProvider{name: "fake-ci-a", attachErr: errors.New("no runner")}, evidence.HealthUnavailable, evidence.ReasonInternalError},
		{"attach panic", &fakeProvider{name: "fake-ci-b", attachPanic: true}, evidence.HealthUnavailable, evidence.ReasonPanic},
		{"attach hang", &fakeProvider{name: "fake-ci-c", attachHang: true}, evidence.HealthUnavailable, evidence.ReasonTimeout},
		{"observe panic", &fakeProvider{name: "fake-ci-d", observePanic: true}, evidence.HealthUnavailable, evidence.ReasonPanic},
		{"freeze hang", &fakeProvider{name: "fake-ci-e", freezeHang: true}, evidence.HealthUnavailable, evidence.ReasonTimeout},
		{"freeze invalid", &fakeProvider{name: "fake-ci-f", freezeInvalid: true}, evidence.HealthUnavailable, evidence.ReasonInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := registered(t, tc.f)
			s := Start(context.Background(), f, fakeHost{}, AttachOptions{}, fastConfig())
			defer s.Close(100 * time.Millisecond)
			s.Offer(collector.Snapshot{})
			time.Sleep(50 * time.Millisecond) // let observe run
			from, to := window()
			began := time.Now()
			section := s.Freeze(context.Background(), from, to)
			if elapsed := time.Since(began); elapsed > fastConfig().FreezeTimeout+1500*time.Millisecond {
				t.Errorf("Freeze took %s; the incident write must not wait on a broken provider", elapsed)
			}
			mustValid(t, section)
			if section.Health.State != tc.state || !hasReason(section, tc.reason) {
				t.Errorf("health = %+v, want %s with %s", section.Health, tc.state, tc.reason)
			}
			if tc.reason != evidence.ReasonPanic && hasReason(section, evidence.ReasonPanic) {
				t.Errorf("spurious PROVIDER_PANIC reported: %+v", section.Health)
			}
		})
	}
}

// B3 on the real runner (2026-11-02): a single observe overran its 2 s budget
// while the host was under memory pressure, the supervisor abandoned the
// session, and every later incident carried an UNAVAILABLE provider section
// (~50k snapshots dropped). A call that finishes inside the overrun grace must
// degrade that incident's health and keep the session alive.
func TestSupervisorSlowCallDegradesOneIncidentAndKeepsTheSession(t *testing.T) {
	f := registered(t, &fakeProvider{name: "fake-ci-slow-once", observeSlow: 80 * time.Millisecond, slowOnce: true})
	cfg := fastConfig()
	cfg.ObserveTimeout = 20 * time.Millisecond
	cfg.OverrunGrace = 2 * time.Second
	s := Start(context.Background(), f, fakeHost{}, AttachOptions{}, cfg)
	defer s.Close(time.Second)
	s.Offer(collector.Snapshot{})
	time.Sleep(150 * time.Millisecond) // the first observe overran and finished
	from, to := window()
	stalled := s.Freeze(context.Background(), from, to)
	mustValid(t, stalled)
	if stalled.Health.State != evidence.HealthDegraded || !hasReason(stalled, evidence.ReasonTimeout) {
		t.Fatalf("health = %+v, want DEGRADED with %s", stalled.Health, evidence.ReasonTimeout)
	}
	s.Offer(collector.Snapshot{})
	time.Sleep(100 * time.Millisecond)
	if f.observedCount() < 2 {
		t.Fatalf("session stopped observing after an overrun: %d observations", f.observedCount())
	}
	next := s.Freeze(context.Background(), from, to)
	mustValid(t, next)
	if next.Health.State != evidence.HealthAvailable {
		t.Fatalf("the overrun must not degrade later incidents: %+v", next.Health)
	}
}

// the other half of the same contract: a call that overruns its budget and
// the grace as well is hung, and the session is abandoned so no further
// provider code runs (the recorder still gets a valid section).
func TestSupervisorHungCallIsAbandonedAfterTheGrace(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := registered(t, &fakeProvider{name: "fake-ci-hung", observeHang: release})
	cfg := fastConfig()
	cfg.ObserveTimeout = 10 * time.Millisecond
	cfg.OverrunGrace = 20 * time.Millisecond
	s := Start(context.Background(), f, fakeHost{}, AttachOptions{}, cfg)
	defer s.Close(100 * time.Millisecond)
	s.Offer(collector.Snapshot{})
	time.Sleep(80 * time.Millisecond)
	from, to := window()
	section := s.Freeze(context.Background(), from, to)
	mustValid(t, section)
	if section.Health.State != evidence.HealthUnavailable || !hasReason(section, evidence.ReasonTimeout) {
		t.Fatalf("health = %+v, want UNAVAILABLE with %s", section.Health, evidence.ReasonTimeout)
	}
	s.Offer(collector.Snapshot{})
	time.Sleep(50 * time.Millisecond)
	if got := f.observedCount(); got != 0 {
		t.Fatalf("an abandoned session still ran provider code: %d observations", got)
	}
}

func TestSupervisorStopsCallingAProviderAfterAPanic(t *testing.T) {
	f := registered(t, &fakeProvider{name: "fake-ci-g", observePanic: true})
	s := Start(context.Background(), f, fakeHost{}, AttachOptions{}, fastConfig())
	defer s.Close(100 * time.Millisecond)
	for i := 0; i < 3; i++ {
		s.Offer(collector.Snapshot{})
	}
	time.Sleep(100 * time.Millisecond)
	from, to := window()
	section := s.Freeze(context.Background(), from, to)
	if section.Health.State != evidence.HealthUnavailable || len(section.Events) != 0 {
		t.Errorf("a panicked session must yield an empty UNAVAILABLE section: %+v", section)
	}
}

func TestRegistryInterpretAllIsolatesUnknownAndInvalidSections(t *testing.T) {
	reg := NewRegistry()
	f := &fakeProvider{name: "fake-ci-h"}
	if err := reg.Register(f); err != nil {
		t.Fatal(err)
	}
	from, _ := window()
	good, _ := (&fakeSession{f: f}).Freeze(context.Background(), from, from)
	good.Redact(evidence.PrivacyConservative)
	bad := good
	bad.Events = []evidence.Event{{Timestamp: from, Type: "FAKECI_NOT_IN_VOCABULARY", Source: evidence.SourceRunnerLog}}
	cancelled := good
	cancelled.Events = []evidence.Event{{Timestamp: from, Type: "FAKECI_JOB_CANCELLED", Source: evidence.SourceRunnerLog}}
	unknown := evidence.Unavailable("never-compiled-in")
	out := reg.InterpretAll([]evidence.Section{good, bad, unknown, cancelled}, nil)
	if len(out) != 4 {
		t.Fatalf("interpretations = %d, want 4", len(out))
	}
	if len(out[0].Generic) != 1 || out[0].Generic[0].Kind != GenericWorkerStarted {
		t.Errorf("valid section not interpreted: %+v", out[0].Generic)
	}
	for _, i := range []int{1, 2} {
		if len(out[i].Generic) != 0 || out[i].Section.Health.State != evidence.HealthUnavailable {
			t.Errorf("section %d: invalid/unknown provider evidence must interpret to nothing: %+v", i, out[i])
		}
	}
	if g := out[3].Generic; len(g) != 1 || g[0].Kind != GenericTerminationIntended || g[0].Intent != IntentCancelled {
		t.Errorf("cancellation not translated to an intended termination: %+v", g)
	}
}

func TestRegistryRejectsBadProviders(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{name: "Bad Name"}); err == nil {
		t.Errorf("invalid provider name accepted")
	}
	if err := reg.Register(&fakeProvider{name: "fake-ci-i"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&fakeProvider{name: "fake-ci-i"}); err == nil {
		t.Errorf("duplicate provider accepted")
	}
}
