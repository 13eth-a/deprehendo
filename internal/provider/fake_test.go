package provider

import (
	"context"
	"errors"
	"sync"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
	"deprehendo/internal/provider/evidence"
)

// fakeProvider is a scriptable provider for supervisor and conformance tests.
type fakeProvider struct {
	name          string
	attachErr     error
	attachPanic   bool
	attachHang    bool
	observePanic  bool
	observeHang   chan struct{} // closed to release
	observeSlow   time.Duration // sleep this long inside observe
	slowOnce      bool          // only the first observe sleeps
	slowSlept     bool
	freezeHang    bool
	freezeInvalid bool
	freezeSecret  bool

	mu       sync.Mutex
	observed int
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Vocabulary() evidence.Vocabulary {
	return evidence.Vocabulary{
		Provider: f.name, EventPrefix: "FAKECI_",
		EventTypes:    []string{"FAKECI_WORKER_STARTED", "FAKECI_JOB_CANCELLED"},
		SocketRoles:   []string{"CONTROL_CHANNEL"},
		EvidenceCodes: []string{"PARENT_IS_SUPERVISOR"},
	}
}

func (f *fakeProvider) Detect(context.Context, HostView) (Detection, error) {
	return Detection{Present: true, Candidates: 1}, nil
}

func (f *fakeProvider) Discover(context.Context, HostView) ([]RunnerInstance, error) { return nil, nil }

func (f *fakeProvider) Attach(ctx context.Context, _ HostView, _ AttachOptions) (Session, error) {
	switch {
	case f.attachPanic:
		panic("attach exploded")
	case f.attachHang:
		<-make(chan struct{})
	case f.attachErr != nil:
		return nil, f.attachErr
	}
	return &fakeSession{f: f}, nil
}

func (f *fakeProvider) Interpret(section evidence.Section, _ *incident.Incident) (Interpretation, error) {
	out := Interpretation{Provider: f.name, Section: section}
	for _, e := range section.Events {
		kind := GenericWorkerStarted
		intent := Intent("")
		if e.Type == "FAKECI_JOB_CANCELLED" {
			kind, intent = GenericTerminationIntended, IntentCancelled
		}
		out.Generic = append(out.Generic, GenericEvent{Timestamp: e.Timestamp, Kind: kind, Intent: intent, Runner: e.Runner, Job: e.Job, Source: e.Source, Confidence: evidence.ConfidenceHigh, ProviderType: e.Type})
	}
	return out, nil
}

type fakeSession struct{ f *fakeProvider }

func (s *fakeSession) Observe(ctx context.Context, _ collector.Snapshot) {
	if s.f.observePanic {
		panic("observe exploded")
	}
	if s.f.observeHang != nil {
		<-s.f.observeHang
	}
	sleep := time.Duration(0)
	if s.f.observeSlow > 0 {
		s.f.mu.Lock()
		if !s.f.slowOnce || !s.f.slowSlept {
			s.f.slowSlept = true
			sleep = s.f.observeSlow
		}
		s.f.mu.Unlock()
	}
	if sleep > 0 {
		time.Sleep(sleep)
	}
	s.f.mu.Lock()
	s.f.observed++
	s.f.mu.Unlock()
}

func (f *fakeProvider) observedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.observed
}

func (s *fakeSession) Freeze(ctx context.Context, from, to time.Time) (evidence.Section, error) {
	if s.f.freezeHang {
		<-make(chan struct{})
	}
	runner, _ := evidence.NewRef("rnr", []byte("salt"), "fake-runner")
	section := evidence.Section{
		Provider: s.f.name, SchemaVersion: evidence.SchemaVersion, Privacy: evidence.PrivacyIdentifiers,
		Health: evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref: runner, Name: evidence.KnownText(evidence.ClassRunnerName, "prod-linux-03", evidence.SourceRunnerConfig),
			Version: evidence.KnownText(evidence.ClassVersion, "2.320.0", evidence.SourceRunnerConfig), Labels: evidence.UnknownText(evidence.ClassLabels),
			Lifecycle: evidence.LifecyclePersistent, Supervisors: []evidence.ProcessRef{{PID: 5218, StartTicks: 1}},
		}},
		Events: []evidence.Event{{Timestamp: from.Add(time.Second), Type: "FAKECI_WORKER_STARTED", Runner: runner, Source: evidence.SourceRunnerLog}},
	}
	if s.f.freezeSecret {
		section.Runners[0].Labels = evidence.KnownText(evidence.ClassLabels, "Bearer ghp_0123456789", evidence.SourceRunnerConfig)
	}
	if s.f.freezeInvalid {
		section.Events[0].Type = "FAKECI_NOT_IN_VOCABULARY"
	}
	return section, nil
}

func (s *fakeSession) Close() error { return errors.New("close is allowed to fail") }

type fakeHost struct{}

func (fakeHost) Processes(context.Context) ([]platform.Process, error) { return nil, nil }
func (fakeHost) Inspect(context.Context, evidence.ProcessRef) (ProcessDetail, error) {
	return ProcessDetail{}, errors.New("no live host in tests")
}
func (fakeHost) Now() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }
func (fakeHost) Salt() []byte   { return []byte("salt") }
