package incident

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"runopsy/internal/provider/evidence"
)

var testVocabOnce sync.Once

// fixtureSection builds a small, valid github-actions-style section for the
// incident tests. the provider registers its vocabulary in production; the
// test registers the same tokens.
func fixtureSection(t *testing.T) evidence.Section {
	t.Helper()
	testVocabOnce.Do(func() {
		evidence.RegisterVocabulary(evidence.Vocabulary{
			Provider: "github-actions", EventPrefix: "GITHUB_",
			EventTypes:    []string{"GITHUB_RUNNER_STARTED", "GITHUB_WORKER_STARTED"},
			SocketRoles:   []string{"CONTROL_CHANNEL"},
			EvidenceCodes: []string{"EXE_BASENAME_MATCH"},
			ClaimValues:   []string{"ASSIGNED"},
		})
	})
	runner, err := evidence.NewRef("rnr", []byte("salt"), "/actions-runner", "prod-linux-03")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := evidence.NewRef("wkr", []byte("salt"), string(runner), "8241@100")
	if err != nil {
		t.Fatal(err)
	}
	job, err := evidence.NewRef("job", []byte("salt"), "/actions-runner", "98123")
	if err != nil {
		t.Fatal(err)
	}
	at := fixture().CaptureStart.Add(time.Second)
	section := evidence.Section{
		Provider: "github-actions", SchemaVersion: evidence.SchemaVersion,
		Privacy: evidence.PrivacyConservative,
		Health:  evidence.Health{State: evidence.HealthAvailable},
		Runners: []evidence.Runner{{
			Ref:         runner,
			Name:        evidence.KnownText(evidence.ClassRunnerName, "prod-linux-03", evidence.SourceRunnerConfig),
			Version:     evidence.KnownText(evidence.ClassVersion, "2.320.0", evidence.SourceRunnerConfig),
			Labels:      evidence.UnknownText(evidence.ClassLabels),
			Lifecycle:   evidence.LifecyclePersistent,
			Supervisors: []evidence.ProcessRef{{PID: 5218, StartTicks: 42}},
		}},
		Workers: []evidence.Worker{{Ref: worker, Runner: runner, Process: evidence.ProcessRef{PID: 8241, StartTicks: 100}, Started: at}},
		Jobs: []evidence.Job{{Ref: job, Runner: runner,
			Repository: evidence.UnknownText(evidence.ClassRepository),
			Workflow:   evidence.UnknownText(evidence.ClassWorkflow),
			Name:       evidence.KnownText(evidence.ClassJobName, "build-linux", evidence.SourceProviderAPI),
			RunID:      evidence.Int64{State: evidence.Unknown, Class: evidence.ClassRunID},
			JobID:      evidence.Int64{State: evidence.Unknown, Class: evidence.ClassJobID},
			Attempt:    evidence.Int64{State: evidence.Unknown, Class: evidence.ClassAttempt},
			Outcome:    evidence.OutcomeRunning,
		}},
		Events: []evidence.Event{{Timestamp: at, Type: "GITHUB_RUNNER_STARTED", Runner: runner, Source: evidence.SourceRunnerLog}},
	}
	if err := section.Validate(); err != nil {
		// A section built at the identifiers level validates as stored; at the
		// conservative level the withheld values appear only after redact, the
		// way the supervisor builds them. validate the final stored shape.
		section.Redact(section.Privacy)
		if err := section.Validate(); err != nil {
			t.Fatalf("fixture section invalid: %v", err)
		}
	}
	return section
}

// TestProviderSectionRoundTrip encodes a bundle with a provider section and
// decodes it, asserting the conservative policy table and that the withheld
// runner name appears in no bundle member.
func TestProviderSectionRoundTrip(t *testing.T) {
	i := fixture()
	i.Providers = []evidence.Section{fixtureSection(t)}
	raw := encoded(t, i, true)
	bundle, err := Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("read with provider section: %v", err)
	}
	if len(bundle.Incident.Providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(bundle.Incident.Providers))
	}
	got := bundle.Incident.Providers[0]
	if got.Runners[0].Version.State != evidence.Known || got.Runners[0].Version.Value != "2.320.0" {
		t.Fatalf("version must stay KNOWN at the conservative level: %+v", got.Runners[0].Version)
	}
	if got.Runners[0].Name.State != evidence.Withheld || got.Runners[0].Name.Value != "" {
		t.Fatalf("runner name must be withheld under the conservative policy: %+v", got.Runners[0].Name)
	}
	if got.Jobs[0].Name.State != evidence.Withheld {
		t.Fatalf("job name must be withheld: %+v", got.Jobs[0].Name)
	}
	for _, member := range zippedMembers(t, raw) {
		if strings.Contains(member, "prod-linux") || strings.Contains(member, "build-linux") {
			t.Fatal("bundle member carries a withheld identifier")
		}
	}
}

// TestProviderSectionIdentifiersExported: at the identifiers level the same
// section keeps its names, the privacy report records it, and SafeText still
// withholds credential-shaped values (§9.2).
func TestProviderSectionIdentifiersExported(t *testing.T) {
	i := fixture()
	section := fixtureSection(t)
	section.Privacy = evidence.PrivacyIdentifiers
	section.Runners[0].Name = evidence.KnownText(evidence.ClassRunnerName, "runner-1", evidence.SourceRunnerConfig)
	i.Providers = []evidence.Section{section}
	raw := encoded(t, i, true)
	bundle, err := Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	got := bundle.Incident.Providers[0].Runners[0].Name
	if got.State != evidence.Known || got.Value != "runner-1" {
		t.Fatalf("identifiers opt-in must export the runner name: %+v", got)
	}
	if !bundle.Incident.Privacy.ProviderIdentifiers {
		t.Fatal("ProviderIdentifiers stays false although an identifiers section was exported")
	}
}

// TestProviderSectionInvalidRejected: a section violating its vocabulary fails
// validation on encode (and would fail the bundle on read).
func TestProviderSectionInvalidRejected(t *testing.T) {
	i := fixture()
	section := fixtureSection(t)
	section.Events[0].Type = "GITHUB_NOT_IN_VOCABULARY"
	i.Providers = []evidence.Section{section}
	var out bytes.Buffer
	if err := Encode(&out, i, false); err == nil {
		t.Fatal("encoding accepted an invalid provider section")
	}
	if err := Validate(i); err == nil {
		t.Fatal("Validate accepted an invalid provider section")
	}
}

// TestOldBundleWithoutProvidersStillReads guards the additive-field contract:
// a bundle written before phase 5 decodes and validates unchanged.
func TestOldBundleWithoutProvidersStillReads(t *testing.T) {
	data, err := os.ReadFile("testdata/v1-minimal.runopsy")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Read(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Incident.Providers) != 0 {
		t.Fatalf("providers = %d, want none", len(bundle.Incident.Providers))
	}
}

// fakeProviderSupervisor is the capture-side stand-in for a provider
// supervisor (the §11.1 finalize hook).
type fakeProviderSupervisor struct {
	name    string
	section evidence.Section
	hang    <-chan struct{}
}

func (f *fakeProviderSupervisor) Name() string { return f.name }

func (f *fakeProviderSupervisor) Freeze(ctx context.Context, from, to time.Time) evidence.Section {
	if f.hang != nil {
		<-ctx.Done() // observe the deadline the capture imposed
	}
	return f.section
}

// TestCaptureFreezesProvidersIntoIncident: a trigger produces a detached
// incident whose provider section is the supervisor's, redacted to the
// configured capture level.
func TestCaptureFreezesProvidersIntoIncident(t *testing.T) {
	writer := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{
		Window:                CaptureWindow{time.Second * 2, 100 * time.Millisecond},
		Writer:                writer,
		ProviderSupervisors:   []ProviderSupervisor{&fakeProviderSupervisor{name: "github-actions", section: fixtureSection(t)}},
		ProviderFreezeTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Observe(sample(time.Now().UTC().Add(-time.Millisecond), 10))
	if _, err := c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	waitCapture(t, c)
	if len(writer.incidents) != 1 {
		t.Fatalf("writer got %d incidents, want 1", len(writer.incidents))
	}
	i := writer.incidents[0]
	if len(i.Providers) != 1 {
		t.Fatalf("providers = %d, want the frozen section", len(i.Providers))
	}
	section := i.Providers[0]
	if section.Runners[0].Version.State != evidence.Known {
		t.Fatalf("version must stay KNOWN: %+v", section.Runners[0].Version)
	}
	if section.Runners[0].Name.State != evidence.Withheld {
		t.Fatalf("capture-time conservative redaction withheld nothing: %+v", section.Runners[0].Name)
	}
}

// TestCaptureFreezeTimeoutBecomesUnavailable: a provider that cannot answer
// within the capture's bound turns into an UNAVAILABLE section and the capture
// still completes (§3.3 "never waits longer").
func TestCaptureFreezeTimeoutBecomesUnavailable(t *testing.T) {
	hang := make(chan struct{})
	defer close(hang)
	writer := &recordingWriter{}
	c, err := NewCapture(CaptureOptions{
		Window:                CaptureWindow{time.Second * 2, 100 * time.Millisecond},
		Writer:                writer,
		ProviderSupervisors:   []ProviderSupervisor{&fakeProviderSupervisor{name: "slow-ci", hang: hang}},
		ProviderFreezeTimeout: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Observe(sample(time.Now().UTC().Add(-time.Millisecond), 10))
	if _, err := c.Trigger(Trigger{Type: "manual"}); err != nil {
		t.Fatal(err)
	}
	waitCapture(t, c)
	if len(writer.incidents) != 1 {
		t.Fatalf("provider freeze delayed the incident write: wrote %d", len(writer.incidents))
	}
	providers := writer.incidents[0].Providers
	if len(providers) != 1 || providers[0].Health.State != evidence.HealthUnavailable {
		t.Fatalf("want one UNAVAILABLE section, got %+v", providers)
	}
	if providers[0].Provider != "slow-ci" {
		t.Fatalf("unavailable section lost the provider name: %+v", providers[0])
	}
}

func zippedMembers(t *testing.T, raw []byte) []string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(data))
	}
	return out
}
