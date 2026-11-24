package fixtures

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deprehendo/internal/provider/evidence"
)

// fixtureRoot is the committed scenario corpus (5.39).
const fixtureRoot = "../../../../testdata/github"

func TestCommittedFixturesLoadAndValidate(t *testing.T) {
	cases, err := LoadAll(fixtureRoot)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no fixtures found")
	}
	required := []string{
		"healthy-idle", "healthy-job", "job-assignment-stall", "communication-stall",
		"worker-oom", "finalization-stall", "runner-self-kill", "orphan-job",
		"normal-ephemeral-exit",
	}
	byname := map[string]*Fixture{}
	for _, fixture := range cases {
		if _, dup := byname[fixture.Name]; dup {
			t.Fatalf("duplicate fixture name %q", fixture.Name)
		}
		byname[fixture.Name] = fixture
	}
	for _, name := range required {
		if byname[name] == nil {
			t.Errorf("missing required scenario %q", name)
		}
	}
}

// TestFixturesMaterializeInstallLayout proves each fixture really builds the
// installation the provider verifies: bin/Runner.Listener, .runner and
// config.sh. A fixture that could not be discovered would silently test
// nothing.
func TestFixturesMaterializeInstallLayout(t *testing.T) {
	cases, err := LoadAll(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			host, err := fixture.Materialize(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, root := range host.Roots() {
				for _, path := range []string{
					filepath.Join(root, "bin", "Runner.Listener"),
					filepath.Join(root, "bin", "Runner.Worker"),
					filepath.Join(root, ".runner"),
					filepath.Join(root, "config.sh"),
				} {
					if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
						t.Errorf("missing installation file %s: %v", path, err)
					}
				}
				diag, err := os.ReadDir(filepath.Join(root, "_diag"))
				if err != nil || len(diag) == 0 {
					t.Errorf("no diagnostic logs under %s", root)
				}
			}
		})
	}
}

// TestFixtureManifestsHoldNoHostData is the privacy gate for the corpus: the
// committed manifests must not contain local paths, URLs, tokens or real
// addresses (5.36/5.39).
func TestFixtureManifestsHoldNoHostData(t *testing.T) {
	cases, err := LoadAll(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"/home/", "/Users/", "https://", "http://", "ghp_", "ghs_", "github_pat_", "Bearer ", "token"}
	for _, fixture := range cases {
		dir := filepath.Join(fixtureRoot, fixture.Name)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, needle := range banned {
				if strings.Contains(string(data), needle) {
					t.Errorf("%s/%s contains %q", fixture.Name, entry.Name(), needle)
				}
			}
		}
	}
}

// TestManifestRoundTripsThroughJSON catches a manifest that only decodes
// because of a missing field name.
func TestManifestRoundTripsThroughJSON(t *testing.T) {
	cases, err := LoadAll(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range cases {
		data, err := json.Marshal(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Errorf("%s marshaled to nothing", fixture.Name)
		}
	}
}

// TestMaterializeIsIncremental: log lines must appear only at their snapshot,
// which is what makes the tail observably incremental.
func TestMaterializeIsIncremental(t *testing.T) {
	fixture, err := Load(filepath.Join(fixtureRoot, "healthy-job"))
	if err != nil {
		t.Fatal(err)
	}
	host, err := fixture.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := host.Roots()[0]
	before, err := os.ReadFile(filepath.Join(root, "_diag", "Runner_20261028-120000-utc.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "Received job message") {
		t.Fatal("later snapshot's log line was present before it was applied")
	}
	if err := host.SetSnapshot(0); err != nil {
		t.Fatal(err)
	}
	if err := host.SetSnapshot(1); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, "_diag", "Runner_20261028-120000-utc.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "Received job message") {
		t.Fatal("snapshot log line was not appended")
	}
	if err := host.SetSnapshot(1); err == nil {
		t.Fatal("re-applying a snapshot was accepted")
	}
}

// TestHostInspectVerifiesIncarnation: a reused PID with different start ticks
// must not resolve, which is the C1 guarantee fixtures rely on.
func TestHostInspectVerifiesIncarnation(t *testing.T) {
	fixture, err := Load(filepath.Join(fixtureRoot, "healthy-idle"))
	if err != nil {
		t.Fatal(err)
	}
	host, err := fixture.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := host.SetSnapshot(0); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := host.Inspect(ctx, evidence.ProcessRef{PID: 5218, StartTicks: 10}); err != nil {
		t.Fatalf("current incarnation did not resolve: %v", err)
	}
	if _, err := host.Inspect(ctx, evidence.ProcessRef{PID: 5218, StartTicks: 11}); err == nil {
		t.Fatal("stale start ticks resolved as the current process")
	}
	if _, err := host.Inspect(ctx, evidence.ProcessRef{PID: 9999, StartTicks: 10}); err == nil {
		t.Fatal("unknown PID resolved")
	}
}
