package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
)

// fixtureBundle reads one repository fixture as a verified bundle.
func fixtureBundle(t *testing.T, name string) (*incident.Bundle, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "incidents", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	bundle, err := incident.Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	sum := sha256.Sum256(raw)
	return bundle, hex.EncodeToString(sum[:])
}

func runDocument(t *testing.T, name string) *Document {
	t.Helper()
	bundle, sha := fixtureBundle(t, name)
	doc, err := Run(bundle, sha, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return doc
}

// TestGoldenFingerprint pins the engine identity (contract §4): a rule, a
// signature or the redaction policy cannot drift without a build failure and
// an AnalyzerVersion bump. update the literals deliberately.
func TestGoldenFingerprint(t *testing.T) {
	engine := EngineIdentity()
	if engine.AnalyzerVersion != "0.4.0" {
		t.Errorf("analyzer version changed to %q; bump it and update this pin", engine.AnalyzerVersion)
	}
	if engine.SignatureVersion != 5 || engine.SignatureSetVersion != 2 {
		t.Errorf("signature identity moved: version=%d set=%d", engine.SignatureVersion, engine.SignatureSetVersion)
	}
	if engine.PrivacyPolicy != "conservative-v1" {
		t.Errorf("privacy policy changed to %q", engine.PrivacyPolicy)
	}
	if len(engine.BundleFormats) != 1 || engine.BundleFormats[0] != (BundleFormat{FormatVersion: 1, SchemaVersion: 1}) {
		t.Errorf("bundle formats changed: %+v", engine.BundleFormats)
	}

	// Rule-set hash: changing, adding or removing a causal rule without
	// bumping rule IDs fails here.
	const wantRules = "5167716d106987cd77cc0da5247f1f883afc1ed432ee8efe77ddf93bde719c70"
	if engine.CausalRules != wantRules {
		t.Errorf("causal rule set hash %q != %q: update rule IDs then refresh this pin", engine.CausalRules, wantRules)
	}

	// the bundled signature set, sorted and named: one line per signature.
	ids := make([]string, 0, 9)
	for _, s := range diagnosis.DefaultSignatures() {
		ids = append(ids, string(s.ID()))
	}
	sort.Strings(ids)
	wantsignatures := strings.Join([]string{
		"BROKER_SOCKET_STALL",
		"CPU_SPIN",
		"DISK_EXHAUSTION",
		"FROZEN_PROCESS",
		"NETWORK_PATH_FAILURE",
		"OOM_KILL",
		"ORPHAN_PROCESS_TREE",
		"PROCESS_GROUP_TERMINATION",
		"RESOURCE_STARVATION",
	}, "\n")
	if strings.Join(ids, "\n") != wantsignatures {
		t.Errorf("signature set changed:\n%s", strings.Join(ids, "\n"))
	}
}

// TestDocumentDeterminism is the local/cloud equality precondition (7.43,
// contract §3.3.4): the document is a pure function of the bundle, so two
// runs (including under a different timezone) produce identical bytes.
func TestDocumentDeterminism(t *testing.T) {
	render := func() []byte {
		doc := runDocument(t, "frozen-worker.deprehendo")
		var out bytes.Buffer
		if err := WriteJSON(&out, doc); err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}
		return out.Bytes()
	}
	first := render()
	for i := 0; i < 2; i++ {
		again := render()
		if !bytes.Equal(first, again) {
			t.Fatalf("second render differs from the first: the analysis path reads a clock or host state")
		}
	}
	t.Setenv("TZ", "Pacific/Auckland")
	if !bytes.Equal(first, render()) {
		t.Fatal("document differs under a different TZ")
	}
}

// TestRunRejectsDigestContract: the sha256 field names the analyzed bytes,
// and a caller that smuggles a display string breaks that meaning for every
// stored document.
func TestRunRejectsDigestContract(t *testing.T) {
	bundle, _ := fixtureBundle(t, "frozen-worker.deprehendo")
	for _, bad := range []string{"", "inc_01", strings.Repeat("Z", 64), strings.Repeat("a", 63) + "!"} {
		if _, err := Run(bundle, bad, Options{}); err == nil {
			t.Errorf("Run accepted digest %q", bad)
		}
	}
	if _, err := Run(bundle, strings.Repeat("a", 64), Options{}); err != nil {
		t.Fatalf("Run rejected a valid digest: %v", err)
	}
}

// TestRunNilBundle guards the worker path against a caller that parsed
// nothing and passed it on.
func TestRunNilBundle(t *testing.T) {
	if _, err := Run(nil, strings.Repeat("a", 64), Options{}); err == nil {
		t.Fatal("Run accepted a nil bundle")
	}
	if _, err := Run(&incident.Bundle{Incident: nil}, strings.Repeat("a", 64), Options{}); err == nil {
		t.Fatal("Run accepted a bundle with no incident")
	}
}

// TestDocumentRecordsFeatures: the stored analysis carries what 7.13–7.24
// render (per-event evidence class, claim-level evidence, privacy report,
// bundle identity) and options when they are not the defaults.
func TestDocumentRecordsFeatures(t *testing.T) {
	doc := runDocument(t, "frozen-worker.deprehendo")
	if doc.DocumentVersion != DocumentVersion {
		t.Fatalf("document version %d", doc.DocumentVersion)
	}
	if doc.Bundle.SHA256 == "" || doc.Bundle.IncidentID == "" {
		t.Fatalf("bundle identity missing: %+v", doc.Bundle)
	}
	if doc.Options != nil {
		t.Fatalf("default options must be absent, got %+v", doc.Options)
	}
	if len(doc.Series) == 0 || len(doc.Timeline) == 0 {
		t.Fatalf("document lost the series/timeline: %d series, %d timeline", len(doc.Series), len(doc.Timeline))
	}
	for _, event := range doc.Timeline {
		if event.Evidence == "" {
			t.Fatalf("timeline event %s has no evidence class", event.ID)
		}
	}
	for _, failure := range doc.Causal.Failures {
		switch failure.Claim {
		case incident.ClaimDirect, incident.ClaimMixed, incident.ClaimInferred, incident.ClaimUnknown:
		default:
			t.Fatalf("failure claim %q is not the contract vocabulary", failure.Claim)
		}
	}
	if doc.Privacy.Policy != incident.PrivacyPolicy {
		t.Fatalf("privacy policy %q", doc.Privacy.Policy)
	}

	nondefault := runDocumentOptions(t, "frozen-worker.deprehendo", Options{MinConfidence: 0.8, Disabled: []diagnosis.SignatureID{diagnosis.SignatureCPUSpin}})
	if nondefault.Options == nil {
		t.Fatalf("non-default options must be documented")
	}
	if nondefault.Options.MinConfidence != 0.8 || len(nondefault.Options.Disabled) != 1 || nondefault.Options.Disabled[0] != diagnosis.SignatureCPUSpin {
		t.Fatalf("options documented as %+v", *nondefault.Options)
	}
}

func runDocumentOptions(t *testing.T, name string, opts Options) *Document {
	t.Helper()
	bundle, sha := fixtureBundle(t, name)
	doc, err := Run(bundle, sha, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return doc
}

// TestPrivacyMetaRespectsRedaction (7.27): the document repeats the bundle's
// privacy report verbatim and never adds information the bundle does not
// carry. the reader already verified the payloads satisfy the policy; the
// document must not re-derive anything beyond it.
func TestPrivacyMetaRespectsRedaction(t *testing.T) {
	doc := runDocument(t, "frozen-worker.deprehendo")
	bundle, _ := fixtureBundle(t, "frozen-worker.deprehendo")
	if doc.Privacy != bundle.Incident.Privacy {
		t.Fatal("document rewrote the bundle's privacy report")
	}
}
