// unit tests for the cloudserver pieces that need no database: the immutable
// local store, the signed POST policy, and metadata extraction from an
// engine document (the 7.6/7.27 rules). the server pipeline itself is
// exercised against a real database in tests/phase7_server_test.go.
package cloudserver

import (
	"context"
	"strings"
	"testing"
	"time"
)

// safeTestOrg is a syntactically valid organization id for key tests.
const safeTestOrg = "org_0123456789abcdef0123456789abcdef"

func TestLocalStoreKeySafety(t *testing.T) {
	for _, escaped := range []string{
		"orgs/../escape",
		"orgs/" + safeTestOrg + "/bundles/UPPER9f2c.deprehendo",
		"/absolute/path",
		"orgs//bundles/empty-segment.deprehendo",
		"orgs/" + safeTestOrg + "/bundles/.deprehendo",
		"path with spaces",
	} {
		if safeKey(escaped) {
			t.Errorf("safeKey(%q) accepted an unsafe key", escaped)
		}
	}
	if !safeKey("orgs/" + safeTestOrg + "/bundles/" + strings.Repeat("a", 62) + "cd.deprehendo") {
		t.Error("safeKey refused the §6 key shape")
	}
}

func TestLocalStoreImmutable(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "orgs/" + safeTestOrg + "/bundles/" + strings.Repeat("a", 64) + ".deprehendo"
	if _, err := store.Put(ctx, key, []byte("first")); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if got, err := store.Get(ctx, key); err != nil || string(got) != "first" {
		t.Fatalf("get: %q, %v", got, err)
	}
	if _, err := store.Put(ctx, key, []byte("second")); err == nil {
		t.Fatal("second put over an existing object must fail (immutable originals)")
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(ctx, key); err == nil {
		t.Fatal("get after delete must fail")
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("delete of a missing object must be idempotent: %v", err)
	}
}

func TestPolicySignAndVerify(t *testing.T) {
	secret := []byte("test-secret")
	p := policyPayload{
		Key:      "orgs/" + safeTestOrg + "/bundles/" + strings.Repeat("9f", 32) + ".deprehendo",
		Org:      safeTestOrg,
		SHA256:   strings.Repeat("9f", 32),
		MinBytes: 22,
		MaxBytes: 1 << 20,
		NotAfter: time.Now().Add(time.Minute).Unix(),
	}
	fields := signedPolicy(p, secret)
	parts := strings.SplitN(string(fields), policyFieldSeparator, 2)
	got, err := parsePolicy(parts[0], p.Key, parts[1], secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.SHA256 != p.SHA256 || got.Org != p.Org {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	// tampering with any part refuses.
	if _, err := parsePolicy(parts[0], "orgs/x/bundles/other.deprehendo", parts[1], secret); err == nil {
		t.Error("mismatched key accepted")
	}
	if _, err := parsePolicy(parts[0], p.Key, parts[1], []byte("other-secret")); err == nil {
		t.Error("wrong secret accepted")
	}
	// an expired policy is refused.
	expired := p
	expired.NotAfter = time.Now().Add(-time.Minute).Unix()
	fields = signedPolicy(expired, secret)
	parts = strings.SplitN(string(fields), policyFieldSeparator, 2)
	if _, err := parsePolicy(parts[0], p.Key, parts[1], secret); err == nil {
		t.Error("expired policy accepted")
	}
}

// the 7.6/7.27 metadata rules: only KNOWN tri-state facts leave the document,
// withheld or unknown facts stay out, and the first reported match is the
// primary diagnosis.
func TestMetadataFromDocument(t *testing.T) {
	doc := `{
	  "Bundle": {"incident_id": "inc_9f", "platform": "linux", "architecture": "amd64"},
	  "Diagnosis": {
	    "TriggeredAt": "2026-11-05T12:00:00Z",
	    "Matches": [
	      {"Signature": "OOM_KILL", "Confidence": 0.9, "confidence_band": "VERY_HIGH", "Severity": "CRITICAL"},
	      {"Signature": "SECOND", "Confidence": 0.1, "confidence_band": "NONE", "Severity": "WARNING"}
	    ]
	  },
	  "Providers": [
	    {"Provider": "github-actions", "Section": {
	      "Runners": [
	        {"Name": {"State": "KNOWN", "Value": "prod-linux-03"}, "Version": {"State": "UNKNOWN"}},
	        {"Name": {"State": "KNOWN", "Value": "second-should-not-win"}}
	      ],
	      "Jobs": [
	        {"Repository": {"State": "WITHHELD", "Value": "secret/value"},
	         "Workflow": {"State": "KNOWN", "Value": "CI"},
	         "Name": {"State": "KNOWN", "Value": "build"},
	         "RunID": {"State": "KNOWN", "Value": 1842}}
	      ]
	    }}
	  ]
	}`
	m := metadataFromDocument([]byte(doc))
	if m.Platform != "linux" || m.Architecture != "amd64" {
		t.Errorf("platform/architecture: %+v", m)
	}
	if m.PrimarySignature != "OOM_KILL" || m.Severity != "CRITICAL" {
		t.Errorf("diagnosis: %q %q", m.PrimarySignature, m.Severity)
	}
	if m.Confidence == nil || *m.Confidence != 0.9 {
		t.Errorf("confidence: %v", m.Confidence)
	}
	if m.ConfidenceBand != "VERY_HIGH" {
		t.Errorf("confidence band must be the document's, not recomputed: %q", m.ConfidenceBand)
	}
	if bad := metadataFromDocument([]byte(`{"Diagnosis": {"Matches": [{"Signature": "X", "Confidence": 0.8, "confidence_band": "SURE"}]}}`)); bad.ConfidenceBand != "" {
		t.Errorf("an unknown band label must not be stored: %q", bad.ConfidenceBand)
	}
	if m.TriggeredAt == nil || *m.TriggeredAt != "2026-11-05T12:00:00Z" {
		t.Errorf("triggered_at: %v", m.TriggeredAt)
	}
	if m.RunnerName != "prod-linux-03" {
		t.Errorf("runner name: %q", m.RunnerName)
	}
	if m.RunnerVersion != "" {
		t.Errorf("unknown runner version must stay empty: %q", m.RunnerVersion)
	}
	if m.Repository != "" {
		t.Errorf("withheld repository must not be copied (7.27): %q", m.Repository)
	}
	if m.Workflow != "CI" || m.Job != "build" {
		t.Errorf("workflow/job: %q %q", m.Workflow, m.Job)
	}
	if m.RunID == nil || *m.RunID != 1842 {
		t.Errorf("run id: %v", m.RunID)
	}
}
