package cloudserver

import (
	"strings"
	"testing"
)

func TestDocumentKeyForEngineIsDeterministicAndSafe(t *testing.T) {
	a := documentKeyForEngine("org_5f1b", "upl_abc", `{"analyzer":"0.4.0"}`)
	b := documentKeyForEngine("org_5f1b", "upl_abc", `{"analyzer":"0.4.0"}`)
	if a != b {
		t.Fatalf("same engine gave different keys: %q vs %q", a, b)
	}
	c := documentKeyForEngine("org_5f1b", "upl_abc", `{"analyzer":"0.5.0"}`)
	if a == c {
		t.Fatalf("different engines share a key: %q", a)
	}
	for _, k := range []string{a, c} {
		if !safeKey(k) {
			t.Fatalf("re-analysis key %q fails safeKey", k)
		}
		if !strings.HasPrefix(k, "orgs/org_5f1b/documents/upl_abc-") || !strings.HasSuffix(k, ".json") {
			t.Fatalf("re-analysis key %q misses the §6 layout", k)
		}
	}
	legacy := documentKeyFor("org_5f1b", "upl_abc")
	if !safeKey(legacy) {
		t.Fatalf("legacy key %q fails safeKey", legacy)
	}
	if a == legacy {
		t.Fatalf("engine key collides with the legacy per-upload key: %q", a)
	}
}
