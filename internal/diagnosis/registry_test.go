package diagnosis

import (
	"testing"
	"time"

	"runopsy/internal/collector"
)

func TestDefaultRegistryStableOrderingAndIDs(t *testing.T) {
	want := []SignatureID{
		SignatureOOMKill, SignatureFrozenProcess, SignatureCPUSpin,
		SignatureDiskExhaustion, SignatureOrphanProcess, SignatureGroupKill,
		SignatureBrokerStall, SignatureNetworkFailure, SignatureStarvation,
	}
	first := DefaultSignatures()
	second := DefaultSignatures()
	if len(first) != len(want) || len(second) != len(want) {
		t.Fatalf("registry length = %d/%d, want %d", len(first), len(second), len(want))
	}
	for index, id := range want {
		if first[index].ID() != id || second[index].ID() != id {
			t.Errorf("registry[%d] IDs=%s/%s, want %s", index, first[index].ID(), second[index].ID(), id)
		}
		if first[index].Description() == "" {
			t.Errorf("%s has no description", id)
		}
	}
}

func TestAnalyzerMetadataIncludesPerSignatureVersion(t *testing.T) {
	end := at(55 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = sampleSeries(t, at(0), 12, 5*time.Second, func(index int) collector.Snapshot {
		s := systemSnapshot(at(0), 30, 80)
		return withProcess(s, 100, 100, "T", 0)
	})
	mustValid(t, i)
	report, err := Analyze(i, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Analyzer != AnalyzerVersion || report.SignatureSet != SignatureSetVersion {
		t.Fatalf("analyzer metadata = %s/%d", report.Analyzer, report.SignatureSet)
	}
	match := findMatch(t, report, SignatureFrozenProcess)
	if match.Version != SignatureVersion {
		t.Errorf("signature version = %d, want %d", match.Version, SignatureVersion)
	}
	if report.Trigger != "manual" || !report.TriggeredAt.Equal(end) {
		t.Errorf("trigger metadata = %q/%s", report.Trigger, report.TriggeredAt)
	}
}

func TestCustomRegistryRejectsDuplicateAndUnknownDisable(t *testing.T) {
	end := at(1 * time.Second)
	i := validIncident(t, at(0), end)
	i.Snapshots = []collector.Snapshot{systemSnapshot(at(0), 30, 80)}
	i.Snapshots[0].Timestamp = at(0)
	mustValid(t, i)
	sig := FrozenProcessSignature{}
	if _, err := NewAnalyzerWithSignatures([]Signature{sig, sig}).Analyze(i, Options{}); err == nil {
		t.Fatal("duplicate signature ID should be rejected")
	}
	if _, err := NewAnalyzer().Analyze(i, Options{Disable: []SignatureID{"NOT_A_SIGNATURE"}}); err == nil {
		t.Fatal("unknown disabled signature should be rejected")
	}
}
