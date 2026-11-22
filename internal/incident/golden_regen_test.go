package incident

import (
	"bytes"
	"os"
	"testing"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// TestRegenerateV1Golden rebuilds testdata/v1-minimal.runopsy from its own
// decoded content. it runs only when RUNOPSY_REGEN_GOLDEN=1, because the
// golden artifact exists to detect unannounced interpretation changes of the
// v1 format: regenerate deliberately, review the diff, and never silently.
// AgentVersion is stamped by encode, so bumping the constant requires one
// regeneration pass to keep the read-path privacy comparison exact.
//
// the regenerated fixture must decode byte-identically to the original apart
// from the stamped version; this test refuses to write anything when the
// fixture no longer round-trips or grew extra records.
func TestRegenerateV1Golden(t *testing.T) {
	if os.Getenv("RUNOPSY_REGEN_GOLDEN") != "1" {
		t.Skip("set RUNOPSY_REGEN_GOLDEN=1 to regenerate testdata/v1-minimal.runopsy")
	}
	const path = "testdata/v1-minimal.runopsy"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Read(bytesReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	beforecount, aftercount := len(bundle.Incident.Snapshots), len(bundle.Incident.Events)
	var out bytes.Buffer
	if err := Encode(&out, bundle.Incident, true); err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	round, err := Read(bytesReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatalf("regenerated bundle does not decode: %v", err)
	}
	if len(round.Incident.Snapshots) != beforecount || len(round.Incident.Events) != aftercount {
		t.Fatalf("regeneration changed record counts: snapshots %d->%d events %d->%d",
			beforecount, len(round.Incident.Snapshots), aftercount, len(round.Incident.Events))
	}
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("regenerated %s (%d bytes)", path, out.Len())
}
