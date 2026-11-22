package platform

import (
	"os"
	"strings"
	"testing"
)

func TestParsePressureCPUFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/proc/pressure_cpu")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParsePressure(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ParsePressure(cpu): %v", err)
	}
	// CPU PSI has only the "some" line on kernels that skip full-CPU.
	if snapshot.Some.Avg10 != 0.12 || snapshot.Some.Avg60 != 0.08 || snapshot.Some.Avg300 != 0.02 || snapshot.Some.Avg600 != 0 {
		t.Fatalf("some = %+v", snapshot.Some)
	}
	if snapshot.HasFull {
		t.Fatalf("cpu full line should be absent: %+v", snapshot.Full)
	}
}

func TestParsePressureIOFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/proc/pressure_io")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParsePressure(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ParsePressure(io): %v", err)
	}
	if !snapshot.HasFull {
		t.Fatal("io fixture should include a full line")
	}
	if snapshot.Full.Avg10 != 0.00 || snapshot.Full.Avg60 != 0.00 {
		t.Fatalf("full = %+v", snapshot.Full)
	}
	if snapshot.Some.Avg10 != 0.03 || snapshot.Some.Avg600 != 0 {
		t.Fatalf("some = %+v", snapshot.Some)
	}
}

func TestParsePressureMemoryFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/proc/pressure_memory")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParsePressure(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ParsePressure(memory): %v", err)
	}
	if snapshot.Some.Avg10 != 1.25 || snapshot.Full.Avg10 != 0.10 || snapshot.Full.Avg600 != 0 {
		t.Fatalf("memory = %+v", snapshot)
	}
}

func TestParsePressureToleratesMissingAvg600(t *testing.T) {
	// Pre-4.20 kernels omit avg600; parsing must still succeed.
	snapshot, err := ParsePressure(strings.NewReader("some avg10=1.00 avg60=0.50 avg300=0.25 total=10\n"))
	if err != nil {
		t.Fatalf("avg-less parse: %v", err)
	}
	if snapshot.Some.Avg10 != 1.00 || snapshot.Some.Avg600 != 0 {
		t.Fatalf("some = %+v", snapshot.Some)
	}
}

func TestParsePressureRejectsMalformedLines(t *testing.T) {
	for _, bad := range []string{
		"someonly\n",
		"bogus avg10=1.00 total=2\n",
		"some avgw=1.00 total=2\n",
		"some avg10=notanumber total=2\n",
	} {
		if _, err := ParsePressure(strings.NewReader(bad)); err == nil {
			t.Errorf("ParsePressure(%q) succeeded, want error", bad)
		}
	}
}
