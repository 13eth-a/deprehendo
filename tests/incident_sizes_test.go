package tests

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/collector"
	"runopsy/internal/incident"
)

func envDuration(name string, fallback time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func bundleBytes(t *testing.T, i *incident.Incident, compressed bool) int {
	t.Helper()
	var encoded bytes.Buffer
	if err := incident.Encode(&encoded, i, compressed); err != nil {
		t.Fatal(err)
	}
	return encoded.Len()
}

// TestPhase2BundleSizes measures the real pipeline for every phase 0 scenario.
// it is opt-in because it runs live processes for a minute or more.
//
//	RUNOPSY_INCIDENT_SIZES=1 go test -run TestPhase2BundleSizes -v ./tests
//
// RUNOPSY_INCIDENT_SAMPLES (default 120) and RUNOPSY_INCIDENT_INTERVAL
// (default 50ms) control the retained timeline length.
func TestPhase2BundleSizes(t *testing.T) {
	if os.Getenv("RUNOPSY_INCIDENT_SIZES") == "" {
		t.Skip("set RUNOPSY_INCIDENT_SIZES=1 to measure live bundle sizes")
	}
	if testing.Short() {
		t.Skip("live size measurement")
	}
	target := envInt("RUNOPSY_INCIDENT_SAMPLES", 120)
	interval := envDuration("RUNOPSY_INCIDENT_INTERVAL", 50*time.Millisecond)
	cases := []struct {
		name string
		args []string
	}{
		{"normal", []string{"normal", "--duration", "30s"}},
		{"cpu-spin", []string{"cpu-spin", "--workers", "2", "--duration", "30s"}},
		{"memory-pressure", []string{"memory-pressure", "--rate", "2MB", "--interval", "100ms", "--limit", "256MB", "--duration", "30s"}},
		{"frozen-worker", []string{"frozen-worker", "--freeze-after", "5s", "--freeze-for", "12s", "--grace", "2s"}},
		{"orphan-process", []string{"orphan-process", "--tasks", "2", "--grace", "15s"}},
		{"socket-stall", []string{"socket-stall", "--stall-duration", "15s", "--stall-after", "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := exec.Command(simPath, append(tc.args, "--json")...)
			var output recorderOutput
			sim.Stdout, sim.Stderr = &output, &output
			if err := sim.Start(); err != nil {
				t.Fatal(err)
			}
			simdone := make(chan error, 1)
			go func() { simdone <- sim.Wait() }()
			simexited := false
			defer func() {
				if !simexited {
					_ = sim.Process.Kill()
					<-simdone
				}
			}()

			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			capture, err := incident.NewCapture(incident.CaptureOptions{
				Window: incident.CaptureWindow{PreTrigger: 60 * time.Second, PostTrigger: 200 * time.Millisecond},
				Writer: incident.FileWriter{Directory: dir},
			})
			if err != nil {
				t.Fatal(err)
			}
			rt, err := agent.New(agent.Options{
				Interval: interval,
				Capacity: 4000,
				Window:   2 * time.Minute,
				Filter:   collector.Filter{PIDs: []int{sim.Process.Pid}, Descendants: true},
				OnSnapshot: func(s collector.Snapshot) {
					capture.Observe(s)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			rundone := make(chan error, 1)
			go func() { rundone <- rt.Run(ctx) }()
			defer func() {
				cancel()
				if err := <-rundone; err != nil {
					t.Errorf("recorder: %v", err)
				}
				closectx, closecancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer closecancel()
				if err := capture.Close(closectx); err != nil {
					t.Errorf("capture: %v", err)
				}
			}()

			deadline := time.Now().Add(time.Duration(target)*interval + 90*time.Second)
			for rt.Status().Samples < uint64(target) && time.Now().Before(deadline) {
				select {
				case err := <-simdone:
					simexited = true
					if err != nil {
						t.Fatalf("scenario ended early: %v\n%s", err, output.String())
					}
					goto sampled
				default:
				}
				time.Sleep(25 * time.Millisecond)
			}
		sampled:
			samples := rt.Status().Samples
			if samples == 0 {
				t.Fatalf("no samples collected: %s", output.String())
			}
			if _, err := capture.Trigger(incident.Trigger{Type: "manual"}); err != nil {
				t.Fatal(err)
			}
			complete := time.Now().Add(20 * time.Second)
			for capture.Status().State != incident.Complete && capture.Status().State != incident.Failed && time.Now().Before(complete) {
				time.Sleep(20 * time.Millisecond)
			}
			status := capture.Status()
			if status.State != incident.Complete {
				t.Fatalf("capture did not complete: %+v", status)
			}
			bundle, err := incident.ReadFile(status.Path)
			if err != nil {
				t.Fatal(err)
			}
			if len(bundle.Incident.Snapshots) == 0 {
				t.Fatal("bundle contains no snapshots")
			}
			stored, err := os.Stat(status.Path)
			if err != nil {
				t.Fatal(err)
			}
			plain := bundleBytes(t, bundle.Incident, false)
			deflated := bundleBytes(t, bundle.Incident, true)
			if deflated > plain {
				t.Fatalf("deflate (%d) larger than store (%d)", deflated, plain)
			}
			persnapshot := float64(stored.Size()) / float64(len(bundle.Incident.Snapshots))
			t.Logf("scenario=%s platform=%s samples=%d events=%d bundle_bytes=%d stored_bytes=%d uncompressed_bytes=%d bytes_per_snapshot=%.0f",
				tc.name, runtime.GOOS, len(bundle.Incident.Snapshots), len(bundle.Incident.Events), deflated, stored.Size(), plain, persnapshot)
			if len(bundle.Incident.Snapshots) > 0 && bundle.Incident.Trigger.Type != "manual" {
				t.Fatalf("trigger = %+v", bundle.Incident.Trigger)
			}
		})
	}
}
