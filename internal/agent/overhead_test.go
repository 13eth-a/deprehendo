package agent

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/platform"
)

func BenchmarkRuntimeSample(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux recorder overhead")
	}
	r, err := New(Options{Interval: time.Second, Capacity: 120, Filter: collector.Filter{PIDs: []int{os.Getpid()}}})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.SampleOnce()
	}
}

// Opt-in measurement, not a brittle machine-specific performance assertion.
func TestRecorderResourceMeasurement(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("DEPREHENDO_MEASURE") != "1" {
		t.Skip("set DEPREHENDO_MEASURE=1 on Linux")
	}
	r, err := New(Options{Interval: time.Second, Capacity: 120, Filter: collector.Filter{PIDs: []int{os.Getpid()}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 125; i++ {
		r.SampleOnce()
	}
	runtime.GC()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	before, ok, err := platform.Find(os.Getpid())
	if err != nil || !ok {
		t.Fatalf("self: %v", err)
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	after, ok, err := platform.Find(os.Getpid())
	if err != nil || !ok {
		t.Fatalf("self: %v", err)
	}
	history := r.History()
	latestbytes := 0
	if len(history) > 0 {
		data, err := json.Marshal(history[len(history)-1])
		if err != nil {
			t.Fatal(err)
		}
		latestbytes = len(data)
	}
	status := r.Status()
	if len(history) == 0 || len(history) > 120 || status.BufferBytes > status.BufferByteCap {
		t.Fatalf("invalid retained history: %+v", status)
	}
	for _, snapshot := range history {
		if len(snapshot.Errors) != 0 || len(snapshot.Processes) != 1 {
			t.Fatalf("resource measurement requires successful collectors and one watched process: errors=%+v processes=%+v", snapshot.Errors, snapshot.Processes)
		}
	}
	if after.StartTicks != before.StartTicks || after.CPUTicks < before.CPUTicks {
		t.Fatal("measurement process identity or CPU counters changed")
	}
	t.Logf("interval=1s window=120s watched_processes=1 host_processes=%d retained=%d heap_after_warmup=%d RSS=%d CPU_one_core_percent=%.3f latest_JSON_bytes=%d retained_payload_estimate=%d collector_errors=%d elapsed=%s", history[len(history)-1].System.ProcessCount, len(history), mem.HeapAlloc, after.RSSBytes, collector.CPUPercentFor(after.CPUTicks-before.CPUTicks, elapsed), latestbytes, status.BufferBytes, status.CollectorErrors, elapsed)
}
