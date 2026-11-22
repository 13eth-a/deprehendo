package analysis

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// the dashboard receives exactly one array per event class (contract §3.3), so
// the payload 7.44 has to keep small is this document, not the bundle. these
// tests measure what this repository can measure (the document the cloud
// stores) at the three sizes 7.44 names. DOM cost is the web app's half and
// cannot be measured until it exists; docs/cloud/performance.md records that
// gap rather than guessing a number for it.

// scaleSnapshotCount is a realistic capture length: two minutes at 1 Hz.
const scaleSnapshotCount = 120

// scaleIncident builds a valid v1 incident with n alternating process events
// spread over the capture and a fixed 1 hz snapshot series, so document growth
// is attributable to the timeline alone.
func scaleIncident(events int) *incident.Incident {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Minute)
	// the default window allows 90 s of pre-trigger capture, so the trigger
	// sits 90 s after the first sample and 30 s before the end.
	triggered := start.Add(90 * time.Second)
	inc := &incident.Incident{
		SchemaVersion: incident.SchemaVersion,
		ID:            fmt.Sprintf("inc_%032x", events),
		CreatedAt:     end,
		TriggeredAt:   triggered,
		CaptureStart:  start,
		CaptureEnd:    end,
		Window:        incident.DefaultWindow(),
		Trigger:       incident.Trigger{Type: "manual"},
		Metadata: incident.Metadata{
			AgentVersion: incident.AgentVersion,
			Host:         incident.HostMetadata{OS: "linux", Architecture: "amd64", CPUCount: 2, MemoryTotal: 16 << 30},
		},
	}
	step := end.Sub(start) / scaleSnapshotCount
	for i := 0; i < scaleSnapshotCount; i++ {
		inc.Snapshots = append(inc.Snapshots, collector.Snapshot{
			Timestamp:    start.Add(time.Duration(i) * step),
			CaptureIndex: i,
			System: &collector.SystemSnapshot{
				CPUAvailable:          true,
				CPUPercentAvailable:   true,
				MemoryStatsAvailable:  true,
				DiskStatsAvailable:    true,
				ProcessCountAvailable: true,
				CPUCount:              2,
				CPUPercent:            40 + float64(i%20),
				MemoryTotal:           16 << 30,
				MemoryUsed:            8 << 30,
				DiskTotal:             64 << 30,
				DiskFree:              32 << 30,
				ProcessCount:          120,
			},
			Processes: []collector.ProcessSnapshot{{
				Process: platform.Process{PID: 100, PPID: 1, PGID: 100, SID: 100, Name: "Runner.Worker", State: "S", Threads: 4, RSSBytes: 256 << 20, StartTicks: 100},
				OpenFDs: 12,
			}},
		})
	}
	span := int64(end.Sub(start))
	for i := 0; i < events; i++ {
		kind := incident.ProcessStarted
		if i%2 == 1 {
			kind = incident.ProcessExited
		}
		pid := 500 + i%50
		inc.Events = append(inc.Events, incident.Event{
			Timestamp:  start.Add(time.Duration(span / int64(events) * int64(i))),
			Type:       kind,
			PID:        pid,
			StartTicks: int64(pid),
			Collector:  "process",
		})
	}
	return inc
}

// scaleDocument encodes, re-reads (so the document is produced from bytes the
// cloud would have, not from the in-memory fixture) and renders one document.
func scaleDocument(t *testing.T, events int) (rawBytes, documentBytes int, run time.Duration, doc *Document) {
	t.Helper()
	var raw bytes.Buffer
	if err := incident.Encode(&raw, scaleIncident(events), true); err != nil {
		t.Fatalf("encode %d-event bundle: %v", events, err)
	}
	bundle, err := incident.Read(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
	if err != nil {
		t.Fatalf("read %d-event bundle: %v", events, err)
	}
	started := time.Now()
	doc, err = Run(bundle, SHA256OfBytes(raw.Bytes()), Options{})
	run = time.Since(started)
	if err != nil {
		t.Fatalf("render %d-event document: %v", events, err)
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, doc); err != nil {
		t.Fatalf("write %d-event document: %v", events, err)
	}
	return raw.Len(), out.Len(), run, doc
}

// TestDocumentScalePayload is 7.44's server-side half: the stored document at
// 100 and 1,000 events, plus 10,000 when opted in. the bounds are deliberately
// loose (they catch a whole class of bloat, not a few bytes of drift); the
// logged table is the number a paging decision is made from.
//
// the 10,000-event case is opt-in: it spends about seven seconds of CPU, and
// run beside the suite's wall-clock tests (the provider churn ratio test and
// the trace correlation windows) it makes them fail. it is a measurement, not
// a regression guard, so CI runs the cheap sizes and the 10,000-event numbers
// in docs/cloud/performance.md are regenerated on demand:
//
//	RUNOPSY_SCALE_10K=1 go test -run TestDocumentScalePayload -v ./internal/analysis
func TestDocumentScalePayload(t *testing.T) {
	if testing.Short() {
		t.Skip("renders document-scale bundles")
	}
	sizes := []int{100, 1000}
	if os.Getenv("RUNOPSY_SCALE_10K") != "" {
		sizes = append(sizes, 10000)
	}
	for _, events := range sizes {
		events := events
		t.Run(fmt.Sprintf("%d-events", events), func(t *testing.T) {
			rawbytes, documentbytes, run, doc := scaleDocument(t, events)
			perevent := float64(documentbytes) / float64(len(doc.Timeline))
			t.Logf("events=%d timeline=%d series=%d nodes=%d bundle=%d B document=%d B (%.0f B/event) run=%s",
				events, len(doc.Timeline), len(doc.Series), len(doc.Causal.Nodes), rawbytes, documentbytes, perevent, run.Round(time.Millisecond))

			if documentbytes <= 0 {
				t.Fatal("document has no size")
			}
			if len(doc.Timeline) == 0 {
				t.Fatal("document has no timeline")
			}
			if len(doc.Series) != scaleSnapshotCount {
				t.Errorf("series has %d snapshots, want %d", len(doc.Series), scaleSnapshotCount)
			}
			// 7.44 paging invariant: index equals position, in capture order,
			// so the dashboard can slice without re-sorting.
			for i := 1; i < len(doc.Timeline); i++ {
				if doc.Timeline[i].Timestamp.Before(doc.Timeline[i-1].Timestamp) {
					t.Fatalf("timeline is not in capture order at index %d", i)
				}
			}
			if documentbytes > 64<<20 {
				t.Errorf("document is %d bytes, above the 64 MiB upload budget", documentbytes)
			}
			if perevent > 4096 {
				t.Errorf("%.0f bytes per timeline event; the dashboard pages this array, so bloat here is paid on every page", perevent)
			}
		})
	}
}

// TestDocumentScaleIsReproducible checks the property paging relies on at
// scale: the same bundle renders the same bytes twice, so a page fetched from
// the cloud and the same page rendered locally agree.
func TestDocumentScaleIsReproducible(t *testing.T) {
	if testing.Short() {
		t.Skip("renders a 1,000-event document twice")
	}
	_, first, _, _ := scaleDocument(t, 1000)
	inc := scaleIncident(1000)
	var raw bytes.Buffer
	if err := incident.Encode(&raw, inc, true); err != nil {
		t.Fatal(err)
	}
	bundle, err := incident.Read(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Run(bundle, SHA256OfBytes(raw.Bytes()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, doc); err != nil {
		t.Fatal(err)
	}
	if out.Len() != first {
		t.Fatalf("second render is %d bytes, first was %d", out.Len(), first)
	}
}
