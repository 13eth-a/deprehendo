package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func decodeAll(t *testing.T, b *bytes.Buffer) []Event {
	t.Helper()
	var got []Event
	dec := json.NewDecoder(b)
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode event %d: %v", len(got), err)
		}
		got = append(got, ev)
	}
	return got
}

func TestEmitJSONContract(t *testing.T) {
	var out bytes.Buffer
	em := New("frozen-worker", &out, nil, true)

	ts := time.Date(2026, 10, 24, 20, 41, 22, 0, time.UTC)
	em.now = func() time.Time { return ts }
	em.Emit("worker_frozen", map[string]any{"pid": 5822})

	line := strings.TrimSpace(out.String())
	if strings.Contains(line, "\n") {
		t.Fatalf("expected one JSON record per line, got %q", line)
	}

	evs := decodeAll(t, &out)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Scenario != "frozen-worker" {
		t.Errorf("scenario = %q, want frozen-worker", ev.Scenario)
	}
	if ev.Type != "worker_frozen" {
		t.Errorf("type = %q, want worker_frozen", ev.Type)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("timestamp = %s, want %s", ev.Timestamp, ts)
	}
	if ev.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp location = %s, want UTC", ev.Timestamp.Location())
	}
	if pid, ok := ev.Data["pid"].(float64); !ok || pid != 5822 {
		t.Errorf("data.pid = %v, want 5822", ev.Data["pid"])
	}

	// the wire format is what the next phase parses; pin the field names.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, key := range []string{"timestamp", "scenario", "type", "data"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing %q field in %s", key, line)
		}
	}
}

func TestEmitOmitsEmptyData(t *testing.T) {
	var out bytes.Buffer
	em := New("normal", &out, nil, true)
	em.Emit("started", nil)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["data"]; ok {
		t.Errorf("empty data should be omitted, got %s", out.String())
	}
}

func TestEmitTextMode(t *testing.T) {
	var human bytes.Buffer
	em := New("socket-stall", nil, &human, false)
	em.now = func() time.Time { return time.Date(2026, 10, 24, 20, 41, 22, 0, time.UTC) }
	em.Emit("stall_detected", map[string]any{"rx_count": 3, "silent_ms": int64(1200)})

	line := human.String()
	for _, want := range []string{"20:41:22.000", "stall_detected", "rx_count=3", "silent_ms=1200"} {
		if !strings.Contains(line, want) {
			t.Errorf("text output %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "{") || strings.Contains(line, `"`) {
		t.Errorf("text output should not be JSON: %q", line)
	}
}

func TestSaySuppressedInJSONMode(t *testing.T) {
	var out, human bytes.Buffer
	em := New("normal", &out, &human, true)
	em.Say("Worker running...")

	if human.Len() != 0 {
		t.Errorf("Say wrote to human stream in JSON mode: %q", human.String())
	}
	if out.Len() != 0 {
		t.Errorf("Say wrote to event stream: %q", out.String())
	}
}

func TestConcurrentEmitProducesWholeRecords(t *testing.T) {
	var out bytes.Buffer
	em := New("cpu-spin", &out, nil, true)

	const writers, perWriter = 16, 25
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				em.Emit("tick", map[string]any{"worker": id, "n": j})
			}
		}(i)
	}
	wg.Wait()

	evs := decodeAll(t, &out)
	if len(evs) != writers*perWriter {
		t.Fatalf("got %d events, want %d", len(evs), writers*perWriter)
	}
	for _, ev := range evs {
		if ev.Type != "tick" || ev.Scenario != "cpu-spin" {
			t.Fatalf("corrupted record: %+v", ev)
		}
	}
}
