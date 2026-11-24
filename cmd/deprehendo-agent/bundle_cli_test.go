package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

func writeTestBundle(t *testing.T, directory, note string, offset time.Duration) string {
	t.Helper()
	at := time.Date(2026, 10, 25, 19, 48, 12, 0, time.UTC)
	i := &incident.Incident{
		SchemaVersion: incident.SchemaVersion, ID: "inc_0123456789abcdef0123456789abcdef",
		CreatedAt: at.Add(31 * time.Second), TriggeredAt: at,
		CaptureStart: at.Add(-10 * time.Second), CaptureEnd: at.Add(20 * time.Second),
		Window:   incident.CaptureWindow{PreTrigger: 10 * time.Second, PostTrigger: 20 * time.Second},
		Trigger:  incident.Trigger{Type: "manual", Note: note},
		Metadata: incident.Metadata{AgentVersion: incident.AgentVersion, Host: incident.LocalHost()},
		Snapshots: []collector.Snapshot{
			{Timestamp: at.Add(-10 * time.Second), Processes: []collector.ProcessSnapshot{{Process: platform.Process{PID: 17, State: "S", Name: "secret-worker"}}}},
			{Timestamp: at.Add(offset), System: &collector.SystemSnapshot{DiskFilesystem: "/sensitive/path"}, Connections: []collector.ConnectionSnapshot{{LocalAddr: "10.0.0.1", RemoteAddr: "192.0.2.2", State: "ESTABLISHED"}}},
			{Timestamp: at.Add(20 * time.Second)},
		},
		Events: []incident.Event{{Timestamp: at, Type: incident.IncidentTriggered}},
	}
	path := filepath.Join(directory, i.ID+".deprehendo")
	var buf bytes.Buffer
	if err := incident.Encode(&buf, i, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPhase2BundleCLI(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := writeTestBundle(t, dir, "runner stopped\nmanual follow-up", 5*time.Second)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"incidents", "list", "--incident-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("list=%d: %s", code, stderr.String())
	}
	for _, want := range []string{"inc_0123456789abcdef0123456789abcdef", "manual", "SIZE"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("list missing %q: %s", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"validate", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("validate=%d: %s", code, stderr.String())
	}
	for _, want := range []string{"Bundle valid", "Schema: v1", "Snapshots: 3", "Integrity: OK"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("validate missing %q: %s", want, stdout.String())
		}
	}

	extracted := filepath.Join(t.TempDir(), "extract")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"extract", path, "--output", extracted}, &stdout, &stderr); code != 0 {
		t.Fatalf("extract=%d: %s", code, stderr.String())
	}
	for _, name := range []string{"manifest.json", "metadata.json", "snapshots.json", "events.jsonl", "privacy.json"} {
		info, err := os.Stat(filepath.Join(extracted, name))
		if err != nil {
			t.Errorf("extract missing %s: %v", name, err)
			continue
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s mode=%o", name, info.Mode().Perm())
		}
	}
	if code := run([]string{"extract", path, "--output", extracted}, &stdout, &stderr); code != 1 {
		t.Fatalf("extract overwrote existing destination: %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inspect", path, "--privacy"}, &stdout, &stderr); code != 0 {
		t.Fatalf("privacy=%d: %s", code, stderr.String())
	}
	for _, want := range []string{"Network addresses    YES", "Filesystem paths     YES", "User note            YES", "Environment variables NO"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("privacy missing %q: %s", want, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), "runner stopped manual follow-up") {
		t.Fatal("note not shown in inspect output")
	}

	for _, args := range [][]string{{"inspect", path, "--snapshot", "1"}, {"inspect", "--at", "+5s", path}} {
		stdout.Reset()
		stderr.Reset()
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("inspect %v=%d: %s", args, code, stderr.String())
		}
		var selected struct {
			Index    int                `json:"index"`
			Offset   time.Duration      `json:"offset_from_trigger"`
			Snapshot collector.Snapshot `json:"snapshot"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &selected); err != nil {
			t.Fatalf("snapshot output: %v: %s", err, stdout.String())
		}
		if selected.Index != 1 || selected.Offset != 5*time.Second || selected.Snapshot.Connections[0].LocalAddr != "[REDACTED]" {
			t.Fatalf("selected=%+v", selected)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inspect", path, "--snapshot", "8"}, &stdout, &stderr); code != 2 {
		t.Fatalf("out of range snapshot=%d", code)
	}
}

func TestUnsupportedFormatVersionsAreSpecific(t *testing.T) {
	base := writeTestBundle(t, t.TempDir(), "", 0)
	bundle, err := incident.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	_ = bundle
	f, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(f, func() int64 { st, _ := f.Stat(); return st.Size() }())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range zr.File {
		r, e := entry.Open()
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		files[entry.Name] = data
	}
	f.Close()
	var manifest incident.Manifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SchemaVersion = 999
	files["manifest.json"], _ = json.Marshal(manifest)
	var raw bytes.Buffer
	w := zip.NewWriter(&raw)
	for _, name := range []string{"manifest.json", "metadata.json", "snapshots.json", "events.jsonl", "privacy.json"} {
		part, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = part.Write(files[name]); e != nil {
			t.Fatal(e)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(t.TempDir(), "unsupported.deprehendo")
	if err := os.WriteFile(corrupt, raw.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = incident.ReadFile(corrupt)
	if err == nil || !strings.Contains(err.Error(), "unsupported Deprehendo bundle schema: 999") {
		t.Fatalf("error=%v", err)
	}
}

func TestOfflineFlagParsingIsStrict(t *testing.T) {
	path := writeTestBundle(t, t.TempDir(), "", 0)
	var out, errb bytes.Buffer
	dest := filepath.Join(t.TempDir(), "out")
	if code := run([]string{"extract", "--output", dest, path}, &out, &errb); code != 0 {
		t.Fatalf("extract flags before path: %d %s", code, errb.String())
	}
	for _, bad := range []string{"1garbage", "1.5", "1 2"} {
		if code := run([]string{"inspect", path, "--snapshot", bad}, &out, &errb); code != 2 {
			t.Errorf("index %q returned %d", bad, code)
		}
	}
	for _, flag := range []string{"--trigger-memory-percent", "--trigger-disk-free-percent"} {
		if code := run([]string{"start", flag, "NaN"}, &out, &errb); code != 2 {
			t.Errorf("%s NaN returned %d", flag, code)
		}
	}
}
