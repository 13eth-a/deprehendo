package incident

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWriterCrashBoundaries(t *testing.T) {
	if os.Getenv("RUNOPSY_CRASH_STEP") != "" {
		writer := FileWriter{Directory: os.Getenv("RUNOPSY_CRASH_DIR"), before: func(step string) error {
			if step == os.Getenv("RUNOPSY_CRASH_STEP") {
				os.Exit(83)
			}
			return nil
		}}
		_, _ = writer.Write(context.Background(), fixture())
		os.Exit(84)
	}
	for _, step := range []string{"write", "sync-file", "close", "publish", "sync-directory"} {
		t.Run(step, func(t *testing.T) {
			dir := privateDir(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWriterCrashBoundaries$")
			cmd.Env = append(os.Environ(), "RUNOPSY_CRASH_STEP="+step, "RUNOPSY_CRASH_DIR="+dir)
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 83 {
				t.Fatalf("unexpected child exit: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			complete := 0
			for _, e := range entries {
				if filepath.Ext(e.Name()) == ".runopsy" {
					complete++
					if _, err := ReadFile(filepath.Join(dir, e.Name())); err != nil {
						t.Fatal(err)
					}
				}
			}
			if step == "sync-directory" && complete != 1 {
				t.Fatal("published artifact missing")
			}
			if step != "sync-directory" && complete != 0 {
				t.Fatal("partial write presented as complete")
			}
			if _, err := CleanupStaleTemps(dir, time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// rebuild updates checksums too, ensuring semantic validation is not merely
// testing that an attacker forgot to rewrite the manifest.
func rebuild(t *testing.T, raw []byte, mutate func(map[string][]byte)) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], err = io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	mutate(files)
	var m Manifest
	if err = json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	for _, name := range members {
		m.Files[name] = digest(files[name])
	}
	files["manifest.json"], err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, name := range append([]string{"manifest.json"}, members...) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestForgedValidChecksumsStillRejectInvalidEvidence(t *testing.T) {
	raw := encoded(t, fixture(), true)
	cases := map[string]func(map[string][]byte){
		"secrets": func(f map[string][]byte) {
			f["snapshots.json"] = bytes.ReplaceAll(f["snapshots.json"], []byte("[REDACTED]"), []byte("password=SECRET"))
		},
		"wrong-policy": func(f map[string][]byte) { f["privacy.json"] = []byte(`{"policy":"trust-me"}`) },
		"unknown-fields": func(f map[string][]byte) {
			f["snapshots.json"] = []byte(`[{"timestamp":"2026-10-25T12:00:00Z","environment":{"TOKEN":"secret"}}]`)
		},
		"unordered": func(f map[string][]byte) {
			var rows []json.RawMessage
			json.Unmarshal(f["snapshots.json"], &rows)
			rows[0], rows[1] = rows[1], rows[0]
			f["snapshots.json"], _ = json.Marshal(rows)
		},
		"bad-events": func(f map[string][]byte) {
			f["events.jsonl"] = []byte(`{"type":"DIAGNOSIS","timestamp":"2026-10-25T12:00:00Z"}`)
		},
		"manifest-identity": func(f map[string][]byte) {
			f["metadata.json"] = bytes.ReplaceAll(f["metadata.json"], []byte(fixture().ID), []byte("inc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			data := rebuild(t, raw, change)
			if _, err := Read(bytes.NewReader(data), int64(len(data))); err == nil {
				t.Fatal("accepted forged semantic corruption")
			}
		})
	}
}
func TestConcurrentCaptureObservationAndTrigger(t *testing.T) {
	w := &recordingWriter{}
	c, _ := NewCapture(CaptureOptions{Writer: w, Window: CaptureWindow{time.Second, 100 * time.Millisecond}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 15 {
				c.Observe(sample(time.Now().UTC(), 10))
				c.Status()
			}
			_, _ = c.Trigger(Trigger{Type: "manual"})
		}()
	}
	wg.Wait()
	waitCapture(t, c)
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.incidents) != 1 {
		t.Fatalf("simultaneous incidents: %d", len(w.incidents))
	}
	if err := Validate(w.incidents[0]); err != nil {
		t.Fatal(err)
	}
}
func TestCompressionAndDecodeMeasurement(t *testing.T) {
	i := fixture()
	base := i.Snapshots[0]
	i.Snapshots = nil
	for n := 0; n < 120; n++ {
		base.Timestamp = i.CaptureStart.Add(time.Duration(n) * time.Millisecond)
		i.Snapshots = append(i.Snapshots, base)
	}
	plain := encoded(t, i, false)
	compressed := encoded(t, i, true)
	if len(compressed) >= len(plain) {
		t.Fatal("compression did not reduce representative payload")
	}
	if len(compressed) > 1<<20 {
		t.Fatal("small representative bundle exceeded 1MiB")
	}
	for _, raw := range [][]byte{plain, compressed} {
		start := time.Now()
		if _, err := Read(bytes.NewReader(raw), int64(len(raw))); err != nil {
			t.Fatal(err)
		}
		t.Logf("bundle_bytes=%d decode_duration=%s", len(raw), time.Since(start))
	}
}
func TestDecompressionBombBound(t *testing.T) {
	// A small compressed member that declares expansion above the budget is
	// rejected from its central-directory metadata, before decompression.
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, name := range append([]string{"manifest.json"}, members...) {
		w, _ := z.Create(name)
		if name == "snapshots.json" {
			chunk := make([]byte, 1<<20)
			for range 65 {
				w.Write(chunk)
			}
		} else {
			w.Write([]byte("{}"))
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(b.Bytes()), int64(b.Len())); err == nil {
		t.Fatal("accepted decompression bomb")
	}
}
