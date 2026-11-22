// phase 7 upload corpus (7.40, integration half of the review).
//
// docs/cloud/contract.md §5.5 lists the hostile and malformed archives the
// worker must be driven with, and docs/cloud/upload-corpus.md mapped each one
// to an incident-reader unit test by name, without ever running the case
// through the worker. this file closes that gap for the cases that do not need
// a multi-hundred-megabyte fixture: each bundle is built here, uploaded
// through the real policy, completed by the real server, and asserted on the
// HTTP answer *and* on what the dashboard can then see.
//
// cases intentionally not driven here, with the reason:
//
//   - 30 MiB expanded valid bundle (§5.5 #15): the same code path as the valid
//     case; it needs ~7 s and ~420 MB, measured in contract §5.2. running it in
//     every `make test-cloud` would dominate the suite.
//   - 250,001-record cap (§5.5 #13): the preflight bounds it in
//     TestJSONPreflightBoundsBeforeTypedAllocation, before any typed
//     allocation; a worker-level copy adds no distinct server behavior.
//   - an old-schema bundle (§5.5 #2): no older decoder exists yet (§7.2), so
//     the case cannot pass until the reader dispatches by version. the
//     unsupported-schema case below proves a bumped version is refused.
package tests

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"runopsy/internal/cloudclient"
	"runopsy/internal/incident"
)

// bundleMembers are the five fixed member names of a v1 archive (the manifest
// plus the four payloads).
var bundleMembers = []string{"metadata.json", "snapshots.json", "events.jsonl", "privacy.json"}

// unzipBundle splits a checked-in bundle into its members, in archive order.
func unzipBundle(t *testing.T, raw []byte) (map[string][]byte, []string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	files := make(map[string][]byte, len(zr.File))
	order := make([]string, 0, len(zr.File))
	for _, file := range zr.File {
		stream, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", file.Name, err)
		}
		data, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			t.Fatalf("read %s: %v", file.Name, err)
		}
		files[file.Name] = data
		order = append(order, file.Name)
	}
	return files, order
}

func cloneFiles(files map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(files))
	for name, data := range files {
		out[name] = append([]byte(nil), data...)
	}
	return out
}

// rehashManifest recomputes the manifest's per-member digests after a change,
// so the reader is asked to refuse the content rather than a checksum the
// attacker forgot to update (the forged-valid-checksums distinction).
func rehashManifest(t *testing.T, files map[string][]byte) {
	t.Helper()
	var manifest incident.Manifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	for _, name := range bundleMembers {
		data, ok := files[name]
		if !ok {
			continue
		}
		sum := sha256.Sum256(data)
		manifest.Files[name] = incident.FileDigest{Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	files["manifest.json"] = encoded
}

type zipEntry struct {
	name   string
	data   []byte
	mode   os.FileMode
	extra  []byte
	method uint16
}

func zipBundle(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o600
		}
		header := &zip.FileHeader{Name: entry.name, Method: entry.method}
		header.SetMode(mode)
		if len(entry.extra) > 0 {
			header.Extra = entry.extra
		}
		dst, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create %s: %v", entry.name, err)
		}
		if _, err := dst.Write(entry.data); err != nil {
			t.Fatalf("write %s: %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return out.Bytes()
}

func entriesFrom(files map[string][]byte, order []string) []zipEntry {
	entries := make([]zipEntry, 0, len(order))
	for _, name := range order {
		entries = append(entries, zipEntry{name: name, data: files[name], method: zip.Deflate})
	}
	return entries
}

// uploadRawAndComplete uploads these exact bytes against the minted policy and
// completes them, returning the complete status and body.
func uploadRawAndComplete(t *testing.T, h *cloudHarness, token string, raw []byte, incidentID string) (int, string) {
	t.Helper()
	client, err := cloudclient.New(h.Endpoint, token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum := sha256.Sum256(raw)
	target, err := client.Create(ctx, cloudclient.CreateRequest{
		SHA256:        hex.EncodeToString(sum[:]),
		SizeBytes:     int64(len(raw)),
		IncidentID:    incidentID,
		SchemaVersion: 1,
		FormatVersion: 1,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if target.Duplicate {
		t.Fatal("expected a fresh upload")
	}
	if err := storagePut(t, h.Endpoint+"/storage", target.Upload.Fields, raw); err != nil {
		t.Fatalf("storage put: %v", err)
	}
	return postComplete(t, h.Endpoint, token, target.UploadID, 120*time.Second)
}

// TestPhase7UploadCorpus drives §5.5's malformed archives through the real
// worker. every refused bundle must answer with the pinned error code and, per
// 7.31/7.32, leave one queryable row carrying the failure status and no
// invented diagnosis.
func TestPhase7UploadCorpus(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	basepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	baseraw, err := os.ReadFile(basepath)
	if err != nil {
		t.Fatal(err)
	}
	basefiles, baseorder := unzipBundle(t, baseraw)
	basebundle, err := readBundleFile(t, basepath)
	if err != nil {
		t.Fatal(err)
	}
	incidentID := basebundle.Manifest.IncidentID

	// mutate applies a member change and fixes the manifest digests.
	mutate := func(change func(map[string][]byte)) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			files := cloneFiles(basefiles)
			change(files)
			rehashManifest(t, files)
			return zipBundle(t, entriesFrom(files, baseorder))
		}
	}

	cases := []struct {
		name       string
		raw        func(*testing.T) []byte
		wantStatus int
		wantCode   string
	}{
		{"valid", func(*testing.T) []byte { return baseraw }, http.StatusOK, ""},
		{"truncated", func(*testing.T) []byte { return baseraw[:len(baseraw)/2] }, http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"duplicate-member", func(t *testing.T) []byte {
			entries := entriesFrom(basefiles, baseorder)
			entries = append(entries, zipEntry{name: "snapshots.json", data: basefiles["snapshots.json"], method: zip.Deflate})
			return zipBundle(t, entries)
		}, http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"sixth-member", func(t *testing.T) []byte {
			entries := entriesFrom(basefiles, baseorder)
			entries = append(entries, zipEntry{name: "notes.json", data: []byte(`{"note":"extra"}`), method: zip.Deflate})
			return zipBundle(t, entries)
		}, http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"symlink-member", func(t *testing.T) []byte {
			entries := entriesFrom(basefiles, baseorder)
			entries = append(entries, zipEntry{name: "link.json", data: []byte("/etc/passwd"), mode: os.ModeSymlink | 0o777})
			return zipBundle(t, entries)
		}, http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"zip64-sizes", func(t *testing.T) []byte {
			entries := entriesFrom(basefiles, baseorder)
			for i := range entries {
				if entries[i].name == "manifest.json" {
					entries[i].extra = []byte{1, 0, 0, 0} // ZIP64 extra field tag
				}
			}
			return zipBundle(t, entries)
		}, http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"unsupported-schema", mutate(func(files map[string][]byte) {
			var manifest incident.Manifest
			if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
				t.Fatalf("parse manifest: %v", err)
			}
			manifest.SchemaVersion = incident.SchemaVersion + 1
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("marshal manifest: %v", err)
			}
			files["manifest.json"] = encoded
		}), http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"forged-identity", mutate(func(files map[string][]byte) {
			forged := bytes.Replace(files["metadata.json"], []byte(incidentID), []byte("inc_ffffffffffffffffffffffffffffffff"), 1)
			if bytes.Equal(forged, files["metadata.json"]) {
				t.Fatal("metadata did not contain the incident id to forge")
			}
			files["metadata.json"] = forged
		}), http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
		{"decompression-bomb", func(t *testing.T) []byte {
			files := cloneFiles(basefiles)
			var bomb bytes.Buffer
			chunk := make([]byte, 1<<20)
			for i := 0; i < 65; i++ { // 65 MiB expanded, above the 64 MiB budget
				bomb.Write(chunk)
			}
			files["snapshots.json"] = bomb.Bytes()
			rehashManifest(t, files)
			return zipBundle(t, entriesFrom(files, baseorder))
		}, http.StatusUnprocessableEntity, "INVALID_BUNDLE"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := newCloudHarness(t, dsn, nil)
			raw := tc.raw(t)
			status, body := uploadRawAndComplete(t, h, h.TokenA, raw, incidentID)
			if status != tc.wantStatus {
				t.Fatalf("complete = %d %s, want %d", status, body, tc.wantStatus)
			}
			if tc.wantCode != "" {
				if code := apiErrorCode(t, body); code != tc.wantCode {
					t.Errorf("error code = %q, want %q (%s)", code, tc.wantCode, body)
				}
			}

			hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents")
			if len(hits) != 1 {
				t.Fatalf("%d incident rows after %s, want 1", len(hits), tc.name)
			}
			row := hits[0]
			if tc.wantStatus == http.StatusOK {
				if got, _ := row["analysis_status"].(string); got != "READY" {
					t.Errorf("analysis_status = %q, want READY", got)
				}
				if row["primary_signature"] == nil {
					t.Errorf("a READY incident has no signature: %v", row)
				}
				bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/analysis", http.StatusOK)
				// L4: the download is the exact archive that was uploaded.
				served := bearerGet(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/bundle", http.StatusOK)
				if !bytes.Equal(served, raw) {
					t.Fatalf("bundle download differs from the uploaded bytes (%d vs %d)", len(served), len(raw))
				}
				return
			}
			if got, _ := row["analysis_status"].(string); got != "REJECTED" {
				t.Errorf("analysis_status = %q, want REJECTED", got)
			}
			if row["primary_signature"] != nil {
				t.Errorf("a rejected bundle produced a signature: %v", row)
			}
			if code := getStatus(t, h.Endpoint, h.TokenA, "/api/incidents/"+incidentID+"/analysis"); code != http.StatusAccepted {
				t.Errorf("analysis endpoint = %d, want 202 (status, not a blank document)", code)
			}
		})
	}
}

// TestPhase7CompleteRecomputesTheDigestFromStoredBytes covers the integrity
// half of 7.10: create records the client's digest as a claim, and complete
// must re-hash what the store actually holds. the stored object is replaced
// with a *different valid bundle*, so only the digest can catch it.
func TestPhase7CompleteRecomputesTheDigestFromStoredBytes(t *testing.T) {
	dsn := cloudTestDSN(t)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	h := newCloudHarness(t, dsn, nil)
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	otherpath := filepath.Join(root, "testdata", "incidents", "disk-full.runopsy")

	raw, err := os.ReadFile(bundlepath)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(otherpath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readBundleFile(t, bundlepath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := cloudclient.New(h.Endpoint, h.TokenA)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum := sha256.Sum256(raw)
	target, err := client.Create(ctx, cloudclient.CreateRequest{
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw)),
		IncidentID: bundle.Manifest.IncidentID, SchemaVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if target.Duplicate {
		t.Fatal("expected a fresh upload")
	}
	if err := client.PutObject(ctx, target.Upload, bundlepath); err != nil {
		t.Fatalf("storage put: %v", err)
	}
	h.Store.tamper(target.Upload.Fields["key"], other)

	status, body := postComplete(t, h.Endpoint, h.TokenA, target.UploadID, 90*time.Second)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("complete over replaced bytes = %d %s, want 422", status, body)
	}
	if code := apiErrorCode(t, body); code != "INVALID_BUNDLE" {
		t.Errorf("error code = %q, want INVALID_BUNDLE", code)
	}
	if hits := fetchJSON[[]map[string]any](t, h.Endpoint, h.TokenA, "/api/incidents"); len(hits) != 0 {
		t.Fatalf("a digest mismatch produced %d incident rows", len(hits))
	}
}
