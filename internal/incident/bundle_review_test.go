package incident

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deprehendo/internal/collector"
)

func TestBundleRejectsCaseAliasPrivacyBypass(t *testing.T) {
	original := encoded(t, fixture(), true)
	for _, alias := range []string{"NAME", "Name", `na\u006de`} {
		raw := rebuild(t, original, func(files map[string][]byte) {
			files["snapshots.json"] = bytes.Replace(files["snapshots.json"], []byte(`"name":"[REDACTED]"`), []byte(`"name":"password=SECRET","`+alias+`":"[REDACTED]"`), 1)
		})
		if _, err := Read(bytes.NewReader(raw), int64(len(raw))); err == nil {
			t.Fatalf("accepted case/escaped alias %s that hides secret from decoded evidence", alias)
		}
	}
}

func TestBundleRejectsUnicodeCaseAliasPrivacyBypass(t *testing.T) {
	raw := rebuild(t, encoded(t, fixture(), true), func(files map[string][]byte) {
		files["snapshots.json"] = bytes.Replace(files["snapshots.json"], []byte(`"state":"S"`), []byte(`"state":"password=SECRET","ſtate":"S"`), 1)
	})
	if _, err := Read(bytes.NewReader(raw), int64(len(raw))); err == nil {
		t.Fatal("accepted Unicode simple-fold alias hiding secret")
	}
}

func TestJSONPreflightBoundsBeforeTypedAllocation(t *testing.T) {
	for name, raw := range map[string][]byte{
		"snapshot-count":      []byte("[" + strings.Repeat("null,", MaxSnapshots) + "null]"),
		"nested-record-count": []byte(`{"processes":[` + strings.Repeat("null,", MaxEvents) + `null]}`),
		"invalid-utf8":        append([]byte(`{"name":"`), 0xff, '"', '}'),
	} {
		t.Run(name, func(t *testing.T) {
			if err := rejectDuplicateKeys(raw); err == nil {
				t.Fatal("accepted unbounded or malformed JSON")
			}
		})
	}
}

func TestCloneRejectsSharedOversizedRecordGraphBeforeMarshal(t *testing.T) {
	i := fixture()
	i.Snapshots = make([]collector.Snapshot, MaxSnapshots)
	shared := make([]collector.ProcessSnapshot, 25)
	for n := range i.Snapshots {
		i.Snapshots[n].Processes = shared
	}
	if _, err := clone(i); err == nil {
		t.Fatal("accepted oversized graph")
	}
}

func TestPublishCancellationDoesNotExposeArtifact(t *testing.T) {
	dir := privateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := FileWriter{Directory: dir, before: func(step string) error {
		if step == "publish" {
			cancel()
		}
		return nil
	}}
	path, err := w.Write(ctx, fixture())
	if !errors.Is(err, context.Canceled) || path != "" {
		t.Fatalf("published after cancellation: %s %v", path, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("left incomplete artifacts: %v %v", entries, err)
	}
}

func TestListBindsFilenameToIncidentIdentity(t *testing.T) {
	dir := privateDir(t)
	data := encoded(t, fixture(), true)
	if err := os.WriteFile(filepath.Join(dir, "inc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.deprehendo"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := List(dir); err == nil {
		t.Fatal("accepted misleading filename")
	}
}

func TestNoteNormalizesUnicodeTerminalControls(t *testing.T) {
	i := fixture()
	i.Trigger.Note = "before\u202eafter\u0085line\u2028break\u2029end"
	if err := (ConservativeRedactor{}).RedactIncident(i); err != nil {
		t.Fatal(err)
	}
	if i.Trigger.Note != "before after line break end" {
		t.Fatalf("unsafe note retained: %q", i.Trigger.Note)
	}
}

func TestReadVersionOneGoldenCompatibility(t *testing.T) {
	bundle, err := ReadFile("testdata/v1-minimal.deprehendo")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.FormatVersion != 1 || bundle.Incident.ID != "inc_11111111111111111111111111111111" || len(bundle.Incident.Snapshots) != 1 || len(bundle.Incident.Events) != 1 || bundle.Incident.Snapshots[0].Processes[0].Name != "[REDACTED]" {
		t.Fatalf("v1 golden changed interpretation: %+v", bundle.Incident)
	}
}

func TestBundleRejectsZIP64MemberExtras(t *testing.T) {
	base := encoded(t, fixture(), false)
	reader, err := zip.NewReader(bytes.NewReader(base), int64(len(base)))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range reader.File {
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		header := &zip.FileHeader{Name: file.Name, Method: zip.Store}
		if file.Name == "manifest.json" {
			header.Extra = []byte{1, 0, 0, 0}
		}
		dst, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = dst.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Read(bytes.NewReader(output.Bytes()), int64(output.Len())); err == nil {
		t.Fatal("accepted unsupported ZIP64 extra")
	}
}

func TestEncodeRejectsInvalidUTF8NoteBeforeJSONReplacement(t *testing.T) {
	i := fixture()
	i.Trigger.Note = string([]byte{0xff})
	var output bytes.Buffer
	if err := Encode(&output, i, true); err == nil {
		t.Fatal("accepted invalid UTF-8 note after JSON replacement")
	}
	if output.Len() != 0 {
		t.Fatal("wrote output for rejected note")
	}
}
