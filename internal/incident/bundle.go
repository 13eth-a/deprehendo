package incident

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const FormatVersion = 1
const SnapshotEncoding = "json-v1"
const maxArchiveBytes = MaxPayloadBytes + 1<<20

// MaxArchiveSize is the largest accepted on-disk archive: the 64 MiB
// expanded-payload budget plus the manifest slack. upload paths (phase 7)
// re-check it before reading so a hostile caller never streams past it.
const MaxArchiveSize = maxArchiveBytes

var members = []string{"metadata.json", "snapshots.json", "events.jsonl", "privacy.json"}

type FileDigest struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Format           string                `json:"format"`
	FormatVersion    int                   `json:"format_version"`
	SchemaVersion    int                   `json:"schema_version"`
	SnapshotEncoding string                `json:"snapshot_encoding"`
	IncidentID       string                `json:"incident_id"`
	CreatedAt        time.Time             `json:"created_at"`
	AgentVersion     string                `json:"agent_version"`
	Platform         string                `json:"platform"`
	Architecture     string                `json:"architecture"`
	Files            map[string]FileDigest `json:"files"`
}

// bundle is returned only after all components, checksums and semantic
// invariants have been validated. no archive paths are ever extracted.
type Bundle struct {
	Manifest Manifest
	Incident *Incident
	// files contains the exact verified v1 archive components, detached from
	// archive storage, for safe transparent extraction.
	Files map[string][]byte
}

func digest(data []byte) FileDigest {
	sum := sha256.Sum256(data)
	return FileDigest{int64(len(data)), hex.EncodeToString(sum[:])}
}

// encode always applies the conservative policy on a detached copy. callers
// cannot bypass redaction by forgetting a preprocessing step.
func Encode(w io.Writer, original *Incident, compressed bool) error {
	i, err := clone(original)
	if err != nil {
		return err
	}
	if err = (ConservativeRedactor{}).RedactIncident(i); err != nil {
		return err
	}
	if err = Validate(i); err != nil {
		return err
	}
	snapshots, events, privacy := i.Snapshots, i.Events, i.Privacy
	i.Snapshots = nil
	i.Events = nil
	i.Privacy = PrivacyReport{}
	metadata, err := json.Marshal(i)
	if err != nil {
		return err
	}
	snapshotdata, err := json.Marshal(snapshots)
	if err != nil {
		return err
	}
	var stream bytes.Buffer
	enc := json.NewEncoder(&stream)
	for _, e := range events {
		if err = enc.Encode(e); err != nil {
			return err
		}
	}
	privacydata, err := json.Marshal(privacy)
	if err != nil {
		return err
	}
	payloads := [][]byte{metadata, snapshotdata, stream.Bytes(), privacydata}
	total := 0
	manifest := Manifest{Format: "runopsy", FormatVersion: FormatVersion, SchemaVersion: SchemaVersion, SnapshotEncoding: SnapshotEncoding, IncidentID: i.ID, CreatedAt: i.CreatedAt, AgentVersion: i.Metadata.AgentVersion, Platform: i.Metadata.Host.OS, Architecture: i.Metadata.Host.Architecture, Files: map[string]FileDigest{}}
	for n, p := range payloads {
		total += len(p)
		manifest.Files[members[n]] = digest(p)
	}
	if total > MaxPayloadBytes {
		return fmt.Errorf("incident: uncompressed bundle budget exceeded")
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(w)
	write := func(name string, p []byte) error {
		method := uint16(zip.Store)
		if compressed {
			method = zip.Deflate
		}
		h := &zip.FileHeader{Name: name, Method: method}
		h.SetMode(0600)
		dst, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		n, err := dst.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		return err
	}
	if err = write("manifest.json", raw); err != nil {
		return err
	}
	for n, p := range payloads {
		if err = write(members[n], p); err != nil {
			return err
		}
	}
	return zw.Close()
}

// encoding/json matches struct fields using unicode simple case folding,
// including aliases such as long-s and kelvin sign, not only ASCII casing.
func foldJSONKey(key string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, key)
}

// rejectDuplicateKeys also caps nesting before typed decoding. the standard
// decoder otherwise silently accepts ambiguous duplicate object keys.
func rejectDuplicateKeys(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("incident: invalid UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	arrayentries := 0
	containers := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("incident: JSON nesting limit exceeded")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		containers++
		if containers > 2*MaxEvidenceRecords {
			return fmt.Errorf("incident: JSON container limit exceeded")
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				keyname := foldJSONKey(name)
				if !ok || seen[keyname] {
					return fmt.Errorf("incident: duplicate/invalid JSON key")
				}
				seen[keyname] = true
				if len(seen) > 256 {
					return fmt.Errorf("incident: JSON object field limit exceeded")
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			entries := 0
			for d.More() {
				entries++
				arrayentries++
				if arrayentries > MaxEvidenceRecords || entries > MaxEvents || (depth == 0 && entries > MaxSnapshots) {
					return fmt.Errorf("incident: JSON record limit exceeded")
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("incident: unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("incident: trailing JSON content")
	}
	return nil
}
func decodeJSON(data []byte, dst any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("incident: trailing JSON content")
	}
	return nil
}
func ReadFile(path string) (*Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("incident: bundle must be a regular file")
	}
	return Read(f, st.Size())
}

// read treats ZIP input as hostile: compressed and expanded bounds, fixed
// members, no duplicates/symlinks/encryption, explicit versions, CRC + SHA-256.
// checksums detect corruption, not malicious rewriting/authenticity.
func Read(r io.ReaderAt, size int64) (*Bundle, error) {
	if size < 0 || size > maxArchiveBytes {
		return nil, fmt.Errorf("incident: archive size exceeds budget")
	}
	// V1 has exactly five entries and never needs ZIP64. check the end
	// record before archive/zip allocates one file object per hostile entry.
	if size < 22 {
		return nil, fmt.Errorf("incident: truncated archive")
	}
	end := make([]byte, min(size, 65557))
	if _, err := r.ReadAt(end, size-int64(len(end))); err != nil {
		return nil, err
	}
	pos := bytes.LastIndex(end, []byte{'P', 'K', 5, 6})
	if pos < 0 || pos+22 > len(end) || pos+22+int(binary.LittleEndian.Uint16(end[pos+20:])) != len(end) {
		return nil, fmt.Errorf("incident: missing ZIP end record")
	}
	e := end[pos:]
	if binary.LittleEndian.Uint16(e[4:]) != 0 || binary.LittleEndian.Uint16(e[6:]) != 0 || binary.LittleEndian.Uint16(e[8:]) != 5 || binary.LittleEndian.Uint16(e[10:]) != 5 {
		return nil, fmt.Errorf("incident: unsupported ZIP member count/layout")
	}
	centralsize := int64(binary.LittleEndian.Uint32(e[12:]))
	centraloffset := int64(binary.LittleEndian.Uint32(e[16:]))
	if centralsize > 65536 || centraloffset+centralsize != size-int64(len(end))+int64(pos) {
		return nil, fmt.Errorf("incident: unsupported ZIP central directory")
	}
	central := make([]byte, centralsize)
	if _, err := r.ReadAt(central, centraloffset); err != nil {
		return nil, err
	}
	for range 5 {
		if len(central) < 46 || !bytes.Equal(central[:4], []byte{'P', 'K', 1, 2}) {
			return nil, fmt.Errorf("incident: malformed ZIP directory")
		}
		if binary.LittleEndian.Uint32(central[20:]) == ^uint32(0) || binary.LittleEndian.Uint32(central[24:]) == ^uint32(0) || binary.LittleEndian.Uint32(central[42:]) == ^uint32(0) || binary.LittleEndian.Uint16(central[34:]) != 0 {
			return nil, fmt.Errorf("incident: ZIP64/multi-disk members are unsupported")
		}
		entrysize := 46 + int(binary.LittleEndian.Uint16(central[28:])) + int(binary.LittleEndian.Uint16(central[30:])) + int(binary.LittleEndian.Uint16(central[32:]))
		if entrysize > len(central) {
			return nil, fmt.Errorf("incident: truncated ZIP directory")
		}
		extraat := 46 + int(binary.LittleEndian.Uint16(central[28:]))
		extraend := extraat + int(binary.LittleEndian.Uint16(central[30:]))
		for extra := central[extraat:extraend]; len(extra) > 0; {
			if len(extra) < 4 {
				return nil, fmt.Errorf("incident: malformed ZIP extra data")
			}
			length := int(binary.LittleEndian.Uint16(extra[2:]))
			if binary.LittleEndian.Uint16(extra) == 1 || length > len(extra)-4 {
				return nil, fmt.Errorf("incident: unsupported/malformed ZIP extra data")
			}
			extra = extra[4+length:]
		}
		central = central[entrysize:]
	}
	if len(central) != 0 {
		return nil, fmt.Errorf("incident: extra ZIP directory entries")
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("incident: archive: %w", err)
	}
	if len(zr.File) != len(members)+1 {
		return nil, fmt.Errorf("incident: unexpected member count")
	}
	files := map[string]*zip.File{}
	allowed := map[string]bool{"manifest.json": true}
	for _, name := range members {
		allowed[name] = true
	}
	var declared uint64
	for _, f := range zr.File {
		if !allowed[f.Name] || files[f.Name] != nil || !f.Mode().IsRegular() || f.Flags&1 != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) {
			return nil, fmt.Errorf("incident: unsafe or duplicate archive member %q", f.Name)
		}
		limit := uint64(MaxPayloadBytes)
		if f.Name == "manifest.json" {
			limit = 64 << 10
		}
		if f.UncompressedSize64 > limit || f.UncompressedSize64 > uint64(MaxPayloadBytes)+65536-declared {
			return nil, fmt.Errorf("incident: expanded size exceeds budget")
		}
		declared += f.UncompressedSize64
		files[f.Name] = f
	}
	read := func(name string, limit int64) ([]byte, error) {
		f := files[name]
		if f == nil {
			return nil, fmt.Errorf("incident: missing member %s", name)
		}
		stream, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		raw, err := io.ReadAll(io.LimitReader(stream, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(raw)) > limit || uint64(len(raw)) != f.UncompressedSize64 {
			return nil, fmt.Errorf("incident: expanded member size mismatch")
		}
		return raw, nil
	}
	raw, err := read("manifest.json", 64<<10)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err = decodeJSON(raw, &m); err != nil {
		return nil, fmt.Errorf("incident: manifest: %w", err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported Runopsy bundle schema: %d", m.SchemaVersion)
	}
	if m.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("unsupported Runopsy bundle format version: %d", m.FormatVersion)
	}
	if m.SnapshotEncoding != SnapshotEncoding {
		return nil, fmt.Errorf("unsupported Runopsy snapshot encoding: %q", m.SnapshotEncoding)
	}
	if m.Format != "runopsy" || len(m.Files) != len(members) {
		return nil, fmt.Errorf("incident: unsupported format or encoding")
	}
	payload := map[string][]byte{}
	var payloadSize int64
	for _, name := range members {
		sum, ok := m.Files[name]
		if !ok || sum.Size < 0 || sum.Size > MaxPayloadBytes {
			return nil, fmt.Errorf("incident: missing/invalid digest %s", name)
		}
		payloadSize += sum.Size
		if payloadSize > MaxPayloadBytes {
			return nil, fmt.Errorf("incident: expanded payload exceeds budget")
		}
		data, err := read(name, sum.Size)
		if err != nil {
			return nil, fmt.Errorf("incident: %s: %w", name, err)
		}
		if digest(data) != sum {
			return nil, fmt.Errorf("incident: %s checksum mismatch", name)
		}
		payload[name] = data
	}
	var i Incident
	if err = decodeJSON(payload["metadata.json"], &i); err != nil {
		return nil, err
	}
	if len(i.Snapshots) != 0 || len(i.Events) != 0 || i.Privacy != (PrivacyReport{}) {
		return nil, fmt.Errorf("incident: duplicate component data in metadata")
	}
	if err = decodeJSON(payload["snapshots.json"], &i.Snapshots); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(payload["events.jsonl"]))
	d.DisallowUnknownFields()
	for {
		var raw json.RawMessage
		err = d.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("incident: events: %w", err)
		}
		var e Event
		if err = decodeJSON(raw, &e); err != nil {
			return nil, err
		}
		i.Events = append(i.Events, e)
		if len(i.Events) > MaxEvents {
			return nil, fmt.Errorf("incident: too many events")
		}
	}
	if err = decodeJSON(payload["privacy.json"], &i.Privacy); err != nil {
		return nil, err
	}
	if err = Validate(&i); err != nil {
		return nil, err
	}
	if m.IncidentID != i.ID || !m.CreatedAt.Equal(i.CreatedAt) || m.SchemaVersion != i.SchemaVersion || m.AgentVersion != i.Metadata.AgentVersion || m.Platform != i.Metadata.Host.OS || m.Architecture != i.Metadata.Host.Architecture {
		return nil, fmt.Errorf("incident: manifest metadata mismatch")
	}
	// A v1 privacy claim is verified by reapplying the policy and comparing the
	// result, not trusted just because privacy.json says no secrets are present.
	// the redactor stamps the current AgentVersion as a normalizing step, so the
	// comparison is made against the stored payload with that same neutral stamp
	// applied: an older but well-formed bundle still reads (golden compatibility),
	// while any payload the policy would rewrite fails here. the manifest check
	// above already ties metadata.AgentVersion to the signed manifest.
	normalized, err := clone(&i)
	if err != nil {
		return nil, err
	}
	normalized.Metadata.AgentVersion = AgentVersion
	clean, err := clone(normalized)
	if err != nil {
		return nil, err
	}
	if err = (ConservativeRedactor{}).RedactIncident(clean); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(clean, normalized) {
		return nil, fmt.Errorf("incident: payload violates declared privacy policy")
	}
	components := make(map[string][]byte, len(payload)+1)
	components["manifest.json"] = raw
	for name, data := range payload {
		components[name] = data
	}
	return &Bundle{Manifest: m, Incident: &i, Files: components}, nil
}

// extract validates the complete artifact before creating an output directory,
// then writes only the fixed v1 component names with private, exclusive files.
// existing destination paths are never replaced.
func Extract(source, destination string) (err error) {
	bundle, err := ReadFile(source)
	if err != nil {
		return err
	}
	if destination == "" {
		return fmt.Errorf("incident: empty extraction directory")
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return fmt.Errorf("incident: create extraction directory: %w", err)
	}
	root, openerr := os.OpenRoot(destination)
	if openerr != nil {
		_ = os.Remove(destination)
		return openerr
	}
	defer root.Close()
	var created []string
	defer func() {
		if err != nil {
			for _, name := range created {
				_ = root.Remove(name)
			}
			// never recursively remove unrelated files another local actor
			// might have placed in an extraction directory during a failure.
			_ = os.Remove(destination)
		}
	}()
	for _, name := range append([]string{"manifest.json"}, members...) {
		data, ok := bundle.Files[name]
		if !ok {
			return fmt.Errorf("incident: missing verified component %s", name)
		}
		f, createerr := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createerr != nil {
			return createerr
		}
		created = append(created, name)
		n, writeerr := f.Write(data)
		if writeerr == nil && n != len(data) {
			writeerr = io.ErrShortWrite
		}
		if writeerr == nil {
			writeerr = f.Sync()
		}
		closeerr := f.Close()
		if writeerr != nil {
			return writeerr
		}
		if closeerr != nil {
			return closeerr
		}
	}
	return nil
}
