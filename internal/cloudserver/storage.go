// cloudserver storage half (checklist 7.7): an immutable object store whose
// keys follow docs/cloud/contract.md §6 exactly, and the signed POST policy
// that uploads bytes into it without the API token ever appearing on the
// storage request.
//
// invariants:
//
//   - A key is written once. put refuses any second write to the same key,
//     so the stored original is immutable by construction (L4).
//   - only keys matching the §6 shapes are accepted; anything else is a
//     programming error the server never makes.
//   - the policy binds the object key, the expected SHA-256 and a short
//     lifetime together under an HMAC; the storage handler accepts nothing
//     the policies did not authorize (upload-api.md §1: "the server must
//     reject a sha256 it did not issue a policy for at complete time").
package cloudserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"runopsy/internal/incident"
)

// store is the storage abstraction (7.7). the MVP is a local directory; an
// S3-compatible implementation can sit behind the same methods.
type Store interface {
	// put stores the bytes under key and returns their length. A second put
	// to the same key must fail: stored originals are immutable.
	Put(ctx context.Context, key string, data []byte) (int64, error)
	// get returns the stored bytes. ErrNoSuchObject marks a missing key.
	Get(ctx context.Context, key string) ([]byte, error)
	// delete removes the object; deleting a missing object is not an error.
	Delete(ctx context.Context, key string) error
}

// ErrNoSuchObject is get's answer for a key that does not exist.
var ErrNoSuchObject = errors.New("cloudserver: no object under that key")

// localStore is one directory tree under root. keys are path-shaped; every
// path segment must be a safe base name, because a hostile key that escapes
// the tree would be a filesystem write elsewhere.
type localStore struct{ root string }

// NewLocalStore creates the storage root. caller owns its durability
// (contract §9: not part of this MVP).
func NewLocalStore(root string) (*localStore, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("cloudserver: storage root: %w", err)
	}
	return &localStore{root: root}, nil
}

// safeKey restricts keys to the shapes this server writes: lowercase path
// segments of [a-z0-9_-], a leading dot refused (no dotfiles), no traversal,
// and a final segment that names a file. the exact bundle-key regex is
// additionally enforced at the storage POST (policyRE).
func safeKey(key string) bool {
	if strings.Contains(key, "..") || strings.ContainsAny(key, " \t\n\r\\") ||
		strings.HasPrefix(key, "/") || len(key) > 300 {
		return false
	}
	segments := strings.Split(key, "/")
	for _, seg := range segments {
		if seg == "" || strings.HasPrefix(seg, ".") {
			return false
		}
		for _, r := range seg {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r == '_', r == '-', r == '.':
			default:
				return false
			}
		}
	}
	return strings.Contains(segments[len(segments)-1], ".")
}

// objectPath maps a key to a file path inside root, refusing escapes.
func (s *localStore) objectPath(key string) (string, error) {
	if !safeKey(key) {
		return "", fmt.Errorf("cloudserver: unsupported storage key %q", key)
	}
	return filepath.Join(s.root, filepath.FromSlash(key)), nil
}

// put stores data atomically: a temporary file in the object's own directory,
// exclusively linked into place, so a key exists only when no partial state
// does and no second put can succeed.
func (s *localStore) Put(_ context.Context, key string, data []byte) (int64, error) {
	path, err := s.objectPath(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, fmt.Errorf("cloudserver: storage directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".put-*")
	if err != nil {
		return 0, fmt.Errorf("cloudserver: storage temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("cloudserver: storage write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("cloudserver: storage sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("cloudserver: storage write: %w", err)
	}
	// O_EXCL link: the second writer loses, and an existing object was
	// never mutated.
	if err := os.Link(tmp.Name(), path); err != nil {
		if os.IsExist(err) {
			return 0, fmt.Errorf("cloudserver: object %q is immutable and already exists", key)
		}
		return 0, fmt.Errorf("cloudserver: storage link: %w", err)
	}
	return int64(len(data)), nil
}

// get reads the whole object (bundle or analysis document: both are bounded
// by the §5.3 archive budget.
func (s *localStore) Get(_ context.Context, key string) ([]byte, error) {
	path, err := s.objectPath(key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSuchObject
	}
	if err != nil {
		return nil, fmt.Errorf("cloudserver: storage read: %w", err)
	}
	return data, nil
}

func (s *localStore) Delete(_ context.Context, key string) error {
	path, err := s.objectPath(key)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cloudserver: storage delete: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// signed POST policy
// ---------------------------------------------------------------------------

// policyTTL bounds how long a minted policy is usable; after that, the
// storage POST fails verification.
const policyTTL = 15 * time.Minute

// policyPayload is one minted policy. the string parts are sorted into the
// signature so a tampered field cannot ride under another field's signature.
type policyPayload struct {
	Key      string `json:"key"`
	Org      string `json:"org"`
	SHA256   string `json:"sha256"`
	MinBytes int64  `json:"min_bytes"`
	MaxBytes int64  `json:"max_bytes"`
	NotAfter int64  `json:"not_after"`
}

// policyRE is the §6 bundle-key shape, enforced end to end: the create
// response and the storage handler must not disagree about what a key looks
// like.
var policyRE = regexp.MustCompile(`^orgs/[a-z0-9_-]+/bundles/[0-9a-f]{64}\.runopsy$`)

// signField and the separator cannot appear inside base64 payload because its
// alphabet excludes them.
const policyFieldSeparator = "\n"

// signedPolicy renders the policy token: base64url payload, then the HMAC
// over that payload, separated by a byte base64 never produces.
func signedPolicy(p policyPayload, secret []byte) []byte {
	data, err := json.Marshal(p)
	if err != nil { // unreachable for value-shape structs
		return nil
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return []byte(payload + policyFieldSeparator + hex.EncodeToString(mac.Sum(nil)))
}

// parsePolicy undoes signedPolicy and verifies the signature and lifetime.
func parsePolicy(payload, policyField, signature string, secret []byte) (*policyPayload, error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return nil, errors.New("policy signature mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("policy payload is not decodable")
	}
	var p policyPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errors.New("policy payload is not valid JSON")
	}
	if p.Key != policyField {
		return nil, errors.New("policy key does not match the field")
	}
	if time.Now().Unix() > p.NotAfter {
		return nil, errors.New("policy has expired")
	}
	return &p, nil
}

// mintUploadPolicy issues the one policy a create needs (7.10): the object
// key derived from the org and digest, the §5.3 size bounds and a short lease.
func mintUploadPolicy(org, sha256hex string, secret []byte) (key string, fields map[string]string) {
	key = fmt.Sprintf("orgs/%s/bundles/%s.runopsy", org, sha256hex)
	payload := policyPayload{
		Key: key, Org: org, SHA256: sha256hex,
		MinBytes: 22, MaxBytes: incident.MaxArchiveSize,
		NotAfter: time.Now().Add(policyTTL).Unix(),
	}
	signed := signedPolicy(payload, secret)
	parts := strings.SplitN(string(signed), policyFieldSeparator, 2)
	return key, map[string]string{
		"key":             key,
		"policy":          parts[0],
		"x-amz-signature": parts[1],
	}
}

// maxUploadOverhead is what multipart framing may add beyond the file alone;
// it is composed with the policy's own budget before the request is read.
const maxUploadOverhead = 1 << 20

// maxUploadBodyBytes is the largest storage POST body worth parsing: one
// archive at the accepted on-disk budget plus framework overhead.
const maxUploadBodyBytes = incident.MaxArchiveSize + maxUploadOverhead

// maxPolicyFieldBytes bounds each non-file form field. A real policy token is
// a few hundred bytes; nothing legitimate comes close.
const maxPolicyFieldBytes = 4 << 10

// maxPolicyFields bounds how many non-file fields a storage POST may carry
// before its file part (the policy uses three).
const maxPolicyFields = 8

// storageRefuse answers a refused storage POST in plain text and counts it.
func (s *Server) storageRefuse(w http.ResponseWriter, status int, message string) {
	s.telemetry.recordStatus(status)
	http.Error(w, message, status)
}

// storagePost implements upload-api.md §2 for this server's own store: verify
// the policy, read exactly one file part within the size bounds, recompute
// the digest and store the object. no authorization header exists on this
// request, and none is needed.
//
// the request is unauthenticated until its policy verifies (7.60), so the
// body is read as a stream and never buffered past what is authorized: the
// whole body is capped at the archive budget, each policy field at a few KiB,
// and the file part is refused unless a valid policy arrived before it.
// every client sends the policy fields first (cloudclient.FieldOrder, then
// the file), so a policy-less body costs the server a few KiB, not 65 MiB of
// memory or temporary files.
func (s *Server) storagePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBodyBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		s.storageRefuse(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	fields := map[string]string{}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			s.storageRefuse(w, http.StatusBadRequest, "missing file part")
			return
		}
		if err != nil {
			s.storageRefuse(w, http.StatusBadRequest, "invalid multipart form")
			return
		}
		// parts are deliberately never close()d: Part.Close drains the rest
		// of the part, which would read a refused file (or an oversized
		// field) to its end. A refusal simply returns; NextPart skips the
		// remainder of a field that was fully read.
		name := part.FormName()
		if name == "file" {
			s.storeFilePart(w, r, part, fields)
			return
		}
		if _, dup := fields[name]; dup || len(fields) >= maxPolicyFields {
			s.storageRefuse(w, http.StatusBadRequest, "invalid multipart form")
			return
		}
		value, err := io.ReadAll(io.LimitReader(part, maxPolicyFieldBytes+1))
		if err != nil || len(value) > maxPolicyFieldBytes {
			s.storageRefuse(w, http.StatusBadRequest, "form field exceeds its size bound")
			return
		}
		fields[name] = string(value)
	}
}

// storeFilePart verifies the policy collected from the fields that preceded
// the file part, then reads the file within the policy's bounds and stores it.
func (s *Server) storeFilePart(w http.ResponseWriter, r *http.Request, file io.Reader, fields map[string]string) {
	p, err := parsePolicy(fields["policy"], fields["key"], fields["x-amz-signature"], s.secret)
	if err != nil {
		s.storageRefuse(w, http.StatusForbidden, "storage policy refused")
		return
	}
	if !policyRE.MatchString(p.Key) {
		s.storageRefuse(w, http.StatusForbidden, "object key does not meet the layout")
		return
	}
	if r.ContentLength > 0 && r.ContentLength > p.MaxBytes+maxUploadOverhead {
		s.storageRefuse(w, http.StatusRequestEntityTooLarge, "upload destination size exceeds the policy")
		return
	}
	// read one byte past the limit, so an oversized POST fails outright
	// rather than paging its way through memory.
	data, err := io.ReadAll(io.LimitReader(file, p.MaxBytes+1))
	if err != nil || int64(len(data)) > p.MaxBytes {
		s.storageRefuse(w, http.StatusRequestEntityTooLarge, "file part exceeds the policy's size bounds")
		return
	}
	if int64(len(data)) < p.MinBytes {
		s.storageRefuse(w, http.StatusBadRequest, "file part is below the policy's size bounds")
		return
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if digest != p.SHA256 {
		s.storageRefuse(w, http.StatusBadRequest, "digest does not match the policy")
		return
	}
	if _, err := s.storage.Put(r.Context(), p.Key, data); err != nil {
		if strings.Contains(err.Error(), "immutable") {
			// another request finished this exact upload. that is success;
			// the bytes are the same by digest comparison.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.telemetry.storageFailures.Add(1)
		s.telemetry.recordStatus(http.StatusInternalServerError)
		s.logf("storage put: %v", err)
		http.Error(w, "storage write failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// readFullRandom is the one random-number site in this file, named to make
// the audit line obvious.
func readFullRandom(b []byte) (int, error) { return rand.Read(b) }
