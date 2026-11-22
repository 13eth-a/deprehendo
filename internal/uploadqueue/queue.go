// package uploadqueue is the phase 7 local upload queue (7.47–7.49): a
// completed incident is persisted on disk first, then queued here and sent to
// runopsy cloud with bounded exponential backoff.
//
// the queue is a single small JSON file owned by one process at a time. it is
// deliberately not a job system: three states, one retry policy, a hard
// attempt cap, and no way for a cloud failure to touch the bundle.
//
// Offline-first invariant (7.49): enqueue only records a path that already
// exists, drain never rewrites or deletes a bundle, and an unreachable cloud
// leaves the entry pending with a later NextAttempt. recording, diagnosis and
// local analysis do not consult this package at all.
package uploadqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// state is the lifecycle of one queued bundle.
type State string

const (
	// pending is queued and not yet uploaded: it is due at NextAttempt.
	Pending State = "pending"
	// uploaded is terminal success; the URL is the incident page.
	Uploaded State = "uploaded"
	// failed is terminal: the policy's attempt budget is spent, the bundle is
	// gone, or the server refused it for good. A manual retry resets it.
	Failed State = "failed"
)

// entry is one queued bundle.
type Entry struct {
	Path        string    `json:"path"`
	State       State     `json:"state"`
	Attempts    int       `json:"attempts,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
	URL         string    `json:"url,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// policy bounds retries (7.48): never an infinite loop consuming resources.
type Policy struct {
	// MaxAttempts is the total number of attempts before an entry is Failed.
	MaxAttempts int
	// BaseDelay is the delay after the first failure; each further failure
	// doubles it.
	BaseDelay time.Duration
	// MaxDelay caps the doubling.
	MaxDelay time.Duration
}

// DefaultPolicy is five attempts at 30 s, 1 m, 2 m, 4 m: about seven minutes of
// retrying, then the incident stays local and the queue shows why.
func DefaultPolicy() Policy {
	return Policy{MaxAttempts: 5, BaseDelay: 30 * time.Second, MaxDelay: time.Hour}
}

// delay is the wait after the given failed attempt (1-based). it doubles from
// BaseDelay and is capped by MaxDelay, so the series is bounded even if
// MaxAttempts were raised.
func (p Policy) Delay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := p.BaseDelay
	if base <= 0 {
		base = DefaultPolicy().BaseDelay
	}
	delay := base
	for i := 1; i < attempt; i++ {
		if delay >= p.MaxDelay && p.MaxDelay > 0 {
			return p.MaxDelay
		}
		delay *= 2
	}
	if p.MaxDelay > 0 && delay > p.MaxDelay {
		delay = p.MaxDelay
	}
	return delay
}

// uploader sends one bundle and returns the incident URL. A duplicate upload
// is success: the server returns the existing incident (7.30).
type Uploader interface {
	Upload(ctx context.Context, bundlePath string) (string, error)
}

// summary counts the queue by state.
type Summary struct {
	Pending  int `json:"pending"`
	Uploaded int `json:"uploaded"`
	Failed   int `json:"failed"`
}

// result reports one Drain.
type Result struct {
	Attempted int `json:"attempted"`
	Uploaded  int `json:"uploaded"`
	Failed    int `json:"failed"`   // terminal failures this pass
	Retrying  int `json:"retrying"` // failed this pass, will be retried later
}

// maxEntries bounds the queue file. pending entries are never dropped; a full
// queue refuses new work instead of silently forgetting an incident.
const maxEntries = 500

// fileState is the on-disk format. the version is checked, never guessed: a
// queue written by a newer build is an error, not a silent reset.
type fileState struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

const fileVersion = 1

// queue is one queue file. methods are safe for concurrent use by this
// process; two processes must not share a path (the agent owns its queue).
type Queue struct {
	path     string
	policy   Policy
	mu       sync.Mutex
	entries  []Entry
	maxItems int

	// now is the clock; tests replace it. never nil after Open.
	Now func() time.Time
}

// open reads the queue at path, creating an empty one when the file is
// absent. the directory is created at 0700 and the file written at 0600 on
// the first save (the queue names local bundle paths).
func Open(path string, policy Policy) (*Queue, error) {
	if path == "" {
		return nil, errors.New("uploadqueue: a queue path is required")
	}
	if policy.MaxAttempts <= 0 {
		policy = DefaultPolicy()
	}
	if policy.BaseDelay <= 0 {
		policy.BaseDelay = DefaultPolicy().BaseDelay
	}
	if policy.MaxDelay <= 0 {
		policy.MaxDelay = DefaultPolicy().MaxDelay
	}
	q := &Queue{path: path, policy: policy, maxItems: maxEntries, Now: time.Now}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return q, nil
	case err != nil:
		return nil, fmt.Errorf("uploadqueue: read %s: %w", path, err)
	}
	var st fileState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("uploadqueue: %s is not valid JSON: %w", path, err)
	}
	if st.Version != fileVersion {
		return nil, fmt.Errorf("uploadqueue: %s has version %d, this build writes %d", path, st.Version, fileVersion)
	}
	q.entries = st.Entries
	return q, nil
}

// path is the queue file.
func (q *Queue) Path() string { return q.path }

// policy is the retry policy in force.
func (q *Queue) Policy() Policy { return q.policy }

// entries is a copy of the queue, oldest first.
func (q *Queue) Entries() []Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Entry, len(q.entries))
	copy(out, q.entries)
	return out
}

// summary counts the queue by state.
func (q *Queue) Summary() Summary {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.summaryLocked()
}

func (q *Queue) summaryLocked() Summary {
	var s Summary
	for _, e := range q.entries {
		switch e.State {
		case Pending:
			s.Pending++
		case Uploaded:
			s.Uploaded++
		case Failed:
			s.Failed++
		}
	}
	return s
}

// enqueue records one saved bundle. added is false when the same path is
// already queued (a repeat trigger over one file must not multiply attempts).
// A previously failed entry is reset: the caller is explicitly asking again.
func (q *Queue) Enqueue(bundlePath string) (Entry, bool, error) {
	abs, err := filepath.Abs(bundlePath)
	if err != nil {
		return Entry{}, false, fmt.Errorf("uploadqueue: resolve %s: %w", bundlePath, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Entry{}, false, fmt.Errorf("uploadqueue: %s is not readable: %w", bundlePath, err)
	}
	if info.IsDir() {
		return Entry{}, false, fmt.Errorf("uploadqueue: %s is a directory", bundlePath)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.Now()
	for i := range q.entries {
		if q.entries[i].Path != abs {
			continue
		}
		switch q.entries[i].State {
		case Uploaded:
			return q.entries[i], false, nil
		case Pending:
			return q.entries[i], false, nil
		case Failed:
			q.entries[i].State = Pending
			q.entries[i].Attempts = 0
			q.entries[i].NextAttempt = now
			q.entries[i].LastError = ""
			q.entries[i].UpdatedAt = now
			return q.entries[i], true, q.saveLocked()
		}
	}
	if len(q.entries) >= q.maxItems {
		return Entry{}, false, fmt.Errorf("uploadqueue: %s already holds %d entries; drain or clear it first", q.path, len(q.entries))
	}
	entry := Entry{Path: abs, State: Pending, NextAttempt: now, UpdatedAt: now}
	q.entries = append(q.entries, entry)
	return entry, true, q.saveLocked()
}

// drain attempts every pending entry that is due, one at a time, and saves
// after each attempt so a crash cannot repeat a completed upload or forget an
// attempt. cancellation stops before the next attempt and leaves the rest
// pending.
func (q *Queue) Drain(ctx context.Context, up Uploader) (Result, error) {
	if up == nil {
		return Result{}, errors.New("uploadqueue: Drain needs an uploader")
	}
	q.mu.Lock()
	now := q.Now()
	var due []string
	for _, e := range q.entries {
		if e.State == Pending && !now.Before(e.NextAttempt) {
			due = append(due, e.Path)
		}
	}
	q.mu.Unlock()

	var res Result
	var saveErr error
	for _, path := range due {
		if err := ctx.Err(); err != nil {
			break
		}
		res.Attempted++
		// the bundle is the evidence: a path that no longer resolves is a
		// terminal failure with a reason, never an upload of something else.
		if _, err := os.Stat(path); err != nil {
			terminal := q.recordFailure(path, fmt.Errorf("bundle is not readable: %w", err), true)
			if terminal {
				res.Failed++
			} else {
				res.Retrying++
			}
			continue
		}
		url, err := up.Upload(ctx, path)
		if err != nil {
			terminal := q.recordFailure(path, err, false)
			if terminal {
				res.Failed++
			} else {
				res.Retrying++
			}
			continue
		}
		q.recordSuccess(path, url)
		res.Uploaded++
	}
	if err := q.save(); err != nil {
		saveErr = err
	}
	return res, saveErr
}

// retry puts every failed entry back to pending with a fresh attempt budget
// (7.48's manual escape hatch). it returns how many were reset.
func (q *Queue) Retry() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.Now()
	count := 0
	for i := range q.entries {
		if q.entries[i].State != Failed {
			continue
		}
		q.entries[i].State = Pending
		q.entries[i].Attempts = 0
		q.entries[i].NextAttempt = now
		q.entries[i].LastError = ""
		q.entries[i].UpdatedAt = now
		count++
	}
	if count == 0 {
		return 0, nil
	}
	return count, q.saveLocked()
}

// recordSuccess marks one entry uploaded. A missing entry (edited file) is
// ignored rather than resurrected.
func (q *Queue) recordSuccess(path, url string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.Now()
	for i := range q.entries {
		if q.entries[i].Path != path {
			continue
		}
		q.entries[i].State = Uploaded
		q.entries[i].URL = url
		q.entries[i].LastError = ""
		q.entries[i].NextAttempt = time.Time{}
		q.entries[i].UpdatedAt = now
		return
	}
}

// recordFailure charges one attempt and reports whether the entry is now
// terminal. terminal=true also covers "the bundle is gone", which retrying
// cannot fix.
func (q *Queue) recordFailure(path string, cause error, gone bool) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.Now()
	for i := range q.entries {
		if q.entries[i].Path != path {
			continue
		}
		e := &q.entries[i]
		e.Attempts++
		e.LastError = clampError(cause)
		e.UpdatedAt = now
		if gone || e.Attempts >= q.policy.MaxAttempts {
			e.State = Failed
			e.NextAttempt = time.Time{}
			return true
		}
		e.State = Pending
		e.NextAttempt = now.Add(q.policy.Delay(e.Attempts))
		return false
	}
	return true
}

// save writes the queue atomically at 0600.
func (q *Queue) save() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.saveLocked()
}

func (q *Queue) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(q.path), 0o700); err != nil {
		return fmt.Errorf("uploadqueue: create directory: %w", err)
	}
	data, err := json.MarshalIndent(fileState{Version: fileVersion, Entries: q.entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("uploadqueue: encode: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(q.path), ".queue-*.json")
	if err != nil {
		return fmt.Errorf("uploadqueue: create temporary file: %w", err)
	}
	tmpname := tmp.Name()
	defer os.Remove(tmpname)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("uploadqueue: restrict permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("uploadqueue: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("uploadqueue: close: %w", err)
	}
	if err := os.Rename(tmpname, q.path); err != nil {
		return fmt.Errorf("uploadqueue: install: %w", err)
	}
	return nil
}

// clampError keeps a stored failure message short and single-line: the queue
// file is printed by the CLI and read by humans.
func clampError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	const max = 300
	if len(s) > max {
		s = s[:max] + "…"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}
