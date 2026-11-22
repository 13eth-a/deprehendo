package incident

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var bundleName = regexp.MustCompile(`^inc_[a-f0-9]{32}\.runopsy$`)

// DefaultDir is the per-user incident directory. the directory itself is
// created by EnsureDir with mode 0700; merely computing the path has no side
// effects.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("incident: locate home directory: %w", err)
	}
	return filepath.Join(home, ".runopsy", "incidents"), nil
}

// EnsureDir creates missing parents with mode 0700 and rejects an existing
// directory that is readable by other users. FileWriter relies on this policy.
func EnsureDir(path string) error {
	if path == "" {
		return fmt.Errorf("incident: empty incident directory")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("incident: create incident directory: %w", err)
	}
	return privateDirectory(path)
}

// RetentionPolicy bounds the local artifact directory. A zero field disables
// that limit; both zero disables pruning entirely. deletion is filesystem
// enumeration only. no index or database is maintained.
type RetentionPolicy struct {
	MaxIncidents int
	MaxAge       time.Duration
}

func (p RetentionPolicy) Validate() error {
	if p.MaxIncidents < 0 || p.MaxAge < 0 {
		return fmt.Errorf("incident: negative retention limit")
	}
	return nil
}

func (p RetentionPolicy) enabled() bool { return p.MaxIncidents > 0 || p.MaxAge > 0 }

// IncidentFile describes one complete retained artifact.
type IncidentFile struct {
	Path    string
	ID      string
	Trigger string
	Size    int64
	ModTime time.Time
}

// list returns validated complete bundles newest first. invalid incident-named
// files are errors rather than entries that look like trustworthy evidence.
func List(directory string) ([]IncidentFile, error) {
	if err := privateDirectory(directory); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make([]IncidentFile, 0, len(entries))
	for _, entry := range entries {
		if !bundleName.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		bundle, err := ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("incident: validate %s: %w", entry.Name(), err)
		}
		if entry.Name() != bundle.Incident.ID+".runopsy" {
			return nil, fmt.Errorf("incident: filename does not match incident identity: %s", entry.Name())
		}
		files = append(files, IncidentFile{Path: path, ID: bundle.Incident.ID, Trigger: bundle.Incident.Trigger.Type, Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(files, func(a, b int) bool {
		if !files[a].ModTime.Equal(files[b].ModTime) {
			return files[a].ModTime.After(files[b].ModTime)
		}
		return files[a].ID > files[b].ID
	})
	return files, nil
}

// PruneResult lists what a prune removed, oldest first.
type PruneResult struct {
	Removed []IncidentFile
}

// prune removes complete bundles beyond the policy, oldest first. only regular
// files named like a published bundle are considered; temp files, symlinks and
// unrelated files are ignored. removal errors are returned together after the
// remaining candidates have been processed, so one stuck file does not stop
// routine cleanup. concurrency: call it while no writer for the same directory
// is publishing, or accept that a just-written bundle is treated like any
// other complete artifact.
func Prune(directory string, policy RetentionPolicy, now time.Time) (PruneResult, error) {
	var result PruneResult
	if err := policy.Validate(); err != nil {
		return result, err
	}
	if !policy.enabled() {
		return result, nil
	}
	if err := privateDirectory(directory); err != nil {
		return result, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return result, err
	}
	files := make([]IncidentFile, 0, len(entries))
	for _, e := range entries {
		if !bundleName.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return result, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		files = append(files, IncidentFile{Path: filepath.Join(directory, e.Name()), ID: strings.TrimSuffix(e.Name(), ".runopsy"), Size: info.Size(), ModTime: info.ModTime()})
	}
	// newest first; name order makes equal timestamps deterministic.
	sort.Slice(files, func(a, b int) bool {
		if !files[a].ModTime.Equal(files[b].ModTime) {
			return files[a].ModTime.After(files[b].ModTime)
		}
		return files[a].Path > files[b].Path
	})
	var failures []error
	for n := len(files) - 1; n >= 0; n-- {
		file := files[n]
		toomany := policy.MaxIncidents > 0 && n >= policy.MaxIncidents
		tooold := policy.MaxAge > 0 && now.Sub(file.ModTime) > policy.MaxAge
		if !toomany && !tooold {
			continue
		}
		if err := os.Remove(file.Path); err != nil {
			failures = append(failures, fmt.Errorf("incident: remove %s: %w", filepath.Base(file.Path), err))
			continue
		}
		result.Removed = append(result.Removed, file)
	}
	sort.Slice(result.Removed, func(a, b int) bool {
		if !result.Removed[a].ModTime.Equal(result.Removed[b].ModTime) {
			return result.Removed[a].ModTime.Before(result.Removed[b].ModTime)
		}
		return result.Removed[a].Path < result.Removed[b].Path
	})
	if len(result.Removed) > 0 {
		dir, err := os.Open(directory)
		if err != nil {
			failures = append(failures, err)
		} else {
			if err = dir.Sync(); err != nil {
				failures = append(failures, fmt.Errorf("incident: sync retention directory: %w", err))
			}
			if err = dir.Close(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return result, errors.Join(failures...)
}
