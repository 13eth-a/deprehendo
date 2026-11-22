package incident

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileWriter requires an existing private directory. Directory/list/retention
// policy belongs to the CLI integration. no write retries happen implicitly.
// temp files are unique, mode 0600 and reside on the destination filesystem.
type FileWriter struct {
	Directory string
	// uncompressed permits measurement of the exact same payload without Deflate.
	Uncompressed bool
	// before is a package-private fault/crash seam; production uses real syscalls.
	before func(string) error
}

func (w FileWriter) step(name string) error {
	if w.before != nil {
		return w.before(name)
	}
	return nil
}
func privateDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("incident: output directory must be private (0700)")
	}
	return nil
}

type contextWriter struct {
	ctx   context.Context
	dst   io.Writer
	left  int64
	fault func(string) error
}

func (w *contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.fault != nil {
		if err := w.fault("write"); err != nil {
			return 0, err
		}
	}
	if int64(len(p)) > w.left {
		return 0, fmt.Errorf("incident: archive byte budget exceeded")
	}
	n, err := w.dst.Write(p)
	w.left -= int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// write publishes with link(2) rather than overwriting rename: a collision
// must never destroy an existing incident. the link is atomic on the same
// filesystem. once published, a directory-sync failure returns path + error
// (durability uncertain), never removes the complete published artifact.
func (w FileWriter) Write(ctx context.Context, i *Incident) (path string, err error) {
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if i == nil || !validID.MatchString(i.ID) {
		return "", fmt.Errorf("incident: invalid incident id")
	}
	if err = privateDirectory(w.Directory); err != nil {
		return "", err
	}
	dir, err := os.Open(w.Directory)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err = w.step("create"); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(w.Directory, ".runopsy-*.tmp")
	if err != nil {
		return "", err
	}
	temp := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(temp) }()
	output := &contextWriter{ctx: ctx, dst: f, left: maxArchiveBytes, fault: w.before}
	if err = Encode(output, i, !w.Uncompressed); err != nil {
		return "", err
	}
	if err = w.step("sync-file"); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = w.step("close"); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = w.step("publish"); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	target := filepath.Join(w.Directory, i.ID+".runopsy")
	if err = os.Link(temp, target); err != nil {
		return "", err
	}
	path = target
	if err = os.Remove(temp); err != nil {
		return path, err
	}
	if err = w.step("sync-directory"); err != nil {
		return path, err
	}
	if err = dir.Sync(); err != nil {
		return path, err
	}
	return path, nil
}

// CleanupStaleTemps removes only regular writer-owned-name temp files older
// than cutoff. call exclusively before starting writers; it is not safe to
// prune an active writer. it never removes .runopsy artifacts or symlinks.
func CleanupStaleTemps(directory string, cutoff time.Time) (int, error) {
	if err := privateDirectory(directory); err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".runopsy-") || !strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return removed, err
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		if err = os.Remove(filepath.Join(directory, e.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
