package incident

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bundlePath(dir string, n int) string {
	return filepath.Join(dir, fmt.Sprintf("inc_%032x.deprehendo", n))
}

func writeBundleFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte("bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirCreatesPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "incidents")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatalf("mode = %v", info.Mode())
	}
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(open); err == nil {
		t.Fatal("accepted a directory readable by other users")
	}
	if err := EnsureDir(""); err == nil {
		t.Fatal("accepted empty directory")
	}
}

func TestDefaultDirIsPerUser(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	dir, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(home, ".deprehendo", "incidents") {
		t.Fatalf("DefaultDir = %q", dir)
	}
}

func TestPruneRetainsNewestCount(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 4; n++ {
		writeBundleFile(t, bundlePath(dir, n), time.Duration(4-n)*time.Minute)
	}
	result, err := Prune(dir, RetentionPolicy{MaxIncidents: 2}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 {
		t.Fatalf("removed %d, want 2", len(result.Removed))
	}
	for n := 0; n < 2; n++ {
		if _, err := os.Stat(bundlePath(dir, n)); !os.IsNotExist(err) {
			t.Errorf("old bundle %d survived: %v", n, err)
		}
	}
	for n := 2; n < 4; n++ {
		if _, err := os.Stat(bundlePath(dir, n)); err != nil {
			t.Errorf("new bundle %d missing: %v", n, err)
		}
	}
	if len(result.Removed) > 0 && !strings.HasSuffix(result.Removed[0].Path, fmt.Sprintf("inc_%032x.deprehendo", 0)) {
		t.Fatalf("removal order oldest first: %+v", result.Removed)
	}
}

func TestPruneMaxAge(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeBundleFile(t, bundlePath(dir, 1), 48*time.Hour)
	writeBundleFile(t, bundlePath(dir, 2), time.Hour)
	result, err := Prune(dir, RetentionPolicy{MaxAge: 24 * time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 1 || !strings.HasSuffix(result.Removed[0].Path, fmt.Sprintf("inc_%032x.deprehendo", 1)) {
		t.Fatalf("removed = %+v", result.Removed)
	}
	if _, err := os.Stat(bundlePath(dir, 2)); err != nil {
		t.Fatal(err)
	}
	// both limits may apply together: an old bundle beyond the count is removed
	// once, not twice.
	writeBundleFile(t, bundlePath(dir, 3), 72*time.Hour)
	result, err = Prune(dir, RetentionPolicy{MaxIncidents: 1, MaxAge: 24 * time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// only the 72h-old bundle is both beyond the count of one and older than
	// 24h; the recent bundle is retained.
	if len(result.Removed) != 1 {
		t.Fatalf("combined prune removed %+v", result.Removed)
	}
}

func TestPruneIgnoresUnrelatedFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeBundleFile(t, bundlePath(dir, 1), 2*time.Hour)
	writeBundleFile(t, bundlePath(dir, 2), time.Minute)
	unrelated := []string{
		filepath.Join(dir, "notes.txt"),
		filepath.Join(dir, "inc_NOTHEX.deprehendo"),
		filepath.Join(dir, "inc_00000000000000000000000000000001.deprehendo.tmp"),
		filepath.Join(dir, ".deprehendo-123.tmp"),
	}
	for _, path := range unrelated {
		writeBundleFile(t, path, 30*24*time.Hour)
	}
	if err := os.Mkdir(filepath.Join(dir, "inc_000000000000000000000000000000ff.deprehendo"), 0700); err != nil {
		t.Fatal(err)
	}
	old := bundlePath(dir, 3)
	writeBundleFile(t, old, 30*24*time.Hour)
	target := filepath.Join(dir, "notes.txt")
	link := filepath.Join(dir, fmt.Sprintf("inc_%032x.deprehendo", 4))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	result, err := Prune(dir, RetentionPolicy{MaxIncidents: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// three regular, correctly named bundles are candidates; the newest is kept
	// regardless of age because MaxAge is disabled. the symlink is not followed.
	if len(result.Removed) != 2 {
		t.Fatalf("removed = %+v", result.Removed)
	}
	for _, path := range append(unrelated, target, link) {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("prune removed unrelated %s: %v", filepath.Base(path), err)
		}
	}
}

func TestPrunePolicyValidationAndDisabled(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeBundleFile(t, bundlePath(dir, 1), 365*24*time.Hour)
	if _, err := Prune(dir, RetentionPolicy{MaxIncidents: -1}, time.Now()); err == nil {
		t.Fatal("accepted negative limit")
	}
	if _, err := Prune(dir, RetentionPolicy{MaxAge: -time.Second}, time.Now()); err == nil {
		t.Fatal("accepted negative age")
	}
	result, err := Prune(dir, RetentionPolicy{}, time.Now())
	if err != nil || len(result.Removed) != 0 {
		t.Fatalf("disabled policy = %+v, %v", result, err)
	}
	if _, err := Prune(filepath.Join(dir, "missing"), RetentionPolicy{MaxIncidents: 1}, time.Now()); err == nil {
		t.Fatal("accepted a missing directory")
	}
}
