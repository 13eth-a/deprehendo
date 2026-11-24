package simulator

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// the parent/child scenarios spawn real children of ./cmd/deprehendo-sim so the
// process table shows a genuine parent/worker hierarchy. under `go test` the
// running process is the test binary, which does not accept scenario
// arguments, so TestMain builds the real sim binary once and every test that
// spawns children routes spawn() through it via simBinaryOverride.
var simBinaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "deprehendo-sim-build")
	if err != nil {
		fmt.Fprintln(os.Stderr, "test setup:", err)
		os.Exit(1)
	}
	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "test setup:", err)
		os.Exit(1)
	}
	buildcmd := exec.Command("go", "build", "-o", filepath.Join(dir, "deprehendo-sim"), "./cmd/deprehendo-sim")
	buildcmd.Dir = root
	if out, err := buildcmd.CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, "go build ./cmd/deprehendo-sim:", err, string(out))
		os.Exit(1)
	}
	simBinaryPath = filepath.Join(dir, "deprehendo-sim")

	code := m.Run()
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, "remove test binary directory:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// moduleRoot walks up from the test's working directory to the directory
// containing go.mod.
func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", wd)
		}
		dir = parent
	}
}

// simBinary returns the path of the test-built deprehendo-sim binary and points
// SimBinary at it for the current test.
func simBinary(t *testing.T) string {
	t.Helper()
	if simBinaryPath == "" {
		t.Skip("sim binary not built")
	}
	prev := simBinaryOverride
	simBinaryOverride = simBinaryPath
	t.Cleanup(func() { simBinaryOverride = prev })
	return simBinaryPath
}
