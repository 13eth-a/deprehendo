// open file-descriptor counting for watched processes. FD exhaustion is a
// real long-running-daemon failure mode, so the recorder counts descriptors
// for the processes the operator explicitly watches.
package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// CountOpenFDs returns how many file descriptors pid currently has open.
// linux scans /proc/<pid>/fd; other platforms report not-implemented. the
// count is a best-effort point-in-time number: descriptors can open or close
// during the scan, which is expected and not an error.
func CountOpenFDs(pid int) (int, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("platform: fd counting not implemented on %s", runtime.GOOS)
	}
	return CountOpenFDsAt(DefaultProcRoot, pid)
}

// CountOpenFDsAt is CountOpenFDs with an injectable /proc-like root so the
// directory walk can be tested against fixture trees on any OS.
func CountOpenFDsAt(root string, pid int) (int, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("platform: fd count pid must be positive, got %d", pid)
	}
	fddir := filepath.Join(root, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fddir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("platform: fd count for pid %d: process gone or inaccessible: %w", pid, err)
		}
		return 0, fmt.Errorf("platform: fd count for pid %d: %w", pid, err)
	}
	return len(entries), nil
}

// CountOpenFDsFor binds descriptor counts to the sampled linux identity.
func CountOpenFDsFor(process Process) (int, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("platform: fd counting not implemented on %s", runtime.GOOS)
	}
	return countOpenFDsForAt(DefaultProcRoot, process)
}

func countOpenFDsForAt(root string, process Process) (int, error) {
	before, err := ReadProcessAt(root, process.PID)
	if err != nil {
		return 0, err
	}
	if before.StartTicks != process.StartTicks {
		return 0, fmt.Errorf("platform: pid %d changed identity before FD count", process.PID)
	}
	count, err := CountOpenFDsAt(root, process.PID)
	if err != nil {
		return 0, err
	}
	after, err := ReadProcessAt(root, process.PID)
	if err != nil {
		return 0, err
	}
	if after.StartTicks != process.StartTicks {
		return 0, fmt.Errorf("platform: pid %d changed identity during FD count", process.PID)
	}
	return count, nil
}
