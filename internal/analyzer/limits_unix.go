//go:build darwin || linux

package analyzer

import (
	"fmt"
	"syscall"
)

// child limits (contract §5.4.3), installed by the child at startup so the
// parent does not need fork-level control:
//
//	RLIMIT_CPU 70 s: one job cannot spin forever; measured: a 30 MB bundle
//	analyzes under it, RLIMIT_CPU 2 s kills it.
//
//	RLIMIT_NOFILE 16: the analysis path needs a handful of descriptors, and
//	16 is far below any collector-level sprawl. measured: the analyzer needs
//	four at its peak.
//
// not RLIMIT_AS: go reserves far more address space than it uses, and
// RLIMIT_AS 1.5 GiB was measured to kill an analyzer holding ~50 MB of heap.
// the hard memory bound is the container's cgroup (one job per container).

const (
	childCPULimitSeconds = 70
	childFileLimit       = 16
)

// InstallChildLimits applies the child's self-limits. A failure is fatal:
// the child refuses to analyze without its own bounds, and the parent maps
// the exit to FAILED_LIMIT.
func InstallChildLimits() error {
	cpu := syscall.Rlimit{Cur: childCPULimitSeconds, Max: childCPULimitSeconds}
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &cpu); err != nil {
		return fmt.Errorf("rlimit cpu: %w", err)
	}
	files := syscall.Rlimit{Cur: childFileLimit, Max: childFileLimit}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &files); err != nil {
		return fmt.Errorf("rlimit nofile: %w", err)
	}
	return nil
}
