//go:build !darwin && !linux

package analyzer

import "fmt"

// InstallChildLimits is unsupported outside darwin/linux (phase 7 contract
// §5.4 targets the linux container host). the child refuses to analyze
// without its own bounds: the parent maps the exit to FAILED_LIMIT rather
// than running an unbounded job.
func InstallChildLimits() error {
	return fmt.Errorf("analyzer: no child resource limits on this platform")
}
