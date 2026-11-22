//go:build !darwin

package agent

import "context"

// darwinExecutableName is only meaningful on macOS; elsewhere inspect reads
// procfs and never calls it.
func darwinExecutableName(context.Context, int) string { return "" }
