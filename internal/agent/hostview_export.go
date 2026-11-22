package agent

import (
	"os"
	"path/filepath"

	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// DefaultStateDir is where `start` and `github discover` keep installation
// state (the provider salt file). ~/.runopsy is the documented location.
func DefaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".runopsy")
	}
	return ""
}

// NewHostView exposes the agent's HostView to cmd/ binaries (the `github
// discover` command uses the same identity/salt rules as the recorder).
func NewHostView(stateDir string) provider.HostView {
	return newHostView(stateDir)
}

// PrivacyFor parses a --privacy value; empty means conservative.
func PrivacyFor(level string) (evidence.PrivacyLevel, bool) {
	switch evidence.PrivacyLevel(level) {
	case "":
		return evidence.PrivacyConservative, true
	case evidence.PrivacyConservative, evidence.PrivacyIdentifiers:
		return evidence.PrivacyLevel(level), true
	default:
		return "", false
	}
}
