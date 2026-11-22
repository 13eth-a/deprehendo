//go:build darwin

package platform

import (
	"fmt"
	"strings"
	"syscall"
)

func readLoadAverage() (LoadAverage, error) {
	raw, err := syscall.Sysctl("vm.loadavg")
	if err != nil {
		return LoadAverage{}, fmt.Errorf("platform: sysctl vm.loadavg: %w", err)
	}
	return ParseLoadAverage(strings.NewReader(raw))
}
