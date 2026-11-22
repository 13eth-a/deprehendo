//go:build linux

package platform

import (
	"fmt"
	"os"
)

func readLoadAverage() (LoadAverage, error) {
	f, err := os.Open("/proc/loadavg")
	if err != nil {
		return LoadAverage{}, fmt.Errorf("platform: open /proc/loadavg: %w", err)
	}
	defer f.Close()
	return ParseLoadAverage(f)
}
