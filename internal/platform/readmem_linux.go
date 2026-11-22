//go:build linux

package platform

import (
	"fmt"
	"os"
)

func readMemInfo() (MemInfo, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemInfo{}, fmt.Errorf("platform: open /proc/meminfo: %w", err)
	}
	defer f.Close()
	return ParseMemInfo(f)
}
