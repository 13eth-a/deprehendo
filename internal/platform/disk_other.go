//go:build !linux && !darwin

package platform

import (
	"fmt"
	"runtime"
)

func statfs(path string) (DiskStats, error) {
	return DiskStats{}, fmt.Errorf("platform: disk usage not implemented on %s", runtime.GOOS)
}
