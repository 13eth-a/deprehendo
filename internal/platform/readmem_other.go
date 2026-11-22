//go:build !linux

package platform

import (
	"fmt"
	"runtime"
)

func readMemInfo() (MemInfo, error) {
	return MemInfo{}, fmt.Errorf("platform: memory accounting not implemented on %s", runtime.GOOS)
}
