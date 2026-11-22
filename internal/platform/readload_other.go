//go:build !linux && !darwin

package platform

import (
	"fmt"
	"runtime"
)

func readLoadAverage() (LoadAverage, error) {
	return LoadAverage{}, fmt.Errorf("platform: load average not implemented on %s", runtime.GOOS)
}
