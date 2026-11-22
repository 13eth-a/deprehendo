package platform

import (
	"runtime"
	"testing"
)

func TestTotalMemoryBytesOnSupportedPlatforms(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("total memory unavailable on %s", runtime.GOOS)
	}
	if got := TotalMemoryBytes(); got == 0 {
		t.Fatalf("TotalMemoryBytes() = 0 on %s", runtime.GOOS)
	}
}
