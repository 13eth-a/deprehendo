package incident

import (
	"runtime"
	"testing"
)

func TestLocalHostMetadata(t *testing.T) {
	host := LocalHost()
	if host.OS != runtime.GOOS || host.Architecture != runtime.GOARCH {
		t.Fatalf("host = %+v, want %s/%s", host, runtime.GOOS, runtime.GOARCH)
	}
	if host.CPUCount < 1 {
		t.Fatalf("cpu count = %d", host.CPUCount)
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if host.MemoryTotal == 0 {
			t.Fatalf("memory total unavailable on %s", runtime.GOOS)
		}
	}
}

func TestCaptureOptionsUseLocalHostMemory(t *testing.T) {
	c, err := NewCapture(CaptureOptions{Writer: &recordingWriter{}, Window: CaptureWindow{}})
	if err != nil {
		t.Fatal(err)
	}
	host := c.options.Metadata.Host
	if host.OS != runtime.GOOS || host.CPUCount < 1 {
		t.Fatalf("default host metadata = %+v", host)
	}
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && host.MemoryTotal == 0 {
		t.Fatalf("default host memory total missing: %+v", host)
	}
	if c.Window() != (CaptureWindow{}) {
		t.Fatalf("window = %+v", c.Window())
	}
}
