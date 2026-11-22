//go:build linux

package platform

// TotalMemoryBytes reports physical memory from /proc/meminfo. an unavailable
// or malformed file yields zero; host metadata is descriptive, not a health
// signal, so this never blocks incident capture.
func TotalMemoryBytes() uint64 {
	info, err := ReadMemInfo()
	if err != nil {
		return 0
	}
	return info.MemTotal
}
