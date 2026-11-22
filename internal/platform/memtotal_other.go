//go:build !linux && !darwin

package platform

// TotalMemoryBytes is unavailable on this platform; incident host metadata
// records zero instead of guessing.
func TotalMemoryBytes() uint64 { return 0 }
