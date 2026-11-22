//go:build darwin

package platform

import (
	"encoding/binary"
	"strconv"
	"strings"
	"syscall"
)

// TotalMemoryBytes reports physical memory from hw.memsize. an unavailable or
// malformed sysctl yields zero rather than failing incident capture.
func TotalMemoryBytes() uint64 {
	raw, err := syscall.Sysctl("hw.memsize")
	if err != nil {
		return 0
	}
	if total, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64); err == nil {
		return total
	}
	// sysctl returns raw little-endian bytes for integer MIB entries, trimmed
	// of trailing NUL bytes (hw.memsize is an 8-byte integer).
	if len(raw) == 0 || len(raw) > 8 {
		return 0
	}
	var buf [8]byte
	copy(buf[:], raw)
	return binary.LittleEndian.Uint64(buf[:])
}
