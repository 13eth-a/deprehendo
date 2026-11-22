// disk space accounting via statfs. the statfs struct differs between linux
// and macOS, so thin per-OS files provide the values; the exported shape stays
// uniform for the collector and snapshot model.
package platform

import "fmt"

// DiskStats is one filesystem's capacity state in bytes and inodes.
type DiskStats struct {
	Filesystem     string
	TotalBytes     uint64
	FreeBytes      uint64 // free blocks, including reserved blocks
	AvailableBytes uint64 // blocks unprivileged processes may allocate
	UsedBytes      uint64 // TotalBytes - FreeBytes
	TotalInodes    uint64
	FreeInodes     uint64
}

// DiskUsage reports capacity for the filesystem containing path. linux uses
// statfs(2); macOS uses the same call with its own structure layout. other
// platforms report not-implemented.
func DiskUsage(path string) (DiskStats, error) {
	if path == "" {
		return DiskStats{}, fmt.Errorf("platform: disk usage path must not be empty")
	}
	stats, err := statfs(path)
	if err != nil {
		return DiskStats{}, err
	}
	stats.Filesystem = path
	return stats, nil
}
