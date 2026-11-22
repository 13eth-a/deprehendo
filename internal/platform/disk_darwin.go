//go:build darwin

package platform

import (
	"fmt"
	"syscall"
)

func statfs(path string) (DiskStats, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return DiskStats{}, fmt.Errorf("platform: statfs %s: %w", path, err)
	}
	blocksize := uint64(fs.Bsize)
	total := fs.Blocks * blocksize
	free := fs.Bfree * blocksize
	return DiskStats{
		TotalBytes:     total,
		FreeBytes:      free,
		AvailableBytes: fs.Bavail * blocksize,
		UsedBytes:      total - free,
		TotalInodes:    fs.Files,
		FreeInodes:     fs.Ffree,
	}, nil
}
