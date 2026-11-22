//go:build unix

package github

import (
	"os"
	"syscall"
)

// fileInode returns the file's inode number, or 0 when unavailable.
func fileInode(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
