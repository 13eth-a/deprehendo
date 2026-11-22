//go:build !unix

package github

import "os"

// fileInode returns 0: no inode identity on this platform.
func fileInode(info os.FileInfo) uint64 { return 0 }
