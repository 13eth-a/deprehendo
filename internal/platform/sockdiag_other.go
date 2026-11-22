//go:build !linux

package platform

import (
	"context"
	"fmt"
	"runtime"
)

// SocketInfos reads tier B tcp_info counters, which need the linux
// NETLINK_SOCK_DIAG socket. elsewhere it reports the capability as missing.
func SocketInfos(ctx context.Context) (map[uint64]SocketInfo, error) {
	return nil, fmt.Errorf("platform: socket progress counters not implemented on %s", runtime.GOOS)
}
