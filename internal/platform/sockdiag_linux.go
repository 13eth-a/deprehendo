//go:build linux

package platform

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// SocketInfos dumps tier B tcp_info for every TCP socket on the host, keyed
// by inode. A family that the kernel does not support is skipped; any other
// failure is returned alongside the sockets already read.
func SocketInfos(ctx context.Context) (map[uint64]SocketInfo, error) {
	out := map[uint64]SocketInfo{}
	var problems error
	for i, family := range []uint8{2, 10} { // AF_INET, AF_INET6
		if err := ctx.Err(); err != nil {
			return out, errors.Join(problems, err)
		}
		infos, err := dumpFamily(family, uint32(i+1))
		if err != nil {
			if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
				continue
			}
			problems = errors.Join(problems, fmt.Errorf("platform: sock_diag family %d: %w", family, err))
			continue
		}
		for _, info := range infos {
			out[info.Inode] = info
		}
	}
	return out, problems
}

func dumpFamily(family uint8, seq uint32) ([]SocketInfo, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, NetlinkSockDiag)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	if err := syscall.Sendto(fd, SockDiagRequest(family, seq), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	var infos []SocketInfo
	buf := make([]byte, 64*1024)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return infos, err
		}
		batch, parseerr := ParseSockDiag(buf[:n])
		infos = append(infos, batch...)
		if parseerr != nil {
			return infos, parseerr
		}
		if containsDone(buf[:n]) {
			return infos, nil
		}
	}
}

// containsDone reports whether a received buffer ends the multi-part dump.
func containsDone(buf []byte) bool {
	for len(buf) >= nlmsgHeaderLen {
		length := int(binary.NativeEndian.Uint32(buf[0:4]))
		if length < nlmsgHeaderLen || length > len(buf) {
			return false
		}
		if buf[4] == nlmsgDone {
			return true
		}
		aligned := (length + 3) &^ 3
		if aligned >= len(buf) {
			return false
		}
		buf = buf[aligned:]
	}
	return false
}
