// tier B socket facts: the kernel's INET_DIAG dump carries tcp_info for each
// TCP socket. the parser is portable and fixture-testable; the netlink socket
// that produces the bytes is Linux-only (sockdiag_linux.go).
package platform

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// netlink and inet_diag constants (linux/netlink.h, linux/sock_diag.h,
// linux/inet_diag.h).
const (
	NetlinkSockDiag       = 4  // NETLINK_SOCK_DIAG
	SockDiagByFamily      = 20 // SOCK_DIAG_BY_FAMILY
	nlmsgHeaderLen        = 16
	nlmsgError            = 2
	nlmsgDone             = 3
	inetDiagReqV2Len      = 56
	inetDiagMsgLen        = 72
	inetDiagInfoAttr      = 2 // INET_DIAG_INFO
	inetDiagInodeOffset   = 68
	inetDiagInfoExtension = 1 << (inetDiagInfoAttr - 1)

	// tcp_info field offsets (linux/tcp.h). the layout is ABI-stable.
	tcpInfoLastDataRecvOffset = 52
	tcpInfoBytesAckedOffset   = 120
	tcpInfoBytesReceivedOff   = 128
	tcpInfoMinLen             = 136
)

// SocketInfo is the tier B measurement for one TCP socket, keyed by inode.
// LastDataRecvMs is the kernel's tcpi_last_data_recv: milliseconds since data
// last arrived. BytesAcked and BytesReceived are cumulative counters, so two
// samples with different values prove progress.
type SocketInfo struct {
	Inode          uint64
	BytesAcked     uint64
	BytesReceived  uint64
	LastDataRecvMs uint32
}

// ErrSockDiagTruncated marks a response whose length fields disagree with its
// payload. the caller treats the whole dump as unusable.
var ErrSockDiagTruncated = errors.New("platform: truncated sock_diag response")

// ParseSockDiag decodes a raw netlink response buffer (one or more messages)
// into socket records. A socket whose tcp_info is missing or too short is
// skipped rather than reported with zero counters, because zero would falsely
// read as "no progress".
func ParseSockDiag(buf []byte) ([]SocketInfo, error) {
	var out []SocketInfo
	for len(buf) >= nlmsgHeaderLen {
		length := int(binary.NativeEndian.Uint32(buf[0:4]))
		msgtype := binary.NativeEndian.Uint16(buf[4:6])
		if length < nlmsgHeaderLen || length > len(buf) {
			return out, ErrSockDiagTruncated
		}
		body := buf[nlmsgHeaderLen:length]
		switch msgtype {
		case nlmsgDone:
			return out, nil
		case nlmsgError:
			return out, fmt.Errorf("platform: sock_diag netlink error")
		default:
			info, ok, err := parseInetDiagMsg(body)
			if err != nil {
				return out, err
			}
			if ok {
				out = append(out, info)
			}
		}
		aligned := (length + 3) &^ 3
		if aligned >= len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return out, nil
}

// parseInetDiagMsg reads one inet_diag_msg and its INET_DIAG_INFO attribute.
// ok is false when the socket carries no usable tcp_info.
func parseInetDiagMsg(body []byte) (SocketInfo, bool, error) {
	if len(body) < inetDiagMsgLen {
		return SocketInfo{}, false, ErrSockDiagTruncated
	}
	info := SocketInfo{Inode: uint64(binary.NativeEndian.Uint32(body[inetDiagInodeOffset : inetDiagInodeOffset+4]))}
	attrs := body[inetDiagMsgLen:]
	for len(attrs) >= 4 {
		alen := int(binary.NativeEndian.Uint16(attrs[0:2]))
		atype := binary.NativeEndian.Uint16(attrs[2:4])
		if alen < 4 || alen > len(attrs) {
			return SocketInfo{}, false, ErrSockDiagTruncated
		}
		if atype == inetDiagInfoAttr {
			tcp := attrs[4:alen]
			if len(tcp) < tcpInfoMinLen {
				return SocketInfo{}, false, nil
			}
			info.LastDataRecvMs = binary.NativeEndian.Uint32(tcp[tcpInfoLastDataRecvOffset:])
			info.BytesAcked = binary.NativeEndian.Uint64(tcp[tcpInfoBytesAckedOffset:])
			info.BytesReceived = binary.NativeEndian.Uint64(tcp[tcpInfoBytesReceivedOff:])
			return info, true, nil
		}
		aligned := (alen + 3) &^ 3
		if aligned >= len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	return SocketInfo{}, false, nil
}

// SockDiagRequest builds the netlink dump request for one address family
// (2 = AF_INET, 10 = AF_INET6). it asks for tcp_info and every TCP state.
func SockDiagRequest(family uint8, seq uint32) []byte {
	total := nlmsgHeaderLen + inetDiagReqV2Len
	buf := make([]byte, total)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(total))
	binary.NativeEndian.PutUint16(buf[4:6], SockDiagByFamily)
	binary.NativeEndian.PutUint16(buf[6:8], 0x301) // NLM_F_REQUEST | NLM_F_DUMP
	binary.NativeEndian.PutUint32(buf[8:12], seq)
	req := buf[nlmsgHeaderLen:]
	req[0] = family
	req[1] = 6 // IPPROTO_TCP
	req[2] = inetDiagInfoExtension
	binary.NativeEndian.PutUint32(req[4:8], 0xffffffff) // all states
	return buf
}
