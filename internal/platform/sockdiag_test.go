package platform

import (
	"encoding/binary"
	"errors"
	"testing"
)

// buildSockDiagMsg makes one inet_diag netlink message carrying a tcp_info
// attribute with the given values at the kernel's field offsets.
func buildSockDiagMsg(inode uint64, lastRecv uint32, acked, received uint64, tcpLen int) []byte {
	tcp := make([]byte, tcpLen)
	if tcpLen >= tcpInfoMinLen {
		binary.NativeEndian.PutUint32(tcp[tcpInfoLastDataRecvOffset:], lastRecv)
		binary.NativeEndian.PutUint64(tcp[tcpInfoBytesAckedOffset:], acked)
		binary.NativeEndian.PutUint64(tcp[tcpInfoBytesReceivedOff:], received)
	}
	attrlen := 4 + tcpLen
	body := make([]byte, inetDiagMsgLen)
	binary.NativeEndian.PutUint32(body[inetDiagInodeOffset:], uint32(inode))
	attr := make([]byte, 4)
	binary.NativeEndian.PutUint16(attr[0:2], uint16(attrlen))
	binary.NativeEndian.PutUint16(attr[2:4], inetDiagInfoAttr)
	body = append(body, attr...)
	body = append(body, tcp...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	msg := make([]byte, nlmsgHeaderLen)
	total := nlmsgHeaderLen + len(body)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(total))
	binary.NativeEndian.PutUint16(msg[4:6], 20) // SOCK_DIAG_BY_FAMILY reply type
	return append(msg, body...)
}

func doneMsg() []byte {
	msg := make([]byte, nlmsgHeaderLen)
	binary.NativeEndian.PutUint32(msg[0:4], nlmsgHeaderLen)
	binary.NativeEndian.PutUint16(msg[4:6], nlmsgDone)
	return msg
}

func TestParseSockDiagReadsTierBFacts(t *testing.T) {
	buf := append(buildSockDiagMsg(88201, 1500, 4096, 8192, 160), doneMsg()...)
	infos, err := ParseSockDiag(buf)
	if err != nil {
		t.Fatalf("ParseSockDiag: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d sockets, want 1", len(infos))
	}
	got := infos[0]
	if got.Inode != 88201 || got.LastDataRecvMs != 1500 || got.BytesAcked != 4096 || got.BytesReceived != 8192 {
		t.Errorf("socket = %+v", got)
	}
}

func TestParseSockDiagSkipsShortTCPInfo(t *testing.T) {
	// A tcp_info too short to hold the counters must not read as zero progress.
	buf := append(buildSockDiagMsg(7, 0, 0, 0, 40), doneMsg()...)
	infos, err := ParseSockDiag(buf)
	if err != nil {
		t.Fatalf("ParseSockDiag: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("short tcp_info produced %+v, want no socket", infos)
	}
}

func TestParseSockDiagRejectsTruncatedLength(t *testing.T) {
	msg := buildSockDiagMsg(9, 1, 2, 3, 160)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)+64))
	if _, err := ParseSockDiag(msg); !errors.Is(err, ErrSockDiagTruncated) {
		t.Errorf("err = %v, want ErrSockDiagTruncated", err)
	}
}

func TestParseSockDiagNetlinkErrorIsReported(t *testing.T) {
	msg := make([]byte, nlmsgHeaderLen)
	binary.NativeEndian.PutUint32(msg[0:4], nlmsgHeaderLen)
	binary.NativeEndian.PutUint16(msg[4:6], nlmsgError)
	if _, err := ParseSockDiag(msg); err == nil {
		t.Error("netlink error message was not reported")
	}
}

func TestSockDiagRequestLayout(t *testing.T) {
	req := SockDiagRequest(2, 5)
	if got := binary.NativeEndian.Uint32(req[0:4]); int(got) != len(req) {
		t.Errorf("length field = %d, want %d", got, len(req))
	}
	if binary.NativeEndian.Uint16(req[4:6]) != SockDiagByFamily {
		t.Errorf("message type is not SOCK_DIAG_BY_FAMILY")
	}
	if req[nlmsgHeaderLen] != 2 || req[nlmsgHeaderLen+1] != 6 {
		t.Errorf("family/protocol = %d/%d, want AF_INET/TCP", req[nlmsgHeaderLen], req[nlmsgHeaderLen+1])
	}
}
