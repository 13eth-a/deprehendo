//go:build linux

package platform

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestLiveSocketInfosReadsTierBCounters opens a real loopback TCP pair, sends
// bytes through it, and checks that the sock_diag dump reports nonzero
// cumulative progress for the client socket, located by its inode.
func TestLiveSocketInfosReadsTierBCounters(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()
	records, err := ConnectionsContext(ctx)
	if err != nil {
		t.Skipf("/proc/net/tcp unavailable: %v", err)
	}
	localPort := uint16(client.LocalAddr().(*net.TCPAddr).Port)
	var inode uint64
	for _, r := range records {
		if r.LocalPort == localPort && r.RemotePort == uint16(ln.Addr().(*net.TCPAddr).Port) {
			inode = r.Inode
		}
	}
	if inode == 0 {
		t.Skip("client socket not visible in /proc/net/tcp (needs a readable namespace)")
	}

	infos, err := SocketInfos(ctx)
	if err != nil {
		t.Skipf("sock_diag unavailable here: %v", err)
	}
	info, ok := infos[inode]
	if !ok {
		t.Fatalf("sock_diag did not report inode %d", inode)
	}
	if info.BytesAcked < 4096 {
		t.Errorf("bytes_acked = %d, want at least 4096 after a 4 KiB write", info.BytesAcked)
	}
}
