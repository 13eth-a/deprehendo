package platform

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseTCPFixture(t *testing.T) {
	f, err := os.Open("../../testdata/proc/net_tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := ParseTCP(f)
	if err != nil {
		t.Fatalf("ParseTCP fixture: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	first := records[0]
	if first.LocalAddr.String() != "127.0.0.1" || first.LocalPort != 0x1F90 {
		t.Fatalf("local = %s:%d, want 127.0.0.1:8080", first.LocalAddr, first.LocalPort)
	}
	if !first.RemoteAddr.IsUnspecified() || first.State != "LISTEN" || first.Inode != 12345 {
		t.Fatalf("listen row = %+v", first)
	}
	second := records[1]
	if second.RemoteAddr.String() != "127.0.0.2" || second.RemotePort != 0x01BB ||
		second.LocalPort != 0xC350 || second.State != "ESTABLISHED" || second.Inode != 54321 {
		t.Fatalf("established row = %+v", second)
	}
}

func TestParseTCPRejectsMalformedRows(t *testing.T) {
	// missing columns entirely.
	if _, err := ParseTCP(strings.NewReader("  0: 0100007F:1F90\n")); err == nil {
		t.Fatal("row with two fields accepted")
	}
	// unparseable port.
	if _, err := ParseTCP(strings.NewReader("  0: 0100007F:ZZZZ 00000000:0000 0A\n")); err == nil {
		t.Fatal("bad port accepted")
	}
	// unsupported address length.
	if _, err := ParseTCP(strings.NewReader("  0: 0100:1F90 00000000:0000 0A\n")); err == nil {
		t.Fatal("short address accepted")
	}
}

func TestParseTCPHasHeaderOnly(t *testing.T) {
	records, err := ParseTCP(strings.NewReader("  sl  local_address rem_address   st ...\n"))
	if err != nil || len(records) != 0 {
		t.Fatalf("header-only parse = %v, %v", records, err)
	}
}

func TestParseHexSockaddrIPv6(t *testing.T) {
	// the kernel prints each 32-bit word of the address little-endian, so
	// ::1 appears as ...01000000 and 127.0.0.1 as ...FFFF00000100007F in
	// /proc/net/tcp6. use the kernel-real spellings, not canonical hex.
	got, err := parseHexSockaddr("00000000000000000000000001000000:0035")
	if err != nil {
		t.Fatal(err)
	}
	one := netip.MustParseAddr("::1")
	if got.addr != one {
		t.Fatalf("addr = %s, want ::1", got.addr)
	}
	if got.port != 0x35 {
		t.Fatalf("port = %d, want 53", got.port)
	}
	// :: (unspecified)
	got, err = parseHexSockaddr("00000000000000000000000000000000:FF06")
	if err != nil {
		t.Fatal(err)
	}
	if !got.addr.IsUnspecified() || got.port != 0xFF06 {
		t.Fatalf("unspecified = %+v", got)
	}
}

func TestTCPStateNames(t *testing.T) {
	states, err := parseTCPStatesAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
		"TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"} {
		if _, ok := states[name]; !ok {
			t.Errorf("state name %q missing from the code table", name)
		}
	}
	if _, err := parseTCPState("FF"); err == nil {
		t.Error("unknown state code accepted")
	}
}

// parseTCPStatesAll inverts the name table for table-completeness checks.
func parseTCPStatesAll() (map[string]struct{}, error) {
	inverted := make(map[string]struct{})
	for code := range tcpStateNames {
		name, err := parseTCPState(code)
		if err != nil {
			return nil, err
		}
		inverted[name] = struct{}{}
	}
	return inverted, nil
}

func TestSocketOwners(t *testing.T) {
	root := t.TempDir()
	link := func(pid, fd int, target string) {
		t.Helper()
		dir := filepath.Join(root, itoa(pid), "fd")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeStatFixture(t, root, pid, 123)
		if err := os.Symlink(target, filepath.Join(dir, itoa(fd))); err != nil {
			t.Fatal(err)
		}
	}
	link(11, 0, "socket:[42]")
	link(11, 1, "pipe:[7]")
	link(22, 3, "socket:[42]") // same socket shared: first scan wins
	link(22, 4, "/etc/hosts")  // regular file: ignored
	// pid 33 has no fd dir at all: raced with exit, tolerated.
	if err := os.MkdirAll(filepath.Join(root, "33"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Non-pid directory: ignored.
	if err := os.MkdirAll(filepath.Join(root, "acpi"), 0o755); err != nil {
		t.Fatal(err)
	}

	owners, err := SocketOwners(root)
	if err != nil {
		t.Fatalf("SocketOwners: %v", err)
	}
	if len(owners) != 1 {
		t.Fatalf("owners = %+v, want single inode entry", owners)
	}
	owner, ok := owners[42]
	if !ok || owner.PID != 11 || owner.FD != 0 {
		t.Fatalf("inode 42 owner = %+v, want pid 11 fd 0", owner)
	}
}

func TestSocketOwnersMissingRoot(t *testing.T) {
	if _, err := SocketOwners(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing root must be an error, not an empty map")
	}
}

func TestSocketInode(t *testing.T) {
	if got, ok := socketInode("socket:[12345]"); !ok || got != 12345 {
		t.Fatalf("socket:[12345] = %d %v", got, ok)
	}
	if _, ok := socketInode("pipe:[1]"); ok {
		t.Fatal("pipe accepted as socket")
	}
	if _, ok := socketInode("socket:[x]"); ok {
		t.Fatal("non-numeric inode accepted")
	}
}

func itoa(v int) string { return strconv.Itoa(v) }

// tier A (causal-semantics.md §7.1): queue, timer and retransmit columns are
// parsed from the rows the collector already reads.
func TestParseTCPTierASocketFacts(t *testing.T) {
	input := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:C350 0200007F:01BB 01 000001F4:00000010 01:00000014 00000003  1000        0 54321 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C351 0200007F:01BB 01 00000000:00000000 04:00000014 0000000A  1000        0 54322 1 0000000000000000 100 0 0 10 0
   2: 0100007F:C352 0200007F:01BB 01 garbage 00:00000000 00000000  1000        0 54323 1 0000000000000000 100 0 0 10 0
`
	records, err := ParseTCP(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	r := records[0]
	if !r.QueuesAvailable || r.TxQueue != 500 || r.RxQueue != 16 || r.Timer != 1 || r.Retransmits != 3 {
		t.Errorf("row 0 tier A = %+v, want tx=500 rx=16 timer=1 retrans=3", r)
	}
	if r := records[1]; !r.QueuesAvailable || r.Timer != 4 || r.Retransmits != 10 {
		t.Errorf("row 1 tier A = %+v, want zero-window probe timer 4 and 10 retransmits", r)
	}
	if r := records[2]; r.QueuesAvailable || r.Inode != 54323 {
		t.Errorf("row 2: a garbled queue column must leave QueuesAvailable false but keep the row: %+v", r)
	}
}
