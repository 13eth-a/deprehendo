// TCP table parsing and socket-ownership lookup. the parsers are portable and
// fixture-testable; the /proc/net readers and the /proc/<pid>/fd scan are
// Linux-only, so no other package needs to know /proc layout.
package platform

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// TCPRecord is one row of /proc/net/tcp(6): an observable TCP socket entry,
// before ownership attribution. inode is 0 when the kernel does not report one.
type TCPRecord struct {
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	State      string
	Inode      uint64

	// tier A socket facts (causal-semantics.md §7.1), parsed from columns the
	// kernel already prints in /proc/net/tcp: tx_queue/rx_queue (bytes not
	// yet acked by the peer / not yet read by the local process), the active
	// timer (1 retransmit, 2 keepalive, 3 TIME_WAIT, 4 zero-window probe) and
	// the unrecovered retransmit-timeout count. QueuesAvailable is false when
	// a kernel row lacks or garbles these columns; the row itself still
	// parses (they are discriminators, never required for a connection).
	QueuesAvailable bool
	TxQueue         uint32
	RxQueue         uint32
	Timer           uint8
	Retransmits     uint32
}

// tcpStateNames maps the kernel's /proc/net/tcp st column to readable names,
// including the pre-established TCP_CLOSE value that older rows report as 00.
var tcpStateNames = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
	"0C": "NEW_SYN_RECV",
	"00": "CLOSE",
}

// connections reads the host TCP table. linux parses /proc/net/tcp and
// /proc/net/tcp6; other platforms return an explicit not-implemented error so
// callers can treat a missing network collector as an expected condition.
func Connections() ([]TCPRecord, error) { return ConnectionsContext(context.Background()) }

func ConnectionsContext(ctx context.Context) ([]TCPRecord, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("platform: TCP table not implemented on %s", runtime.GOOS)
	}
	return ConnectionsAt(ctx, "/proc/net")
}

// ConnectionsAt preserves readable families and parsed rows when another
// family fails. only an absent IPv6 table is an expected optional resource.
func ConnectionsAt(ctx context.Context, root string) ([]TCPRecord, error) {
	var out []TCPRecord
	var problems error
	for _, family := range []string{"tcp", "tcp6"} {
		if err := ctx.Err(); err != nil {
			return out, errors.Join(problems, err)
		}
		path := filepath.Join(root, family)
		f, err := os.Open(path)
		if err != nil {
			if family == "tcp6" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			problems = errors.Join(problems, fmt.Errorf("platform: open %s: %w", path, err))
			continue
		}
		records, parseerr := ParseTCP(f)
		f.Close()
		out = append(out, records...)
		if parseerr != nil {
			problems = errors.Join(problems, fmt.Errorf("platform: parse %s: %w", path, parseerr))
		}
	}
	return out, problems
}

// ParseTCP parses the /proc/net/tcp(6) tabular format from any reader,
// including fixture files. the header line ("sl  local_address ...") is
// skipped; malformed rows are errors, not silently dropped data.
func ParseTCP(r io.Reader) ([]TCPRecord, error) {
	scanner := bufio.NewScanner(r)
	var out []TCPRecord
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Fields(line)[0] == "sl" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return out, fmt.Errorf("platform: malformed tcp row %q", line)
		}
		local, err := parseHexSockaddr(fields[1])
		if err != nil {
			return out, fmt.Errorf("platform: local address in %q: %w", line, err)
		}
		remote, err := parseHexSockaddr(fields[2])
		if err != nil {
			return out, fmt.Errorf("platform: remote address in %q: %w", line, err)
		}
		state, err := parseTCPState(fields[3])
		if err != nil {
			return out, fmt.Errorf("platform: state in %q: %w", line, err)
		}
		record := TCPRecord{LocalAddr: local.addr, LocalPort: local.port, RemoteAddr: remote.addr, RemotePort: remote.port, State: state}
		parseTierA(&record, fields)
		// column 9 is the socket inode; later kernel-specific columns are optional.
		if len(fields) >= 10 {
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				return out, fmt.Errorf("platform: inode in %q: %w", line, err)
			}
			record.Inode = inode
		}
		out = append(out, record)
	}
	return out, scanner.Err()
}

// parseTierA reads tx_queue:rx_queue (field 4), tr:tm->when (field 5) and
// retrnsmt (field 6). any malformed column leaves QueuesAvailable false.
func parseTierA(record *TCPRecord, fields []string) {
	if len(fields) < 7 {
		return
	}
	txhex, rxhex, ok := strings.Cut(fields[4], ":")
	if !ok {
		return
	}
	tx, errtx := strconv.ParseUint(txhex, 16, 32)
	rx, errrx := strconv.ParseUint(rxhex, 16, 32)
	trhex, _, ok := strings.Cut(fields[5], ":")
	if !ok {
		return
	}
	timer, errtr := strconv.ParseUint(trhex, 16, 8)
	retrans, errre := strconv.ParseUint(fields[6], 16, 32)
	if errtx != nil || errrx != nil || errtr != nil || errre != nil {
		return
	}
	record.QueuesAvailable = true
	record.TxQueue, record.RxQueue = uint32(tx), uint32(rx)
	record.Timer, record.Retransmits = uint8(timer), uint32(retrans)
}

type hexSockaddr struct {
	addr netip.Addr
	port uint16
}

// parseHexSockaddr parses kernel "/proc/net" address columns like
// "0100007F:1F90" (IPv4) or 32-hex-digit IPv6 with ":port". the address bytes
// are printed as one or four native-endian 32-bit words, i.e. reversed.
func parseHexSockaddr(s string) (hexSockaddr, error) {
	colon := strings.LastIndexByte(s, ':')
	if colon <= 0 || colon == len(s)-1 {
		return hexSockaddr{}, fmt.Errorf("missing port: %q", s)
	}
	rawhex, porthex := s[:colon], s[colon+1:]
	port, err := strconv.ParseUint(porthex, 16, 32)
	if err != nil || port >= 1<<16 {
		return hexSockaddr{}, fmt.Errorf("port %q", porthex)
	}
	if len(rawhex) == 8 {
		addr, err := parseHexIPv4(rawhex)
		if err != nil {
			return hexSockaddr{}, err
		}
		return hexSockaddr{addr: addr, port: uint16(port)}, nil
	}
	if len(rawhex) == 32 {
		addr, err := parseHexIPv6(rawhex)
		if err != nil {
			return hexSockaddr{}, err
		}
		return hexSockaddr{addr: addr, port: uint16(port)}, nil
	}
	return hexSockaddr{}, fmt.Errorf("unsupported address length %q", rawhex)
}

func parseHexIPv4(s string) (netip.Addr, error) {
	word, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipv4 address %q: %w", s, err)
	}
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], uint32(word))
	return netip.AddrFrom4(b), nil
}

func parseHexIPv6(s string) (netip.Addr, error) {
	var b [16]byte
	for i := 0; i < 4; i++ {
		word, err := strconv.ParseUint(s[8*i:8*i+8], 16, 64)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("ipv6 address %q: %w", s, err)
		}
		binary.NativeEndian.PutUint32(b[4*i:4*i+4], uint32(word))
	}
	return netip.AddrFrom16(b), nil
}

func parseTCPState(s string) (string, error) {
	name, ok := tcpStateNames[s]
	if !ok {
		return "", fmt.Errorf("unknown TCP state code %q", s)
	}
	return name, nil
}

// SocketOwner says which readable process holds a socket, and at which fd.
type SocketOwner struct {
	PID        int
	FD         int
	StartTicks int64
}

// SocketOwners maps socket inodes ("socket:[inode]" targets under
// /proc/<pid>/fd) to a holding process. the scan is inherently racy and
// best-effort: processes that exit or cannot be read are skipped; a socket
// reachable from several processes reports one arbitrary holder. the passed
// root replaces /proc so tests can exercise the walk against fixture trees.
func SocketOwners(root string) (map[uint64]SocketOwner, error) {
	return SocketOwnersContext(context.Background(), root)
}

// SocketOwnersContext ties each FD scan to a stable PID/start identity. the
// caller must still compare StartTicks with its sampled process table before
// attribution: TCP and FD tables are not an atomic kernel snapshot.
func SocketOwnersContext(ctx context.Context, root string) (map[uint64]SocketOwner, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("platform: read %s: %w", root, err)
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid > 0 && entry.IsDir() {
			pids = append(pids, pid)
		}
	}
	return socketOwnersForPIDs(ctx, root, pids, nil)
}

// SocketOwnersForContext only scans selected identities, avoiding unrelated
// process descriptor walks when an operator watches a specific workload.
func SocketOwnersForContext(ctx context.Context, root string, processes []Process) (map[uint64]SocketOwner, error) {
	pids := make([]int, 0, len(processes))
	expected := make(map[int]int64, len(processes))
	for _, p := range processes {
		if p.PID <= 0 {
			continue
		}
		if _, ok := expected[p.PID]; ok {
			continue
		}
		pids = append(pids, p.PID)
		expected[p.PID] = p.StartTicks
	}
	return socketOwnersForPIDs(ctx, root, pids, expected)
}

func socketOwnersForPIDs(ctx context.Context, root string, pids []int, expected map[int]int64) (map[uint64]SocketOwner, error) {
	owners := make(map[uint64]SocketOwner)
	failed := 0
	var first error
	note := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
			failed++
			if first == nil {
				first = err
			}
		}
	}
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return owners, err
		}
		before, err := ReadProcessAt(root, pid)
		if err != nil {
			note(err)
			continue
		}
		if expected != nil && before.StartTicks != expected[pid] {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(root, strconv.Itoa(pid), "fd"))
		if err != nil {
			note(err)
			continue
		}
		pending := make(map[uint64]SocketOwner)
		for _, fdentry := range fds {
			if err := ctx.Err(); err != nil {
				return owners, err
			}
			fd, err := strconv.Atoi(fdentry.Name())
			if err != nil || fd < 0 {
				continue
			}
			target, err := os.Readlink(filepath.Join(root, strconv.Itoa(pid), "fd", fdentry.Name()))
			if err != nil {
				note(err)
				continue
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			if _, exists := pending[inode]; !exists {
				pending[inode] = SocketOwner{PID: pid, FD: fd, StartTicks: before.StartTicks}
			}
		}
		after, err := ReadProcessAt(root, pid)
		if err != nil {
			note(err)
			continue
		}
		if before.StartTicks != after.StartTicks {
			continue
		}
		for inode, owner := range pending {
			if _, exists := owners[inode]; !exists {
				owners[inode] = owner
			}
		}
	}
	if failed > 0 {
		return owners, fmt.Errorf("platform: %d socket ownership reads unavailable: %w", failed, first)
	}
	return owners, nil
}

// socketInode extracts the numeric inode from a "socket:[123]" link target.
func socketInode(target string) (uint64, bool) {
	const prefix, suffix = "socket:[", "]"
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, suffix) {
		return 0, false
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, prefix), suffix), 10, 64)
	if err != nil || inode == 0 {
		return 0, false
	}
	return inode, true
}
