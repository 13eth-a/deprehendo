package trace

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// sequence of §6.3 b: the agent refuses a tracer whose environment cannot be
// its own. a tracer from another boot (a stale socket file surviving a
// reboot), a tracer from a different PID namespace (it reports PIDs that are
// meaningless to the agent), or a tracer that stamps events on a different
// clock (cross-process ordering would be meaningless). this file reads the
// agent's own identity with the exact same rules as trace-rs's
// proc_connector.rs: a fact the OS does not expose stays unknown ("", 0),
// unknown is never fabricated, and unknown never mismatches.

// LocalIdentity is the agent side's own §6.3 b environment.
type LocalIdentity struct {
	// BootID is /proc/sys/kernel/random/boot_id; unknown when the OS does
	// not expose it.
	BootID string
	// PIDNamespaceInode is the inode rendered in /proc/self/ns/pid's
	// "pid:[<inode>]" link target; 0 when unknown.
	PIDNamespaceInode uint64
}

// localIdentityFn is a seam; tests override it to simulate hosts whose
// identity differs from the fake tracer's handshake.
var localIdentityFn = localIdentity

// localIdentity reads the agent's own §6.3 b facts.
func localIdentity() LocalIdentity {
	id := LocalIdentity{PIDNamespaceInode: namespaceInode()}
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
			id.BootID = strings.TrimSpace(string(raw))
		}
	}
	return id
}

// namespaceInode mirrors the rust tracer: parse the inode out of the
// /proc/self/ns/pid link target ("pid:[4026531836]"); 0 when unavailable.
func namespaceInode() uint64 {
	link, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return 0
	}
	open := strings.Index(link, "[")
	close := strings.Index(link, "]")
	if open < 0 || close < 0 || open >= close {
		return 0
	}
	n, err := strconv.ParseUint(link[open+1:close], 10, 64)
	if err != nil {
		return 0
	}
	return n
}
