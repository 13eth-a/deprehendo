//go:build linux

package trace

// H9 / 6.52: a real permission refusal.
//
// kernel 7.0 accepts an unprivileged proc-connector subscribe, and a
// non-initial network namespace answers ECONNREFUSED rather than EPERM
// (TestFallbackOnRealKernelRefusal covers that case). the connector's own
// capability check therefore cannot produce EPERM on such a kernel.
//
// the refusal produced here is still the kernel's: a seccomp filter (the
// mechanism a hardened host or a container runtime uses) returns EPERM for
// `bpf()` and for `socket(AF_NETLINK)`. the tracer is unmodified and sees
// exactly what it would see on a host that denies those syscalls. it must
// report a named permission refusal (not a missing mechanism, not a generic
// error) and the agent must degrade once, saying it keeps polling, instead
// of restarting against a policy that will not change.

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	prSetNoNewPrivs   = 38
	prSetSeccomp      = 22
	seccompModeFilter = 2

	seccompRetAllow = 0x7fff0000
	seccompRetErrno = 0x00050000
	seccompRetData  = 0x0000ffff

	bpfLD  = 0x00
	bpfW   = 0x00
	bpfAbs = 0x20
	bpfJmp = 0x05
	bpfJeq = 0x10
	bpfK   = 0x00
	bpfRet = 0x06
)

// seccompDataArgs0 is the offset of seccomp_data.args[0]: int nr (4), u32
// arch (4) and u64 instruction_pointer (8) come first.
const seccompDataArgs0 = 16

// installEPERMSandbox denies bpf() and socket(AF_NETLINK) with EPERM. the
// filter is inherited across exec, so the tracer runs under it unmodified.
func installEPERMSandbox() error {
	filter := []syscall.SockFilter{
		{Code: bpfLD | bpfW | bpfAbs, K: 0},                                  // A = seccomp_data.nr
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 5, K: sysBPF},                     // bpf -> deny
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 1, K: uint32(syscall.SYS_SOCKET)}, // socket -> check
		{Code: bpfRet | bpfK, K: seccompRetAllow},
		{Code: bpfLD | bpfW | bpfAbs, K: seccompDataArgs0},                   // A = args[0] (domain)
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 1, K: uint32(syscall.AF_NETLINK)}, // netlink -> deny
		{Code: bpfRet | bpfK, K: seccompRetAllow},
		{Code: bpfRet | bpfK, K: seccompRetErrno | seccompRetData&uint32(syscall.EPERM)},
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %v", errno)
	}
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter,
		uintptr(unsafe.Pointer(&prog)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("PR_SET_SECCOMP: %v", errno)
	}
	return nil
}

// TestSeccompExecHelper is the exec target of the wrapper the test writes.
// it is inert in an ordinary `go test` run; when the wrapper invokes it, it
// installs the EPERM filter and execs the real tracer with the same argv.
func TestSeccompExecHelper(t *testing.T) {
	if os.Getenv("DEPREHENDO_SECCOMP_HELPER") != "1" {
		return
	}
	tracer := os.Getenv("DEPREHENDO_SECCOMP_TRACER")
	if tracer == "" {
		t.Fatalf("DEPREHENDO_SECCOMP_TRACER is not set")
	}
	if err := installEPERMSandbox(); err != nil {
		t.Fatalf("install the seccomp sandbox: %v", err)
	}
	argv := append([]string{tracer}, flag.Args()...)
	if err := syscall.Exec(tracer, argv, os.Environ()); err != nil {
		t.Fatalf("exec %s: %v", tracer, err)
	}
}

// fieldIs reports whether a "name<space>value" line of the tracer's
// capabilities report carries exactly want.
func fieldIs(text, name, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(line, name) && fields[len(fields)-1] == want {
			return true
		}
	}
	return false
}

func TestFallbackOnRealPermissionRefusal(t *testing.T) {
	if sysBPF == ^uint32(0) {
		t.Skip("no bpf(2) syscall number for this architecture")
	}
	bin, why := ResolveBinary(os.Getenv("DEPREHENDO_TRACE_BINARY"))
	if bin == "" {
		t.Skipf("tracer binary not available: %s", why)
	}
	testbin, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	wrapper := filepath.Join(t.TempDir(), "deprehendo-trace-eperm")
	script := fmt.Sprintf(
		"#!/bin/sh\nDEPREHENDO_SECCOMP_HELPER=1 DEPREHENDO_SECCOMP_TRACER=%q exec %q -test.run=TestSeccompExecHelper -- \"$@\"\n",
		bin, testbin)
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatalf("write the wrapper: %v", err)
	}

	// the tracer itself must name the kernel's refusal as a permission
	// problem: both backends were refused with EPERM, so this is the
	// 6.52 path, not 6.53's unsupported kernel.
	out, err := exec.Command(wrapper, "capabilities").CombinedOutput()
	if err != nil {
		t.Fatalf("capabilities under the EPERM sandbox: %v\n%s", err, out)
	}
	text := string(out)
	t.Logf("tracer report under the seccomp EPERM sandbox:\n%s", text)
	if !fieldIs(text, "kernel refused", "yes") {
		t.Fatalf("the sandboxed tracer did not report a refusal:\n%s", text)
	}
	if !strings.Contains(text, "insufficient permission") {
		t.Fatalf("the refusal was not classified as a permission error:\n%s", text)
	}
	if !strings.Contains(text, "Operation not permitted") {
		t.Fatalf("the kernel's own errno text was lost:\n%s", text)
	}

	m := NewManager(ManagerConfig{
		Binary:             wrapper,
		BaseBackoff:        10 * time.Millisecond,
		MaxBackoff:         40 * time.Millisecond,
		StartTimeout:       5 * time.Second,
		CommandTimeout:     time.Second,
		MaxConsecutiveFail: 5,
	})
	runUntilDone(t, m, 20*time.Second)
	h := m.Health()
	assertPollingFallback(t, h, "insufficient permission")
	if !h.Caps.Unsupported {
		t.Fatalf("health lost the refusal: %+v", h.Caps)
	}
}
