//! Minimal netlink syscalls used by the proc-connector backend.
//!
//! Unsafe audit (6.41 / docs/tracing/architecture.md §7): this file holds
//! the crate's entire FFI surface. Every exported function is safe-to-call;
//! its single invariant is that each raw FFI function matches the glibc
//! signature and only touches buffers the caller owns for the duration of
//! the call. No pointers escape; no aliased state is retained across calls.

#![allow(clippy::missing_safety_doc)]

use std::io;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockAddrNl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;
const NETLINK_CONNECTOR: i32 = 11;

// the glibc externs. exactly six, each one signature-checked against the
// platform ABI; all buffers are caller-owned, single-use, and never aliased.
mod raw {
    extern "C" {
        pub(super) fn socket(domain: i32, socktype: i32, protocol: i32) -> i32;
        pub(super) fn bind(fd: i32, addr: *const super::SockAddrNl, addrlen: u32) -> i32;
        pub(super) fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
        pub(super) fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
        pub(super) fn close(fd: i32) -> i32;
        pub(super) fn setsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *const i32,
            len: u32,
        ) -> i32;
        // Linux-only here: macOS has no prctl(2), and supervised mode is
        // refused on non-Linux before these are reachable.
        #[cfg(target_os = "linux")]
        pub(super) fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
        #[cfg(target_os = "linux")]
        pub(super) fn getppid() -> i32;
    }
}

// prctl(2) option for "signal me when my parent dies":
// <linux/prctl.h> PR_SET_PDEATHSIG, and the signal it carries.
#[cfg(target_os = "linux")]
const PR_SET_PDEATHSIG: i32 = 1;
pub const SIGKILL_NUM: i32 = 9;

/// Ask the kernel to SIGKILL this process when its parent dies (§6.3 a):
/// today a killed agent left a privileged tracer running forever, and a
/// new agent started a second one. Returns false when the call was refused
/// or does not exist on this OS, and the caller then refuses supervised
/// mode rather than risking a tracer that cannot die.
#[cfg(target_os = "linux")]
pub fn set_pdeathsig(sig: i32) -> bool {
    // SAFETY: prctl takes five integer words; none of them are pointers here.
    let rc = unsafe { raw::prctl(PR_SET_PDEATHSIG, sig as u64, 0, 0, 0) };
    rc == 0
}

#[cfg(not(target_os = "linux"))]
pub fn set_pdeathsig(_sig: i32) -> bool {
    false
}

/// The parent's PID: the check that closes the race between fork and
/// prctl. If the parent died before the signal was armed, the kernel
/// reparented us to init (or a subreaper): supervised mode must not start.
#[cfg(target_os = "linux")]
pub fn parent_pid() -> i32 {
    unsafe { raw::getppid() }
}

#[cfg(not(target_os = "linux"))]
pub fn parent_pid() -> i32 {
    -1
}

/// Open a raw netlink connector socket. Returns the borrowed fd; the caller
/// retains ownership of closing it.
pub fn socket_connector() -> io::Result<i32> {
    let fd = unsafe { raw::socket(AF_NETLINK, SOCK_RAW, NETLINK_CONNECTOR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Bind as an anonymous netlink endpoint subscribed to `groups`.
pub fn bind_groups(fd: i32, groups: u32) -> io::Result<()> {
    let addr = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0, // let the kernel assign; multiple listeners coexist
        nl_groups: groups,
    };
    let rc = unsafe { raw::bind(fd, &addr, std::mem::size_of::<SockAddrNl>() as u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn send(fd: i32, buf: &[u8]) -> io::Result<usize> {
    let n = unsafe { raw::send(fd, buf.as_ptr(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Receive up to buf.len() bytes. Returns (n, would-block).
pub fn recv(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { raw::recv(fd, buf.as_mut_ptr(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Close; idempotent for closed fds is NOT guaranteed, so sessions own fds
/// exactly once (Drop in FdGuard is the only closer).
pub fn close(fd: i32) {
    unsafe {
        raw::close(fd);
    }
}

const SOL_SOCKET: i32 = 1;
const SO_RCVBUF: i32 = 8;
const SO_RCVBUFFORCE: i32 = 33;

/// Best effort: raise the socket receive buffer to `bytes`. SO_RCVBUFFORCE
/// ignores net.core.rmem_max but needs CAP_NET_ADMIN; SO_RCVBUF is capped by
/// rmem_max. Either failing leaves the current size.
pub fn grow_receive_buffer(fd: i32, bytes: i32) {
    let len = std::mem::size_of::<i32>() as u32;
    // SAFETY: `bytes` lives for the call and `len` is its exact size.
    let forced = unsafe { raw::setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bytes, len) };
    if forced != 0 {
        unsafe {
            raw::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, len);
        }
    }
}
