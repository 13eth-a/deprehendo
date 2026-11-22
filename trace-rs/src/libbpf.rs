//! libbpf FFI for the eBPF backend (contract §2.2, §11.2).
//!
//! Unsafe audit (6.41): this file, like `nix.rs`, holds the crate's FFI
//! surface. Rules the rest of the crate must not break:
//!   - every raw extern here matches the libbpf 1.x C signature exactly
//!     (checked against the `/usr/include/bpf/libbpf.h` that built the
//!     kernel object);
//!   - every exported function is safe-to-call; ownership is explicit and
//!     RAII-owned in `Object`/`Link`/`PollRing`, so kernel programs cannot
//!     outlive their loader by accident;
//!   - ring-buffer samples reach the callback as `(ptr, len)` and are
//!     parsed byte-wise by the caller, never transmuted into a struct
//!     (§11.2: samples are parsed with length checks and `from_le_bytes`);
//!   - `Send` is asserted for the three handles with a documented
//!     single-owner rationale, because the backend moves them into one
//!     worker thread and libbpf itself does not thread its handles.
//!
//! No Cargo dependency on libbpf-rs: crates.io egress is blocked on this
//! project's hosts and the crate is deliberately near dependency-free. The
//! hand-written FFI surface is small on purpose: open/load, enumerate
//! programs and maps, attach tracepoints (and one raw tracepoint), hash
//! map updates from user space, and poll a ring buffer. Linking needs
//! `libbpf-dev` (the `bpf` shared library), which the build notes and CI
//! declare.
//!
//! On non-Linux the whole eBPF module graph is cfg'd out
//! (`ebpf_backend::probe` refuses before any of this compiles in); the
//! stub types here only keep the module tree typecheckable there.
#![allow(clippy::missing_safety_doc)]
#![allow(dead_code)]

use std::ffi::CStr;
use std::io;

#[cfg(target_os = "linux")]
mod raw {
    // opaque types: only ever referenced through pointers from this module.
    #[repr(C)]
    pub struct BpfObject {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct BpfProgram {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct BpfMap {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct BpfLink {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct RingBuffer {
        _private: [u8; 0],
    }

    // Ring-buffer sample callback: `fn(ctx, data_ptr, data_len) -> i32`.
    // returning non-zero would stop the poll early; ours never does.
    pub type SampleFn = unsafe extern "C" fn(*mut u8, *mut u8, usize) -> i32;

    extern "C" {
        pub(super) fn libbpf_set_print(fn_: *const u8);
        pub(super) fn libbpf_strerror(err: i32, buf: *mut u8, len: usize) -> i32;

        pub(super) fn bpf_object__open_file(
            path: *const std::os::raw::c_char,
            opts: *const u8,
        ) -> *mut BpfObject;
        pub(super) fn bpf_object__load(obj: *mut BpfObject) -> i32;
        pub(super) fn bpf_object__close(obj: *mut BpfObject);
        pub(super) fn bpf_object__next_program(
            obj: *mut BpfObject,
            prev: *mut BpfProgram,
        ) -> *mut BpfProgram;
        pub(super) fn bpf_object__next_map(obj: *mut BpfObject, prev: *mut BpfMap) -> *mut BpfMap;

        pub(super) fn bpf_program__name(prog: *mut BpfProgram) -> *const u8;
        pub(super) fn bpf_program__attach_tracepoint(
            prog: *mut BpfProgram,
            category: *const std::os::raw::c_char,
            name: *const std::os::raw::c_char,
        ) -> *mut BpfLink;
        pub(super) fn bpf_program__attach_raw_tracepoint(
            prog: *mut BpfProgram,
            name: *const std::os::raw::c_char,
        ) -> *mut BpfLink;

        pub(super) fn bpf_link__destroy(link: *mut BpfLink) -> i32;

        pub(super) fn bpf_map__name(map: *mut BpfMap) -> *const u8;
        pub(super) fn bpf_map__fd(map: *mut BpfMap) -> i32;

        pub(super) fn bpf_map_lookup_elem(fd: i32, key: *const u8, value: *mut u8) -> i32;
        pub(super) fn bpf_map_update_elem(
            fd: i32,
            key: *const u8,
            value: *const u8,
            flags: u64,
        ) -> i32;
        pub(super) fn bpf_map_delete_elem(fd: i32, key: *const u8) -> i32;

        // libbpf 1.x exports the ring buffer API without the `bpf_` prefix
        // (`ring_buffer__new`, ...); the `bpf_` names do not exist to link.
        pub(super) fn ring_buffer__new(
            fd: i32,
            cb: Option<SampleFn>,
            ctx: *mut u8,
            opts: *const u8,
        ) -> *mut RingBuffer;
        pub(super) fn ring_buffer__poll(rb: *mut RingBuffer, timeout_ms: i32) -> i32;
        pub(super) fn ring_buffer__free(rb: *mut RingBuffer);
    }
}

// silence libbpf's stderr chatter before the first call (loader notes are
// noise on a daemon that logs to stderr; failures surface through return
// codes and `strerror`). NULL is documented in libbpf as "disable logging".
// SAFETY: swaps a logging callback for none; no ownership involved.
#[cfg(target_os = "linux")]
pub fn set_print(silent: bool) {
    if silent {
        unsafe { raw::libbpf_set_print(std::ptr::null()) };
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_print(_silent: bool) {}

/// libbpf's error string for a negative libbpf error code, bounded.
#[cfg(target_os = "linux")]
pub fn strerror(err: i32) -> String {
    let mut buf = [0u8; 256];
    // SAFETY: a caller-owned buffer with its exact length.
    let rc = unsafe { raw::libbpf_strerror(err, buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        format!("libbpf error {err}")
    }
}

#[cfg(not(target_os = "linux"))]
pub fn strerror(err: i32) -> String {
    format!("libbpf error {err}")
}

// ---- object ----------------------------------------------------------------

/// A loaded BPF object. Owns the kernel handle; drop closes it. Every
/// attached `Link` created from this object must be dropped *before* the
/// object. the backend struct enforces that with its field order
/// (ring, links, object).
#[cfg(target_os = "linux")]
pub struct Object {
    inner: *mut raw::BpfObject,
}

// SAFETY: the raw pointer is dereferenced only inside this module, the
// object is used by the single thread that owns the backend, and no state
// is shared across calls.
#[cfg(target_os = "linux")]
unsafe impl Send for Object {}

#[cfg(target_os = "linux")]
impl Object {
    /// Open and load a compiled `.o`. Attaches nothing. Returns the libbpf
    /// reason on failure; the caller decides fallback vs. refusal.
    pub fn open_and_load(path: &std::path::Path) -> io::Result<Object> {
        if !path.exists() {
            return Err(io::Error::other(format!(
                "BPF object {} is missing (build requires clang + bpftool; see docs/tracing/architecture.md)",
                path.display()
            )));
        }
        let cpath = std::ffi::CString::new(path.to_string_lossy().into_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `cpath` is a valid NUL-terminated string owned for the
        // call; `opts` NULL selects libbpf defaults.
        let obj = unsafe { raw::bpf_object__open_file(cpath.as_ptr(), std::ptr::null()) };
        if obj.is_null() {
            return Err(io::Error::other("bpf_object__open_file: NULL"));
        }
        // SAFETY: `obj` is a live handle from open_file.
        let rc = unsafe { raw::bpf_object__load(obj) };
        if rc < 0 {
            unsafe { raw::bpf_object__close(obj) };
            return Err(io::Error::other(format!(
                "bpf_object__load: {}",
                strerror(rc)
            )));
        }
        Ok(Object { inner: obj })
    }

    fn program_symbol(prog: *mut raw::BpfProgram) -> String {
        // SAFETY: `prog` is a valid program of a live object; the returned
        // pointer is static data for the object's lifetime.
        let name = unsafe { raw::bpf_program__name(prog) };
        if name.is_null() {
            return "<unnamed>".into();
        }
        // SAFETY: reads to NUL within the pointed-to static string.
        unsafe { CStr::from_ptr(name as *const std::os::raw::c_char) }
            .to_string_lossy()
            .into_owned()
    }

    fn programs(&mut self) -> Vec<(*mut raw::BpfProgram, String)> {
        let mut out = Vec::new();
        // SAFETY: next_program with a NULL `prev` enumerates each program
        // once and returns NULL at the end.
        let mut prev: *mut raw::BpfProgram = std::ptr::null_mut();
        loop {
            let p = unsafe { raw::bpf_object__next_program(self.inner, prev) };
            if p.is_null() {
                break;
            }
            let sym = Self::program_symbol(p);
            out.push((p, sym));
            prev = p;
        }
        out
    }

    /// Attach one tracepoint program by its C symbol name. The returned
    /// `Link` owns the attachment and detaches on drop.
    pub fn attach_tracepoint(
        &mut self,
        symbol: &str,
        category: &str,
        name: &str,
    ) -> Result<Link, String> {
        let prog = self
            .programs()
            .into_iter()
            .find(|(_, s)| s == symbol)
            .map(|(p, _)| p)
            .ok_or_else(|| format!("program {symbol} not in object"))?;
        let cat = std::ffi::CString::new(category).map_err(|e| e.to_string())?;
        let tp = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        // SAFETY: `prog` belongs to this live object; both C strings are
        // valid for the duration of the call.
        let link = unsafe { raw::bpf_program__attach_tracepoint(prog, cat.as_ptr(), tp.as_ptr()) };
        if link.is_null() {
            return Err(format!("attach_tracepoint {category}/{name} failed"));
        }
        Ok(Link { inner: link })
    }

    /// Attach one raw tracepoint (no category part) by symbol name.
    pub fn attach_raw_tracepoint(&mut self, symbol: &str, name: &str) -> Result<Link, String> {
        let prog = self
            .programs()
            .into_iter()
            .find(|(_, s)| s == symbol)
            .map(|(p, _)| p)
            .ok_or_else(|| format!("program {symbol} not in object"))?;
        let tp = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        // SAFETY: as attach_tracepoint.
        let link = unsafe { raw::bpf_program__attach_raw_tracepoint(prog, tp.as_ptr()) };
        if link.is_null() {
            return Err(format!("attach_raw_tracepoint {name} failed"));
        }
        Ok(Link { inner: link })
    }

    /// The fd of the named map, for ring-buffer setup and user-space watch
    /// updates. Returns None when the object has no such map.
    pub fn map_fd(&mut self, name: &str) -> Option<i32> {
        // SAFETY: next_map with a NULL `prev` enumerates each map once.
        let mut prev: *mut raw::BpfMap = std::ptr::null_mut();
        loop {
            let m = unsafe { raw::bpf_object__next_map(self.inner, prev) };
            if m.is_null() {
                return None;
            }
            let mname = unsafe { raw::bpf_map__name(m) };
            let text = if mname.is_null() {
                String::new()
            } else {
                // SAFETY: reads to NUL within libbpf-owned static data.
                unsafe { CStr::from_ptr(mname as *const std::os::raw::c_char) }
                    .to_string_lossy()
                    .into_owned()
            };
            if text == name {
                let fd = unsafe { raw::bpf_map__fd(m) };
                return Some(fd);
            }
            prev = m;
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: one handle, closed exactly once; attached links must have
        // been dropped first (struct field order guarantees it).
        unsafe { raw::bpf_object__close(self.inner) };
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub struct Object;

// ---- link ------------------------------------------------------------------

/// One attached program; detaches on drop, exactly once.
#[cfg(target_os = "linux")]
pub struct Link {
    inner: *mut raw::BpfLink,
}

// SAFETY: the link is used by the owning thread's attach/drop only; the
// kernel side runs asynchronously by design.
#[cfg(target_os = "linux")]
unsafe impl Send for Link {}

#[cfg(target_os = "linux")]
impl Drop for Link {
    fn drop(&mut self) {
        // SAFETY: one link, one destroy; losing it would leak an attached
        // program after the process's maps were torn down.
        unsafe { raw::bpf_link__destroy(self.inner) };
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub struct Link {
    _unused: u8,
}

// ---- User-space map control (the watch set, §5) ----------------------------

/// BPF_NOEXIST: insert only when the key is absent.
#[cfg(target_os = "linux")]
pub const BPF_NOEXIST: u64 = 1;

/// Insert or update one record. `key`/`value` are the raw little-endian
/// encodings the BPF side declared for the map.
#[cfg(target_os = "linux")]
pub fn map_update(fd: i32, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
    // SAFETY: both buffers are caller-owned for the duration and the map's
    // declared key/value sizes; libbpf parses by size, not by aliasing.
    let rc = unsafe { raw::bpf_map_update_elem(fd, key.as_ptr(), value.as_ptr(), flags) };
    if rc < 0 {
        return Err(io::Error::other(format!(
            "bpf_map_update_elem: {}",
            strerror(rc)
        )));
    }
    Ok(())
}

/// Delete one record.
#[cfg(target_os = "linux")]
pub fn map_delete(fd: i32, key: &[u8]) -> io::Result<()> {
    // SAFETY: caller-owned key buffer for the duration.
    let rc = unsafe { raw::bpf_map_delete_elem(fd, key.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::other("bpf_map_delete_elem"));
    }
    Ok(())
}

/// Copy out one record's value; false when absent.
#[cfg(target_os = "linux")]
pub fn map_lookup(fd: i32, key: &[u8], value: &mut [u8]) -> bool {
    // SAFETY: caller-owned buffers, sizes as declared.
    let rc = unsafe { raw::bpf_map_lookup_elem(fd, key.as_ptr(), value.as_mut_ptr()) };
    rc == 0
}

// ---- ring buffer -----------------------------------------------------------

/// Sample callback handed to the ring pump. Named type keeps clippy's
/// `type_complexity` quiet without changing the surface.
type SampleCallback = Box<dyn FnMut(&[u8])>;

struct Callback {
    f: SampleCallback,
}

/// One ring-buffer consumer. Owns the ring handle and the sample callback;
/// frees both on drop (and must be dropped before the `Object`, which the
/// backend's field order guarantees).
pub struct PollRing {
    #[cfg(target_os = "linux")]
    inner: *mut raw::RingBuffer,
    /// Heap-allocated so the libc callback can own it by address; freed on
    /// Drop. Never touched from any thread but the poll owner's.
    cb: *mut Callback,
}

// SAFETY: `inner` is used only from the owning thread's poll(); `cb` is a
// stable heap address written once at construction and freed in drop, and
// the callback runs only while poll() is running on the owning thread.
#[cfg(target_os = "linux")]
unsafe impl Send for PollRing {}

#[cfg(target_os = "linux")]
impl PollRing {
    /// Subscribe to the ring buffer at `fd`, invoking `cb` for each prior
    /// (unconsumed) and future sample.
    pub fn new<F: FnMut(&[u8]) + 'static>(fd: i32, cb: F) -> io::Result<PollRing> {
        let slot: *mut Callback = Box::into_raw(Box::new(Callback { f: Box::new(cb) }));
        // SAFETY: the ctx pointer handed to libbpf is the stable address of
        // the leaked box, owned by the returned PollRing until drop; the
        // callback receives it back and dereferences it exactly there.
        let rb = unsafe {
            raw::ring_buffer__new(
                fd,
                Some(sample_trampoline),
                slot as *mut u8,
                std::ptr::null(),
            )
        };
        if rb.is_null() {
            // SAFETY: nobody saw the box; reclaim it.
            unsafe { drop(Box::from_raw(slot)) };
            return Err(io::Error::other("ring_buffer__new"));
        }
        Ok(PollRing {
            inner: rb,
            cb: slot,
        })
    }

    /// Drain available samples, waiting up to `timeout_ms` for the first.
    /// Returns the number of samples consumed, or an error (which never
    /// tears down the ring. the caller may poll again).
    pub fn poll(&self, timeout_ms: i32) -> io::Result<i32> {
        // SAFETY: one ring, used exclusively from this handle's thread.
        let rc = unsafe { raw::ring_buffer__poll(self.inner, timeout_ms) };
        if rc < 0 {
            return Err(io::Error::other(format!(
                "ring_buffer__poll: {}",
                strerror(rc)
            )));
        }
        Ok(rc)
    }
}

// SAFETY: `ctx` is the `Callback` leaked in `PollRing::new` and still owned
// by the live PollRing; `data` is a valid sample of exactly `len` bytes for
// the callback's duration (libbpf contract).
#[cfg(target_os = "linux")]
extern "C" fn sample_trampoline(ctx: *mut u8, data: *mut u8, len: usize) -> i32 {
    let slot = unsafe { &mut *(ctx as *mut Callback) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    (slot.f)(bytes);
    0
}

#[cfg(target_os = "linux")]
impl Drop for PollRing {
    fn drop(&mut self) {
        // SAFETY: free the ring first (no future callbacks), then reclaim
        // the callback box.
        unsafe { raw::ring_buffer__free(self.inner) };
        unsafe { drop(Box::from_raw(self.cb)) };
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub struct PollRing;
