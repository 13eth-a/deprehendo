//! Build script (no Cargo build-dependencies allowed: crates.io egress is
//! blocked on this project's hosts, and the crate stays near
//! dependency-free).
//!
//! What it decides, per contract §2.2:
//!   - On Linux, compile the BPF C package (`src/ebpf/deprehendo.bpf.c`) with
//!     the system clang into `$OUT_DIR/deprehendo.bpf.o` and record the path
//!     in `DEPREHENDO_BPF_O` for the loader. A host without clang, or a
//!     compile failure, does NOT break the build: it produces no path, so
//!     the loader reports `unavailable` with the honest reason at runtime
//!     (§2.4: degrade with a reason, never a fake).
//!   - On Linux, link the system libbpf (`libbpf-dev`); the FFI surface in
//!     `libbpf.rs` matches libbpf 1.x.
//!   - On non-Linux, nothing is compiled or linked: the eBPF module graph
//!     is cfg'd out, and `backend::select_backend()` refuses.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if cfg!(not(target_os = "linux")) {
        return; // macOS build unchanged: no BPF, no libbpf.
    }

    // compile the BPF C package if clang exists.
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("cargo manifest dir");
    let src = PathBuf::from(&manifest).join("src/ebpf/deprehendo.bpf.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo out dir"));
    let obj = out_dir.join("deprehendo.bpf.o");

    // libbpf's bpf_tracing.h needs the target architecture; derive it from
    // the cargo target instead of assuming x86 (the lima VM is arm64).
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let bpf_arch = match target_arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        "s390x" => "s390",
        "powerpc64" => "powerpc",
        other => other,
    };
    let arch_define = format!("-D__TARGET_ARCH_{bpf_arch}");

    let clang = which("clang");
    let mut embedded = false;
    if let Some(clang) = clang {
        // CO-RE needs the BTF-based vmlinux.h committed at
        // src/ebpf/vmlinux.h and libbpf's headers from libbpf-dev.
        let status = Command::new(&clang)
            .args([
                "-O2",
                "-g",
                "-target",
                "bpf",
                &arch_define,
                "-Wall",
                "-Wno-unused-function",
                "-I",
                "src/ebpf",
                "-c",
                src.to_str().expect("ebpf source path"),
                "-o",
                obj.to_str().expect("ebpf object path"),
            ])
            .status();
        match status {
            Ok(s) if s.success() => {
                embedded = true;
            }
            _ => {
                println!(
                    "cargo:warning=deprehendo-trace: clang failed on src/ebpf/deprehendo.bpf.c; \
                     the binary will report the eBPF backend unavailable with a reason"
                );
            }
        }
    } else {
        println!(
            "cargo:warning=deprehendo-trace: clang not found; the eBPF backend will be \
             unavailable (build the tracer on a host with clang, as in CI)"
        );
    }

    if embedded {
        // the loader reads this env at runtime; the object travels with the
        // cargo build, no need to hunt for a manifest-relative path twice.
        println!("cargo:rustc-env=DEPREHENDO_BPF_O={}", obj.display());
    }

    // libbpf from libbpf-dev / libbpf1. declared unconditionally on linux:
    // a missing library is a *link* error naming itself, which is the
    // honest failure mode (do not silently degrade a binary that was
    // supposed to collect).
    println!("cargo:rustc-link-lib=dylib=bpf");
    // also try cargo's target dir + /usr/lib/bpf (debian layout).
    if !target_arch.is_empty() {
        println!("cargo:rustc-link-search=/usr/lib/{target_arch}-linux-gnu");
    }

    // the vmlinux.h + headers leave in-tree; recompile when they change.
    println!("cargo:rerun-if-changed=src/ebpf/deprehendo.bpf.c");
    println!("cargo:rerun-if-changed=src/ebpf/tp_defs.h");
    println!("cargo:rerun-if-changed=src/ebpf/vmlinux.h");
}

/// Minimal `which`: the build stays std-only.
fn which(name: &str) -> Option<String> {
    let path = env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}
