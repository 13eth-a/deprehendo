# Phase 6: adversarial review and test pass

Owner: adversarial. Scope: the Phase 6 items assigned to adversarial in the allocation
plan (6.42 and 6.43 fuzzing, 6.44 fixtures, 6.52 and 6.53 fallbacks), plus
adversarial review of the decoders and the trace/polling merge against
`docs/tracing/contract.md` §3.3, §6 and §9.1.

This pass was re-based onto the settled tree after engineering's LOSS/HEALTH fix
(protocol 2). Everything below was checked against that tree.

## Findings

| ID | Finding | Status | Evidence |
|---|---|---|---|
| H1 | Rust `read_frame` accepted message kind 0 and went past kind 4. Go accepts kinds 1..=6 (EVENT, HANDSHAKE, CONTROL, ACK, LOSS, HEALTH). A cross-language divergence on the frame boundary. | Fixed: Rust accepts 1..=6, matching Go. | `oversized_and_unknown_frames_are_refused_before_allocation`, `TestFramingRefusesKindZeroAndOversize`, `FuzzReadFrame` |
| H2 | Rust `decode_ack` accepted any op. Go refuses ack ops outside 1..=6. | Fixed: Rust refuses ops outside OP_ADD..=OP_ADD_CGROUP. | `unknown_ack_ops_are_refused_like_go_does`, `FuzzDecodeAck` |
| H3 | `deprehendo-trace capabilities` claimed `process exec: yes` and `process exit: yes` without touching the kernel. Inside `unshare -n` the connector refuses the listener (ECONNREFUSED, os error 111), so the claim was false. Contract §6.8: Go must not assume a feature exists. | Fixed: the probe opens and closes a real connector subscription. A refusal sets `unsupported`, the capability states become `unavailable` with the reason, and the handshake carries `selection_reason` (new field). The label is now `kernel refused`. | `unshare -n deprehendo-trace capabilities` prints `process exec no [unavailable]`, `kernel refused yes`, and the refusal reason |
| H4 | `deprehendo-trace debug` retried a refused subscription forever, printing `resubscribe failed` in a loop. | Fixed: debug exits rc=1 at once, naming the kernel refusal. The message previously said "tracing backend is Linux-only", which was wrong; corrected. | `unshare -n deprehendo-trace debug 1` → rc=1, one line, no loop |
| H5 | The session started the collector thread even when the kernel had refused it, so it spun on subscribe retries for the life of the session. | Fixed: the collector is not started on an unsupported probe. The session keeps its event sender alive so controls still work. | `transport.rs` (`idle_tx`); `TestFallbackOnRealKernelRefusal` |
| H6 | The Go manager ignored the handshake's `unsupported` flag and went to `StateActive`. A permanent refusal would look like a working tracer. The first fix also left the state at `StateStopped` because `GaveUp` was never set. | Fixed: a refusal degrades once to `StateUnavailable` with `GaveUp` set, the tracer's reason (from `selection_reason`), and no restarts. The reason always says "continuing in polling mode". | `TestFallbackWhenTracerRefusesMechanism`, `TestFallbackOnRealKernelRefusal`, `TestUnavailableReasonAlwaysPromisesPolling` |
| H7 | Contract §9.1: `incident.Merge` pairs a snapshot exit with a tracer exit on PID and a 2 s window when one side has no start time (zero start_ticks). §9.1 requires identities to be compatible; the current rule is unsafe. Reproduced: a zero start time on the polling side pairs with a tracer exit of a different identity. | **Open.** Replacing the merge is contract §14 item 5 (engineering). The reproduction is a skipped test with the gap named in its reason. | `TestMergeUnknownIdentityGapKnownToday` (skipped; reproduced earlier by an unskipped probe that failed as predicted) |
| H8 | Contract §3.3 rules 1 and 3 (sender of a generated signal; group-exit conversion) cannot be tested: no backend observes signals yet. | **Not testable yet.** Revisit with the eBPF backend (contract §14 item 4). | none |
| H9 | 6.52 asks for a real permission refusal. On this 6.18 kernel an unprivileged uid subscribes successfully, so EPERM cannot be produced here. | **Fixed 2026-11-04.** Kernel 7.0 permits an unprivileged connector subscribe and answers ECONNREFUSED (not EPERM) in a non-initial netns, so the connector's own check cannot yield EPERM there. Reproduced with a real kernel denial instead: a seccomp filter returns EPERM for `bpf()` and `socket(AF_NETLINK)` and the unmodified tracer classifies both as `insufficient permission: ...`. An unforced EPERM is also visible under `unshare -U --map-root-user` (`bpf_object__load: Operation not permitted`, then connector fallback). | `TestFallbackOnRealPermissionRefusal`; `unshare -U --map-root-user deprehendo-trace capabilities` |
| H10 | `TestPhase2AcceptanceMatrix` (`./tests`) failed once in three runs with the tracer on PATH, on an incident-evidence timing check. It passed in the other two runs and without the tracer. | **Resolved 2026-11-04.** Two independent causes. (1) The process-exit assertion accepted only `PROCESS_EXITED`; the §9.1 merge can let `TRACE_PROCESS_EXIT` own that entry, so both types are now accepted. (2) On the Lima VM the log showed the inspected bundle was triggered by a *different* process: every case watches the same name, a leftover simulator from an earlier case exited first, and `waitForBundle` returned that bundle, which had no event for this case's PID. The case now waits for a bundle carrying its simulator's exit. | Two race-enabled matrix runs and the full `go test -race ./...` on the VM |
| H11 | Go's `Handshake` does not decode `boot_id`, `pid_namespace_inode`, `event_clock`, or per-capability states. So the §6.3 b identity checks (refuse a tracer from another boot or PID namespace) are not enforced on the Go side. | **Open.** Belongs to engineering (protocol §6.3 b). Only `selection_reason` was added here. | `schema.go` `Handshake` |
| H12 | Go's `decodeControl` and `decodeAck` reject op 7 (`OP_ADD_CGROUP`), which Rust defines. | **Resolved (November 4, 2026):** `OpAddCgroup` is accepted and labelled `ADD_CGROUP`; the Rust test mirror accepts the same op, and unknown ops still end the session. Go still does not send op 7 (cgroup watches are later); a backend that cannot filter by cgroup refuses it in the ack. | `TestAddCgroupControlAccepted` |

## Build fixes outside adversarial's files

Two fixes were needed to build on Linux x86_64 at all. Both touch files other
owners wrote; flagged for review rather than silently absorbed.

- `internal/platform/monotonic_linux.go`: `syscall.Syscall` returns three
  values, and `syscall.CLOCK_MONOTONIC` is not exported on every Go version.
  Now uses the literal `1` with the three-value form. Owner: platform.
- `trace-rs/src/libbpf.rs` (engineering's file): C-string extern parameters were
  `*const u8`, but `c_char` is `i8` on x86_64, so the bindings did not compile.
  Changed to `*const std::os::raw::c_char` for the three path/name arguments.

## Fuzzing (6.42, 6.43)

- **Go, native fuzzing** (`internal/trace/framing_fuzz_test.go`): five targets,
  `FuzzReadFrame`, `FuzzDecodeEvent`, `FuzzDecodeControl`, `FuzzDecodeHandshake`,
  `FuzzDecodeAck`. Each ran 30 s on the settled tree with no failures. Seeds are
  the seven Rust-encoded fixtures plus hand-written malformed frames. The frame
  checks now cover kinds 5 and 6 (LOSS, HEALTH). An accepted event must
  survive a re-encode unchanged.
- **Rust, deterministic property tests** (`trace-rs/src/framing.rs`,
  `fuzz_tests`): 20,000 random byte streams, 8,000 mutated valid frames (bit
  flips, truncation, appended garbage), every truncation point of 64 events,
  event round trips, oversize and unknown-kind refusal before allocation, and
  control and ack bounds. Seeds are fixed, so any failure reproduces. This is a
  seeded search, not coverage-guided: `cargo-fuzz` was not available offline.

## Fixtures (6.44)

Seven fixtures in `testdata/trace/` decode in Go. The fixture tests run in the
trace package.

## Fallbacks (6.52, 6.53)

- 6.53, unsupported kernel: a real kernel refusal. The tracer runs in a network
  namespace other than the initial one (`unshare -n`, root). The test runs the
  actual tracer binary and expects `unavailable`, the kernel reason,
  "continuing in polling mode", and no restarts. It passes on this host.
- 6.52, permission refusal: a seccomp filter denies `bpf()` and
  `socket(AF_NETLINK)` with EPERM. The real tracer reports `insufficient
  permission` and `kernel refused yes`, and the manager degrades once with
  "continuing in polling mode" and no restarts. See H9.

## Limits of this verification

- The eBPF backend cannot be built here: the build has no BPF object (no
  `clang`/`bpftool`, no `bpf/bpf_helpers.h`). The binary reports eBPF as
  unavailable, and falls back to the proc connector. Every eBPF claim is
  unverified.
- Linking needs `libbpf`, which is not installed here. A link-only stub
  (`libbpf.so`, no-op symbols) was used. Wire-compat tests run with that stub on
  `LD_LIBRARY_PATH`. They prove the protocol, not libbpf behaviour.
- The Go incident package (`internal/incident`) could not be built in the sandbox
  because it depends on `internal/collector` and `internal/provider/evidence`,
  which were not staged. The merge edge tests were run in an isolated copy
  containing `tracemerge.go` and the `Event` type from `model.go` (type
  copied; the collector pointer field replaced). The tests pass against the
  current `tracemerge.go`. Run the full incident package on the Mac.

## Verification (sandbox, Linux 6.18.44, root)

- Rust: `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test`: 19 unit, 8 protocol, 5 wire-compat, all pass.
- Go: `go vet ./internal/trace/` clean; `go test ./internal/trace/` passes, and
  `TestFallbackOnRealKernelRefusal` runs (not skipped) against the rebuilt tracer.
- Go merge edge tests: `TestMergeWindowBoundary`,
  `TestMergeConsumesEachPollingEventOnce`, `TestMergeNeverInventsOrLosesEvidence`,
  `TestMergeNeverPairsAcrossPIDReuse` pass; `TestMergeUnknownIdentityGapKnownToday`
  is skipped with the §9.1 reason.
- Go toolchain is 1.24.7 here; the Mac `go.mod` says 1.27.1. The sandbox run used
  a temporary `go 1.24` line in a scratch copy, which is not written back.

## Handed back

- H7 (§9.1 merge): engineering, contract §14 item 5. principal re-review after it.
- H8 (§3.3 rules 1 and 3): with the eBPF backend, contract §14 item 4.
- ~~H9 (real EPERM)~~ **verified 2026-11-04**: seccomp-denied `bpf()`/netlink; see the H9 row.
- ~~H10 (intermittent `TestPhase2AcceptanceMatrix`)~~ **resolved 2026-11-04**: bundle-selection race fixed; see the H10 row.
- H11 (§6.3 b identity checks on the Go side): engineering, protocol §6.3 b.
- H12 (op 7 on the Go side): align with cgroup watches.
