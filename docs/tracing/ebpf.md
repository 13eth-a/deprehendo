# eBPF backend (6.17–6.20)

> **Status: implemented and live-verified (2026-11-03, kernel
> 6.18/x86_64).** `trace-rs/src/libbpf.rs` (hand-rolled FFI, no new crates:
> crates.io stayed untouched, the backend links the system `libbpf-dev`
> 1.x), `trace-rs/src/ebpf_backend.rs` (attach + ring pump + watch control)
> and `trace-rs/src/ebpf/runopsy.bpf.c` (the kernel programs). The proc
> connector remains the automatic fallback.
>
> Verified live with `scripts/ebpf-e2e.sh`: `runopsy-trace capabilities`
> unprivileged refuses with the privilege reason and selects the proc
> connector; as root every claimed row reports `attached`, and a real
> session captured for a watched subtree `PROCESS_EXEC /bin/sh`,
> `PROCESS_EXIT exit=7`, both child execs, `SIGNAL_SENT signal=15 fact=1`
> and `PROCESS_EXIT signal=15 fact=2` in order with clean sequence numbers.
> CI runs all of this in the `trace-ebpf-live` job.
>
> **principal re-review (2026-11-03), same kernel class:** stop/resume named the
> wrong process (the SIGCHLD recipient, i.e. the parent) and never reported a
> resume; stops of unwatched processes leaked; a pidfd send was reported as a
> group send to pgid 13 and `kill(-1)` would have been a send to pgid 1; a dead
> PID in the watch set produced fake WATCH_FULL loss on every resync. All fixed
> and covered by the extended `scripts/ebpf-e2e.sh`, which fails the previous
> tracer on each. The build derives the BPF target architecture instead of
> assuming x86.
>
> **arm64, root (2026-11-04):** on the Lima VM (kernel 7.0.0-34-generic,
> aarch64) the release tracer built against the system clang and libbpf 1.6.3,
> `runopsy-trace capabilities` reported backend `ebpf` with all five capability
> rows `attached`, and `sudo -n scripts/ebpf-e2e.sh` printed `EBPF-E2E-OK`
> (exec/exit, in-kernel `SIGNAL_SENT`, exit-by-SIGTERM with `fact=2`,
> stop/resume). Every claim in this document is now verified on x86_64 and
> aarch64.
>
> **Watch-set ack ordering (2026-11-04), found by the arm64 live run.** The
> transport acked a watch control as soon as the user-space set was applied,
> while the pump mirrored it into the kernel `watched` map on its next poll
> (up to 100 ms later). Processes started in that window were filtered as
> unwatched and nothing counted them as loss: two live capture tests saw 0 of
> 24 and 0 of 400 edges. The ACK now waits for the pump's `mark_synced` and
> becomes an error ACK if the mirror does not complete, so coverage starts
> exactly at the ACK. After the fix the same tests capture 24/24 and 400/400
> with zero reported loss.

## Why eBPF is the eventual primary

The proc connector can observe exactly two classes: exec and exit. The Phase 6
acceptance gate also requires stop/resume, useful signal evidence, and OOM
evidence for Phase 3 signatures and Phase 4 causality. Those cannot be derived
from cn_proc at all, so a proc-connector-only tracer would close Phase 6 with
gate rows unmet.

The contract therefore makes eBPF the primary backend and keeps the proc
connector as the fallback:

```text
eBPF (programs attached)        → primary
proc connector (subscribed)     → fallback
neither                         → tracing unavailable, polling-only
```

Selection in `auto` mode tries them in that order, and each failure reason is
reported to the agent as the capability reason instead of being swallowed
(`docs/tracing/fallback.md`).

## The seam that already exists

`trace-rs/src/backend.rs` defines the only thing the rest of the crate knows
about collection:

```rust
pub trait TraceBackend {
    fn name(&self) -> &'static str;
    fn run(&self, watch: Arc<WatchSet>, out: SyncSender<TraceEvent>,
           loss: Arc<AtomicU64>, stop: Arc<AtomicBool>);
}
```

`transport.rs` (socket, framing, controls), `schema.rs` (the wire contract) and
the Go side in `internal/trace` never learn how events are produced. Adding the
eBPF backend is therefore additive: no transport, protocol or agent change, and
no eBPF assumption leaks into `event`/`transport`/Go code.

## Attach points (contract §2.3)

| Event | Attach point |
|---|---|
| `PROCESS_EXEC` | `sched:sched_process_exec` (`filename`, `pid`, `old_pid`) |
| `PROCESS_EXIT` | `sched:sched_process_exit` (`group_dead` gates the process-level exit) |
| fork, internal only | `sched:sched_process_fork` raw tracepoint (parent/child `task_struct` pointers; in-kernel watch inheritance + user-space mirror) |
| `SIGNAL_SENT` | `sys_enter_{kill,tkill,tgkill,rt_sigqueueinfo,rt_tgsigqueueinfo,pidfd_send_signal}` with the exit handlers; the enter side records the sender operand, the exit side emits once with the syscall return. Gated on the **watched sender** at enter time |
| rule-1 marking | `signal:signal_generate`: a kernel-generated signal with an attributable `si_code` (`SI_USER`/`SI_TKILL`/`SI_QUEUE`) inside the syscall window marks the pending send |
| `PROCESS_STOPPED` / `PROCESS_RESUMED` | job-control stop confirmed by `SIGCHLD` with `CLD_STOPPED` (§3.5); resume by `CLD_CONTINUED`, or by a generated `SIGCONT` for a stopped subject, reported once. The subject of a `CLD_*` SIGCHLD is `current` (the process that stopped or resumed); the tracepoint's `pid` field is the SIGCHLD recipient, its parent. Gated on the watched subject. `signal:signal_deliver` is deliberately **not** attached: the confirmation paths above are the honest ones, so `signal delivered` facts stay `not_collected` |
| `OOM_KILL` | `oom:mark_victim` (`pid` is the victim; `current` is never the victim) |

Identity (`tgid`, `start_boottime`, pgid, `real_parent->tgid`) is read from
`task_struct` by CO-RE **in the same program**. It is never re-read from
`/proc` afterwards: the process may be gone by then, which is the whole reason
the tracer exists.

Events reach user space through a BPF ring buffer, then take the same path as
proc-connector events: watch-set filter → bounded queue → socket.

Toolchain: system `clang -target bpf` (CO-RE, committed `vmlinux.h` from
kernel 6.18) and the system libbpf (`libbpf-dev` ≥ 1.x). `build.rs` compiles
`src/ebpf/runopsy.bpf.c` at cargo build time; a toolchain without clang
builds a binary that reports the backend `unavailable` with the honest
reason while the rest keeps working. The crate stays dependency-free; no
crates.io API or FFI-generator was added.

Kernel floor is 5.15 (`bpf_task_from_pid`, enforced at runtime by the
availability check; ring buffer needs 5.8). Below it the backend reports
`unavailable: kernel too old` with the reason and `auto` falls back; a
kernel-version guess never sets a capability to `true`.

## Capability honesty (6.8/6.16)

A capability is `true` only when its programs actually attached. In
particular:

- `oom_kill` is `false` unless `oom:mark_victim` attached.
- `signals` is `false` unless the syscall and signal tracepoints attached.
- Lockdown in confidentiality mode blocks kernel reads: reported as
  unavailable, not as a silent empty stream.

Go must never assume a feature exists because the backend name says "eBPF".
The handshake carries the real booleans, and signature confidence is gated on
them (`internal/incident/quality.go`, `docs/tracing/fallback.md`).

## Failure modes to keep in mind while implementing

| Failure | Required behavior |
|---|---|
| verifier rejects a program | capability `false` with the reason; tracer still serves what did attach |
| attach succeeds, ring buffer fills | counted loss (`TRACE_EVENTS_DROPPED`), never a silent gap |
| tracer crashes mid-stream | Go survives, degrades, restarts with backoff (6.39/6.40) |
| `unsafe`/FFI in the backend | confined to the module, every block documented with its invariant (6.41, contract §11) |

## What is deliberately not here

General syscall tracing, socket/file/scheduler events, per-thread lifecycle,
argv, environment and UIDs. See contract §1 and
[`architecture.md`](architecture.md) § Scope.
