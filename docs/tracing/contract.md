# Phase 6 tracing contract (principal)

**Author:** principal · **Date:** 2026-11-02 · **Status:** normative.

This document holds the principal decisions for Phase 6: 6.2 scope, 6.3 schema
semantics, 6.17 backend choice, 6.25 backpressure, 6.32 evidence quality and
6.57 schema policy. It also holds the invariants that the principal reviews hold the
implementation to (6.4, 6.7, 6.11, 6.13–6.16, 6.19–6.20, 6.23–6.24,
6.27–6.28, 6.34, 6.36, 6.39–6.41, 6.54, 6.60). Where `architecture.md`,
`protocol.md` or `fallback.md` disagree with it, this document wins.

The review that produced it, with every finding and its status, is
`docs/reviews/phase6-principal-review.md`.

Kernel facts marked **[6.18]** were observed on a live Linux 6.18 kernel during
the review, with tracefs and the proc connector, not taken from memory. The
raw captures are summarized in §3.

---

## 1. Scope (6.2)

The tracer exists because **polling cannot reliably capture short-lived or
high-resolution lifecycle events**. Each event class below exists for one
thing polling cannot do.

| Class | Why it exists (what polling cannot do) | Backend |
|---|---|---|
| `PROCESS_EXEC` | Sees children that live and die between two samples, with the executable at exec time | proc connector, eBPF |
| `PROCESS_EXIT` (per process, never per thread) | The exit status of a process the agent is not the parent of, and the exact exit instant | proc connector, eBPF |
| `SIGNAL_SENT` | Who asked for a signal, and to what address (one PID, a process group, everything) | eBPF only |
| `SIGNAL_GENERATED` | Which processes the kernel actually queued it for, and with what result | eBPF only |
| `SIGNAL_DELIVERED` | Whether the target ran a handler, ignored it or took the default action | eBPF only |
| `PROCESS_STOPPED` / `PROCESS_RESUMED` | Job-control stops and continues as they happen, instead of a `T` state seen later | eBPF only |
| `OOM_KILL` | The victim the OOM killer chose, at the moment it chose | eBPF only |

Fork is not a stream event in v1. The tracer uses it internally to watch
children from birth (§5). Emitting `PROCESS_FORK` (type 7) is an allowed
additive change once Go needs a child's parent before it execs.

**Non-goals.** These are refused, not deferred by accident:

- General syscall, socket, file or scheduler tracing.
- Per-thread lifecycle. Threads matter only through thread-group semantics.
- argv, environment, UIDs.
- Anything Phase 1 already measures. The tracer never reports CPU, memory,
  file descriptors or pressure. The OOM event does not forward the kernel's RSS
  fields; Phase 1 owns memory.
- Processes in a non-initial PID namespace (§2.4).
- The cgroup freezer and ptrace stops. They are not job-control stops (§3.5).

## 2. Backend (6.17–6.20)

> **Implementation status (November 3, 2026).** Landed as specified except
> three recorded deviations:
> 1. **Toolchain (§2.2):** no `libbpf-rs`/`libbpf-cargo` — the loader is a
>    hand-rolled FFI against the system `libbpf-dev` 1.x
>    (`trace-rs/src/libbpf.rs`), keeping the crate crates.io-free; `build.rs`
>    compiles the C package with system `clang -target bpf` and the crate
>    still builds on macOS with the backend refusing.
> 2. **Kernel floor:** runtime enforcement says 5.15 (`bpf_task_from_pid`),
>    not the §2.4 sketch's 5.8 — the identity helper is the floor.
> 3. **`SIGNAL_DELIVERED`:** `signal:signal_deliver` is not attached; the
>    stop/resume confirmations run through `SIGCHLD`/`SIGCONT` exactly as
>    §3.5 specifies, and `signal delivered` facts report
>    `not_collected` with that reason instead of being fabricated.
> Live verification: `scripts/ebpf-e2e.sh` + the CI `trace-ebpf-live` job.

### 2.1 Decision

**eBPF is the Phase 6 primary backend and is required for Phase 6
acceptance. The proc connector stays as the fallback backend.**

This reverses `architecture.md`'s "proc connector first, eBPF later". The
acceptance gate requires stop/resume, useful signal evidence, and Phase 3 and
Phase 4 consuming them. The proc connector cannot provide any of these, by
construction: it has no signal, stop or OOM events. Shipping it as the only
backend would close Phase 6 with five gate rows unmet.

After the review fixes, the proc connector is a good fallback. It needs no BTF
and no privilege on recent kernels, and it captured every exec and exit of a
10,000-process burst (`phase6-principal-review.md` §3). Selection in `auto` mode:

```text
eBPF (attach succeeded) → proc connector (subscribe succeeded) → unavailable
```

Each step reports its own failure reason. A capability is `true` only when its
programs actually attached. Kernel-version guesses never set one.

### 2.2 Toolchain

Use `libbpf-rs` with `libbpf-cargo` and BPF programs in C:

- stable Rust, with the most mature CO-RE support;
- the smallest `unsafe` surface in our own code (§11);
- the verifier checks the C side.

`aya` needs a nightly toolchain and `bpf-linker` for BPF-side Rust, which is a
standing CI cost for no product gain.

The eBPF dependency is `[target.'cfg(target_os = "linux")'.dependencies]`, so
the crate keeps building and testing on macOS. BPF objects are built in the
Lima VM and in CI. `vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` and
committed with the kernel release it came from.

### 2.3 Attach points

All of these are present with these fields on 6.18 **[6.18]**:

| Event | Attach point | Fields used | Context (`current`) |
|---|---|---|---|
| EXEC | `sched:sched_process_exec` | `filename`, `pid`, `old_pid` | the exec'ing task |
| EXIT | `sched:sched_process_exit` | `pid`, `group_dead` | the exiting thread |
| fork (watch inheritance) | `sched:sched_process_fork` | `parent_pid`, `child_pid` | the parent |
| SIGNAL_SENT | `syscalls:sys_enter_kill`, `sys_enter_tkill`, `sys_enter_tgkill`, `sys_enter_rt_sigqueueinfo`, `sys_enter_rt_tgsigqueueinfo`, `sys_enter_pidfd_send_signal`, and the matching `sys_exit_*` | target argument, signal, return value | the sender |
| SIGNAL_GENERATED | `signal:signal_generate` | `sig`, `code`, `pid`, `group`, `result` | **not reliably the sender** (§3.3) |
| SIGNAL_DELIVERED | `signal:signal_deliver` | `sig`, `code`, `sa_handler` | the target thread |
| OOM_KILL | `oom:mark_victim` | `pid`, `comm` | **not the victim** (§3.6) |

Identity fields (`tgid`, `start_boottime`, `real_parent->tgid`, the pgid) are
read from `task_struct` with CO-RE in the same program, never from `/proc`
afterwards. Events reach user space through a BPF ring buffer.

Kernel floor: **5.8**, for the ring buffer, `CAP_BPF` and
`bpf_ktime_get_boot_ns`, plus BTF at `/sys/kernel/btf/vmlinux`. Below that, the
eBPF backend reports `unavailable` with a reason and `auto` falls back. If
`group_dead` is missing from BTF, read `task->signal->live == 0` instead.

### 2.4 Privilege and environment (6.20)

| Backend | Needs |
|---|---|
| eBPF | `CAP_BPF` and `CAP_PERFMON` (5.8+); `CAP_SYS_RESOURCE` too below 5.11 (memlock); `CAP_SYS_ADMIN` on older kernels. Lockdown in confidentiality mode blocks kernel reads: reported as unavailable. |
| proc connector | No privilege on 6.18 **[6.18]**: uid 65534 with no `CAP_NET_ADMIN` subscribed and received events. Older kernels refuse an unprivileged listener; as far as I know the relaxation landed in 6.6. Ubuntu 22.04 (5.15) therefore needs `CAP_NET_ADMIN`. Check on the VM with `runopsy-trace capabilities` as a non-root user. Works only in the initial network namespace. |
| proc connector receive buffer | The default netlink buffer (~208 KiB) dropped about 20% of the exits of a 200-process burst. The tracer now requests 16 MiB. `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`; otherwise the request is capped at `net.core.rmem_max`, which is 212992 on stock Ubuntu. Deployments without the capability should raise `net.core.rmem_max` to at least 16 MiB. Drops are visible either way (§7). |

Both backends report PIDs in the initial PID namespace. **The tracer and the
agent must both run in the initial PID namespace.** Otherwise the tracer
reports `unavailable: PID_NAMESPACE`; it never translates PIDs by guesswork.

Grant capabilities to the tracer binary (file capabilities, or systemd
`AmbientCapabilities=`). Never run the whole agent as root just for tracing.

## 3. Event semantics (6.9–6.16)

### 3.1 What the kernel showed [6.18]

| Experiment | Observed |
|---|---|
| `/bin/kill -TERM` to a 3-thread Python with the default SIGTERM action | One `signal_generate sig=15` in the `kill` process. **Every thread's `signal_deliver` reports `sig=9`.** Exit status 143, which is SIGTERM. Exits: two threads with `group_dead=false`, the leader with `group_dead=true`. |
| SIGTERM to a shell that traps it and exits 0 | `signal_deliver sig=15 sa_handler=<address>`, then the exit 10 ms later with status 0 |
| `kill -TERM 0` from a session leader with two children | Three `signal_generate` events, all in the **sender's** context, the sender included. Nothing in `signal_generate` says "process group". |
| SIGSTOP, then SIGCONT, then SIGKILL to `sleep` | STOP: `signal_deliver sig=19 sa_handler=0`, then SIGCHLD `code=5` (CLD_STOPPED) generated **in the stopped process's context**. CONT: `signal_generate sig=18 res=1` (**"ignored", yet the process resumed**), then SIGCHLD `code=6` (CLD_CONTINUED). KILL: SIGCHLD `code=2` (CLD_KILLED). |
| proc connector, a process with one extra thread that exits 7 | Thread exit `(pid 4844, tgid 4842, status 0, exit_signal -1)`; process exit `(4842, 4842, 0x0700, 17)`. `PROC_EVENT_EXIT` is `0x80000000`. |

### 3.2 EXEC and EXIT

- **EXEC** carries the executable path and the identity of the process (§4).
  With the proc connector, both are read from `/proc` when the event is
  received. A process that has already exited by then yields an unknown
  identity and path: 0.3–0.5% of 10,000 `/bin/true` runs. That is unknown,
  never wrong (§4).
- **EXIT** is emitted once per thread group, when the group dies. With eBPF
  that is `group_dead`; with the proc connector it is `pid == tgid`. A thread
  exit is never a process exit. The Runner's .NET processes retire threads
  constantly.
- **The termination signal comes only from the exit status.** The status is
  what the parent's `wait` would see: `signal->group_exit_code` for a group
  exit, otherwise the leader's `exit_code`. A low-7-bits value is the signal;
  otherwise `(status >> 8) & 0xff` is the code. This is the only source of
  "killed by signal S" (§3.1, first row).

### 3.3 Signals: three facts, never interchangeable

| Fact | Meaning | Source |
|---|---|---|
| `SIGNAL_SENT` | Process Y **asked** for signal S to address A: a PID, a thread, a process group (from `-pgid`, or from `0`, resolved to Y's pgid at send time), or everything (`-1`). Carries the syscall's return value. | kill-family syscall entry and exit |
| `SIGNAL_GENERATED` | The kernel **queued** S for task X, with a result: 0 queued, 1 ignored, 2 already pending, 3 overflow, 4 info lost. The kernel calls result 0 `DELIVERED`. **We do not**: queued is not delivered. | `signal_generate`, one per target |
| `SIGNAL_DELIVERED` | Target X **dequeued** S and took the default action, ignored it, or ran a handler (from `sa_handler`: 0, 1, otherwise). | `signal_deliver` in X's context |

Rules:

1. **The sender of a generated signal is known only when** the generation
   happens inside a kill-family syscall of `current` (a per-task flag set at
   `sys_enter_*` and cleared at `sys_exit_*`) **and** `si_code` is `SI_USER`
   (0), `SI_TKILL` (-6) or `SI_QUEUE` (-1). Then the sender is `current`.
   Otherwise the sender is unknown and the event says so. Kernel-originated
   signals are not sent by whoever happens to be `current`:
   - the OOM killer's SIGKILL is `SI_KERNEL` in the allocating task's context;
   - SIGCHLD is `CLD_*` in the child's context;
   - also faults, timers and terminal hangups.
2. **Group addressing is visible only in `SIGNAL_SENT`.** `signal_generate`
   shows the fan-out, one event per member (§3.1, third row). A
   `SIGNAL_GENERATED` carries the `send_id` of its `SIGNAL_SENT` when there is
   one, so Go can count the fan-out.
3. **Group-exit conversion.** Once a fatal signal starts a group exit, the
   kernel delivers SIGKILL to every thread (§3.1, first row). A `signal_deliver
   sig=9` that follows a fatal generated signal other than SIGKILL, for the
   same thread group, is marked `group_exit_conversion` and is never reported
   as "SIGKILL delivered".
4. **A result is not an effect.** SIGCONT reported as "ignored" still resumed
   the stopped process (§3.1, fourth row). Resume is judged by §3.5, not by the
   result field.

### 3.4 What each fact allows us to claim (6.14, 6.34)

| Claim | Requires | Edge, quality |
|---|---|---|
| X was killed by signal S | `EXIT(X)` with termination signal S | fact, direct |
| Y sent S | `SIGNAL_SENT` by Y, or `SIGNAL_GENERATED` with sender Y (rule 1) | fact, direct |
| Y's signal killed X | `SIGNAL_GENERATED(S → X, sender Y, queued)` at t1, `EXIT(X)` killed by S at t2 > t1, and no other sender queued S for X in [t1, t2] | `CAUSES`, direct. With two senders: "killed by S; S sent by {Y, Z}", with no single cause. |
| X shut down in response to S | `SIGNAL_DELIVERED(S → X, handler)`, then `EXIT(X)` with an exit **code** | `TRIGGERED`, direct. Not "killed by S". |
| X was OOM-killed | `OOM_KILL(victim X)` | fact, direct. The Phase 5 path (exit by SIGKILL plus a cgroup `oom_kill` rise) stays as derived evidence. |
| X stopped / resumed | §3.5 | fact, direct |

Signal timing alone never licenses `CAUSES`. This is the Phase 4 causal
discipline unchanged.

### 3.5 Stop and resume (6.12)

- **`PROCESS_STOPPED`** is a delivered SIGSTOP, SIGTSTP, SIGTTIN or SIGTTOU
  with the default action, **confirmed** by SIGCHLD with `si_code`
  `CLD_STOPPED` (5) generated in the stopped process's context **[6.18]**.
  - SIGTSTP, SIGTTIN and SIGTTOU to an orphaned process group are dequeued
    but discarded. The confirmation is what tells these cases apart.
  - If the parent set `SA_NOCLDSTOP`, no SIGCHLD is generated. The stop is
    then "delivered, unconfirmed", one confidence step lower.
- **`PROCESS_RESUMED`** is SIGCHLD with `CLD_CONTINUED` (6), or SIGCONT
  generated for a stopped target. Resume happens at generation, whatever the
  result field says (§3.3, rule 4).
- ptrace stops and the cgroup freezer are not job-control stops and never
  produce these events. `FROZEN_PROCESS` keeps its polling basis for them.

### 3.6 OOM (6.16)

- `oom:mark_victim` names the victim in its `pid` field. `current` is
  whichever task triggered the allocation, so it is never the victim and
  never "the killer".
- The SIGKILL that follows is `SI_KERNEL` in that same unrelated context.
  Rule 1 keeps it from being attributed to a sender.
- The event carries the victim's identity and the victim's cgroup id, read
  from the victim task. The constraint (memcg or global) is `UNKNOWN` unless a
  later kprobe on `oom_kill_process` provides it; that is not required.
- `uid` and the RSS fields are not forwarded (§1, §12).
- The OOM capability is `true` only if `mark_victim` attached. No fixture or
  build may claim it otherwise.

## 4. Identity (6.11)

- **Key:** `(tgid, start_ticks)`. `start_ticks = start_boottime_ns /
  10,000,000` (USER_HZ = 100). This equals `/proc/<pid>/stat` field 22 and
  Phase 1's `StartTicks`.
- Every event carries the identity of each process it names: subject, sender,
  target, parent. `0` means unknown, and unknown is never matched as if known.
- eBPF reads identity in the kernel, so it is exact.
- The proc connector reads `/proc` when the event is received. It accepts the
  result only if that process had started by the event time (the
  `started_by` check, implemented). A PID reused after the event therefore
  yields unknown, not the new process.
- **Matching in Go.** Equal PIDs with both identities known and different are
  different processes. If one side is unknown, they match only when the known
  identity's observed lifetime covers the event time. That means it was seen
  alive at or before the event, and no other identity for that PID started
  before the event.
- Late events are merged by timestamp when the bundle freezes. An event is
  never dropped for arriving late.

## 5. Watch set and filtering (6.22–6.23)

1. **Inheritance at fork, inside the tracer.** A child of a watched process
   is watched from its fork, before it can run. An agent round trip would
   arrive after a short-lived child has gone, which is the case the tracer
   exists for. This is implemented for the proc connector; with eBPF the fork
   program updates the in-kernel map.
2. **Removal at exit, inside the tracer** (implemented), so a reused PID does
   not inherit a dead process's watch.
3. **Reset at every handshake** (implemented). A new agent session never
   inherits a previous session's PIDs.
4. **Identity-keyed controls (to do).** `ADD_PROCESS` and `REMOVE_PROCESS`
   carry `(pid, start_ticks)`. The tracer refuses an add whose start time does
   not match the live process (`STALE_IDENTITY`). `ADD_CGROUP` watches a
   cgroup id.
5. **Filter rule.** A signal passes if its sender or its target is watched.
   An OOM victim passes if it is watched or is in a watched cgroup.
6. **Coverage starts when watching starts:** at the add's ack, or at birth for
   an inherited child. Earlier events were not observed. For a backend that
   filters in the kernel (eBPF) the ack is written only after the set is in
   the kernel map; a mirror that does not complete is an error ack, never an
   implied watch (`protocol.md`).
7. **A full watch set is loss** (implemented). The child that could not be
   inherited is recorded as a gap (§7), never silently unwatched.

## 6. Protocol (6.3–6.7, 6.24, 6.57)

### 6.1 Encoding (review of 6.4)

**Keep JSON payloads in the length-prefixed frames for Phase 6. Do not move to
protobuf now.**

- The Go module is stdlib-only, and protobuf would be its first dependency.
- The measured cost is small: the tracer used about 7% of one CPU at 550
  processes per second, JSON included.
- The evolution properties the plan wanted from protobuf come from the rules
  in §6.4.

Revisit this when sustained rates pass about 50,000 events per second, or when
a third language joins. The decision is the reviewer's, against the plan's
stated preference, and is recorded here so it is not relitigated by accident.

### 6.2 Invariants

```text
Rust may crash; Go must survive.
Go may die; Rust must exit, never keep running without it.
Unknown optional field          → ignored.
Unknown event type              → kept, labelled TRACE_EVENT_<n>, excluded from diagnosis.
Unknown enum value in a field   → UNKNOWN, never the zero/default meaning.
Unsupported protocol version    → rejected at the handshake, with a reason.
Malformed frame                 → session ends; the agent keeps recording.
A session's first event         → sequence 1 (implemented both sides).
```

### 6.3 Required changes (for engineering)

**Status (November 2, 2026): a–f are implemented** in `trace-rs` and
`internal/trace`, with the Go↔Rust contract tests passing against the
production binary (`trace-rs/tests/wire_compat_test.rs`) and the Rust bytes
decoding in Go (`internal/trace/compat_test.go`). Details per row:

| # | Change | Why |
|---|---|---|
| a | The tracer sets `PR_SET_PDEATHSIG(SIGKILL)`. In supervised mode it serves exactly one session and exits on EOF; the accept loop is for standalone `--socket` debugging only. | Today a killed agent leaves a privileged tracer running forever, and a new agent starts a second one. |
| b | The handshake adds `boot_id`, the PID-namespace inode, `event_clock`, the selected backend, and per-capability `{state, reason}`. | The agent can refuse a tracer from another boot or namespace, and report why a capability is missing. |
| c | The pump reads controls at least every 256 events. | Under an event backlog acks are starved, the agent's command timeout fires and it kills a healthy tracer. |
| d | New `LOSS` frame (kind 5): `{stage, count_at_least, first_ns, last_ns}`. Stages: `KERNEL`, `RESUBSCRIBE`, `WATCH_FULL`, `QUEUE`. | Gaps say *that* events were lost; windows say *when*, which coverage needs (§7). |
| e | New `HEALTH` frame (kind 6), once a second: counters, queue depth, uptime. The agent treats 5 s of silence as a hung tracer. | Today a hung tracer is never detected, because the agent sends no controls. |
| f | Controls are identity-keyed (§5, item 4). | PID reuse safety for watch updates (6.23). |

The socket path can stay. It lives in an agent-private `0700` directory, and
`socketpair` with an inherited fd is a later simplification, not a fix.

### 6.4 Compatibility policy (6.57)

- **`PROTOCOL_VERSION`** covers frame kinds, the handshake and control
  semantics. It is negotiated as a range.
- **`SCHEMA_VERSION`** covers the meaning of event payloads. It must match
  exactly.

| Change | Version | Old reader must |
|---|---|---|
| New optional field | none | ignore it. Go's decoder already does; Rust must never use `deny_unknown_fields`. |
| New event type number | none | keep it as `TRACE_EVENT_<n>` and exclude it from diagnosis |
| New value in an existing enum (fact, source, result, disposition, stage) | none | read it as UNKNOWN, never as the zero value |
| Changed meaning, unit or required-ness of a field | `SCHEMA_VERSION` bump | reject at the handshake |
| New frame kind | `PROTOCOL_VERSION` minor bump | not receive it; the newer peer sends it only after negotiating |

Numbers are never reused. Fixtures are regenerated in the same commit as any
schema change. The cross-language test must decode **production** bytes in
both directions: Rust-encoded events in Go (done), and Go-encoded controls in
the **production** Rust decoder (done: `wire_compat_test.rs` speaks Go's exact
framing to the `runopsy-trace` server and asserts the ack field names).

## 7. Loss and coverage (6.25–6.27)

### 7.1 Where events can be lost, and how it becomes visible

| Stage | Example | Visible as |
|---|---|---|
| Kernel | proc connector `ENOBUFS`; eBPF ring-buffer reserve failure (a per-CPU counter in the BPF program) | a sequence gap (implemented for the proc connector); a `LOSS` frame (to do) |
| Resubscribe or attach downtime | connector reset | a gap (implemented) |
| Full watch set | inheritance refused | a gap (implemented) |
| Tracer queue | the bounded 4096-event channel is full | a gap: the sequence is stamped before enqueueing (existing) |
| Session death | tracer crash, socket loss | the session ends; coverage stops at the last event |
| Agent | any bounded channel in Go | the agent counts it into the same reliability report |

A gap of 1 from a kernel overrun means **at least one** event was lost. The
kernel does not say how many.

### 7.2 Coverage

Signal coverage for process P over an interval [t0, t1] is **complete** only
if all of these hold:

- the signal capability was available for the whole interval;
- P was watched for the whole interval (§5, item 6);
- no loss overlapped the interval. Until `LOSS` frames carry windows, any gap
  in the session between t0 and t1 counts.

If any condition fails, coverage is **incomplete**. Without a tracer it is
**none**. The bundle records coverage per event class (6.48).

### 7.3 What diagnosis may conclude

- **A received trace event is a fact.** Loss elsewhere never discounts it.
- **Absence is evidence only under complete coverage.** "No signal was sent to
  X" requires complete signal coverage for X over the window. Under incomplete
  or no coverage, diagnosis falls back to the Phase 3/4 inference, with
  neither a penalty nor a bonus.
- A report never says "no signal occurred" when coverage was incomplete. It
  says the signal evidence was incomplete, and why.

## 8. Clocks (6.28)

- **The event time is the kernel's own timestamp.** The proc connector's event
  header carries `CLOCK_MONOTONIC` from when the event happened; the tracer now
  uses it instead of its own read time. eBPF uses `bpf_ktime_get_ns`
  (`CLOCK_MONOTONIC`).
- **`CLOCK_MONOTONIC` is the ordering clock for all streams.** Both processes
  share one kernel. `CLOCK_BOOTTIME` is used only to compare against process
  start times (§4).
- **The agent must stamp every snapshot** with the monotonic time at the start
  and end of its read. Go's `time.Now` does not expose an absolute monotonic
  value, so read it with `syscall.Syscall(SYS_CLOCK_GETTIME, ...)`.
- **Ordering:**
  - trace against trace: by `monotonic_ns`, then by sequence;
  - trace against snapshot: *before* the snapshot's read start, *after* its
    read end, otherwise **concurrent**. The causal engine treats concurrent
    events as unordered.
- **Wall time is for display only.** It is the agent's wall clock minus the
  monotonic age of the event. No ordering or causal claim ever uses wall
  time. Today's merge orders by wall-clock milliseconds; that must change
  (review, finding O11).

## 9. Merge, deduplication and evidence quality (6.29–6.32)

### 9.1 Deduplication

A trace `EXIT(P, t)` and a snapshot disappearance of P are the same exit only
if:

- the identities are compatible (§4); and
- t falls in (the read start of the last snapshot that listed P, the read end
  of the first snapshot that did not].

Otherwise both are kept and the disagreement is recorded as a conflict.
**Implemented (November 3, 2026)** in `internal/incident/tracemerge.go`: the
pair merges only when the identities are compatible — equal known start
times; and when one side carries none, only when the known identity's
observed lifetime (what the polling stream itself saw) covers the event
time, with no other identity of that PID plausibly owning it. Otherwise both
facts survive and the disagreement is recorded in `Event.Conflicts`
(`merge_identity_mismatch/uncovered/ambiguous`, a closed vocabulary the
bundle validation enforces). The snapshot interval is approximated by the
dedup window, because merged differ events no longer carry their bounding
snapshot times; the identity rule — the half of §9.1 that §4 makes decisive
— is enforced exactly.

EXEC pairs with first appearance by the same rule. The merged event keeps
both sources (6.30).

### 9.2 Evidence quality

Quality is scoped to a claim; it is not one universal ranking.

| Value | Meaning |
|---|---|
| `DIRECT_KERNEL` | a kernel trace event observed the fact as it happened |
| `DIRECT_PROCESS` | read from `/proc` or cgroup files, about that process, at that time |
| `DERIVED_SNAPSHOT` | inferred from the difference between snapshots |
| `PROVIDER_LOG` | stated in a provider's log |
| `PROVIDER_API` | stated by a provider's API |
| `UNKNOWN` | none of the above |

| Claim | Strongest | Then |
|---|---|---|
| a process exited, with its status | DIRECT_KERNEL | DERIVED_SNAPSHOT (instant and status unknown) |
| a signal was sent, and by whom | DIRECT_KERNEL | nothing else can establish a sender |
| an OOM kill | DIRECT_KERNEL (victim) | DIRECT_PROCESS (cgroup counter) > DERIVED (SIGKILL plus pressure) |
| a stop | DIRECT_KERNEL | DIRECT_PROCESS (state `T`) |
| a job's outcome | PROVIDER_API ≥ PROVIDER_LOG | the kernel knows nothing of jobs |

- **A finding's quality is its weakest necessary premise.** It is `direct`
  only if every necessary premise is `DIRECT_*`. Reports show "Evidence
  quality: direct | mixed | inferred" (6.61).
- **Corroboration adds confidence, not quality.** The current
  `direct_corroborated` value mixes the two and is replaced.

## 10. Signature and causal upgrades (6.33–6.36)

| Target | Direct (eBPF) | Proc connector only |
|---|---|---|
| `PROCESS_GROUP_TERMINATION` | `SIGNAL_SENT` to group G by Y, the fan-out queued, and two or more members exiting by S (or a handled shutdown) within 100 ms → HIGH, direct | two or more members of one pgid killed by the same signal within 10 ms of each other → MEDIUM, mixed. No sender is named. |
| `FROZEN_PROCESS` | a confirmed `PROCESS_STOPPED` → HIGH, direct | no change: polling |
| `OOM_KILL` | `OOM_KILL(victim)` → HIGH, direct | no change: the Phase 5 counter path |
| `ORPHAN_PROCESS_TREE` | the exact exit instant of the parent, plus the children's parent identity at exec | the same, from the proc connector |
| `CPU_SPIN` | no trace contribution. That is a non-goal, stated so nobody adds one. | — |

**GitHub cancellation (6.35).** The §10A.5 intent cover stays. Trace evidence
adds the sender. A kill inside the cancellation window that was not sent by
the runner's own processes is **not** covered, so the cover tightens.

**Runner self-termination (6.36).** Direct when:

- a process in the job tree, identified at send time, sends to a group that
  contains Runner.Listener (S2 showed that the job, the worker and the
  listener share one pgid), or sends directly to the Listener or the Worker;
  and
- the chain `SENT → GENERATED → DELIVERED → EXIT` is present.

The Listener is .NET and handles SIGTERM, so its link is "handled SIGTERM,
shut down", a `TRIGGERED` edge, unless its exit status is the signal. The
plan's flagship text ("received SIGTERM → exited") must render that way when
the exit status is a code.

## 11. Failure isolation, restart, unsafe (6.39–6.41)

### 11.1 Failure isolation

The supervisor (`internal/trace/manager.go`) is sound: capped backoff, a
give-up rule, a single owner of `Wait`, kill followed by wait. Required on top
of it:

- §6.3 a (die with the agent) and e (detect a hung tracer);
- after a restart, the agent re-pushes its full watch set, because the
  tracer's maps died with the old process;
- a missing binary is "not installed" and degrades at once. Fixed in this
  review; it used to spend 3.75 s of restart backoff.

The attack list for integration (6.40), with the expected outcome in every case
being "the recorder continues and the bundle says tracing was degraded":

- SIGKILL of the tracer mid-frame;
- SIGSTOP of the tracer (hang);
- the tracer filling its socket while the agent is stopped;
- 100k events queued at a crash;
- a restart while a watched PID has been reused;
- garbage after a valid handshake;
- a handshake from a tracer of another boot.

Coverage (November 3, 2026, principal re-review): every case has a test.
`internal/trace/isolation_test.go` covers SIGKILL mid-frame, the hang
(silence watchdog), garbage after the handshake, the other-boot handshake,
**100k events queued at a crash** (`TestHundredThousandQueuedEventsSurviveACrash`)
and **a re-push naming a reused PID** (`TestReusedWatchedPIDIsRefusedNotAdopted`).
Against the real tracer, `internal/trace/attack_linux_test.go` covers **the
socket filling while the agent is stopped** (`TestLiveSocketFillWhileAgentStalled`:
the session survives and every missing process is reported loss) and the
reused identity (`TestLiveRefusesWatchOfReusedIdentity`). Two defects were found
and fixed doing this: the supervisor closed a crashed tracer's session without
reading the events already in the socket (114 of 100,000 lost in the test),
and a re-push carried bare PIDs, so a PID reused during a restart was adopted.
The agent now pushes `(pid, start_ticks)` and the tracer refuses stale PIDs
one by one (protocol: ACK `stale`).

### 11.2 `unsafe` and FFI (6.41)

The whole surface:

- **`nix.rs`:** six libc calls (`socket`, `bind`, `send`, `recv`, `close`,
  `setsockopt`). Every buffer is caller-owned and valid for the call, and every
  fd has exactly one closer. To do: open the socket with `SOCK_CLOEXEC`.
- **`clock_gettime`:** writes a 64-bit `timespec`. A compile-time check now
  refuses 32-bit targets, where `time_t` would not match.
- **`signal()` in debug mode:** the handler is an `extern "C" fn(i32)` that
  only does an atomic store, which is async-signal-safe. It used to set a flag
  nothing read, so Ctrl-C did nothing; fixed.

Rules for the eBPF backend:

- ring-buffer samples are parsed from `&[u8]` with length checks and
  `from_le_bytes`, never transmuted;
- kernel structure reads happen only in BPF C, via `BPF_CORE_READ`;
- the `unsafe` in the generated skeleton is pinned by the `libbpf-rs` version
  and is not counted as ours.

## 12. Privacy (6.54)

Tracing adds exec paths, `comm`, signal numbers and PIDs.

- Exec paths reach a bundle only through Phase 2 redaction, with the path
  class: home directories become `~` and the runner work directory becomes
  `<work>`.
- Never collected: argv, environment, UID. The OOM event's `uid` and RSS are
  dropped in the tracer.
- Raw trace recording (6.46) is debug-only. Raw `kernel-events.bin` does not
  enter bundles in v1; bundles carry normalized events only (6.47).

## 13. Acceptance gate, as of this review

| Capability | Status |
|---|---|
| Rust tracer runs independently | ✅ (`runopsy-trace debug` verified on 6.18) |
| Go↔Rust protocol versioned | ✅ |
| Process exec captured | ✅ proc connector, verified 10,000/10,000 |
| Process exit captured | ✅ after this review (it captured none on a real kernel before) |
| Stop/resume captured | ✅ eBPF, live on 6.18/x86_64 after the re-review fixed the subject (it named the parent and lost every resume); the proc connector does not collect it |
| Useful signal evidence | ✅ eBPF: `SIGNAL_SENT` with sender and addressed target (process, group, or `kill(-1)` with no invented group); bundles keep sender and group |
| PID reuse safe | ✅ tracer (identity-keyed watch map, per-PID STALE refusal of re-pushes), agent (pushes identities), merge (§9.1 identity rule, ambiguity under observed reuse) |
| Trace and polling streams merge | ✅ the capture merges at freeze (engineering item 1) |
| Tracer crash doesn't kill the agent | ✅ (tested; §6.3 a/e landed — pdeathsig, supervision timer); events already written before a crash are delivered |
| Tracing unavailable → polling | ✅ |
| Event drops detectable | ✅ including kernel-side drops and a full kernel watch map; a dead watched PID no longer reports loss that did not happen |
| Trace evidence enters `.runopsy` | ✅ events carry provenance in bundles, and `SIGNAL_SENT`/`OOM_KILL` now reach the causal graph with exact identity (November 4, 2026) |
| Phase 3 signatures consume it | ✅ signal-bound rules see TRACE_* exits; `OOM_KILL@5` consumes the tracer's victim-naming record as its own evidence (November 4, 2026) |
| Phase 4 causality consumes it | ✅ EXEC/EXIT/STOPPED/RESUMED are kernel-direct; `SIGNAL_TERMINATES_PROCESS@1` and the direct-record path of `OOM_CAUSES_PROCESS_EXIT@2` are live (November 4, 2026) |
| GitHub job correlation survives | ✅ verified on a real runner 2026-11-04 (Lima self-hosted, `selfhosted-e2e`): job accepted/assigned/completed `SUCCEEDED` correlated with tracing active (`proc_connector`, 280 traced exits, 0 lost) and **no failure claim**. The false `PROCESS_GROUP_TERMINATION` on a successful job's cleanup is fixed: a stated job outcome covers the job's observed tree, so the leftover job processes the runner SIGKILLs at job end (their own PGID, `signal:9`) are context. Run `41950041166` before (0.80 CRITICAL) and `41950705732` after (no match); fixture `testdata/github/selfhosted-e2e-job-success/` |
| Overhead benchmarked | ✅ live: 7% of one CPU and 2.6 MiB as root at 570 processes/s; 22.5% and 5.2 MiB as uid 501 at 1,800 processes/s with stock `rmem_max` (`benchmarks.md`) |

## 14. Work queue

**engineering, in order:**

1. ~~Agent wiring~~ **done** (November 2, 2026): `start --tracing`, watch-set
   push, `TracingSource`, capture merge at freeze; see HANDOFF.md.
2. ~~Protocol items §6.3 a–f~~ **done** (November 2, 2026): supervised mode +
   PDEATHSIG, handshake identity fields, 256-event control bound, LOSS and
   HEALTH frames, hung-tracer detection, STALE_IDENTITY acks; both test
   suites green.
3. ~~Crate as library plus binary~~ **done** (`src/lib.rs`; integration tests
   use the production schema and decoder, finding O17).
4. ~~The eBPF backend (§2)~~ **done** (November 2, 2026): EXEC and EXIT live
   against a real kernel (6.19 POC parity with the proc connector); signals
   (§3.3), stop/resume (§3.5) and OOM (§3.6) attached with per-capability
   states; see HANDOFF.md. Not buildable in sandboxes without libbpf.
5. ~~Merge and quality~~ **done** (November 2, 2026): TRACE_* extraction into
   the causal graph with trace provenance; §10 signature upgrades live. The
   remaining §9.1 gap — a zero start_ticks pairing on PID and time alone —
   was closed on November 3, 2026 (identity rule + recorded conflicts;
   `TestMergeUnknownIdentityWithoutCoverageStaysTwoFacts` replaced the skipped
   adversarial reproduction).

**adversarial:** fuzz the Go decoder and the production Rust control decoder
(6.42–6.43); edge cases for §3.3 rules 1 and 3 and for §9.1.

**secondary:** cross-language round trips against production code; the §6.4
policy tests; clock tests (§8).

**integration:** ~~the 100k churn run on the Lima VM, as a non-root user with
stock `rmem_max`~~ **done** (November 3, 2026): 100,000/100,000 processes
captured on both edges with zero accounted loss at `rmem_max` 212992, flat
5,164 KiB RSS; the run also found and fixed `Session.Err()` wedging
`Close()`/`Done()`. Method and numbers: `docs/tracing/benchmarks.md`;
findings: `docs/reviews/phase6-integration-churn.md`. The §11.1 attack list is
covered by `internal/trace/isolation_test.go`; the queue-fill,
100k-events-at-crash and PID-reuse-at-restart cases were added by the principal
re-review (§11.1).

**principal re-review:** ~~after engineering items 1 and 4: the eBPF program sources and
the merge, before signatures consume them~~ **done** (November 3, 2026):
eBPF run live as root on 6.18/x86_64 (libbpf built from source in the
sandbox), six defects fixed and covered by `scripts/ebpf-e2e.sh`; merge
identity extended to both-unknown pairs; the three open §11.1 cases tested,
with two defects fixed. Findings: `docs/reviews/phase6-principal-rereview.md`.

**Phase 6 queue: complete.** The November 4 follow-up closed the arm64 root
eBPF run (Lima, `EBPF-E2E-OK` with every capability attached), H12
(`ADD_CGROUP` on the Go decoder and the Rust test mirror), the `SIGNAL_SENT`/
`OOM_KILL` consumption rows (`SIGNAL_TERMINATES_PROCESS@1`, the direct-record
path of `OOM_CAUSES_PROCESS_EXIT@2`, `OOM_KILL@5`), and GitHub job correlation
on a real runner: a successful job's cleanup is no longer a failure claim. A
real EPERM refusal (adversarial H9) was reproduced on November 4, 2026 with
seccomp-denied `bpf()`/netlink on the Lima VM: the unmodified tracer classifies
it as `insufficient permission` and the manager degrades once
(`internal/trace/fallback_linux_test.go`).
