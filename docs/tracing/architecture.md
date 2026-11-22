# Tracing architecture (Phase 6)

> **Normative decisions live in [`contract.md`](contract.md)** (principal, 2026-11-02):
> eBPF is the required primary backend and the proc connector is the fallback
> (§2), plus event semantics, identity, loss and clock rules. Where this page
> disagrees with the contract, the contract wins.

## Why Rust exists at all

The honest answer: **polling cannot reliably capture short-lived or
high-resolution lifecycle events.** Not "Rust is faster."

A 1 Hz or 2 Hz snapshot loop can miss an entire process life:

```text
sample N:   process absent
    ↓ (process lives 8 ms, exits)
sample N+1: process absent again
```

Phase 6 adds a second sensor class with a different fidelity profile:

```text
Go polling  = broad, inexpensive system state (whole-host truth)
Rust tracer = precise high-frequency lifecycle events (scoped, filtered)
```

The rest of Runopsy does not care which language produced the evidence;
both feed the same event stream, timeline, signatures and causal engine.

## Component boundaries

```text
Linux kernel (cn_proc / netlink connector)
        ↓ subscribe, recv
Rust tracer (trace-rs/, out-of-process)
        ↓ filtered TraceEvents over one Unix socket
Go agent  (internal/trace/)
        ↓ normalized events, loss/restart bookkeeping
Phase 1 snapshots + Phase 5 provider events → timeline → signatures → causality
```

Deliberately **not** in Phase 6: general syscall tracing, socket lifecycle,
file activity, eBPF deployment (see non-goals below).

## Scope (supported events) and why each exists

| Event                | Why it exists |
|----------------------|---------------|
| PROCESS_EXEC         | job process trees appear faster than the sampler can see; short-lived children of Runner.Worker (6.9) |
| PROCESS_EXIT         | exit status + exit-by-signal; supports OOM_KILL, orphan-job, and process-group-termination inference (6.10) |

Known-unsupported in Phase 6 (advertised as capability `false`, not
silently missing): signal sent/delivered, stop/resume, direct OOM-kill.
cn_proc does not expose them; the tracer refuses to fake support (6.14/6.16).
The polling path remains authoritative for those facts until a backend that
can observe them ships.

### Non-goals

- General syscall tracing (different product; different privacy posture).
- Socket lifecycle events (Phase 5 already models connection-level state by
  polling; revisit only with evidence polling cannot provide).
- eBPF as the Phase 6 backend (see below — designed-for, not implemented).
- Replacing any Phase 1 collector.

## Backend separation (6.17/6.18)

`TraceBackend` is a trait (`trace-rs/src/backend.rs`): `name()` and
`run(watch, out, loss, stop)`. Nothing above the trait knows how events are
collected, only that a bounded sender receives `TraceEvent`s. The Phase 6
backend is `proc_connector`; an eBPF backend (6.19 successor) slots in with
zero transport or agent changes.

### Why proc-connector first, eBPF later

cn_proc (netlink connector) is unprivileged on modern kernels, needs no
kernel modules, no CO-RE toolchain and no CI kernel matrix, and covers the
two events Phase 6 strictly needs (exec, exit with wait status). eBPF would
add stronger coverage (signals, stop/resume, OOM) but also privilege
requirements, verifier debugging, and a much larger unsafe/FFI surface. The
backend seam keeps that upgrade cheap; it is deliberately postponed until the
Go↔Rust protocol is stable in production use.

### Privilege model (6.20)

| backend        | privilege |
|----------------|-----------|
| proc_connector | unprivileged on 6.18 (verified); older kernels need CAP_NET_ADMIN (contract §2.4); initial network namespace only; subscribe failure is reported and collection degrades, never panics |
| eBPF (future)  | CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN pre-5.8); to be documented when implemented |

The agent must degrade gracefully on capability loss:

```text
eBPF/tracing unavailable → polling-only mode
not: eBPF/tracing unavailable → Runopsy unusable
```

## Watch-set and filtering (6.22/6.23)

Kernel events arrive at host scale; the tracer filters before the socket:
only PIDs in the watch set are forwarded. The agent resolves trees, cgroups
and provider context itself (it owns Phase 1 + Phase 5 state) and pushes
plain PID lists with ADD/REMOVE/RESET controls. The kernel-side rule stays a
simple set so updates stay atomic. PID reuse safety is the agent's job at the
identity level (`start_ticks` + PID), not a kernel-filter property.

## Fixtures, replay and the debug surface (6.44/6.45/6.48/6.56/6.58)

### Fixtures

`testdata/trace/*.bin` are written by the **production Rust encoder**
(`runopsy-trace genfixtures testdata/trace`), not by a mirrored Go struct, so
the Go suite decodes exactly what the tracer emits. They cover one event
each: exec, exit-by-signal, SIGNAL_SENT, observed stop, OOM, a deliberate
sequence gap (`dropped-events.bin`) and a mis-versioned payload
(`unknown-version.bin`) that must be rejected loudly, never silently.

```sh
make trace-fixtures   # regenerate + run the Go cross-language decode check
```

Treat fixture regeneration as a protocol change: it goes in the same commit
as any framing or schema edit, in both languages.

### Replay

Both sides read the same framed wire format:

```sh
runopsy-trace replay trace.bin          # Rust decoder, per-event text
runopsy-agent trace replay trace.bin    # Go decoder (the incident data path)
```

The Go form also summarises frame counts, bad samples, and the sequence-gap
loss total so evidence completeness is visible without re-parsing (6.26/6.27).

### Debug CLI

```sh
runopsy-agent trace capabilities   # runopsy-trace's capability report
runopsy-agent trace status         # mode + binary the agent would use
```

Both resolve the tracer binary the way the supervisor does; a missing binary
is a degraded message, not a fatal error.

### Agent wiring and debug recording (6.21/6.46)

```sh
runopsy-agent start --tracing auto --trace-debug-output /tmp/trace.bin
```

`start` supervises the tracer next to the recorder (`trace.Manager`): mode
resolution, spawn, handshake, restarts with backoff, and health. The decoded
events are counted and, when `--trace-debug-output` is set, written as frames
that both replay commands read back. Recording is debug-only: it is never the
default, and it is bounded and reports truncation.

The bundle's `tracing` reliability section is stamped from the supervisor's
health at finalize time, after the tracer has stopped — so `active` in a bundle
always describes a session that was running when the incident was captured.

Honest limit: the events are **not merged into the timeline or the bundle's
event stream yet** (6.29/6.47). `start` says so at launch instead of implying
that trace evidence is already contributing to diagnoses.

### Reliability metadata in bundles (6.48)

Every incident written by an agent with a configured tracer carries a
`tracing` reliability report stamped at finalize time — supervision state,
backend, a bounded degradation reason and the observed `/events_lost` total.
The redactor bounds the reason like all free text; a failed report source
degrades to "no tracing section", never a failed capture. Downstream
diagnosis reads it as evidence completeness: **lost events mean incomplete
signal evidence, not absent signal evidence.**

## Backpressure and loss (6.25–6.27)

Source-side sequence stamping, bounded queue, explicit loss counter: see
`docs/tracing/protocol.md` § Sequence. The decisive design rule: **drops are
never silent, and silence after drops is never interpreted as "nothing
happened."**

## Concurrency and unsafe audit (6.41)

- `trace-rs/src/nix.rs` holds the crate's socket FFI surface: six extern fns
  (socket, bind, send, recv, close, setsockopt), each signature-checked against the
  platform ABI, each touching only caller-owned buffers, none retaining
  pointers across calls. Every export is a safe wrapper; no `unsafe` escapes
  into other modules.
- `clock_gettime` in `proc_connector.rs` writes only into a caller-owned
  zeroed `Timespec`; a compile-time check refuses 32-bit targets, whose
  `time_t` would not match. `signal()` in `main.rs` (debug mode) installs a
  handler that only performs an atomic store. Full inventory: contract §11.2.
- fd ownership: exactly one closer per fd (`FdGuard` drop or explicit close
  on session teardown); transfer by `std::mem::forget` at the single
  ownership handoff in `subscribe()`.
- Sharing is `Arc<WatchSet>` + the loss counter only. No `unsafe` anywhere
  else in the crate.

## Loss-of-tracer / failure isolation (6.39/6.40)

```text
tracer crash / socket close → session ends, agent degrades, restart w/ backoff
tracer hang                 → agent-side deadlines; worst case polling-only
malicious/garbage frames    → bounded decode, session torn down, agent alive
kernel subscription fails   → tracer reports degraded capability, keeps serving
```

The invariant is architectural, not a runtime patch: **the Rust enhancement
may degrade; the Go recorder must continue.**

## Privacy posture (6.54)

Phase 6 collects strictly less than it could:

- executable path for EXEC only; **argv and environment are never collected**
- no UIDs, no network endpoints, no file activity
- watch-set filtering means Sims' job churn on an unrelated namespace is
  never forwarded at all
- the trace stream carries exactly the JSON schema of
  `docs/tracing/protocol.md` and nothing else

The Phase 2 privacy framework (redaction policy, incident privacy report)
remains in force for anything copied into bundles; raw trace recording is a
debug-only feature, never a production default (6.46).
