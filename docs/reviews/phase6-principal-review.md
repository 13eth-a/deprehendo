# Phase 6 principal review: tracer, protocol and integration

**Reviewer:** principal · **Date:** 2026-11-02
**Scope:** the principal items in the Phase 6 allocation. That is the primary items
6.2, 6.3, 6.17, 6.25, 6.32 and 6.57 (decided in `docs/tracing/contract.md`)
and the review items 6.4, 6.7, 6.11, 6.13–6.16, 6.19, 6.20, 6.23, 6.24, 6.27,
6.28, 6.34, 6.36, 6.39–6.41, 6.49–6.51, 6.54 and 6.60, all reviewed against
the canonical tree as of this date.
**Method:** every kernel-facing claim was checked on a live Linux 6.18 kernel
(root, tracefs and the proc connector available). The fixed tracer was run
against that kernel: the Rust live test, the Go live tests, the 6.19 demo, and
1k/10k/100k process churn.

## 1. Verdict

**Phase 6 is not acceptable yet.** The slice that landed is well structured:

- a backend trait;
- a versioned, length-framed protocol;
- a careful supervisor;
- honest capability flags;
- fixtures written by the production encoder.

But it had never met a real kernel:

- **No exits were captured.** The tracer decoded no process exit on a live
  kernel (O1, O2).
- **Thread exits would have looked like process exits** (O3).
- **New processes were never watched**, so it could not capture the
  short-lived processes it exists for (O4).
- **Nothing in the agent starts it, feeds it a watch set, or puts its events
  into a bundle** (O5).

The first four are fixed here, with tests built from real kernel bytes. The
fifth, and the backend decision (O6), are the remaining work. The proc
connector cannot meet five rows of the acceptance gate, so eBPF is required
(contract §2.1).

After the fixes, the proc connector backend works well:

- every exec and exit of 100,000 short-lived processes, with no loss (§3);
- the 6.19 demo on a real kernel;
- the Go live tests passing against the real tracer for the first time. They
  are skipped wherever no tracer binary is installed, which was everywhere.

## 2. Findings

Severity is as in earlier phases: S1 means a wrong conclusion or missing
evidence reaches the user; S2 means more certainty than the evidence supports,
or a silent gap; S3 is latent, documentation, or test-only.

| ID | Sev | Where | Finding | Status | Test |
|---|---|---|---|---|---|
| O1 | S1 | `proc_connector.rs` | `PROC_EVENT_EXIT` was `9`. The kernel's value is `0x80000000` [6.18]. No exit event was ever recognized on a real kernel. The synthetic fixtures could not show this, because they were written by the same code. | **Fixed** | `real_kernel_exit_by_sigterm_is_decoded`, `real_kernel_exit_code_is_decoded` (recorded 6.18 bytes) |
| O2 | S1 | `proc_connector.rs` | The exit payload layout was wrong: it read the wait status from `process_pid` and the tgid from `exit_signal`, which is 17. The real order is `pid, tgid, exit_code, exit_signal, ppid, ptgid` [6.18]. | **Fixed** | same |
| O3 | S1 | `proc_connector.rs` | Exits were keyed on the tgid alone. The kernel reports one exit per **thread** (`tid 4844, tgid 4842, exit_signal -1`) [6.18], so every thread a .NET Runner retires would have become an exit of the Listener or the Worker. | **Fixed**: only `pid == tgid` is a process exit | `thread_exit_is_not_a_process_exit`; the live test watches its own multithreaded process |
| O4 | S1 | `proc_connector.rs`, `watch.rs` | No fork handling. Only PIDs the agent had already pushed were forwarded, so any process born after the agent's last update was invisible. The Go live tests worked around this by `exec`ing in an already-watched PID. | **Fixed**: children of watched processes are watched from fork, and exited processes are unwatched | `children_of_a_watched_process_are_watched_from_fork`, `live_short_lived_grandchild_is_captured` |
| O5 | S1 | agent | Nothing in production starts the `Manager`, sends a watch control, calls `incident.Merge`, or sets `TracingSource`. There is no `--tracing` flag (6.21). Bundles never contain trace evidence. | **Open**: engineering queue item 1 | — |
| O6 | S1 | backend | The proc connector has no signal, stop or OOM events. Five gate rows (stop/resume, signal evidence, Phase 3 and Phase 4 consumption, the self-kill demo) are unreachable with it. | **Decided**: eBPF primary, proc connector fallback (contract §2) | — |
| O7 | S2 | `proc_connector.rs` | Kernel-side loss was silent. `ENOBUFS` closed and resubscribed without counting anything, and the resubscribe downtime was also uncounted. With the default ~208 KiB buffer, a 200-process burst lost about 20% of its exits (193/200 execs, 163/200 exits). | **Fixed**: overruns and resubscribes open a sequence gap; the receive buffer is raised to 16 MiB (best effort) | Go `TestLiveTracerOverhead` now passes with 200/200 and 0 loss |
| O8 | S2 | `proc_connector.rs`, `session.go`, `replay.go` | Loss before a session's first event was invisible. Rust numbered the first event 2, and Go counted gaps only after its first event. | **Fixed**: the first event is 1 and both readers count from 0 | `TestNoteSequenceCountsLossBeforeTheFirstEvent`, `a_full_watch_set_is_a_visible_gap` |
| O9 | S2 | tracer, `tracemerge.go` | `start_ticks` was never set, so the merge matched trace and snapshot events by PID within 2 s, which is unsafe under PID reuse (6.11). | **Tracer fixed**: identity from `/proc` with a reuse check. **Merge open** (contract §4, §9.1) | `pid_reuse_after_the_event_yields_unknown_identity`, `stat_parsing_survives_hostile_comm` |
| O10 | S2 | `proc_connector.rs` | Events were stamped with the tracer's read time, not the kernel's event time. With a receive backlog that misorders events and misreports latency. | **Fixed**: the proc event header's kernel timestamp. `docs/tracing/benchmarks.md`'s latency now includes the kernel-to-tracer hop. | `real_kernel_exit_by_sigterm_is_decoded` asserts the kernel stamp |
| O11 | S2 | `tracemerge.go` | The merge orders by wall-clock milliseconds, against `protocol.md` and 6.28, and polling events carry no monotonic stamp. Sub-millisecond signal-then-exit ordering is lost, and a wall-clock step reorders events. | **Open** (contract §8) | — |
| O12 | S2 | `transport.rs` | The watch set outlived the session. A reconnecting agent inherited PIDs that might belong to other processes by then. | **Fixed**: reset at every handshake | — |
| O13 | S2 | `transport.rs` | A killed agent leaves the tracer running forever: there is no `PR_SET_PDEATHSIG`, and it returns to its accept loop. The next agent starts another one. | **Open** (contract §6.3 a) | — |
| O14 | S2 | `transport.rs` | The pump drains events before it reads controls. Under a sustained backlog, acks are starved and the agent's command timeout kills a healthy tracer. | **Open** (§6.3 c) | — |
| O15 | S2 | `manager.go` | Nothing detects a hung tracer. There is no heartbeat, and the agent sends no controls, so `CommandTimeout` never fires. | **Open** (§6.3 e) | — |
| O16 | S3 | `manager.go` | A configured binary that does not exist went through the full restart backoff (3.75 s) instead of "not installed". `TestManagerMissingBinaryDegrades` and `TestRecorderContinuesWhenTracerIsUnavailable` failed on every run. | **Fixed**: an explicit path is checked, never replaced by a PATH lookup, and a missing one degrades at once | both tests pass; `TestResolveBinaryOverride` updated |
| O17 | S3 | `trace-rs/tests` | The "cross-language" Rust tests decode with a mirror struct in `tests/support.rs`, not the production schema. Go-encoded controls are never decoded by the production Rust code. | **Open**: make the crate a library plus a binary | — |
| O18 | S3 | fixtures | `signal.bin`, `process-stop.bin` and `oom.bin` claim `source = proc_connector`, a backend that cannot produce them. `oom.bin` carries `exit_code 137`, a shell convention (128 + 9), not a kernel fact. | **Open**: `source = synthetic`, no exit code on OOM | — |
| O19 | S3 | `debug` mode | The SIGINT/SIGTERM handler set a flag that nothing read, so Ctrl-C and SIGTERM did nothing. | **Fixed** | demo below |
| O20 | S3 | docs | The privilege rule ("unprivileged since ~2.6.37") was wrong. It is unprivileged on 6.18 [6.18] and needs `CAP_NET_ADMIN` on older kernels; the buffer limit was not mentioned. | **Fixed** in `architecture.md`, `fallback.md` and contract §2.4 | — |
| O21 | S3 | `proc_connector.rs`, `main.rs` | `clock_gettime` assumes a 64-bit `timespec`. Current clippy (1.97) rejects two patterns in the touched code. | **Fixed**: a compile-time 64-bit check, lint-clean | `cargo clippy -D warnings` |
| O22 | S3 | `tracemerge.go` | `EvidenceQuality` returns `direct_corroborated`, which mixes quality and confidence. | **Open** (contract §9.2) | — |

## 3. Measurements on a real kernel (6.37, 6.49–6.51)

Linux 6.18, a release build of the fixed tracer, running as root (so the
16 MiB buffer was granted). A watched shell runs N back-to-back `/bin/true`
processes, and the tracer catches each one by fork inheritance.

| N | Wall | EXEC captured | EXIT captured | Sequence-gap loss | Tracer CPU | Peak RSS |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1.8 s | 1,000 | 1,000 | 0 | 0.13 s (7.0%) | 2.4 MiB |
| 10,000 | 17.9 s | 10,000 | 10,000 | 0 | 1.32 s (7.4%) | 2.6 MiB |
| 100,000 | 175.7 s | 100,000 | 100,000 | 0 | 12.91 s (7.3%) | 2.5 MiB |

- **Memory does not grow with churn**, so neither the identity cache nor the
  watch set leaks.
- **0.3–0.5% of execs** (483 of 100,000) arrive after the process has already
  exited. Their path and identity are recorded as unknown, never guessed. The
  eBPF backend reads identity in the kernel and removes this.
- **Against polling:** a 1 Hz sampler takes 176 samples over the 100,000 run,
  so it can see at most 176 of these processes.
- **Still to measure:** these numbers are for root on an idle VM. The run as a
  non-root user with stock `net.core.rmem_max`, where overruns become visible
  gaps instead, is integration's (contract §14).

The 6.19 demo, `runopsy-trace debug <shell-pid>`, with the shell running
`/bin/echo hello` and then a child that kills itself with SIGTERM:

```text
PROCESS_EXEC pid=5410 seq=4 ... path=/usr/bin/echo
PROCESS_EXIT pid=5410 seq=5 ... exit=0
PROCESS_EXEC pid=5411 seq=6 ... path=/usr/bin/dash
PROCESS_EXIT pid=5411 seq=7 ... signal=15 fact=2
PROCESS_EXIT pid=5406 seq=8 ... exit=3
```

Ctrl-C then ended it cleanly.

## 4. Reviewed with no finding

- The supervisor's single owner of `Wait`, its kill-then-reap, and its capped
  backoff with give-up (6.39).
- Bounded frame decoding and the oversize-length rejection (6.6).
- Capability honesty: no backend claims signals, stops or OOM (6.8, 6.16).
- The no-argv/no-environment rule (6.54).
- The bounded reliability reason in bundles (6.48).
- The Go replay decoder (6.45).
- The GitHub correlation test (6.60). It is synthetic, but it says so and
  checks real PPID/PGID relationships. It stays valid until the eBPF backend
  lets it run against the kernel.

## 5. Verification

- `cargo fmt --check`, `cargo clippy --all-targets -D warnings` and
  `cargo test` all pass: 17 tests, including the live kernel test.
- `go vet ./...` and gofmt are clean.
- `go test ./...` passes with and without a tracer on `PATH`, and with
  `-race`. Only the two platform tests that need a real cgroup2 mount fail in
  the review sandbox, as before.
- The gated suites (`RUNOPSY_E2E_GITHUB=1 RUNOPSY_E2E_CAUSAL=1
  RUNOPSY_REVIEW_AUDIT=1`) and `GOOS=darwin go build ./...` both pass.

The Rust dependencies were built from their GitHub sources at the exact locked
versions, because crates.io was unreachable from the review sandbox. Nothing
about that build is in the tree.
