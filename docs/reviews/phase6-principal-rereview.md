# Phase 6: principal re-review (eBPF sources, merge, §11.1)

Reviewer: principal, November 3, 2026. Scope from contract §14: the eBPF
program sources and the merge, before signatures consume them; plus the
§11.1 attack cases the isolation suite did not reach.

## How this was verified

The eBPF backend was run live as root in a Linux 6.18.44 (x86_64) sandbox
with BTF: libbpf 1.5.0 was built from source (libelf headers from the
elfutils mirror), the tracer linked against it, tracefs mounted. All five
capabilities attach. `scripts/ebpf-e2e.sh` was extended to check every
defect below; it **fails on the previous tracer** (six distinct failures)
and passes on the fixed one. This is the same kernel class as engineering's
original E2E, which explains the "6.18/x86_64" in the eBPF handoff entry:
the eBPF backend has still never run as root on the arm64 Lima VM.

## Findings and fixes

| ID | Severity | Finding | Status |
|---|---|---|---|
| O1 | S1 | `PROCESS_STOPPED` named the wrong process. The `CLD_STOPPED` SIGCHLD is queued for the parent, so `signal_generate`'s `pid` is the parent; the stopped process is `current` (contract §3.1, §3.5). Live: `kill -STOP <child>` reported the watched parent as stopped. | Fixed; subject is `current` |
| O2 | S1 | `PROCESS_RESUMED` was never reported: the stop marker was keyed on the parent, so both resume paths missed. | Fixed; reported exactly once across the two sources |
| O3 | S2 | Stop/resume was not gated on the watch set: a stop anywhere on the host was emitted (under its parent's PID) and filled the 4096-entry `stopped` map. | Fixed; gated on the watched subject |
| O4 | S2 | `pidfd_send_signal` used target `-13` as a sentinel, which fell into the group branch: reported as a send to process group 13. A real `kill(-13)` was indistinguishable. | Fixed; explicit mode, target taken from the generated recipient |
| O5 | S2 | `kill(-1)` (everything the sender may signal) would be reported as a send to process group 1. | Fixed; pid and pgid 0, broadcast flag (not run live: as root it signals every process) |
| O6 | S2 | A dead PID in the agent's watch set got an "any identity" kernel entry on every resync **and** a WATCH_FULL loss count each time: fake "events dropped" (15 in a short live run, 0 without it) and PID-reuse adoption (§6.3 f). | Fixed; dead PIDs get no entry and no loss; unit-tested decision function |
| O7 | S3 | A full kernel watch map at fork returned silently (the comment claimed a WATCH_FULL loss). Fork also skipped a stale entry left by an earlier process with the same PID, so the child's events then mismatched and were dropped. | Fixed; counted as WATCH_FULL, stale entry overwritten |
| O8 | S3 | A panic in the ring-buffer callback crosses libbpf's `extern "C"` frame and aborts the tracer. | Fixed; contained, counted as kernel loss |
| O9 | S3 | `build.rs` hard-coded `-D__TARGET_ARCH_x86` and an x86_64 library path; the Lima VM is arm64. | Fixed; derived from the cargo target (arm64 build not run) |
| O10 | S3 | `tp_defs.h` claimed libbpf rejects layout drift at load; it does not (plain structs). Layouts match the 6.18 format files exactly. | Comment corrected |
| O11 | S2 | `FromTrace` dropped a `SIGNAL_SENT`'s sender and addressed group, so a bundle could not say who sent a signal (§3.4) and a group send read as "PID 0". | Fixed; additive `sender_pid`, `target_pgid` on incident events |
| O12 | S3 | §9.1: a pair with both start times unknown still merged on PID and time, even when the polling stream saw the PID reused inside the window. | Fixed; refused as `merge_identity_ambiguous` |
| O13 | S4 | `Merge` sorted the caller's slices in place (the capture's live trace buffer). | Fixed; sorts copies |
| O14 | S1 | §11.1 "100k events queued at a crash": when the tracer exited, the supervisor closed the session without reading what was already in the socket. The new test lost 114 of 100,000 complete events. | Fixed; bounded drain to end of stream (2 s); 100,000/100,000 in 3 of 3 runs |
| O15 | S1 | §11.1 "restart while a watched PID has been reused": the agent pushed bare PIDs, so the tracer resolved each PID's identity at push time and adopted a reused PID. The protocol's STALE_IDENTITY check existed but Go never sent identities, and the tracer refused the **whole** ADD on one stale PID, which would have made every re-push fail and restart. | Fixed; agent pushes `(pid, start_ticks)`; tracer refuses stale PIDs one by one (ACK `stale`); agent drops and counts them (`watches_stale`) |

Reviewed and found sound: the FFI surface in `libbpf.rs` (signatures,
buffer ownership, ring callback lifetime); the tracepoint layouts on 6.18;
exit-status decoding (`group_exit_code` else the leader's `exit_code`);
rule-1 marking; the §9.1 identity rule for known start times; Go-side §6.3 b
identity enforcement; the `Session.Err()` publish-once fix.

## §11.1 attack list, now complete

| Case | Test | Result |
|---|---|---|
| tracer fills its socket while the agent is stopped | `TestLiveSocketFillWhileAgentStalled` (real tracer, 2 s stall, 3,000 processes) | session survives; every missing process is reported loss (eBPF: 94 lost, 94 reported; proc connector: 145 and 145) |
| 100k events queued at a crash | `TestHundredThousandQueuedEventsSurviveACrash` | all 100,000 delivered in order, restart, heap flat (after O14) |
| restart while a watched PID has been reused | `TestReusedWatchedPIDIsRefusedNotAdopted`, `TestLiveRefusesWatchOfReusedIdentity` | stale PID refused alone, rest applied, no restart, no events for the refused PID (after O15) |
| SIGKILL mid-frame, hang, garbage after handshake, other boot | existing `isolation_test.go` | unchanged |

## Verification (sandbox, Linux 6.18.44, root)

- Rust: `cargo fmt`, `cargo clippy --all-targets -D warnings` clean;
  `cargo test` 27 unit (8 new), 8 protocol, 5 wire-compat, all pass.
- eBPF: `scripts/ebpf-e2e.sh` passes on the fixed tracer, fails on the old.
- Go: `gofmt -l` empty, `go vet ./...` clean. Full `go test ./...` with the
  eBPF tracer: everything passes except three environmental tests (a docs
  README not present in the sandbox copy, no readable `/proc/1/fd`, no
  cgroup2 mount); the same three fail with the old tracer.
- Live trace tests pass on both backends (eBPF, and proc connector forced
  with `RUNOPSY_TRACE_BPF_OBJECT=/nonexistent.o`).
- Flakes seen, not reproduced: one full-suite run where three live trace
  tests captured nothing (passed in three later full runs and alone), and one
  of seven `go test -race` runs of `internal/trace` (passed six others,
  including the same configuration). Both under parallel package load; the
  failing test of the race run was not captured.
- Toolchain: Go 1.24.7 locally with an alternate modfile; `go.mod` (1.27.1)
  was not changed.

## Open, outside this review

- ~~A root eBPF run on arm64 (the Lima VM)~~ **done 2026-11-04**: the Lima VM
  passed `scripts/ebpf-e2e.sh` as root with every capability attached.
- ~~Real EPERM refusal (adversarial H9)~~ **done 2026-11-04**: kernel 7.0 allows an
  unprivileged subscribe and answers ECONNREFUSED in a netns, so the EPERM is
  produced by a seccomp filter denying `bpf()`/`socket(AF_NETLINK)`; the
  unmodified tracer reports `insufficient permission` and the agent degrades
  once with no restarts. ~~op 7 on the Go control decoder (H12)~~ **done**: the Go
  decoder and the Rust test mirror accept `ADD_CGROUP`.
- ~~`SIGNAL_SENT`/`OOM_KILL` consumption by Phase 3/4 rules~~ **done**:
  `SIGNAL_TERMINATES_PROCESS@1` and the direct-record path of
  `OOM_CAUSES_PROCESS_EXIT@2` ship with tests, and `OOM_KILL@5` consumes the
  tracer's victim record. GitHub correlation on a real runner remains.
- Compatibility note: a new agent with an old tracer would have its whole
  ADD refused on one stale PID. Both ship from this repository together.
