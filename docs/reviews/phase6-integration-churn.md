# Phase 6 integration: the 100k churn run on the Lima VM

**Role:** integration · **Date:** 2026-11-03
**Scope:** the integration item in `docs/tracing/contract.md` §14 — the 100k
process churn run on the Lima VM, as a non-root user with stock
`net.core.rmem_max`. The §11.1 fault-injection list is not part of this run;
its status is recorded at the end.

## 1. Verdict

**The run is complete and lossless.** 100,000 short-lived processes were
captured on both edges, as uid 501 with no capabilities, with
`net.core.rmem_max` at stock 212992. No sequence gap and no upstream loss were
observed, tracer peak RSS stayed at 5,164 KiB, and the stream never restarted.

The run found one defect, in the Go session rather than the tracer:
`Session.Err()` permanently wedged `Close()`/`Done()` when called on a live
session. It is fixed, with a regression test.

## 2. Environment

| | |
|---|---|
| Host | Lima VM `deprehendo`, Ubuntu, kernel 7.0.0-34-generic, 4 vCPU, aarch64 |
| Tracer | `deprehendo-trace 0.1.0`, release build (`cargo build --release`, 20.5 s) |
| Backend | `proc_connector`; eBPF attach refused with an explicit reason: no `CAP_BPF`/`CAP_PERFMON` |
| User | uid 501 (`homeacc`), no capabilities, no sudo for the tracer |
| `net.core.rmem_max` | 212992 for the acceptance run (stock), 4194304 for a second run |
| Agent side | the Linux test binary of `internal/trace`, cross-compiled `GOOS=linux GOARCH=arm64` |

The eBPF sources compiled in the VM (`libbpf-dev` 1.6.3 is installed), so the
build side of the eBPF backend is verified on this host. The attach was
correctly refused for an unprivileged user and fell back with the reason
recorded in `selection_reason` — the path an unprivileged deployment takes.

## 3. Method

`TestLiveChurn` (new, `internal/trace/churn_linux_test.go`, opt-in through
`DEPREHENDO_LIVE_CHURN=N`; `make trace-churn-live` runs 100,000):

1. Start the real tracer and connect the production `Session` over its
   Unix socket.
2. Start one `sh` blocked on stdin, put its PID in the watch set, then release
   it. The shell runs `/bin/true` back to back N times.
3. Count **distinct PIDs** with an EXEC and an EXIT event, the sequence gaps
   and the LOSS-frame totals, the tracer's CPU and RSS from `/proc`, and the
   capture→receive latency reservoir.
4. Drain until the counters stop moving, then assert:
   - a shortfall in captured processes must come with accounted loss, and
     loss may not be reported when every process was captured;
   - one uninterrupted stream (no restarts, no session error);
   - the tracer's peak RSS under 128 MiB and CPU per event under 5 ms.

The children are watched through fork inheritance, which is what the agent
relies on between watch-set pushes. The driver shell's own exit is captured
too, which is why `EXIT` pids are one above the request.

## 4. Results

| `net.core.rmem_max` | Wall | EXEC pids | EXIT pids | Events | Loss (gaps / upstream) | Tracer CPU | Peak RSS | p50 / p99 latency |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 212992 (stock) | 56.2 s | 100,000 | 100,001 | 200,001 | 0 / 0 | 12.63 s (22.5%) | 5,164 KiB | 55.9 ms / 107.2 ms |
| 4,194,304 | 52.8 s | 100,000 | 100,001 | 200,001 | 0 / 0 | 12.36 s (23.4%) | 5,168 KiB | 40.4 ms / 97.5 ms |

At 1,000 processes the same harness reported 1,000/1,001 with 5,164 KiB peak,
so RSS is flat across two orders of magnitude of churn.

Interpretation, with its limits:

- **The 208 KiB buffer is sufficient for this churn shape.** About 1,800
  processes/s and 3,600 events/s did not overrun it. principal's 20% loss was a
  200-process *burst* into the same buffer, and this run says nothing about
  burst headroom at stock `rmem_max`.
- **CPU share is higher than the root run** (22.5% vs 7.3% of one core).
  Different host and per-process cost: this VM churns processes roughly 3×
  faster, and the proc connector wakes per event. Per event the cost is
  unchanged (~63 µs of tracer CPU here).
- **Latency is collection-cadence bound.** p50 40–56 ms across the two runs,
  far above the Go bridge's own microsecond-scale numbers, because the proc
  connector delivers in batches. It is a real capture→receive measurement,
  not an inferred one.

## 5. Findings

| # | Sev | Finding | Fix | Test |
|---|---|---|---|---|
| D1 | S2 | `Session.Err()` called `s.errOnce.Do(func(){})`. Any status reader polling a **live** session consumed the publish-once, so when the reader loop ended it neither stored the terminal error nor closed `closedCh`: `Done()` never fired and `Close()` blocked forever on `<-s.closedCh`. The churn harness deadlocked in cleanup exactly this way. | `errMu` now guards the error value; `errOnce` only publishes (store, then close). `Close()` reads through `Err()`. | `TestErrOnLiveSessionDoesNotWedgeShutdown` (calls `Err()` on a live session, then requires `Close` to return and `Done` to be closed) |
| D2 | S3 | No live churn harness existed. `TestPipelineChurn` is synthetic (real framing/session, fake tracer) and `TestLiveTracerOverhead` stops at 200 processes, so the §14 run had no reproducible command. | `TestLiveChurn` + `make trace-churn-live`, both documented in `docs/tracing/benchmarks.md`. | `TestLiveChurn` at 1,000 and 100,000 |

## 6. State of the §11.1 attack list

The list is integration's other assignment; this run did not attempt it. What
exists today:

- covered by `internal/trace/isolation_test.go`: SIGKILL mid-frame, garbage
  after a valid handshake, hung handshake, absent socket, a mid-frame
  truncation, an incompatible handshake version;
- covered by the identity tests: a handshake from another boot or PID
  namespace;
- **not covered:** SIGSTOP of the tracer (a true hang the silence watchdog
  should catch), the tracer filling its socket while the agent is stopped,
  100k events queued at a crash, and a restart while a watched PID has been
  reused.

## 7. Verification

- `TestLiveChurn` at 1,000 and 100,000 (stock and 4 MiB `rmem_max`), all
  passing, on the Lima VM.
- `TestErrOnLiveSessionDoesNotWedgeShutdown` and `go test ./internal/trace` on
  the macOS host.
- `gofmt -l .`, `go vet ./...`, `go build ./...`, `go test ./...` on the host;
  `cargo build --release` (including the eBPF objects) in the VM.
