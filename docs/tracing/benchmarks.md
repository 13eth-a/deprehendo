# Tracer performance and churn measurements (6.49–6.51)

Phase 6's acceptance gate says the tracer "must remain lightweight". This
document records what is measured, how, where it runs, and — importantly —
which numbers the harness cannot produce yet.

## What is measured

| Metric | Where it comes from | Honest caveat |
|---|---|---|
| events received / lost | Go `trace.Throughput`, driven by sequence numbers (6.26) | "lost = 0" means no *observed gap*; it is not proof that the kernel emitted everything |
| events/sec | received ÷ observation window | a mean, not a burst peak |
| capture→receive latency | `Session.Latency`: event `monotonic_ns` + handshake anchor vs receive time | `monotonic_ns` is the kernel's own event stamp (principal review O10), so this includes kernel→tracer collection and the socket hop |
| p50 / p95 / p99 | `LatencyStats` nearest-rank over a bounded reservoir | bounded at 65 536 samples; overflow is reported, never averaged away |
| clock skew | negative samples counted separately | a negative "latency" is a broken anchor, not a fast event |
| tracer CPU | `/proc/<pid>/stat` utime+stime of the tracer child | Linux only; USER_HZ=100 is a kernel ABI constant |
| tracer RSS / peak | `/proc/<pid>/status` VmRSS, VmHWM | Linux only |
| tracer-side queue depth | **not measured from Go** | it is a Rust counter (`QUEUE_DEPTH` in `trace-rs/src/transport.rs`); the Go agent can see the *consequence* (sequence gaps: `session.Lost()` / `incident.TraceReliability.EventsLost`) but not the instantaneous depth |

Nothing in the report is inferred or filled in. A metric that could not be
observed is omitted or named as a note, never printed as zero.

## Two layers, measured separately

The Go and Rust halves fail for different reasons, so they are measured
separately rather than blended into one flattering number.

### 1. Go bridge — always runnable

`internal/trace/bench_test.go`

```bash
go test -count=1 -run TestPipelineChurn -v ./internal/trace
RUNOPSY_TRACE_CHURN=100000 go test -count=1 -run TestPipelineChurn -v ./internal/trace
go test -run '^$' -bench . -benchmem ./internal/trace
```

`TestPipelineChurn` drives N synthetic events through the **real** encoder,
the **real** Unix-socket framing and the **real** session reader, then asserts:
no sequence gap, contiguous sequences, no stream restart, and bounded heap
growth (a per-event retention bug shows up immediately at 10k/100k). Sizes are
1 000 by default and 10 000 / 100 000 via `RUNOPSY_TRACE_CHURN`, matching the
1k/10k/100k plan. The benchmarks cover the decode path, a full frame
round-trip, and percentile computation.

### 2. Live tracer — Linux only

`internal/trace/live_linux_test.go`

```bash
make trace-live                     # builds the tracer, then runs the live tests
# or:
RUNOPSY_TRACE_BINARY=$PWD/bin/runopsy-trace go test -count=1 -run TestLive -v ./internal/trace
```

- `TestLiveShortLivedProcessCapture` (6.37): N shells block on stdin, their
  PIDs are put in the watch set, then they are released and `exec` a
  microsecond-lived program. The tracer must see both edges for ≥ 80% of them;
  a 5 ms process-table poll (five times faster than the product default) is
  run concurrently as the baseline, and the trace coverage must not be below
  it.
- `TestLiveTracerOverhead` (6.49/6.50): the same burst, with tracer CPU and
  RSS read from `/proc` before and after. Budgets are deliberately loose
  (≤ 5 ms CPU per event, ≤ 128 MiB RSS, ≤ 50% of one CPU during the burst) —
  they exist to catch order-of-magnitude regressions, not to police a few
  percent on shared CI.

Both tests **skip with a reason** when the tracer binary is missing or the
backend advertises no exec support. A skipped measurement is reported as
missing, not as a passing budget.

## Repeated failure isolation (6.40)

`internal/trace/isolation_test.go` re-executes the test binary as a fake
tracer and attacks the supervisor with each production failure mode:
corrupt frame, mid-frame truncation, panic, `SIGKILL`, hung handshake, absent
socket, incompatible handshake version. Every case asserts the *supervisor*
survives and the reason is reported; none asserts that the tracer succeeded.

`tests/trace_isolation_test.go` then proves the end-to-end invariant: while
tracing is unavailable, the recorder still samples, triggers and saves a
bundle, and that bundle carries `tracing.state = unavailable` with a reason —
so a later reader can never mistake a missing trace stream for evidence that
no signal occurred (6.27).

## Live 100k churn on Linux (contract §14, integration)

The measurements above were taken as root, where `SO_RCVBUFFORCE` grants the
tracer a 16 MiB receive buffer. The deployment case is different: an
unprivileged agent on a host at stock `net.core.rmem_max`, where the kernel
caps the buffer and an overrun has to surface as a gap.

Run on the Lima Ubuntu VM (kernel 7.0.0-34-generic, 4 vCPU) as uid 501 with
no capabilities. eBPF attach was refused for lack of `CAP_BPF`/`CAP_PERFMON`
and the proc connector was selected with that reason, which is the expected
unprivileged path:

```sh
CARGO_TARGET_DIR=/tmp/runopsy-target cargo build --release --manifest-path trace-rs/Cargo.toml
GOOS=linux GOARCH=arm64 go test -c -o bin/trace-churn.test ./internal/trace
RUNOPSY_TRACE_BINARY=/tmp/runopsy-target/release/runopsy-trace \
  RUNOPSY_LIVE_CHURN=100000 ./bin/trace-churn.test -test.run TestLiveChurn -test.v -test.timeout 20m
# or, on Linux with the Go toolchain: make trace-churn-live
```

The driver is one watched `sh` running `/bin/true` back to back; every child is
watched through fork inheritance, the path a real agent relies on between
watch-set pushes. `exit_pids` is one above the request because the driver
shell's own exit is captured too.

| `net.core.rmem_max` | Build | Backend | Wall | EXEC pids | EXIT pids | Loss (gaps / upstream) | Tracer CPU | Peak RSS | p50 latency |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| 212992 (stock) | release | proc_connector | 56.2 s | 100,000 | 100,001 | 0 / 0 | 12.63 s (22.5%) | 5,164 KiB | 55.9 ms |
| 212992 (stock) | release | proc_connector | 53.2 s | 100,000 | 100,001 | 0 / 0 | 11.91 s (22.4%) | 5,160 KiB | 48.4 ms |
| 212992 (stock) | release | proc_connector | 50.6 s | 100,000 | 100,001 | 0 / 0 | 11.62 s (23.0%) | 5,116 KiB | 62.3 ms |
| 4,194,304 | release | proc_connector | 52.8 s | 100,000 | 100,001 | 0 / 0 | 12.36 s (23.4%) | 5,168 KiB | 40.4 ms |
| 4,194,304 | debug | proc_connector | 52.4 s | 100,001 | 100,001 | 0 / 0 | 21.39 s (40.8%) | 5,660 KiB | 44.5 ms |
| 4,194,304 | debug | ebpf | 51.9 s | 100,000 | 100,001 | 0 / 0 | 23.46 s (45.2%) | 11,788 KiB | 134.5 ms |

`make trace-churn-live` builds a **debug** tracer, which is what the debug
rows measure: CPU and p50 are higher than the release rows for the same work,
and the eBPF row is the only root run in this table. The VM's driver/CPU
contention also varies between runs, so wall time is not comparable across
days.

- **Coverage is complete at stock `rmem_max`.** 100,000/100,000 processes
  were seen on both edges at 212,992 bytes per socket, and reproduced twice on
  2026-11-04 at that sysctl on the current tree (3,800 and 4,000 events/s,
  every process on both edges, 0 gaps, 0 upstream drops, test exit 0). At this
  rate the 208 KiB buffer is sufficient, so the 20% loss principal measured is a
  *burst* property (200 processes into the same buffer), not a property of
  steady churn. The 4 MiB rows are a different configuration, kept for
  comparison.
- **Netlink socket drops are not the loss mechanism here.** A third 100k run
  at stock `rmem_max`, taken while the host was also running the Go race
  suite, delivered 98,048 of 100,000 processes with 3,904 sequence gaps and
  3,905 upstream drops — all at stage `queue` — while
  `/proc/net/netlink` reported **0** drops on the tracer's socket and an
  `Rmem` peak of 37,440 bytes. The loss was the tracer's own bounded queue
  shedding under backpressure, not the kernel socket. The run reports both
  numbers, and the harness now records the tracer socket's drops and queue
  depth in every note. It also records how many processes the driver itself
  spawned, and skips with that count when the driver could not produce the
  burst, so an environment limit can no longer look like silent tracer loss.
- **Loss is allowed only when it is accounted.** Two runs on 2026-11-04 did
  lose events: 199,999 and 199,998 of 200,000 received, with 2 and 3 missing
  sequence numbers and 2/2 and 2/3 gaps reported by the session — accounted
  loss, which is the outcome the test exists to measure, not a silence. Those
  runs also exposed that the gate itself was wrong: it failed any sequence
  gap even when the loss counters named it, and it failed reported loss
  whenever all 100,000 processes were captured (the watched driver shell's
  own exit is outside the count, so `exit_pids` is `n+1`). The gate now
  compares the missing sequence numbers the sink observed with what the
  session accounted for; a missing process with no loss still fails, as does
  a gap the session did not report.
- **Memory is flat.** 5,164 KiB peak at 1,000 processes and 5,164 KiB at
  100,000, so neither the identity cache nor the watch set grows with churn.
- **"Lossless" is the weaker, honest claim.** The test fails if a missing
  process has no accounted loss, or if the sink saw more missing sequence
  numbers than the session reported. It does not assume the kernel emitted
  everything it never delivered.
- **Latency is dominated by the collection cadence**, not by the socket: p50
  40–56 ms with a 212–254 ms tail, against 5 ms p95-scale numbers for the Go
  bridge alone. The proc connector wakes in batches; eBPF removes part of
  this hop.
- **Not compared to polling here.** The 100k run is a throughput and memory
  test; the sampling comparison is `TestLiveShortLivedProcessCapture`
  (6.37), which uses microsecond-lived targets.

## Where the numbers land

Run `make trace-live` on the Linux CI runner to produce a current report, and
`make trace-churn-live` for the opt-in 100k process run. This repository's
development host is macOS, where the kernel tracer is `unsupported` by design:
no live numbers are claimed from it. The numbers above were produced on the
Lima VM, and they say which user and which kernel they came from.
