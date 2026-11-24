# Phase 6 secondary audit: cross-language review and secondary's item status

**Auditor:** secondary review · **Date:** 2026-11-02
**Scope:** secondary's Phase 6 lane — 6.21 tracing config, 6.44 trace fixtures,
6.46 debug recording, 6.55 Rust CI, 6.58 debug CLI, 6.62 direct-vs-inferred
causal report, 6.63 documentation — plus the independent-review share of
6.3/6.17/6.26/6.30/6.32/6.38/6.47/6.56/6.61 and the Go↔Rust round trips.
**Not covered here:** the principal decisions and kernel review
(`docs/reviews/phase6-principal-review.md`, `docs/tracing/contract.md`), the adversarial
fuzz pass, and the integration performance/churn measurements.

## Verdict

**secondary's items are complete and the suites are green**: Go `gofmt`/`build`/`vet`
and `go test ./...`, Rust `cargo fmt --check`, `cargo clippy --all-targets -- -D
warnings` and `cargo test --all-targets`.

**Phase 6 as a whole is still not acceptable**, and this audit does not change
that: the eBPF backend (contract §2) and the agent's use of the tracer are
still open. Those are principal's contract §14 queue and engineering's implementation.

Two **S1** cross-language defects were found and fixed in this pass. Both were
invisible to every existing test, and both would have broken the live path the
moment the agent exercised the feature.

## 1. Findings

Severity as in Phase 4/5: **S1** a wrong conclusion reaches the user or a whole
invariant is dead, **S2** more certainty than the evidence (or a behavior that
silently diverges), **S3** latent or fidelity.

| # | Sev | Where | Finding | Fix | Test |
|---|---|---|---|---|---|
| L1 | S1 | `internal/trace/schema.go`, `trace-rs/src/schema.rs` | `Control.PIDs` had no `omitempty`, so Go encoded a nil operand list as `"pids":null`. The Rust decoder deserializes `Vec<u32>` and rejects JSON null, so **every** command without PIDs — PING, SHUTDOWN, FLUSH, and RESET with an empty set — would have ended the session the first time the agent sent one. Both unit suites passed because each decoded its own encoder's output. | Go omits `pids` when empty; Rust normalizes `null` **and** absent to an empty list, so an older agent also works. | `TestControlOmitsEmptyOperands` (Go), `production_server_speaks_go_control_protocol` (sends `{"op":3}`, `{"op":5,"pids":null}` and asserts the acks) |
| L2 | S1 | `trace-rs/tests/support.rs`, `protocol_test.rs` | The "cross-language" Rust suite re-implemented the schema, framing and decoders instead of calling the production modules, and the crate is a binary so nothing else could reach them. The Go↔Rust contract was therefore never exercised against the tracer that ships — which is exactly how L1 survived the earlier review rounds. | `trace-rs/tests/wire_compat_test.rs` drives the **production binary**: `replay` over Go-encoded frames and a `--socket` session speaking Go's handshake and controls. Go pins the same golden literals and header (`TestGoGoldenWireBytes`, `TestFrameHeaderGolden`), so a drift on either side fails both suites. | 5 Rust tests × 12 Go compat tests |
| L3 | S2 | `trace-rs/src/main.rs` `replay_mode` | Rust replay aborted on the first undecodable event payload; the Go decoder counts it and keeps going, deliberately, so one corrupt record cannot hide the rest of a recording. Same file, two different verdicts across languages. | Rust replay counts bad samples, prints each and continues; a broken **frame** (truncated/oversized/unknown kind) still aborts, because the boundaries are gone. | `production_replay_counts_a_bad_sample_and_keeps_going`, `production_replay_rejects_a_broken_frame` |
| L4 | S3 residual | `internal/trace/session.go` handshake | The agent's `monotonic_ns` handshake field is filled from `time.Now().UnixNano()` — a wall-clock reading under a monotonic name. Causal ordering is safe (events carry the tracer's `CLOCK_MONOTONIC`, and `Merge` orders on that), but the 6.49–6.51 latency budget anchors on the wall clock, so a clock step between handshake and receipt corrupts p50/p95/p99 instead of being detected. Fix: sample the agent's monotonic clock for the handshake field (Go's monotonic reading via `time.Since(start)` needs no syscall) and compare receipt on the same base. Not changed here: the measurement API is 6.49–6.51's, and the defect only manifests across a wall step. | `TestLatencyRefusesAnUnusableAnchor` covers the adjacent, reachable failure: no reading or an out-of-tolerance anchor is refused, never averaged in as `0` |
| L5 | S3 gap | `cmd/deprehendo-agent/inspect.go` (`status`) | 6.38 asks for tracer health in `deprehendo-agent status`. The command still reports only the recorder's state, so backend, drops and queue health are not visible from it. `deprehendo-agent trace status` covers mode + binary resolution, and bundles carry the reliability section, but the 6.38 row is not met. Left for 6.38's owner (engineering); it needs the runtime's manager handle in the status path. | — | — |

## 2. Reviewed with no finding

- **6.3/6.4 schema and policy.** Snake_case tags are the contract; omit-when-zero
  rules keep "not captured" distinguishable from a real zero (`exit_code:0`
  survives as evidence); an unknown event number is preserved and labelled
  `TRACE_EVENT_<n>`, never dropped and never guessed; an unknown `SignalFact`
  becomes `UNKNOWN` rather than the zero/default meaning; a schema mismatch is
  refused at decode; version negotiation is range overlap; an unknown frame
  kind or control op ends the session instead of being skipped.
- **6.26/6.30/6.31 merge.** The tracer copy owns the normalized entry and the
  differ's observation survives as corroboration underneath it; unmatched
  polling evidence is never deleted; a PID-reuse pair (same PID, different
  start ticks) is not deduplicated even inside the time window; ordering is
  wall time then monotonic.
- **6.32/6.61 evidence quality.** `direct`, `direct_corroborated` and
  `snapshot_derived` are derived from provenance, and the report renders them
  without promoting an inferred chain to a direct one.
- **6.47/6.48 bundle.** The `tracing` reliability section validates state,
  backend and a bounded reason; `events_lost` reaches the report as
  "incomplete evidence", and bundles without the section still decode.
- **6.21 config.** Mode parsing/normalization, invalid-value rejection,
  environment-then-flag precedence, and "disabled never probes the binary".
- **6.46 recording.** Recorded frames are byte-equivalent to what the replay
  decoder reads; bounds and truncation are reported rather than silent.
- **6.58 CLI.** `status` resolves the agent's own mode before asking the binary
  (a mode/binary mismatch is a configuration error, not a healthy tracer); a
  missing binary is a degraded message with exit 1, never a false success.
- **6.55 CI.** The `trace-rs` job runs fmt, clippy `-D warnings` and
  `--all-targets` tests on Ubuntu, which now includes the wire-compat suite;
  `trace-live` keeps the kernel measurements on Linux only.
- **6.44 fixtures.** `testdata/trace/*.bin` are produced by the production Rust
  encoder and decode in the Go suite, including the deliberate sequence gap and
  the mis-versioned payload.

## 3. secondary deliverables

| Item | State |
|---|---|
| 6.21 tracing-mode configuration (`auto`/`ebpf`/`proc`/`disabled`, env + flag, validation) | done |
| 6.44 trace fixtures (production-encoder fixtures + Go decode check) | done |
| 6.46 `--trace-debug-output` recording (bounded, replayable, reported) | done, and wired: `deprehendo-agent start --tracing MODE --trace-debug-output FILE` now supervises the tracer, records the decoded stream, stamps the bundle's `tracing` section from the supervisor's health, and logs a final `tracer state= events= events_lost= recorded_events=` line. Events are counted, not merged into the timeline/bundle event stream yet (6.29/6.47, engineering); start says so at launch rather than implying otherwise. |
| 6.55 Rust CI (fmt, clippy `-D warnings`, all targets, live job) | done |
| 6.58 `deprehendo-agent trace status\|capabilities\|replay` | done |
| 6.62 direct-vs-inferred causal report | done |
| 6.63 docs: this audit, `ebpf.md`, `permissions.md`; existing `architecture.md`, `protocol.md`, `fallback.md`, `contract.md`, `benchmarks.md` | done |
| Review share (6.3, 6.17, 6.26, 6.30, 6.32, 6.38, 6.47, 6.56, 6.61) | done, with L1–L5 above |

## 4. Verification run for this pass

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=1 ./...
cd trace-rs && cargo fmt --all -- --check \
  && cargo clippy --all-targets -- -D warnings \
  && cargo test --all-targets
```

All green: 18 Go packages, 5 wire-compat tests, 8 protocol tests, 7 backend
unit tests. The live kernel measurements (`make trace-live`,
`DEPREHENDO_TRACE_CHURN=10000`) are Linux-only and were not run on this macOS
host; they run in the `trace-live` CI job.

Start was also exercised against the built binary (macOS, 3 s run):

```text
Tracing: auto (eBPF → proc connector → polling only)
Trace recording: /tmp/…/trace.bin
…
tracer state=unavailable reason="tracing is Linux-only; continuing in polling mode" events=0 events_lost=0 restarts=0 recorded_events=0
```

which is the intended degradation: tracing off, recording intact, exit 0.
