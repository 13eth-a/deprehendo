# deprehendo

**Release scope:** phases 1–7.

deprehendo exists to answer a narrow question: when an autonomous agent or a long
job dies, *what actually happened?* "Exit code 1" is not an answer. A frozen
child process, an orphaned grandchild, a full heap, or a TCP connection that is
open but no longer answering are all different failures with the same symptom,
and they need different fixes.

> **Status: Phases 0–2 implemented and acceptance-tested; Phase 3 conservative
> v1 has completed implementation and architecture reviews and evidence-strength calibration.** The Phase 0 fault-injection simulator and a
> foreground flight recorder are available. The agent samples host
> load/CPU/memory/disk, process tables, TCP sockets, PSI, and cgroup state into
> a bounded rolling buffer, with process filtering and partial-failure
> snapshots. A private Unix socket exposes live status, the latest snapshot,
> retained history, and manual incident triggering. A trigger freezes a
> configurable pre/post window into a checksummed, redacted `.runopsy` bundle
> that can be inspected offline. Configuration uses CLI flags; no config file
> is needed.

## Current implementation

| Area | Status |
|---|---|
| Phase 0 simulator | `runopsy-sim` scenarios create process, memory, CPU, signal, and socket conditions |
| Agent binary | `runopsy-agent start`, `status`, and `version`; foreground-only |
| Snapshot model | `collector.Snapshot` with optional System/Pressure/Cgroup sections, `ProcessSnapshot`, `ConnectionSnapshot`, per-cycle collector timings, and an `Errors` list |
| Host system collector | load average, aggregate CPU utilisation (Linux), memory (Linux), disk capacity for `--watch-fs`; independent sensors, partial failures reported per cycle |
| Process filtering | `--watch-pid`, `--watch-name`, `--watch-tree` select watched processes while still sampling the full table for tree expansion |
| FD count | Linux, watched processes only; `open_fds` per process |
| Sampling | configurable interval; one synchronous cycle at a time (no overlap/backlog), missed ticks counted |
| Ring buffer | chronological, capacity `ceil(window/interval)`; age expiry and estimated retained-payload byte budget, including fixed ring slots |
| Process metadata | PID, PPID, PGID, SID, name, state, threads, RSS; Linux adds clock-tick accounting; macOS thread count is unavailable (zero); expensive host-wide thread enumeration is avoided |
| Process CPU deltas | Linux only, keyed on PID + start-time identity (PID-reuse safe); first sample of a process reports 0 |
| Process tree | rebuilt per snapshot; missing parents become roots, pid 1 never assumed |
| TCP collector | Linux `/proc/net/tcp` + `tcp6` parser with readable state names and fixture tests |
| Socket ownership | socket inode → `/proc/<pid>/fd` scan, best-effort attribution with fd number |
| PSI | Linux `/proc/pressure/{cpu,memory,io}` parsers with fixtures |
| Cgroups | agent and watched-process unified (v2) cgroups: identity-checked path, `memory.current`, `memory.max`, `cpu.max`, explicit availability flags |
| Partial failures | one failed collector contributes a `CollectionError` record; the snapshot keeps everything else |
| Self-monitoring | per-cycle and cumulative per-collector timing/errors, uptime, samples, missed samples, buffer utilization; timing is logged at debug and health counters at shutdown |
| Shutdown | SIGINT/SIGTERM graceful cancellation |
| Logging | structured `slog` shutdown summary and configurable log level |
| Inspection/configuration | private mode-0600 Unix control socket for `status`, `dump`, `dump --history`, manual `trigger`, and incident status; CLI flags configure sampling, selection and collector enablement |
| Incident capture | single active incident; default 90s pre / 30s post window; independent bounded prehistory; snapshots and derived events frozen without stopping the recorder |
| Incident triggers | manual control-socket trigger with note, watched-process stopped or opt-in disappearance, memory used-percent and disk-free-percent thresholds with continuous-duration debounce |
| Incident bundles | versioned ZIP (`manifest.json`, `metadata.json`, `snapshots.json`, `events.jsonl`, `privacy.json`), SHA-256 component checksums, conservative export redaction, atomic publication |
| Incident storage | private incident directory, no-overwrite writes, startup stale-temp cleanup, count/age retention |
| Incident inspection | offline `inspect` summary and factual `--timeline`; schema, archive, checksum and privacy validation before output |
| Phase 4 event timeline | offline `timeline` text/JSON, rule-backed causal graph, stable edge explanation, Phase 3 links and explicit unknown-cause reports |

The existing simulator scenarios and usage are described below. The command
`runopsy-sim --help` lists all registered scenarios.

## Requirements

- Go 1.27.1 or newer (`go version`)
- Linux or macOS for the Phase 0 simulator. Linux is the target platform for
  agent collection; macOS currently provides process-table development support.

## Build and checks

```bash
make build          # bin/runopsy-agent, bin/runopsy-sim
make test           # unit + scenario tests
make race           # tests under the race detector
make lint           # gofmt check + go vet + race tests
make acceptance     # end-to-end simulator CLI/JSON/signal/cleanup matrix
```

Without make:

```bash
go build ./...
go test ./...
```

## Phase 1 flight-recorder core

```text
Linux kernel (/proc, /sys/fs/cgroup)        macOS (ps identity/RSS only)
                    \                    /
                     platform collectors
                              ↓
              collector.Scheduler — one synchronous cycle per tick,
              per-collector timing, partial-failure snapshots
                              ↓
          Snapshot (Processes, Connections, Pressure, Cgroup, Metrics, Errors)
                              ↓
                Ring buffer (window/interval snapshots)
                              ↓
          live `status`, latest `dump`, chronological `dump --history`
```

Build with:

```bash
go build -o ./bin/runopsy-agent ./cmd/runopsy-agent
```

Commands:

```bash
./bin/runopsy-agent start [--interval 1s] [--window 120s] [--log-level info] [--watch-fs /]
./bin/runopsy-agent start --watch-name runopsy-sim --watch-tree --window 120s
./bin/runopsy-agent start --watch-pid 5842 --watch-tree
./bin/runopsy-agent status
./bin/runopsy-agent status --json
./bin/runopsy-agent version
./bin/runopsy-agent dump          # latest retained snapshot from running agent
./bin/runopsy-agent dump --history # retained rolling timeline as JSON
./bin/runopsy-agent dump --once    # standalone sample (no process CPU baseline)
./bin/runopsy-agent trigger --note "runner stopped accepting jobs"
./bin/runopsy-agent inspect FILE --timeline --privacy  # offline summary/events/privacy
./bin/runopsy-agent inspect FILE --at -10s             # nearest snapshot to trigger-10s
./bin/runopsy-agent inspect FILE --snapshot 47         # zero-based snapshot index
./bin/runopsy-agent validate FILE
./bin/runopsy-agent extract FILE --output incident/
./bin/runopsy-agent timeline FILE --causal
./bin/runopsy-agent timeline FILE --json --report
./bin/runopsy-agent timeline FILE --explain-edge ED_...
./bin/runopsy-agent incidents list
./bin/runopsy-agent start --collect-network=false --collect-cgroups=false
```

`start` runs in the foreground, prints configuration and platform, and records
snapshots into the ring buffer sized by `ceil(window/interval)`. Samples expire
by age even when queried after recording stops. `--max-buffer-mb` (default 64)
bounds estimated retained Go payload, not total RSS; oversized samples are
counted as dropped without erasing valid history. `dump` reads the running
recorder; `dump --once` takes an independent sample. Both print JSON: host
counts, process entries with `cpu_percent`, TCP connections with ownership
`pid`/`fd` when resolvable, PSI and cgroup sections on Linux, individual
collector timings in `metrics`, and a per-cycle `errors` list. A collector
failing never blanks the other sections.

Collector notes:

- Process CPU deltas compare consecutive samples keyed on PID **plus**
  start-time ticks, so a recycled PID starts a fresh baseline instead of
  producing negative or absurd values. Percentages are per core and may exceed
  100 for multi-threaded processes; the first sample of any process reports 0.
  Linux is the only platform exposing clock ticks, so macOS always reports 0
  here.
- Process trees are rebuilt each cycle from PPIDs inside the same snapshot;
  parents that vanished become roots (nothing is fabricated), and pid 1 is
  never assumed to exist (container PID namespaces).
- The TCP collector parses `/proc/net/tcp` and `/proc/net/tcp6` (halved
  little-endian kernel word order) into readable state names; ownership comes
  from a socket-inode to `/proc/<pid>/fd` scan and is first-wins when a socket
  is shared.
- PSI reads `/proc/pressure/{cpu,memory,io}`; missing resources produce partial
  errors while readable resources survive. Cgroups cover the agent and explicitly
  watched processes. Cgroup v1 is unsupported and reported as an error, not as
  an unlimited v2 group. `memory_max_set` means the literal `max` (unlimited);
  availability flags distinguish missing controller data from a valid zero.
  These are direct group limits, not computed effective ancestor limits.
- `/proc` and `/sys/fs/cgroup` layout is confined to `internal/platform`;
  parsers are pure functions verified against `testdata/proc` fixtures so they
  run on any OS. The host collector composes load, CPU, memory, and disk
  sensors; a failing sensor is named in `snapshot.errors` while the rest of the
  section survives.
- Watch filtering keeps only the selected process tree in each snapshot, but
  `system.process_count` still reports the host total sampled that cycle.
  FD counts are collected only for watched processes on Linux.
- The live Linux acceptance matrix covers `normal`, `cpu-spin`,
  `memory-pressure`, `frozen-worker`, `orphan-process`, `process-tree`,
  `socket-stall`, and exit/fatal-signal disappearance. This is observation,
  not diagnosis: the recorder retains evidence without interpreting causes.
- The sampling loop is serial (no overlapping cycles); ticks consumed by a
  slow cycle are counted as missed samples. Each collector records total,
  last, and average duration plus cycle/error counts. `--log-level debug`
  emits per-collector timing at shutdown; the INFO summary includes uptime,
  sample/error/missed counts, buffer use, last sample, process and connection
  counts. `status` inspects the live recorder (text or `--json`); it returns an
  error if no agent is listening. `dump --history` retrieves the rolling timeline.
  All inspection commands accept `--socket PATH` to select the agent. The default
  socket is user-specific under the OS temporary directory. Normal shutdown
  removes it; a stale socket after SIGKILL must be removed explicitly.
- Linux process thread count comes from `/proc/<pid>/stat`; macOS thread counts
  are unavailable (zero). `open_fds=-1` means not counted or unavailable; zero
  is a valid count. TCP descriptor zero is retained in JSON.
- `--collect-processes=false`, `--collect-network=false`,
  `--collect-pressure=false`, and `--collect-cgroups=false` disable sections
  without reporting failures. All default to true. Configuration is CLI-only.
  PID and name selectors form a union; `--watch-tree` is a boolean modifier.

On macOS the process table comes from `ps` (PID/PPID/PGID/SID/state/
RSS-in-KB/name); TCP, PSI, cgroup, and socket-ownership collection report
explicit not-implemented errors inside `snapshot.errors` instead of pretending
to collect.

## Phase 2 incident capture

Phase 2 preserves the useful part of the recording as a portable `.runopsy`
artifact. It answers "what evidence existed around this failure?" and deliberately
adds no root-cause diagnosis.

```text
continuous recording
        ↓
  90s prehistory + trigger + 30s post-window
        ↓
     immutable incident
        ↓
 incident.runopsy (versioned ZIP + JSON components)
        ↓
 inspect --timeline (offline, checksum-verified)
```

```bash
./bin/runopsy-agent start --watch-name runopsy-sim --trigger-on-stop
./bin/runopsy-sim frozen-worker

./bin/runopsy-agent start --trigger-memory-percent 95 \
    --trigger-disk-free-percent 2 --trigger-duration 5s
./bin/runopsy-agent trigger
./bin/runopsy-agent inspect ~/.runopsy/incidents/inc_....runopsy --timeline
```

Start flags for capture and storage:

- `--capture-pre`, `--capture-post` — evidence window (default `90s` / `30s`).
  The capture keeps its own bounded prehistory, so it can retain more than the
  recorder's `--window` once the recorder has been running that long.
- `--incident-dir` — bundle directory (default `~/.runopsy/incidents`, created
  with mode 0700; override for `/var/lib/...` deployments).
- `--max-incidents` — retained bundles (default 50; `0` disables the count
  limit), `--max-incident-age` — optional age limit (default off).
- `--trigger-on-stop` — trigger when a watched process enters a stopped state;
  requires `--watch-pid`/`--watch-name` and process collection.
- `--trigger-on-process-exit` — trigger when a successfully observed watched
  identity disappears; requires the same watch selector. Intentional exits also
  trigger under this opt-in factual rule; process-collector failures reset its
  baseline rather than being mistaken for process death.
- `--trigger-memory-percent`, `--trigger-disk-free-percent`,
  `--trigger-duration` — factual resource thresholds held continuously for the
  duration (default 5s). Unavailable sensors reset the duration.

Behavior and guarantees:

- `trigger` goes through the private Unix control socket, prints the incident
  ID, and waits for the save. `--note TEXT` attaches a bounded, control-character
  normalized human note. The recorder continues sampling throughout.
- `incidents list` enumerates and validates bundles in the default directory (or
  `--incident-dir PATH`), `validate` reports schema/counts/integrity, and
  `extract` writes only the fixed verified archive members to a new private
  destination. Extraction never overwrites an existing destination.
- `inspect --snapshot N` outputs one zero-based snapshot as JSON;
  `inspect --at -10s` picks the nearest timestamp relative to trigger (RFC3339
  timestamps are also accepted). `--privacy` lists exported category presence.
- Only one incident is active at a time. A second trigger (manual or automatic)
  is rejected; the command reports the conflict rather than creating an
  overlapping capture.
- A watched-process stop fires once per continuous stopped episode per
  PID+start-time identity, so a frozen worker does not create an incident every
  sample.
- Bundle encoding always clones and redacts first. Environment variables,
  command lines, hostnames, repository names and logs are not collected;
  process names, network addresses, paths and free-form errors are replaced.
- Writes use a unique private temp file, file `fsync`, atomic no-overwrite
  publication, and a directory `fsync`. A failed or interrupted save never looks
  like a complete bundle. Stale writer temps older than an hour are removed at
  startup; only complete, correctly named bundles are subject to retention.
- Offline `inspect` validates the archive layout, schema/encoding versions,
  SHA-256 component checksums, timestamps, limits and declared privacy policy
  before printing. It never extracts archive members.

See [`internal/incident/README.md`](internal/incident/README.md) for the state
machine, format contract, limits, crash/disk-full semantics and APIs.

### Measured bundle sizes

Live Linux (Go 1.27.1 container, `RUNOPSY_INCIDENT_SIZES=1`, 50ms interval, one
watched process tree, ~124 retained snapshots):

| Scenario | Snapshots | Events | Stored (deflate) | Uncompressed |
|---|---:|---:|---:|---:|
| normal | 124 | 1 | 14,390 B | 281,537 B |
| cpu-spin | 124 | 2 | 16,102 B | 285,519 B |
| memory-pressure | 123 | 2 | 16,581 B | 282,166 B |
| frozen-worker | 124 | 9 | 17,806 B | 381,283 B |
| orphan-process | 124 | 15 | 18,513 B | 430,665 B |
| socket-stall | 124 | 5 | 15,623 B | 340,722 B |

Representative dense payload (120 snapshots, 12 processes, 8 sockets, PSI and
cgroup sections, 2,322 derived events), darwin/arm64:

| Encoding | Bundle | Encode | Decode | Alloc/encode | Alloc/decode |
|---|---:|---:|---:|---:|---:|
| Store | 1,291,842 B | 22.0ms | 48.3ms | 17.7MB | 26.1MB |
| Deflate | 46,398 B | 25.1ms | 50.3ms | 15.8MB | 26.2MB |

Deflate is the default and reduced the dense payload 28x. Ordinary filtered
incidents stay in the tens-of-KB range, comfortably below the "hundreds of KB
to a few MB" target. Reproduce with:

```bash
RUNOPSY_INCIDENT_SIZES=1 go test -run TestPhase2BundleSizes -v ./tests
go test -run '^$' -bench 'BenchmarkBundle(EncodeRich|DecodeRich)' -benchmem ./internal/incident
```

The live matrix is Linux in a container with a filtered process tree; it is not
a production-scale inventory of a large host. macOS measurements are smaller
because TCP, PSI and cgroup collection is unavailable there.

The seven-scenario Phase 2 CLI acceptance matrix passed on Linux/arm64 in a
container: manual captures for normal, CPU spin, orphan process and socket
stall; automatic captures for memory threshold, stopped process and process
exit. Each case validates its bundle, pre/post evidence and offline commands.
The memory case uses a deliberately low host threshold to exercise the trigger;
it does not prove the injected workload caused host memory pressure. The
The capture state machine, bounded reader, privacy and persistence behavior passed implementation and architecture review. Independent review remains open; v1 remains a local
format contract rather than a released public compatibility promise. User-supplied notes are not
secret-scanned; checksums detect corruption, not forgery.

The CLI surface also includes validated `incidents list`, `extract`, `validate`,
`inspect --at/--snapshot/--privacy`, trigger notes, and opt-in watched-process
exit triggers. The process-exit rule is intentionally factual: it cannot
classify a watched process's disappearance as normal or unexpected.

## Phase 0 simulator

```text
runopsy-sim <scenario> [flags]

  --duration DUR   overall runtime; 0 means the scenario's default
  --verbose        include extra detail
  --json           emit newline-delimited JSON events on stdout
  -h, --help       help (scenario-specific flags appear here too)
```

Exit codes: `0` success (including Ctrl+C), `1` scenario failure or cleanup
failure, `2` usage error. `exit --code N` deliberately exits `N`; fatal
`signal` runs are reported by the caller as 128+signal.

### Available scenarios

| Scenario | Creates |
|---|---|
| `normal` | healthy baseline process |
| `cpu-spin` | busy workers pegging CPU |
| `memory-pressure` | retained resident memory growth up to a limit |
| `frozen-worker` | a SIGSTOPed child, observed in the live process table |
| `orphan-process` | reparented children surviving an early worker kill |
| `process-tree` | process-group kill vs single-process kill semantics |
| `exit` / `signal` | chosen exit codes and real signal death |
| `socket-stall` | open TCP connection with no application-level progress |

### `normal` — healthy baseline

```bash
./bin/runopsy-sim normal --duration 10s
```

Runs for the requested duration, does a small amount of CPU work every 500 ms,
sleeps in between, and exits 0. `SIGINT`/`SIGTERM` stop it cleanly.

### `socket-stall` — open socket, zero progress

```bash
./bin/runopsy-sim socket-stall
./bin/runopsy-sim socket-stall --ping-interval 100ms --stall-threshold 500ms \
                              --stall-duration 5s --stall-after 3
```

A local TCP server answers pings. After `--stall-after` responses it stops
answering without closing the socket, and later resumes on the same connection.
The client declares a stall only after `--stall-threshold` of silence.The simulator's ESTABLISHED claim is inferred from read timeouts and no EOF;
the Phase 1 Linux recorder independently verifies kernel TCP state and ownership.

### `cpu-spin` and `memory-pressure`

```bash
./bin/runopsy-sim cpu-spin --workers 4 --duration 10s
./bin/runopsy-sim memory-pressure --rate 50MB --interval 1s --limit 1GB
```

CPU workers do bounded chunks of arithmetic. Memory pressure retains allocations
and touches pages to make them resident; the default limit is conservative and
it does not invoke kernel OOM.

### `frozen-worker`, `orphan-process`, and `process-tree`

```bash
./bin/runopsy-sim frozen-worker
./bin/runopsy-sim orphan-process --tasks 2 --grace 1s
./bin/runopsy-sim process-tree --settle 1.2s --between 600ms
```

These scenarios use real helper processes. They verify stopped-worker state,
child reparenting, and the difference between killing a process group and one
PID, then clean up their child trees.

### `exit` and `signal`

```bash
./bin/runopsy-sim exit --code 137
./bin/runopsy-sim signal --signal TERM
```

`exit` ends with a chosen code. `signal` raises supported signals on itself;
fatal signals end with the kernel-observed status, e.g. TERM is 143 to the
waiting caller. STOP is resumed by a helper process.

## Event stream

The simulator's `--json` option emits one NDJSON event per line, with UTC
`timestamp`, `scenario`, `type`, and optional `data`. Text mode combines human
narration and events; JSON mode suppresses narration.

## Layout

```text
cmd/runopsy-agent/       # foreground agent entry point
cmd/runopsy-sim/         # Phase 0 fault-injection CLI
internal/agent/          # runtime wiring, status, JSON dump adapters
internal/collector/      # snapshot model, scheduler, ring buffer, tree, CPU tracker
internal/platform/       # /proc and ps adapters: processes, TCP, PSI, cgroups
internal/incident/       # capture state machine, triggers, bundle format, retention
internal/simhelper/      # hidden helper processes for simulator trees
internal/simulator/      # simulator scenarios and CLI
internal/events/         # simulator text/NDJSON event stream
testdata/proc/           # deterministic Linux proc input fixtures
```

## Verification and limitations

Completion verification used Go 1.27.1 on darwin/arm64 and live linux/arm64
(Docker with `--init`, `GOMAXPROCS=2`). `go test -race -count=1 -timeout=5m ./...`,
`go vet ./...`, and `go build ./...` passed on both. The full `tests` package
includes the simulator matrix, real CLI inspection, chronological history,
collector-disable flags, Ctrl+C and control-socket cleanup. Fixture tests cover
PID reuse, malformed inputs, partial failures, missing parents, wraparound,
age expiry, payload limits and detached concurrent reads.

Reproduce resource measurements on Linux (not under `-race`):

```bash
RUNOPSY_MEASURE=1 go test -v -count=3 ./internal/agent -run TestRecorderResourceMeasurement
go test -run '^$' -bench . -benchmem ./internal/platform ./internal/collector ./internal/agent
```

The measurement warms 120 retained snapshots and then samples at 1s for six
seconds. It reports process CPU (one-core percentage), RSS, Go live heap,
serialized snapshot size, retained-payload estimate, host process count and
collector errors. This is a short development-container measurement, not a
production performance guarantee. The initial run alongside verification used
15.0 MiB RSS, 0.53 MiB live heap, 0.48 MiB retained payload, 3.3 KiB latest JSON,
and 9.19% of one core, with no collector errors and four visible processes.
After correcting cancelled shutdown cycles being retained as failed samples,
three valid repeat runs (three visible processes, one watched) retained all 120
samples with zero collector errors: RSS 13.7–15.2 MiB, live heap 0.51–0.56 MiB,
retained payload 0.45 MiB, latest JSON about 3.1 KiB, CPU 2.66–7.00% of one core.
The <1% CPU aspiration was not demonstrated. These small-container measurements
do not establish overhead on a large production process table.

Representative microbenchmarks on that Linux container (`-benchtime=200ms`):

| Operation | Time/op | Allocation/op |
|---|---:|---:|
| Process stat parsing | 1.25 µs | 552 B |
| Enumerate 100 fixture processes | 6.06 ms | 192 KB |
| Parse 100 TCP rows | 436 µs | 70 KB |
| Socket ownership, 100 processes / 400 FDs | 3.64 ms | 520 KB |
| Serialize 1,000-process snapshot | 741 µs | 133 KB |
| Ring append | 144 ns | 0 B |
| Full live sample, one watched PID | 2.00 ms | 166 KB |

Known Phase 1 boundaries: memory limits budget retained payload, not transient
collection/query allocations or total RSS. Samples are not atomic kernel
transactions; short-lived processes and connections between ticks can be missed.
TCP visibility is the agent's network namespace; other namespaces are not entered.
Cgroups cover v2 direct membership/limits, not v1 or effective ancestor limits.
macOS remains a development platform, not Linux collector parity. No config-file
parser, automatic service installation, persistence, diagnosis, SaaS or GitHub
integration is included.

The simulator models a stalled application peer, not a dead network path,
half-open NAT mapping, or packet loss. Orphan reparenting depends on launchd or
init/subreaper behavior. Adopted zombies are the adopter's reaping responsibility.

## Phase 3 diagnosis engine

`runopsy-agent analyze FILE [--json] [--explain] [--report] [--min-confidence F]`
produces a deterministic offline report from a verified bundle. Analyzer 0.3.1,
signature set 2, implements nine stable hypotheses with structured supporting
and contradicting evidence, missing-data explanations, and explicit ambiguity.
Scores are declared evidence weights, **not probabilities**. Required evidence
cannot be bypassed by lowering the confidence threshold.

The architecture/implementation review and item **3.33 confidence calibration** are recorded in
[the calibration protocol](docs/signatures/CALIBRATION.md) and
[signature reference](docs/signatures/README.md). Review corrected missing
collector data being treated as healthy, evidence extending through observation
gaps, ambiguous PID ownership, and invalid custom-rule scores. The CLI always
shows ambiguous rival explanations and rejects nonfinite thresholds.

## Phase 4 timeline and causal graph

`runopsy-agent timeline FILE` renders deterministic normalized events from a
verified bundle. Add `--causal` for versioned-rule edges and root candidates,
`--json` for the graph/report JSON shape, `--report` for combined signature
and causal output, and `--explain-edge EDGE` for a rule/evidence explanation.
The CLI is also wired into the command usage text above.
Diagnosis matches link to relevant event IDs when `--report` is enabled. If
there is an observed failure but no supported causal root, the report says
`UNKNOWN` and names missing telemetry rather than inventing a cause.

Causality is deliberately stricter than chronology: `PRECEDES` is order only;
`CAUSES` and `CONTRIBUTES_TO` require an explicit rule and evidence contract.
Phase 4 semantics remain provisional pending architecture review. Current v1 bundles
do not contain kernel OOM records, socket byte-progress counters, or runner/job
role telemetry, so those events and rules remain dormant. See
[causality](docs/causality.md), the [event model](docs/event-model.md), and the
[versioned rule registry](docs/causal-rules/README.md).

Three hypotheses deliberately remain rejected with v1 telemetry:

- `OOM_KILL`: memory pressure plus a disappearance cannot prove an OOM kill
  without an OOM event or equivalent causal evidence.
- `CPU_SPIN`: sustained CPU and no child changes cannot distinguish a stuck
  loop from productive single-process work without application progress.
- `BROKER_SOCKET_STALL`: an established socket and a watched owner cannot
  establish stalled work without byte progress and application expectations.

Their observed facts, scores and missing requirements remain available in
`--explain` and JSON. Watching a process is selection, not failure evidence.
Other rules describe recorded stopped state, disk pressure, reparenting,
coordinated disappearance, network symptoms and resource pressure; they do not
establish intent or a proven root cause. See the reference for each boundary.

`runopsy-agent evaluate testdata/incidents` compares predictions against the
original nine injected fault labels and ten healthy labels. The reviewed
baseline is **16/19 correct top diagnoses, 0 healthy false positives, 13 UNKNOWN**:
ten healthy cases and three faults that v1 cannot distinguish. The three misses
remain false negatives in the confusion matrix; their labels were not rewritten
to inflate accuracy. Synthetic fixtures are a regression corpus, not an estimate
of production accuracy. Graded calibration tests compare stronger/weaker
support, contradictions, missing evidence and required-evidence gates.

`RUNOPSY_E2E_DIAGNOSIS=1 go test ./tests -run '^TestPhase3DiagnosisEndToEnd$'`
exercises live frozen-worker and watched-exit captures, plus Linux sustained CPU.
The CPU case now requires an explained rejected hypothesis; the recorder has no
application progress sensor. Benchmarks cover small, medium and large captures.

The requested architecture/implementation review and calibration work close review defects, but
**the original full Phase 3 acceptance matrix is not yet satisfied**. Confirmed
OOM, CPU-spin and broker-stall diagnoses need additional recorder evidence;
real disk/OOM/network-loss/group-kill end-to-end evaluations and independent
review also remain.

## Phase 7 hosted viewer (MVP) — backend

Phase 7 is designed in `docs/cloud/contract.md`: `runopsy-cloud` is an
optional viewer and storage layer; diagnosis never moves into it. The service
runs the same `internal/analysis` code the CLI runs, so an uploaded incident
shows exactly the diagnosis `runopsy-agent analyze` produces. The landed
backend:

```bash
# One analysis document, byte-stable across every caller:
./bin/runopsy-agent analyze incident.runopsy --document doc.json

# The isolated analyzer worker (contract §5.4), invoked by the cloud:
go build -o bin/runopsy-analyzer ./cmd/runopsy-analyzer
bin/runopsy-analyzer -parent -bundle incident.runopsy   # one job, one child

# The server: migrate, mint a token, serve the upload and read API:
./bin/runopsy-cloud migrate -database "$DSN"
./bin/runopsy-cloud token -database "$DSN" -user u_1 -org org_1 -org-name "Acme"
./bin/runopsy-cloud serve -database "$DSN" -storage-root ./storage

# The whole backend against a throwaway Postgres (docker):
make test-cloud
```

- `internal/analysis` + `analyze --document` produce the `runopsy.analysis`
  v1 document (engine identity, causal graph with per-event evidence class,
  timeline, resource series), a pure function of the bundle bytes — the
  "local/cloud results identical" invariant is byte equality on this file.
- `cmd/runopsy-analyzer` is the hostile-input worker: bundle on stdin, one
  child per job, `RLIMIT_CPU`/`RLIMIT_NOFILE` limits, `REJECTED`/
  `FAILED_LIMIT`/`FAILED_CRASH` statuses, nothing logged from bundle content.
- The CLI: `runopsy-agent login -endpoint URL` stores a personal token at
  `~/.config/runopsy/config.json` (0600), and `runopsy-agent upload
  incident.runopsy` validates the bundle locally, uploads the exact bytes, and
  prints the dashboard URL. `login -auto-upload` opts into the local queue
  (`runopsy-agent queue [--retry]`), which retries with bounded backoff and
  never risks the local bundle. Wire shapes: `docs/cloud/upload-api.md`.
- The server: `internal/cloudserver` behind `runopsy-cloud serve`, with
  Postgres migrations (`db/migrations/`, applied and tested by the real
  runner), an immutable local object store, digest verification on completion
  and on download, per-organization abuse limits, org-scoped read endpoints
  with search and filters (`docs/cloud/read-api.md`), and count-only
  operational telemetry (`docs/cloud/operations.md`).
- Not yet built: the Next.js dashboard rendering, browser auth/organizations,
  the re-analysis endpoint, and an S3-compatible store (the MVP store is a
  directory).
- Secondary review of the document schema and the migrations (with
  three SQL defects fixed) is in `docs/reviews/phase7-secondary-review.md`;
  the dashboard scaffold is `web/`; the authorization matrix that is now
  executed against Postgres is `docs/cloud/authz-matrix.md`.

## License

MIT. See `LICENSE`.
