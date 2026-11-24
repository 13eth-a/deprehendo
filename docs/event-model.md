# Event model

Phase 4 turns verified `.deprehendo` bundles into a deterministic, normalized event
stream. The implementation lives in `internal/causal`; it is offline and does
not use an LLM to infer causes.

## Event shape

An event has a stable content-derived ID, canonical type, original wall-clock
timestamp, sequence number, subject reference, typed-factual data, provenance,
and optional episode duration/onset state. The Go schema is `causal.Event`.

Event IDs use `EV_` plus a truncated SHA-256 over event type, subject, timestamp,
onset-known state, sorted data fields, and a duplicate ordinal. The ordinal is
assigned after canonical sort, so duplicate facts remain distinct and stable
for an unchanged bundle. Provenance does not influence an ID.

## Subjects

`SubjectRef{Kind, ID}` keeps event identity structured:

| Kind | ID example |
|---|---|
| process | `5842@123456` (PID and process start ticks) |
| socket | `inode-88201` or a local/remote tuple when no inode is available |
| filesystem | bundle filesystem label |
| cgroup | bundle cgroup path |
| process_group | `pgid:5842` |
| host | `local` |

Subjects are built only from recorded bundle facts. A redacted label remains a
valid local key; it does not gain global identity.

## Ordering and time

Wall timestamps are preserved. Events are sorted by timestamp, declared
same-timestamp type precedence, subject, and stable ID. `Sequence` is the
canonical index (a dense tie-break order), not capture order and not sub-sample
timing; canonical order is never evidence of order (causal-semantics.md P7).
Relative timeline offsets use the capture start when available, otherwise the
earliest event.

Snapshots are processed in **capture order** (bundle order, or
`CaptureIndex` when the bundle records one), never re-sorted by wall time. A
backward wall-clock step emits `CLOCK_DISCONTINUITY{backward}` and the stepped
samples are analysed co-instant with the last trusted sample; a forward hole
larger than 30 s emits `TIMELINE_GAP`. Neither bridges an episode, and an
edge whose endpoints straddle either is demoted to LOW (D4). The bundle schema
does not yet carry a monotonic offset, so discontinuities are flagged rather
than normalized away.

## Provenance and episodes

Every event names one or more bundle event, trigger, or snapshot references.
Derived events name a versioned extraction rule. Resource events carry an
`episode` instance ID (`memory:host:local#2`, `disk:<fs>#1`, `cgroup:<path>#1`,
`io:host:local#1`); rules bind within an episode, and each episode closes with
its recovery event (`MEMORY_RECOVERED`, `DISK_RECOVERED`, `IO_PRESSURE_ENDED`,
`CGROUP_LIMIT_CLEARED`, `CPU_SATURATION_ENDED`). Severe events
(`MEMORY_LIMIT_REACHED`, `CGROUP_LIMIT_REACHED`, `DISK_EXHAUSTED`) carry
`severe_samples`, the number of samples observed at the severe level; one sample
is reported as an unconfirmed reading, not a failure (4.27).

Process events carry typed identity (`pid`, `start_ticks`, `ppid`, `pgid`);
rules never read identity from `data`, whose numbers become floats after a JSON
round-trip. A pressure condition already
active at its first usable sample is represented by an `*_ACTIVE` event with
`onset_unknown: true`; it is not assigned an invented start time. Paired episode
ends carry an observed duration. Unknown telemetry does not establish recovery
or bridge an episode.

## Event classes

Every event has a `class` (causal-semantics.md §5.1): CONDITION (can initiate a
failure), FAILURE (needs an explanation), or CONTEXT. A recorded process exit
is a failure anchor only with failure context: a recorded non-normal status, the
trigger names it, it has a causal cause or consequence, or a memory/cgroup limit
was unresolved when it happened. Other exits are reported as a count. The exit
status itself is opportunistic: a sample that catches the process as a zombie
records its terminal wait status (`exit:<code>`/`signal:<n>`); a reaped,
vanished PID records no status and stays UNKNOWN.

## v1 observability boundary

The collector/bundle currently supports recorded process lifecycle, connection
open/close, host memory/disk, PSI, cgroup memory, process state/CPU, and
incident-trigger facts. The following event types are reserved but not emitted
from v1 data because required telemetry is absent:

- `OOM_EVENT`: no kernel OOM event stream.
- `NETWORK_PROGRESS_STOPPED` / `NETWORK_PROGRESS_RESUMED`: no socket byte or
  application-progress counters. Connection snapshots now carry the Tier A
  socket facts from `/proc/net/tcp` (`tx_queue`, `rx_queue`, `timer`,
  `retransmits`, with `queues_available`), which are the stall-shape
  discriminators of §7.2; progress itself still needs Tier B (`tcp_info`).
- `RUNNER_STARTED`, `WORKER_STARTED`, `WORKER_EXITED`: no generic job-role
  identity telemetry.

Sampling disappearance is not converted into a process exit. An unavailable
collector is UNKNOWN, not evidence that an event did not occur. The reserved
event names make the schema extensible, not claims about observed data.
