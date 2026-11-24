# Tracer protocol (`deprehendo-trace` ↔ Go agent)

Status: Phase 6 (implemented). The Rust tracer and the Go agent exchange
events and control messages over one Unix-domain socket. This document is the
human-readable form of the contract; the machine form lives in two mirrored
files that MUST be changed together:

- Go: `internal/trace/schema.go` (+ `internal/trace/framing.go`)
- Rust: `trace-rs/src/schema.rs` (+ `trace-rs/src/framing.rs`)

Any change on one side without the other is a protocol bug. The test suites on
each side assert identical frame layout, JSON tag names, enum numbers and
version constants; both suites fail on drift.

## Transport

- Unix domain socket (datagram-free, stream mode), path supplied by the
  agent. Created with `0600` permissions; one live agent connection at a
  time.
- No FFI. The tracer is a separate process; a tracer crash can never take
  the agent down and vice versa (Phase 6 failure-isolation invariant).
- The agent connects first and always sends the first frame (a HANDSHAKE).
  A session without a valid handshake is torn down immediately.

## Framing

Every message on the wire is one frame:

```text
offset  size  field
0       4     message kind, u32 little-endian
4       4     payload length N, u32 little-endian
8       2     payload schema version, u16 little-endian
10      2     reserved (zero)
12      N     payload (JSON unless noted)
```

Kinds (stable numbers, never renumbered):

| kind | name      | direction   |
|-----:|-----------|-------------|
| 1    | EVENT     | tracer → agent |
| 2    | HANDSHAKE | both        |
| 3    | CONTROL   | agent → tracer |
| 4    | ACK       | tracer → agent |

Rules:

- A declared length above `MAX_FRAME_SIZE` (1 MiB) is a protocol error, the
  session ends. Never an allocation.
- A frame boundary EOF is a clean close; a partial header or partial payload
  followed by EOF or a timeout is fatal framing state and ends the session —
  partial state is never treated as silence.
- One socket read is never assumed to be one frame.
- Malformed payloads inside a valid frame are rejected frame-by-frame
  (session ends; the agent keeps running in polling mode).

## Handshake

The agent's first frame is a HANDSHAKE; the tracer replies with its own.

| field             | type   | notes |
|-------------------|--------|-------|
| `protocol_version`| u32    | newest protocol this side speaks |
| `min_version`     | u32    | oldest protocol this side accepts |
| `tracer_version`  | string | build identifier (agent accepts either; same field) |
| `capabilities`    | object | see below |
| `monotonic_ns`    | i64    | CLOCK_MONOTONIC at capture (Linux) for offset anchoring |
| `wall_unix_ms`    | i64    | epoch milliseconds, disclosure only |
| `schema_version`  | u16    | event payload schema version |

Negotiation (identical rule mirrored both sides): the session continues only
when the peer's `[min_version, protocol_version]` range contains our
`PROTOCOL_VERSION`, and the peer `schema_version` equals ours. Incompatible
versions end the session immediately with a diagnostic on stderr.

### Capabilities (6.8)

| field           | meaning |
|-----------------|---------|
| `process_exec`  | exec lifecycle events available |
| `process_exit`  | exit lifecycle events available |
| `signals`       | signal sent/delivered observations available |
| `stop_resume`   | stop/resume state observations available |
| `oom_kill`      | direct OOM-kill observations available |
| `backend`       | collection mechanism identifier (Phase 6: `proc_connector`) |
| `kernel`        | kernel release string, or `unknown` |
| `privileged`    | backend required/obtained elevated privilege |
| `unprivileged`  | backend works without elevated privilege |
| `unsupported`   | platform cannot support any backend (non-Linux) |

The agent must consult this before assuming a feature exists. In Phase 6 the
proc-connector backend honestly advertises `process_exec: true`,
`process_exit: true`, and `false` for signals / stop-reume / oom-kill: cn_proc
exposes no such events, and the tracer never claims a capability it cannot
observe (6.14/6.16: no faked support).

## Event frame payload (EVENT)

JSON, exact tag names (snake_case, identical on both sides):

| field            | type     | notes |
|------------------|----------|-------|
| `schema_version` | u16      | must equal ours or the event is rejected |
| `sequence`       | u64      | per-session monotonic; a receive gap = loss (6.26) |
| `monotonic_ns`   | i64      | CLOCK_MONOTONIC ns; the ordering anchor (6.28) |
| `wall_unix_ms`   | i64      | epoch ms; disclosure only, never ordering |
| `clock_offset_ns`| i64      | reserved for offset reconciliation; omitted when 0 |
| `type`           | u16      | event-type number (below) |
| `pid`            | u32      | subject PID (not identity: see `start_ticks`) |
| `ppid`           | u32      | optional; omitted when 0 |
| `pgid`           | u32      | optional; omitted when 0 |
| `start_ticks`    | i64      | kernel process-identity key; PID≠identity (6.11) |
| `exec_path`      | string   | EXEC only. argv/env deliberately absent (6.54) |
| `exit_code`      | i32      | optional; **present 0 is a real exit(0)**, absence = unknown |
| `signal`         | u8       | source signal number, 0 = none |
| `sender_pid`     | u32      | signal sender when the backend can know it |
| `fact`           | u8       | signal-fact level (below), 0 = none |
| `source`         | u8       | provenance: which backend produced this |

Event types (stable numbers):

| n | name                |
|--:|---------------------|
| 1 | PROCESS_EXEC        |
| 2 | PROCESS_EXIT        |
| 3 | SIGNAL_SENT         |
| 4 | PROCESS_STOPPED     |
| 5 | PROCESS_RESUMED     |
| 6 | OOM_KILL            |
| 0 | HANDSHAKE (never a stream event) |

Signal facts (6.14 — what the mechanism actually established; never
interchangeable):

| n | name                  |
|--:|-----------------------|
| 1 | SIGNAL_SENT           |
| 2 | FACT_EXITED_BY_SIGNAL |
| 3 | FACT_OBSERVED_STOP    |

Provenance values:

| n | source          |
|--:|-----------------|
| 1 | proc_connector  |
| 2 | synthetic (replay/tests) |

Unknown enum numbers: events with unknown `type` are labelled
`TRACE_EVENT_UNKNOWN` and preserved; the numeric contract never renumbers or
reuses.

## Control frame payload (CONTROL → ACK)

| field | type     | notes |
|-------|----------|-------|
| `op`  | u8       | control op number (below) |
| `pids`| []u32    | subject PIDs; every control is acked |
| `start_ticks` | []i64 | optional, ADD only: the identity of each PID (`start_ticks[i]` for `pids[i]`, 0 = unknown, no claim); omitted when no identity is known |

Operations: `1` ADD_PROCESS, `2` REMOVE_PROCESS, `3` RESET_WATCH_SET,
`4` FLUSH, `5` PING, `6` SHUTDOWN, `7` ADD_CGROUP (§5 item 4). Unknown ops are
refused in the ack, never ignored. PID 0 and watch sets above
`MAX_WATCH_SET_ENTRIES` (4096) are refused. `SHUTDOWN` is acked first, then
ends the tracer process cleanly.

`ADD_CGROUP` is defined on both sides now (H12), but the Phase 6 agent does not
send it: cgroup watches are a later feature. A backend that cannot filter by
cgroup answers the ack with `err` instead of silently watching nothing, so the
op can never be mistaken for an applied request.

The ACK carries `{op, watches, err, stale}`: `err` is empty on success or a
short refusal reason. `stale` (optional, omitted when empty) lists the PIDs of
an ADD whose claimed identity no longer matches the live process: it died, or
its PID now belongs to another process (contract §6.3 f). Those PIDs are
refused one by one and the rest of the ADD applies, so a set re-pushed after a
tracer restart never adopts a reused PID and never fails as a whole. The agent
drops refused PIDs from its desired set and counts them (`watches_stale` in
tracer health); the next snapshot re-adds a PID under its current identity if
that process is in the watched tree.

The ACK for `ADD_PROCESS`/`REMOVE_PROCESS`/`RESET_WATCH_SET` is ordered by
backend. The proc connector filters in user space, so its ACK means the set is
already being applied. The eBPF backend filters in the kernel against the
`watched` map, so its ACK is written only after the pump has mirrored the set
into that map (`WatchSet::mark_synced`, waited for by the transport). If the
mirror does not complete within 2 s the ACK carries `err` instead of
`watches`, so an unapplied push is never mistaken for coverage. Without this
ordering a process that execs or exits between the ACK and the kernel write is
filtered as unwatched and nothing counts it as loss; the arm64 live run caught
exactly that (`HANDOFF.md`, 2026-11-04).

## Sequence, loss and backpressure (6.25–6.27)

- The first event of a session is sequence 1, so a loss before it is a gap
  too. Kernel-side overruns, resubscribe downtime and a full watch set skip
  sequence numbers on purpose (contract §7.1).
- Sequence numbers are stamped at the source thread, before enqueueing, so
  a drop in the event queue between the kernel collector and the socket pump
  is *never silent*: a drop shows up as a received
  sequence gap (the agent counts it) and the tracer-side `loss` counter.
- The event queue is bounded (4096). Producers never block on a full queue.
- Loss semantics are inherited from the Phase 3 UNKNOWN discipline: dropped
  events mean "evidence stream incomplete", never "nothing happened".
  Diagnosis code treats signal evidence over a lossy stream accordingly.
- Per-session sequence resets at every handshake; the agent records a
  tracer restart when it sees a new handshake (6.39).

## Clocks (6.28)

`monotonic_ns` is the ordering key for all trace-vs-trace comparisons.
Wall time is transported for humans. Because both processes run on the same
kernel, CLOCK_MONOTONIC is directly comparable; the handshake exchange of
anchor readings is for offset disclosure, not correction, and no causal claim
is ever made from wall-clock comparison alone.

## Lifecycle (6.7)

```text
agent starts tracer (--socket PATH)
  agent → HANDSHAKE          tracer ← validates, replies HANDSHAKE
  agent ↔ CONTROL/ACK (ADD/REMOVE/RESET/PING/SHUTDOWN)
  tracer → EVENT ... (stream)
agent disconnects → tracer session ends, process returns to accept
agent sends SHUTDOWN → acked, tracer exits, socket file removed
tracer crash → agent detects EOF, degrades to polling, optional restart/backoff
```

Failure-isolation invariants (6.40): the Rust enhancement may degrade; the Go
recorder must continue. A hung, crashed or malicious tracer can never panic
the agent; every frame decode is bounded and every session error is contained.

## Compatibility policy (6.57)

- Adding optional JSON fields (omitted when zero) is backward compatible.
- Changing a field's meaning or removing/renaming one bumps
  `SCHEMA_VERSION` and requires dual-side changes in the same commit.
- Unknown event `type` numbers: preserve and label, never drop.
- Unknown control `op` numbers: refuse in the ack.
- Unsupported protocol major version: reject cleanly at the handshake.
