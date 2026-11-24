# Phase 2 incident core

This package implements the approved core scope plus the integrated trigger,
storage, retention and inspection adapters. The independent architecture/independent audit
remains outstanding. No external dependency or service is required. Observation
remains factual; no diagnosis is added.

## Integration

Create `Capture` before recording and feed **every completed sample in timestamp
order** using `agent.Options.OnSnapshot: capture.Observe`. Its private bounded
prehistory operates independently of ring wraparound. Call `capture.Trigger`
from the manual/automatic trigger adapter, and `capture.Close(ctx)` on shutdown.
The CLI must arrange its own incident directory (0700) and startup cleanup.
Use `DefaultWindow()` explicitly for 90s before / 30s after; a zero window
intentionally means zero, useful for immediate captures.

```go
capture, err := incident.NewCapture(incident.CaptureOptions{
    Window: incident.DefaultWindow(),
    Writer: incident.FileWriter{Directory: privateDirectory},
})
// Handle err before constructing the agent.
recorder, err := agent.New(agent.Options{
    Interval: time.Second, Capacity: 120,
    OnSnapshot: capture.Observe,
})
// Manual or automatic trigger adapter:
id, err := capture.Trigger(incident.Trigger{Type: "manual"})
// Graceful teardown: stop recorder, then capture.Close(shutdownContext).
```

The agent wires a `SnapshotRule` pipeline (`agent.NewIncidentPipeline`) so the
same callback feeds prehistory, evaluates factual triggers, and reports the
saved path. The control socket exposes `POST /trigger` and `GET /incident`;
`deprehendo-agent trigger [--note TEXT]` polls the latter until the bundle is published. Notes are explicitly supplied user text and may contain sensitive information; they are not secret-scanned. They are bounded to 1024 UTF-8 bytes, and Unicode control, format and line/paragraph separator characters are normalized before export.

The completed-sample callback receives detached data outside the scheduler's
history lock, serialized with collection. It must return promptly and must not
reenter collection. Capture copies data and updates memory only; writer IO and
event derivation run outside both recording and capture locks.

### State and failure semantics

- `IDLE -> CAPTURING_POST -> FINALIZING -> COMPLETE | FAILED`.
- `COMPLETE | FAILED -> CAPTURING_POST` only on another explicit trigger.
- Duplicate triggers during capture/finalization return an error, not another ID.
- Random 128-bit `inc_` IDs are independent of private text and host identity.
- Timestamp boundaries are inclusive; snapshots are strictly chronological.
- A collection begun before the trigger but observed after it is included if it
  completes before finalization and lies inside the capture boundary.
- Timer finalization does not wait for a stalled collector. Later completions
  are not retroactively added. Sampling is discrete, not an atomic kernel view.
- Default capture budget is 32 MiB of serialized snapshot payload per history /
  active capture, at most 10,000 snapshots; newest samples displace oldest,
  setting `truncated`. This is not an RSS cap. Event/metadata/serialization
  copies consume additional memory. Export payload is capped at 64 MiB.
- Shutdown during post-capture saves a truncated partial incident. Close's
  context bounds waiting; the writer continues. A process crash during capture
  loses volatile data; no completed artifact or recovery promise is made.
- A failed write leaves `FAILED` with an error, without stopping Observe or the
  recorder. No implicit retry storm. A new explicit trigger may try again.

`Differ` handles PID+start-tick reuse, state changes, connection tuple/inode
appearance/disappearance and collector failures. Missing process/network
sections do not fabricate exit/close events; baselines survive failures. The
first sample establishes baseline without inventing starts. The CLI's
`--trigger-on-process-exit` uses `WatchedProcessExitRule` and a filtered watched
selection; it requires a successful process observation and does not treat an
unavailable sample as death. Its baseline resets across collector failures to
avoid inferring an exit over an unknown interval. This is an explicit factual
opt-in: intentional watched-process shutdowns also trigger, as Phase 2 does not
classify expected versus unexpected exits. Debounce fires once per continuous observed episode
and resets on unavailable, below-threshold or out-of-order observations. Its
caller controls threshold selection and sampling-gap policy. Rule objects are
owned by a single sampling goroutine; Capture itself is concurrency-safe.

### Trigger rules

`SnapshotRule` is the integration point for factual automatic triggers:

- `ResourceRules` reads only the host system section. `Memory.Value` is a used
  percentage (`>=`), `DiskFree.Value` a free percentage (`<=`); both require the
  condition to hold for the rule's continuous `Duration` via `Debounce`.
  Missing/invalid sensors reset the episode and never fire.
- `StoppedProcessRule` inspects the watched selection and fires once when a
  process identity (PID + start ticks) is first seen in state `T`/`t`. It fires
  once per continuous episode and resets when that identity runs again or the
  process section is unavailable. Callers must feed the watched selection; the
  agent rejects `--trigger-on-stop` without a watch selector.
- `WatchedProcessExitRule` is wired to `--trigger-on-process-exit`; it fires
  once for an identity observed in consecutive successful process-table samples
  and absent in the newer sample. It requires a watch selector and collection.
  Since it is factual, graceful and unexpected disappearance are treated alike.

Rules return only factual trigger types (`memory_threshold`, `disk_threshold`,
`process_stopped`, `process_exit`). No diagnosis is inferred from a state or
threshold crossing. The agent refuses a second concurrent trigger; the caller
sees "already active" rather than a second incident.

### Directory and retention

- `DefaultDir` resolves `~/.deprehendo/incidents`; `EnsureDir` creates missing
  parents with mode 0700 and rejects an existing group/world-accessible
  directory.
- `CleanupStaleTemps(dir, cutoff)` removes only writer-owned temp files older
  than the cutoff and must run before writers start. The agent uses a one-hour
  cutoff, so a crash leaves a temp until the next start but never presents it as
  a bundle.
- `RetentionPolicy{MaxIncidents, MaxAge}` is applied by `Prune`. Zero disables
  that limit; both zero disables pruning. Only regular files named
  `inc_<32 hex>.deprehendo` are candidates; symlinks, directories, temp files and
  unrelated names are ignored. Removal is oldest-first, deterministic on equal
  timestamps, and returns all removal errors after processing the candidates.
- The agent applies retention once at startup (before writers) and after each
  completed save. A prune failure is logged and never changes a successful save
  into a failed incident.

## `.deprehendo` v1 format

ZIP with Store (measurement) or Deflate (default); exactly five regular members:

| Member | Contents |
|---|---|
| `manifest.json` | format=`deprehendo`, format_version=1, schema_version=1, snapshot_encoding=`json-v1`, ID/time, agent/platform/architecture, SHA-256 and expanded byte sizes |
| `metadata.json` | incident header, capture bounds/window, trigger, host and process identities; snapshots/events fields are null here |
| `snapshots.json` | JSON array of Phase 1 snapshot structs, durations as integer nanoseconds, timestamps RFC3339 |
| `events.jsonl` | typed factual JSON event stream, chronological (ties allowed) |
| `privacy.json` | conservative-v1 policy and present-sensitive-category flags |

Archive, evidence schema, snapshot encoding, and agent version are distinct.
V1 is strict: unknown fields/members, duplicate JSON keys and unsupported versions
are errors, not silently ignored evidence. New fields need an explicit schema /
encoding decision. An old v1 reader rejects v2 rather than interpreting it as v1.
A checked-in `testdata/v1-minimal.deprehendo` artifact is decoded independently of
the current encoder as a v1 compatibility regression. No compatibility with a
hypothetical pre-v1 format is claimed. There are no
attachments, arbitrary metadata maps, raw environment, executable paths or command
lines in this schema; the bounded trigger note is an explicit user-text exception.

Reader limits: 65 MiB archive, 64 MiB expanded component total (+64 KiB manifest),
five central-directory entries checked before ZIP object allocation, bounded
member reads, JSON nesting <=64, at most 256 fields per object, 10,000 snapshots,
100,000 events and 250,000 evidence records across snapshots, process metadata
and events. Structural JSON array/container limits apply before typed allocation.
Case-insensitive duplicate field aliases and invalid UTF-8 are rejected. Traversal,
extra/duplicate entries, directories, symlinks, unsupported compression/encryption,
ZIP64 layouts, checksum mismatches, invalid timestamps and semantic inconsistencies
are rejected. Reader never extracts files. Heap amplification from decoded JSON
is additional to byte limits; do not advertise 64 MiB as a total memory ceiling.
Checksums/ZIP CRC detect corruption, **not authenticity** or malicious rewriting.

## Privacy

`Encode` always clones and redacts, so calling the writer without a redaction
prepass cannot bypass policy. Policy uses an allowlist, not regex detection:

- Never collect environment, command lines, hostnames, repository names or logs.
- Export process numeric identities, state/counters; process names replaced.
- Replace network addresses, filesystem and cgroup paths.
- Normalize state/collector/OS/architecture/CPU-limit strings to bounded values.
- Replace free-form collection error text; errors still identify the collector.
- Typed event fields only, no arbitrary metadata bag.

Privacy category flags report **field/category presence** in the exported artifact,
including redacted placeholders. For example, `network_addresses=true` means
network-address fields are present as `[REDACTED]`, not that original addresses
survived. `user_note=true` means explicitly supplied note text is present. The
flags do not describe live recorder memory, which retains names/addresses/paths. Reader verifies policy by reapplying
it to the decoded artifact. This is conservative data minimization, not a promise
of anonymity: timing, PIDs, ports and resource patterns remain correlatable.
`ProcessMetadata` captures PID/PPID/PGID/SID/start ticks; executable, command-line
and UID collection is deliberately omitted under the approved privacy scope.

## Atomic persistence and crash semantics

Existing private directory only. Unique `.deprehendo-*.tmp` (0600), encode, file
fsync, close, atomic same-filesystem **hard link without overwrite**, remove temp,
then directory fsync. A collision fails without changing an existing artifact.
Requires a filesystem supporting hard links/fsync; unsupported storage fails.
Before publication a crash leaves at most a temp. After publication a crash can
leave a complete bundle plus a temp, or a complete bundle with uncertain
power-loss durability. A directory-fsync failure returns **path plus error**;
consumers must not silently retry/overwrite or interpret that as no artifact.
Ordinary errors remove the temp. Startup may call `CleanupStaleTemps` exclusively
before starting writers; only old regular matching temps are deleted. Do not
run cleanup concurrently with writing. The output directory and parents are
trusted operator-controlled paths; this is not a defense against another process
with the same UID replacing them.

## Verification and measurements

Tests cover round trips and determinism, forged checksums with invalid evidence,
privacy bypass text, traversal/duplicate members, corrupt components, unsupported
versions, oversized decompression, JSON duplicates, PID reuse/unavailable sensors,
debounce, concurrent triggers, detached ownership, budget/wraparound, shutdown,
ENOSPC injected at each persistence stage, short writes, collision preservation,
and abrupt subprocess exits at crash boundaries. Real simulator -> recorder ->
capture -> bundle -> offline Read integration confirms post-save recording.
No physical power-cut test or real full-filesystem mount test is claimed; ENOSPC
is injected through the same write-stage error handling.

Run:

```bash
go test -race -count=1 ./...
go vet ./...
go test -run '^$' -fuzz FuzzBundleRead -fuzztime=10s ./internal/incident
go test -run '^$' -bench BenchmarkBundleEncode -benchmem ./internal/incident
```

Representative dense payload (120 snapshots, 12 processes, 8 sockets, PSI and
cgroup sections, 2,322 derived events), darwin/arm64:

| Encoding | Bundle | Encode | Decode | Alloc/encode | Alloc/decode |
|---|---:|---:|---:|---:|---:|
| Store | 1,291,842 B | 22.0ms | 48.3ms | 17.7MB | 26.1MB |
| Deflate | 46,398 B | 25.1ms | 50.3ms | 15.8MB | 26.2MB |

Live Linux scenario matrix (~124 snapshots, filtered process tree, 50ms
interval): stored deflate bundles were 14.4–18.5 KB (281–431 KB uncompressed)
for normal, cpu-spin, memory-pressure, frozen-worker, orphan-process and
socket-stall. See the root README for the table and reproduction commands.
These are development measurements, not production capacity claims.

## Remaining Phase 2 assignments (other models)

CLI support now includes `incidents list`, safe `extract`, `validate`,
`inspect --at/--snapshot/--privacy`, bounded trigger notes, and the opt-in
watched-process exit adapter. Host metadata supplies safe OS/architecture/CPU count and best-effort memory
total; hostname, kernel version, command lines, environment, repository names
and logs remain deliberately uncollected under conservative-v1. Independent
architecture/independent format/privacy audit remains outstanding before treating v1 as a
released public contract. The seven-scenario CLI acceptance matrix passed on
Linux/arm64 in a container; the memory case uses a low host threshold to test
the pipeline and does not prove causation by the simulated workload.
