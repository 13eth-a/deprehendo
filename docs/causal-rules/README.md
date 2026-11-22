# Causal rule registry: v1

The executable registry is `internal/causal/rules.go`; the binding semantics
are in [`../causal-semantics.md`](../causal-semantics.md) (§1 relations, §2
bands, §3 rule contracts). `TestCausalRulesReadmeMatchesRegistry` fails if this
table and `Rules()` disagree, so update both in one change.

Every rule declares tri-state checks (PRESENT / ABSENT / UNKNOWN). A required
check that is ABSENT or UNKNOWN produces a recorded rejection, never an edge. A
contradicting check that is PRESENT vetoes the edge; one that is UNKNOWN
demotes it (D1). `CAUSES` needs at least one PRESENT discriminator (E4).
"Dormant" means the discriminator reads telemetry that v1 bundles never
contain, so the rule cannot fire on a v1 capture. Phase 6 trace merge can
supply two of those observations directly — the tracer's `oom:mark_victim`
record and its signal-send observation — and then the rule is live for that
bundle with no new inference: both are kernel facts.

| Rule | Relation | Ceiling | Required (discriminator in bold) | Binding / bounds | v1 status |
|---|---|---|---|---|---|
| `OOM_CAUSES_PROCESS_EXIT@2` | CAUSES | HIGH | **OOM_RECORD_IDENTIFIES_VICTIM**, SAME_SUBJECT_AS_VICTIM, EXIT_NOT_NORMAL | identity; ≤ 2 s | live with Phase 6 tracer evidence: the `oom:mark_victim` record names the victim identity; the sampled cgroup counter still answers UNKNOWN here |
| `SIGNAL_TERMINATES_PROCESS@1` | CAUSES | HIGH | **SIGNAL_TARGETS_VICTIM**, SIGNAL_SEND_OBSERVED, EXIT_MATCHES_SIGNAL | exact identity, or group send via the member's PGID; ≤ 2 s | live with Phase 6 tracer evidence: the send observation and the exit's `EXITED_BY_SIGNAL` fact must name the same signal |
| `MEMORY_LIMIT_CAUSES_OOM@2` | CAUSES | MEDIUM | **HOST_OOM_OBSERVED**, MEMORY_AT_LIMIT | source active at target; ≤ 30 s | dormant |
| `CGROUP_LIMIT_CAUSES_OOM@1` | CAUSES | HIGH | **OOM_RECORD_NAMES_CGROUP**, SAME_CGROUP_SUBJECT | source active at target | dormant |
| `CGROUP_OOM_KILLS_MEMBER@1` | CAUSES | MEDIUM | **OOM_COUNTER_OBSERVED**, VICTIM_EXITED_IN_CGROUP, EXIT_NOT_NORMAL; contradiction NORMAL_EXIT_BEFORE_OOM | identity; ≤ 5 s | live: first OOM edge that fires on v1 telemetry (sampled `memory.events` counter rise inside the window it records; the victim is its exit_record's cgroup stamp) |
| `MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1` | ESCALATES_TO | — | SAME_QUANTITY_SAME_EPISODE | same episode; same instant allowed | live |
| `MEMORY_ACTIVE_ESCALATES_TO_LIMIT@1` | ESCALATES_TO | — | SAME_QUANTITY_SAME_EPISODE | same episode; same instant allowed | live |
| `MEMORY_RECOVERY_FOLLOWS_ONSET@2` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live |
| `MEMORY_ACTIVE_RECOVERY_FOLLOWS_ONSET@2` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live |
| `PROCESS_EXIT_CAUSES_REPARENT@2` | CAUSES | MEDIUM (PID-only identity, D2) | **REPARENTED_FROM_EXITED_PID**, EXIT_IS_LAST_EXIT_OF_PARENT; contradiction CHILD_REPARENTED_BEFORE_EXIT | typed PPID lineage; ≤ 5 s | live |
| `PROCESS_STOP_ENDS_CPU_SATURATION@2` | CAUSES | MEDIUM | **SATURATION_END_AT_OR_AFTER_STOP**; contradiction CPU_SATURATION_HALTED_WITHOUT_STOP | process identity; ≤ 5 s | live (never makes a root: it explains the end of an anomaly) |
| `CPU_SATURATION_RESOLVES@1` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live |
| `PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1` | CAUSES | HIGH | SOCKET_OWNED_BY_STOPPED_IDENTITY, **STALL_SHAPE_LOCAL_NOT_READING** | typed socket owner | live: the stall records its owner's PID and start-time, and the shape check reads `recv_q` |
| `NETWORK_RECOVERY_FOLLOWS_STALL@2` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live (NETWORK_PROGRESS_STOPPED/RESUMED emitted from Tier B byte counters) |
| `DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1` | ESCALATES_TO | — | SAME_QUANTITY_SAME_EPISODE | same episode; same instant allowed | live |
| `DISK_LOW_ACTIVE_ESCALATES_TO_EXHAUSTION@1` | ESCALATES_TO | — | SAME_QUANTITY_SAME_EPISODE | same episode; same instant allowed | live |
| `DISK_RECOVERY_FOLLOWS_ONSET@2` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live |
| `DISK_LOW_ACTIVE_RECOVERY_FOLLOWS_ONSET@2` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live |
| `IO_PRESSURE_RESOLVES@1` | RECOVERY_OF | — | EPISODE_RECOVERY_OBSERVED | same episode; nearest | live |
| `WORKER_EXIT_CAUSES_INCIDENT@1` | CAUSES | MEDIUM | **WORKER_EXIT_MATCHES_TRIGGER** | runner job handle | dormant (no runner/job roles until Phase 5) |

## Retired rules

Do not reuse these IDs. Stored explanations that name them predate the
2026-10-27 architecture pass.

| Retired | Reason | Replacement |
|---|---|---|
| `OOM_CAUSES_PROCESS_EXIT@1`, `MEMORY_LIMIT_CAUSES_OOM@1` | discriminator changed to the kernel OOM record (§3.2) | the `@2` rules |
| `CGROUP_LIMIT_PRECEDES_OOM@1` | strength inverted (§3.3) | `CGROUP_LIMIT_CAUSES_OOM@1` |
| `MEMORY_PRESSURE_CAUSES_LIMIT_BREACH@1` | one quantity crossing two thresholds is not causation (§1.3, A3) | `MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1` |
| `MEMORY_RECOVERY_FOLLOWS_LIMIT@1`, `DISK_RECOVERY_FOLLOWS_EXHAUSTION@1` | recovery must close the episode onset (A2) | the `…_FOLLOWS_ONSET@2` rules |
| `PROCESS_EXIT_CAUSES_REPARENT@1` | PID-only binding (A22) | `@2` |
| `PROCESS_GROUP_TERM_CAUSES_GROUP_EXIT@1` | self-explanation: the group event is derived from the exits (P2, A4) | none; member exits are the group anchor's evidence |
| `PROCESS_STOP_ENDS_CPU_SATURATION@1` | read a `stall_ms` key no stop event carries | `@2` |
| `CPU_SATURATION_CONTRIBUTES_TO_FREEZE@1` | wrong target (state T is not caused by CPU load) | none until a worker-progress event exists (§7.4) |
| `DISK_PRESSURE_PRECEDES_EXHAUSTION@1` | same-quantity escalation (§1.3) | `DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1` |
| `NETWORK_STALL_PRECEDES_INCIDENT@1` | could never fire: compared a socket stall against a host-subject trigger with no episode | none |
| `NETWORK_RECOVERY_FOLLOWS_STALL@1` | re-versioned with episode binding | `@2` |
