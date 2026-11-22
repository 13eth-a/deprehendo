# Phase 4: principal reviews and audit

**Reviewer:** principal  
**Date:** 2026-10-27  
**Code reviewed:** the shared workspace as of the engineering, secondary and integration
Phase 4 slices (`internal/causal`, `cmd/runopsy-agent/timeline.go`,
`testdata/causal`, `tests/phase4_e2e_test.go`, `docs/causality.md`,
`docs/event-model.md`, `docs/causal-rules/README.md`).  
**Companion spec:** [`../causal-semantics.md`](../causal-semantics.md), the
binding decisions for 4.6/4.7/4.9/4.10/4.11/4.15/4.25/4.43.  
**Executable findings:** `internal/causal/principal_audit_test.go`. Run them with
`RUNOPSY_REVIEW_AUDIT=1 go test ./internal/causal -run PrincipalAudit -v`. On the
reviewed code all 14 failed. Re-run after the adversarial pass: 9 pass and 5 still
fail (A3, A5, A6, A8, A11). By default they skip, so the suite stays green.

## Verification performed in this pass

- **Linux re-run (item 5, Lima VM, aarch64, cgroup2fs, Go 1.27.1, uid 501)**:
  `go vet ./...` clean. The CI test command, `sudo -E env ... go test -race
  -count=1 -timeout=5m ./...`, exits 0 with all 10 packages OK. CI now runs
  this test step as root, because `internal/platform` reads `/proc/1/fd`,
  which a normal user cannot open. The causal package also passes with
  `RUNOPSY_REVIEW_AUDIT=1 -race`.
  - Fixed a test bug in `tests/simulator_test.go`: the process-cleanup helper
    read the `tasks` count in the `started` event as a PID list. It recorded
    PID 2 (`kthreadd`), so `TestProcessScenariosRespectShortDurationAndCleanChildren`
    failed every run. The helper now reads `tasks` as a PID list only when it
    is an array.
  - One `simulator` `-race` run failed a frozen-worker timing check and passed
    on rerun. It is not yet root-caused; treat it as a known flake.
- Superseded: the sandbox run below. Its `/proc/1/fd` and PID 1 notes were
  environment limits, now resolved by running as root in CI and by the
  `tasks` fix.
- First **Linux** run of Phase 4 (linux/amd64 sandbox, Go 1.24.7 with a local
  `go` directive override; the repo pins 1.27.1, which this sandbox could not
  download; not committed): `go test -race -count=1` green for
  `internal/causal`, `cmd/runopsy-agent` and `internal/diagnosis`. The full
  suite fails only on sandbox limits (no cgroup2 mount, restricted
  `/proc/1/fd`, PID 1 reaping in `TestProcessScenariosRespectShortDuration…`).
  These are not Phase 4 code issues.
- `RUNOPSY_E2E_CAUSAL=1 go test ./tests -run TestPhase4CausalEndToEnd`: PASS on
  Linux. Memory: honest no-episode outcome. Socket: "no socket facts
  observed". The sandbox exposes `/proc/net/tcp` but the simulator's sockets
  did not surface, so this run is **inconclusive for socket facts**.
- **Host run (Lima VM, aarch64, cgroup2fs), `RUNOPSY_E2E_CAUSAL=1 go test
  ./tests -run TestPhase4CausalEndToEnd`**: PASS. The socket-stall half now
  observes 7 socket facts from `/proc/net/tcp`, so the earlier inconclusive
  caveat is closed for Tier A facts. The flagship stall chain is still not
  exercised: v1 has no `NETWORK_PROGRESS_*` extractor, and the E2E says so.
- Every S1 and S2 finding below was reproduced with a constructed input
  before being written down (the A11 subject-scoping half and A15 by
  running the shipped fixtures through the CLI path). S3 items are from code
  reading and are marked as such by having no reproduction column entry.

---

## Part 1: Reviews of engineering-primary items (principal as reviewer)

Verdicts: **APPROVE** · **APPROVE WITH CHANGES** (merge-worthy, changes
queued) · **CHANGES REQUIRED** (current behaviour makes a claim that is wrong or
unsupported) · **NOT REVIEWABLE** (deliverable absent).

### 4.1 Event model — APPROVE WITH CHANGES

Strong: a stable vocabulary; unobservable types are declared but never emitted;
every event carries provenance; IDs are content-addressed; onset-unknown is
a first-class flag.

Changes:
1. **Identity in `Data` is untyped** (`A18`). Rules read `Data["pgid"].(int)`
   and `Data["from_ppid"].(int)`. After any JSON round-trip (stored
   timeline, dashboard API, fixture loaded from JSON) these become `float64`,
   and the rules silently stop matching. Move PID/PPID/PGID/StartTicks to
   typed fields (spec §4.2).
2. **The ID stability scope is undocumented.** IDs hash `Data`, so adding a
   display key changes every ID. Document "stable per bundle and extractor
   version".
3. **`Sequence` comment is false** (`A13`): it is the canonical index after
   sorting, not "original capture order".
4. **IO PSI emits `DISK_PRESSURE_STARTED`** with a host subject, so two
   different quantities (free space vs IO stall time) share one type. Split
   into `IO_PRESSURE_*` (spec §3.3).
5. `extract.go` computes memory percent without the `MemoryUsed <=
   MemoryTotal` guard that Phase 3 applies (`diagnosis/context.go:810`,
   `incident/rules.go:53`), so inconsistent input can exceed 100%. Use the
   same guard.
6. Add the `Class` field (CONDITION / FAILURE / CONTEXT, spec §5.1).

### 4.4 Event ordering — APPROVE WITH CHANGES

Deterministic total order: yes, tested. Original timestamps preserved: yes.
"Never fabricate finer timing than collected": **not yet**:

1. `Before()`/`After()` in `compare.go` return the canonical tie-break as if
   it were order. No rule uses them yet, but they are exported helpers named
   for observed order. Rename them and add `ObservedBefore` (spec P7).
2. `typeRank` puts `PROCESS_EXITED` (rank 0) before `MEMORY_LIMIT_REACHED`
   (rank 3) at the same instant, so a timeline shows the effect above its
   candidate cause. That is acceptable only if the renderer visibly groups
   equal-timestamp events ("same sample"). secondary: add the grouping marker.
3. `relationDirectionOK` admits CAUSES in **either** direction at equal
   timestamps. Only the cycle check prevents A→B and B→A both existing.
   Require `same_instant: true` plus D5 (spec P6).

### 4.19 Timeline normalization — CHANGES REQUIRED

1. **There is no monotonic timeline.** Bundles carry wall timestamps only;
   `Relative` is wall − CaptureStart. The comments in `events.go` and
   `docs/event-model.md` claiming a "normalized monotonic timeline" are
   untrue today.
2. **Backward clock steps are silently re-sorted, which fabricates
   history** (`A7`, reproduced). Samples `[T+0 50%, T+2 95%, T−3 99.5%,
   T+4 99.5%]` (a 5 s NTP step back) produce `MEMORY_PRESSURE_ACTIVE` and
   `MEMORY_LIMIT_REACHED` *before capture start*, then a
   `MEMORY_RECOVERED` at T+0 that never happened, and **no**
   `CLOCK_DISCONTINUITY`. The cause: the 4.38 fix sorts snapshots by wall
   time *before* the discontinuity detector runs, so "backward" can never be
   observed. The existing test passes only because its 2-minute step turns,
   after sorting, into a >30 s forward gap.
3. Required: Phase 1 records `CaptureIndex` and a monotonic offset per
   snapshot (`time.Since(recorderStart)`, already free in Go). Phase 4 orders
   samples by capture index, computes durations/gaps from monotonic offsets,
   and treats wall time as a display label. Until Phase 1 lands, bundle order
   is capture order for recorder-written bundles (spec §10 item 1). Coordinate
   with integration: the fuzz property "array order is not evidence" stays true
   for recorded events, not for samples.
4. (4.20 note for adversarial) A forward gap of >30 s is labelled
   `CLOCK_DISCONTINUITY`, but without monotonic data it cannot be told apart
   from a sampling hole. Emit `TIMELINE_GAP` for holes. Also, nothing
   downstream reacts to either event today: given the A3 input with a 58 s
   hole instead of 18 s, the cross-episode CAUSES edge spans the emitted
   `CLOCK_DISCONTINUITY` at full band. Apply P4/D4.

### 4.22 Memory causality — CHANGES REQUIRED

1. **A jump straight to the limit loses the limit fact** (`A10`). 50% → 99.5%
   between two samples emits only `MEMORY_PRESSURE_STARTED`. The machine sets
   `limitCrossed` without emitting the event unless the onset is unknown. The
   same bug exists in the disk machine (60% → 3% free gives no
   `DISK_EXHAUSTED`). Sudden spikes are the typical pre-OOM shape, so this
   hits 4.46 directly.
2. **Pressure → limit is not causation** (spec §1.3): it is one quantity
   crossing two thresholds. Use `ESCALATES_TO`.
3. **Cross-episode CAUSES** (`A3`). The rule has no gap or episode binding, so
   a pressure episode that *recovered* at T+2 "causes" a limit reached at
   T+22 in a later episode. Reproduced.
4. **Recovery never registers** (`A2`). `MEMORY_RECOVERY_FOLLOWS_LIMIT` hangs
   the recovery on the limit event, but `Recovered` is read from the root
   (the pressure event). A healthy build that briefly touches 98% and
   recovers is reported as an **unhealthy PRIMARY root cause** (`A1`,
   reproduced).
5. **Host vs cgroup strength is inverted.** Host limit → OOM is CAUSES MEDIUM,
   while cgroup limit → OOM is only PRECEDES LOW. A cgroup at `memory.max`
   with an OOM record for that cgroup is the canonical mechanism (spec §3.3).
6. **Cgroup crossings have no hysteresis** (`A23`). The episode resets on any
   sample below 98%, so a cgroup wobbling at 97.9/98.1% emits a new
   `CGROUP_LIMIT_REACHED` per wobble. Three events for one episode,
   reproduced. The code comment claims otherwise.
7. Minor: the `memoryMachine` doc comment says recovery is "back below 95";
   the code (correctly, per the fixture notes) uses 85.
8. Host/cgroup OOM distinction in the type system: good, keep it.

### 4.24 CPU causality — CHANGES REQUIRED (low urgency: both rules dormant)

Both CPU rules are dormant **for the wrong reasons**:
- `PROCESS_STOP_ENDS_CPU_SATURATION@1` requires `MatchStallWindow`, which reads
  `stall_ms`, a key no stop event ever carries.
- `CPU_SATURATION_CONTRIBUTES_TO_FREEZE@1` requires `MatchNoOtherCause`, which
  always returns false. It also targets `PROCESS_STOPPED` (state T), which
  CPU load cannot cause. The plan's "CPU + no progress + no external pressure
  → CONTRIBUTES_TO *stall*" needs a progress event v1 doesn't have.

The plan's key safety property ("never HIGH CPU → DEADLOCK") holds today only
by accident. Retire/re-version per spec §3.3. Also: per-process
`CPU_SATURATION` (≥85% of one core) is the process's own behaviour, a
symptom such as CPU_SPIN, not an external condition. Spec §5.1 makes it
CONTEXT and reserves host-level `CPU_CONTENTION_*` (PSI cpu) as the CONDITION.

### 4.28 Incident-boundary reasoning — APPROVE WITH CHANGES

Memory, disk, CPU and process-stop handle "already active at first
observation" correctly, and the renderer says "onset not captured".
Gaps:
1. **IO pressure and cgroup limits** claim an observed onset at the first
   sample (`A17`, reproduced).
2. A STARTED event emitted after a sensor gap claims onset at the post-gap
   sample, although the crossing happened somewhere in the gap. Add
   `onset_window: (last-known-below, observed-at]` to every crossing (spec
   §4.2), and render windows wider than one sampling interval.

### 4.29 Missing causal precursor — APPROVE

No code path back-fills a precursor. `OOM_EVENT` is root-eligible, so an
OOM → exit chain without memory data starts at the OOM as specified. Two
asks: (1) add the explicit test "OOM record + exit only → root OOM_EVENT,
note 'upstream memory condition not observed'" once
`OOM_CAUSES_PROCESS_EXIT@2` can fire on synthetic input; (2) the
unknown-cause report's *missing evidence* is two static strings. Compute it
from UNKNOWN checks (spec §8.1 #7).

### 4.37 Counterfactual tests (adversarial primary) — NOT REVIEWABLE

adversarial's corpus has not been delivered. The one existing test,
`TestCounterfactualOomRemovalChangesConclusion` (engineering), is weak: the
OOM → exit rule cannot fire, so the "with OOM" graph never reaches the
exit, and the final comparison passes vacuously whenever the
"without" graph has no roots. It does not test the 4.37 target ("definite
OOM kill" vs "memory exhaustion suspected").

Acceptance criteria for adversarial's delivery (I will review against these):
- Each pair asserts the **conclusion level** (FailureAnalysis status,
  root kind, band), not edge counts.
- Each removal changes the conclusion in the expected direction and **never
  strengthens** it.
- Plus one property test over all golden fixtures: removing any event that
  appears as PRESENT evidence in an edge's checks never raises that edge's
  band or any chain band through it.

Required pairs (minimum):

| # | Base | Counterfactual | Expected change |
|---|---|---|---|
| 1 | limit + OOM record + SIGKILL exit | remove OOM record | EXPLAINED → UNKNOWN with alternative "OOM suspected" |
| 2 | same | remove limit/pressure | root becomes `OOM_EVENT` + "upstream not observed" (not UNKNOWN) |
| 3 | same | exit recorded normal | contradiction veto; no edge |
| 4 | same | exit 20 min later | no edge (MaxGap) |
| 5 | same | exit before OOM | no edge |
| 6 | same | OOM names 5842@A, exit is 5842@B | no edge (identity) |
| 7 | orphan | child first seen already under PPID 1 | no reparent edge; parent exit UNKNOWN |
| 8 | orphan | reparent observed before parent exit | contradiction veto |
| 9 | group kill | keep one member exit | no group event |
| 10 | pressure → limit | recovery inserted between them | two episodes; no cross-episode edge |
| 11 | limit → OOM | limit recovered before OOM | `MEMORY_RECOVERED_BEFORE_OOM` vetoes |
| 12 | disk exhausted at end | exhaustion sample removed | no anchor; healthy |
| 13 | any edge | discontinuity inserted between endpoints | band → LOW |
| 14 | episode | UNKNOWN sensor sample inside | no recovery, no edge across |
| 15 | (after Tier A) stall `PEER_SILENT` | flip to `PATH_LOSS` | broker/path primary swaps |

### 4.47 Socket-stall E2E (integration primary) — APPROVE as a v1 honesty test; acceptance row NOT MET

The test correctly guards against fabrication: no `NETWORK_PROGRESS_*`, no
broker diagnosis without telemetry, and "No validated causal root" in text.
But:
1. The Phase 4 acceptance-matrix row "socket stall: causal chain correct" is
   **not met** and cannot be with v1 telemetry. `HANDOFF.md`/`README.md` must
   not describe the flagship demo as working.
2. When the environment yields no socket facts, the test still PASSes.
   That happened on Linux in this pass. Keep the pass, but print a
   summary line that says "flagship chain not exercised", so a green run is
   not misread.
3. Target graph and telemetry: spec §7.5 and §7.1 (Tier A is nearly free:
   `/proc/net/tcp` is already read, and `tx_queue`/`rx_queue`/`tr`/`retrnsmt`
   are parsed past and thrown away).

### adversarial review verdicts (4.37, 4.39, gated audit re-run)

These verdicts record the adversarial pass against the criteria above. adversarial did not
change production code, so the five open audit findings stay with engineering.

- **4.37 Counterfactual tests — APPROVE WITH CHANGES.** The corpus is in
  `internal/causal/counterfactual_test.go` and `rule_negatives_test.go`.
  Pairs 1, 2, 7, 8, 9, 10, 11, 12, 13 and 14 are covered and run on v1. Each
  case asserts the conclusion level (anchor status, band), and
  `statusRank`/`bandWeight` check that no removal strengthens a conclusion.
  Open items against the acceptance criteria:
  - The golden-fixture property test ("removing any PRESENT evidence never
    raises an edge or chain band") is now written as `TestGoldenFixtureRemovalNeverStrengthens`. It removes every event of each golden fixture and compares edge bands (keyed by rule and endpoint types), chain candidate bands and anchor statuses. Gated run: 11 golden fixtures pass, 2 events-mode fixtures are skipped by design.
  - Pairs 3, 4, 5 and 6 need a kernel OOM record. The OOM rule is dormant on
    v1, so these are not run; a pass would be vacuous.
  - Pair 15 needs Tier A network telemetry (not in v1).
  - `TestCounterfactualOomRemovalChangesConclusion` is removed; the pairs above replace it.
- **Rule-level negatives (adversarial, this pass):** `TestRuleNegativesReparentIdentity` adds the identity boundary for `PROCESS_EXIT_CAUSES_REPARENT@2` (a child naming a different PPID must not link to the exit). The rule declares no `MaxGap`, so there is no reparent timing boundary to test; `ORPHAN` timing is covered by pairs 7 and 8. Open question for the next owner: an unbounded gap means a reparent observed long after an exit still links. **Resolved:** `MaxGap` is now 5 s (five default 1 s samples), enforced by `TestRuleNegativesReparentGap`. A reparent observed later does not link.
- **Adversarial verdicts on rules read this pass:** `OOM_CAUSES_PROCESS_EXIT`, `MEMORY_LIMIT_CAUSES_OOM`, `CGROUP_LIMIT_CAUSES_OOM@1` are APPROVED as contracts but DORMANT on v1, so their timing boundaries (2s and 30s `MaxGap`) and identity checks cannot be verified against live data. `MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1` APPROVED (escalation and same-instant cases covered). `PROCESS_EXIT_CAUSES_REPARENT@2` APPROVED with the gap question above. Recovery, CPU, network and disk rules were not re-read in this pass and keep their earlier verdicts.
- **4.39 Rule-level negatives — APPROVE.** `rule_negatives_test.go` covers
  memory escalation (episode instance, limit before onset), memory recovery
  (episode-local), CPU stop-ends-saturation (ordering, process identity) and
  disk escalation (filesystem identity). Each negative is preceded by a base
  case that must fire, so the negatives are not vacuous. Still missing:
  timing-boundary negatives for the reparent and OOM rules are now in place:
  `TestRuleNegativesReparentGap` and `TestRuleNegativesOOMTimingBoundary`. The OOM test holds its two unobservable record checks PRESENT for the duration of the test, so only the timing and direction decide the outcome. Its positive case proves the swap works, so the negatives are not vacuous.
- **Gated principal audit re-run — 9 pass, 5 fail.** Passing: A1 (×2), A4, A7, A9,
  A10, A17, A22, A23. Still failing and open for engineering: A3 (cross-episode
  CAUSES), A5 (contradiction status), A6 (tied roots), A8 (root confidence is
  the strongest link), A11 (FROZEN_PROCESS links CPU saturation).
- **Not reviewed by adversarial:** A2 (recovered memory episode), A12, A15 and the
  S3 items. A2 is covered by the A1 test, which passes.

---

### Adversarial review: recovery, CPU, network and disk rules (adversarial, item 4)

This pass read every rule in `internal/causal/rules.go` that the earlier pass left out, and checked each evaluator it depends on. Verdicts:

- **Memory recovery (`MEMORY_RECOVERY_FOLLOWS_ONSET@1`, `MEMORY_ACTIVE_RECOVERY_FOLLOWS_ONSET@1`): APPROVED.** Episode-bound through `EPISODE_RECOVERY_OBSERVED`, with `NearestOnly`. The memory events carry the episode (`extract.go`).
- **CPU saturation resolves (`CPU_SATURATION_RESOLVES@1`): APPROVED.** Episode-bound, identity exact. CPU saturation events carry the episode (`extract.go`, the saturation episode builder).
- **CPU stop ends saturation (`PROCESS_STOP_ENDS_CPU_SATURATION@2`): CHANGED, now bounded.** The rule had no `MaxGap`, so a stop followed much later by an unrelated saturation end still linked at MEDIUM. It now has `MaxGap: 5 * time.Second`, the same bound as the reparent rule. `TestRuleNegativesCPUStopEndsSaturation` covers a saturation end 10s after the stop, and it does not link.
- **CPU halted without stop (`CPU_SATURATION_HALTED_WITHOUT_STOP`): APPROVED, with a wording nit.** The logic is right: a saturation end between stop and target contradicts the link. The PRESENT detail says "ended without a recorded stop between them", but the stop is the source event itself, so the text is misleading. Non-blocking.
- **Disk pressure and low-active escalation to exhaustion (`DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1`, `DISK_LOW_ACTIVE_ESCALATES_TO_EXHAUSTION@1`): APPROVED.** `SAME_QUANTITY_SAME_EPISODE` checks the episode and the subject. Disk events carry the episode (`extract.go`, the disk episode builder). Same-instant is allowed only within one episode.
- **Disk recovery (`DISK_RECOVERY_FOLLOWS_ONSET@1`, `DISK_LOW_ACTIVE_RECOVERY_FOLLOWS_ONSET@1`): APPROVED.** Episode-bound.
- **IO pressure resolves (`IO_PRESSURE_RESOLVES@1`): APPROVED.** The IO episode carries its id. Identity is scope, which is correct for a host-level quantity.
- **Network rules (`PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1`, `NETWORK_RECOVERY_FOLLOWS_STALL`): APPROVED as dormant contracts.** Their checks return UNKNOWN in v1. Also, `extract.go` has no extractor that emits `NETWORK_PROGRESS_*` events, so they cannot fire even if the checks were filled in. This is a known Phase 1 dependency.
  - **Update (post-audit):** a `NETWORK_PROGRESS` extractor now lives in `internal/causal/network_progress.go` and emits `NETWORK_PROGRESS_STOPPED`/`RESUMED` from Tier B byte counters. `STALL_SHAPE_LOCAL_NOT_READING` is a real evaluator (PRESENT when the stall's `recv_q > 0`). `SOCKET_OWNED_BY_STOPPED_IDENTITY` is now a real evaluator: the collector keeps the socket owner's start-time, the stall event records the owner's PID and start-time, and the check binds the stopped process incarnation (a reused PID is ABSENT, an unresolved owner is UNKNOWN). Covered by `TestSocketOwnedByStoppedIdentityBindsOnIncarnation` and `TestNetworkStallRecordsOwnerIdentity`.
- **`NETWORK_STALL_PRECEDES_INCIDENT@1`: REMOVED (dead contract).** It requires `SAME_QUANTITY_SAME_EPISODE` between a network stall and `INCIDENT_TRIGGERED`. The incident trigger carries no episode (`extract.go`, the incident builder sets only type, time, subject and trigger), and the subject is `SubjectHost "local"`, which never equals a socket subject. The check therefore returns ABSENT every time, so this rule could never fire. Owner decision: drop it. It is removed from `rules.go`, and the docs are updated. Its removal also removed the only PRECEDES rule, so the two PRECEDES validator tests in `graph_compare_test.go` now use `PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1` as the rule ID. The error paths they check do not depend on which rule is named.
- **Worker exit (`WORKER_EXIT_CAUSES_INCIDENT@1`): APPROVED as dormant.** `WORKER_EXIT_MATCHES_TRIGGER` returns UNKNOWN, and the role binding is documented as unavailable in v1.

**Open items from this pass:** none in the rule review. The CPU bound and the network-rule removal are both in the tree.

## Part 2: Final Phase 4 audit

**Brief:** find every place where the code makes a stronger claim than the
evidence supports. This audit covers the code *as it stands*. After engineering
implements spec §10, adversarial and secondary re-run it (per the plan), starting from
`principal_audit_test.go`.

Severity: **S1** a wrong causal or health conclusion reaches the user · **S2**
a conclusion presented with more certainty or completeness than it has ·
**S3** a latent defect, or documentation that misdescribes the guarantee.

| ID | Sev | Where | The claim | What the evidence supports | Reproduction | Spec |
|---|---|---|---|---|---|---|
| A1 | S1 | `graph.go` `Roots()` | "ROOT CAUSE: MEMORY_PRESSURE_STARTED" (oom-chain fixture; brief-98% healthy build) | The chain reaches no failure; the worker exit is unconnected. "Root cause" of nothing. | `TestPrincipalAuditA1…` (×2) | §5.2 |
| A2 | S1 | `graph.go` `chainTo` `Recovered` | Fully recovered memory episode reported unhealthy, PRIMARY | Recovery is observed, but hung on the limit event while `Recovered` reads the root | `TestPrincipalAuditA1RecoveredCondition…` | §5.5, §3.3 |
| A3 | S1 | `rules.go` `MEMORY_PRESSURE_CAUSES_LIMIT_BREACH@1` | A recovered episode CAUSES a later episode's limit; two PRIMARY/SECONDARY roots | Episodes are independent | `TestPrincipalAuditA3…` | P3 |
| A4 | S1 | `PROCESS_GROUP_TERM_CAUSES_GROUP_EXIT@1` | "Group termination CAUSES member exit" (3 edges; PRIMARY root) | The group event was *derived from* those exits: circular | `TestPrincipalAuditA4…` | P2 |
| A7 | S1 | `extract.go` snapshot sort | Pre-capture memory episode plus a recovery | A 5 s backward clock step; nothing recovered | `TestPrincipalAuditA7…` | review 4.19 |
| A5 | S2 | `graph.go` `Explain` | "Contradictions: none recorded" | Contradiction checks are never evaluated (`ruleContradiction` reads a key no extractor sets) | `TestPrincipalAuditA5…` | §2.3, §8.2 I2 |
| A6 | S2 | `Roots()` sort | PRIMARY chosen among equally supported independent candidates | Canonical order is not evidence; the tie is real ambiguity | `TestPrincipalAuditA6…` | §5.4, §6 |
| A8 | S2 | `rootConfidence` | Root band = strongest outgoing edge (HIGH) | Chain is only as strong as its weakest link (LOW) | `TestPrincipalAuditA8…` | §2.4 |
| A9 | S2 | `rootCandidateTypes` includes FAILURE types | "Root cause: PROCESS_EXITED" (orphan fixture) | The parent's exit is itself unexplained: root cause UNKNOWN, known chain exit → reparent | `TestPrincipalAuditA9…` | §5.2 |
| A11 | S2 | `signature_link.go` | FROZEN_PROCESS "related events" include CPU saturation; links are type-only, so any process's events attach to the diagnosis | Only the diagnosed subject's stop/resume events are evidence | `TestPrincipalAuditA11…` (type half) | §10 item 7 |
| A15 | S2 | `timeline.go` `buildUnknownCause` | Silence about an unexplained exit whenever any root exists elsewhere | Every failure needs its own analysis | (CLI; covered by §5.6 fixture updates) | §5.2 |
| A12 | S2 | engine (no P4) | CAUSES across a timeline discontinuity at full band | The gap is unobserved; the band must drop | A3 input with a 58 s hole (probe) | P4, D4 |
| A22 | S2 | `subjectsOverlap` (PID-only) | A stale PID-800 incarnation CAUSES the reparent | The child was observed under a *later* PID 800 | `TestPrincipalAuditA22…` | §3.3 |
| A10 | S2 (under-claim) | `memoryMachine`/`diskMachine` | Episode has pressure but "never reached the limit" | 99.5% was observed | `TestPrincipalAuditA10…` | §10 item 3 |
| A17 | S3 | `ioPressureMachine`, `crossingEpisode` | Observed onset at capture start | Condition already active; onset unknown | `TestPrincipalAuditA17…` | 4.28 |
| A23 | S3 | `crossingEpisode` | Three cgroup-limit "episodes" | One episode wobbling at the boundary | `TestPrincipalAuditA23…` | 4.3 |
| A13 | S3 | `events.go` | `Sequence` = "original capture order" | It is the canonical index | — | §4.3 |
| A14 | S3 | `RootCandidate.Downstream` (`downstream_effects`) | "N downstream effects" | It counts paths, not distinct events | — | §4.2 |
| A16 | S3 | `docs/causal-rules/README.md` | Group rule "normally rejects", "DISK_EXHAUSTION_PRECEDES_PRESSURE", "extraction does not emit DISK_EXHAUSTED" | All three contradict the code (the group rule fires in the golden fixture) | — | secondary, 4.48 |
| A18 | S3 | rules reading `Data[...].(int)` | Lineage matched | Silently unmatched after a JSON round-trip | — | §4.2 |
| A19 | S3 | `resolveEdge` by rule ID | "The" edge for RULE@1 | The first of possibly many | — | secondary |
| A20 | S3 | `docs/event-model.md`, `events.go` | "Normalized monotonic timeline" | Wall-clock deltas only | — | review 4.19 |
| A21 | S3 | `Rejected` (engine) | — (output-size risk) | One `RejectedEdge` per source×target pair failing a required check. With process churn (e.g. 1,000 exits × 100 reparents) this is O(n·m) entries in `--json`. Cap the rejections, or record one per source with a count. | — | integration, 4.41 |

### What is right (keep it)

- **No fabricated observability.** No path emits `OOM_EVENT`, socket
  progress or worker roles. The no-fabrication fixture checks and fuzz
  assertions are excellent, and they caught nothing because there was
  nothing to catch.
- The rejected-edge record (every non-edge is inspectable) is the right
  foundation for spec §8.
- Onset-unknown as a first-class flag, sensor-gap honesty in the memory
  machine, and the threshold-once/hysteresis design (memory) are all correct.
- integration's `NearestOnly` and O(n) validation fixes are sound. NearestOnly
  is a crude stand-in for episode binding; spec §3.1 `Binding` subsumes it.
- The healthy fixtures are the most valuable tests in the package. Every new
  rule must keep them green.

### Overall verdict

Phase 4 is **not done**. The engine never invents *observations*, but it does
invent *conclusions*: four S1 paths put a wrong root cause or health verdict
in front of the user, and three of them fire on golden or near-golden inputs.
All of them trace to the decisions engineering had to make provisionally without an
architect: the root definition, episode binding, and treating derived and
summary events as causes. Those decisions are now made (spec §1–§8). The fix
list is §10 of the spec. Items 1–5 are the critical path, roughly two engineering
slices. No item requires new Phase 1 telemetry except the network chain
(§7) and the monotonic offset (review 4.19).

The acceptance matrix today, honestly:

| Scenario | Events | Chain | Root | No false claims |
|---|---|---|---|---|
| OOM | ⚠ limit lost on jumps (A10) | ✗ (OOM unobservable; v1-honest) | ✗ wrong root reported (A1) | ✗ |
| frozen process | ✅ | n/a | ✅ UNKNOWN | ✅ |
| CPU spin | ✅ | ✗ (dormant rules) | ✅ none claimed | ✅ |
| disk exhaustion | ⚠ exhausted lost on jumps (A10) | ⚠ PRECEDES only | ✅ UNKNOWN | ⚠ reports healthy (§5.6) |
| orphan process | ✅ | ✅ edge correct | ⚠ effect labelled root (A9) | ⚠ |
| process-group kill | ✅ | ✗ circular (A4) | ✗ | ✗ |
| socket stall | ✅ (open only) | ✗ (no telemetry) | ✅ none claimed | ✅ |
| network failure | ✅ | n/a | ✅ UNKNOWN | ✅ |
| healthy workload | ✅ | ✅ none | ✅ none | ⚠ brief-98% case fails (A1/A2) |

---

## Part 3: Post-remediation re-audit (principal, 2026-10-28)

**Scope:** the workspace after the engineering §10 remediation and adversarial's 4.37 and
rule-review passes. The method is the same as Part 2: every finding below was
reproduced with a constructed input before it was written down, and each now
has a permanent regression test in `internal/causal/principal_audit_test.go`
(`TestPrincipalReaudit…`, not gated). These were fixed in this pass, not handed off.

### Remediation verdict

All 23 Part 2 findings are closed in code, and the 14 original audit tests pass
ungated. One test-quality problem: the adapted **A8** test and the `a8`
fixture put the weaker edge *first*, so the original bug (root band =
strongest edge leaving the root) also passes them. A mutation that restores
that bug leaves both green. `TestPrincipalAuditA8bWeakLinkDownstreamOfStrongHead`
(HIGH head, MEDIUM downstream) fails under the mutation and passes on the real
code. The implementation was right; the test could not have caught a regression.

### New findings

| ID | Sev | The claim / defect | Fix | Test |
|---|---|---|---|---|
| R1 | S1 | D3 capped competing edges at MEDIUM without the stacking rule. A PID-only (D2) reparent edge ended at MEDIUM with D2+D3 recorded, `Validate` (V3) re-graded it LOW and rejected the graph, so **`timeline` exited with "invalid graph"** on any bundle with competing reparent edges | `demoteCompetition` re-grades through `capBand` | `R1` |
| R5 | S1 | Report rendered **"Root cause: PROCESS_EXITED (UNEXPLAINED_HEAD)"** under an UNKNOWN status, i.e. A9 again at the render layer, and listed each failure as its own candidate | no self-candidates (spec §5.2); renderer derives the cause line only from status/kind (§8.3 wording: Root cause / Most likely / Possible / AMBIGUOUS / UNKNOWN; "Earliest known link" for heads) | A9 (revised), fixtures |
| R11 | S1 | Cgroup-limit episodes ended silently, so a cgroup that touched its limit and fell back to 50% stayed an **unrecovered failure; capture unhealthy** (A2 for cgroups) | `CGROUP_LIMIT_CLEARED` recovery event | `R11` |
| R13 | S1 | Every recorded exit was a failure anchor (v1 has no exit status, and the recorder watches all processes), so each short-lived helper became **"Failure PROCESS_EXITED, root cause UNKNOWN"** | exit failure context (spec §5.1); other exits reported as a count | `R13` |
| R6 | S2 | The 90% crossing was reported as a **"contributing factor (MEDIUM)"** to the 98% crossing of the same episode, i.e. the common-cause error in softer words | escalation-only reach is the anchor's known chain (spec §5.2) | graph-compare test, fixtures |
| R8 | S2 | Member exits of a group kill were separate primary failures (the headline was a member exit, not the group), because exit events lacked the typed PGID the fold reads | typed PGID on exit events | group test, fixture |
| R2 | S2 | `EXIT_IS_LAST_EXIT_OF_PARENT` never checked for a later exit of the same PID. With PID reuse inside 5 s **both incarnations "caused" the reparent**; A22 passed only via MaxGap | the check rejects when a later incarnation exited first | `R2` |
| R7 | S2 | "OOM suspected" was listed as an alternative explanation **for the memory limit** (an OOM follows a limit), and "write failure suspected" for a full disk (a consequence, not a cause) | suspicions apply to exit failures only | fixtures |
| R12 | S2 | A severe reading in a single final sample was a failure (Phase 3's `healthy-disk-brief` baseline became "Failure DISK_EXHAUSTED") | severe anchors need ≥ 2 severe samples (4.27); one reading is "noteworthy, persistence not observed" | `R12` |
| R9 | S3 | Group event froze at two members (`member_pids [21 22]` for three exits); a second, separate kill of the same PGID was suppressed | cluster absorbs members for its window; new window, new event | `R9` |
| R3 | S3 | An edge across a backward clock step got no D4: the discontinuity carries the stepped-back wall time, so a timestamp "between" test misses it | window-overlap test over the ambiguous wall range | `R3` |
| R10 | S3 | **Performance regression (4.41).** Every source × target pair was evaluated, rejected pairs were appended, and each pair rescanned all events; end-to-end at 10k samples took 1.96 s and 303 MB | per-Apply index: same-episode targets by episode, binary-searched MaxGap window, precomputed recoveries/discontinuities. Now 92 ms and 34 MB on the same box, roughly linear again (fixtures pin identical edge sets) | benchmarks |
| R4 | S3 | `MEMORY_AT_LIMIT` read the reading from the OOM target instead of the limit source (dormant) | read the source | — |
| R14 | S3 | `alternatives` had `omitempty`, so the "checked, empty" list (I2) never reached JSON | always serialized | E2E |
| R15 | process | **The gated Phase 4 E2E was broken by the remediation** (it read the retired `root_candidates`/`unknown_cause` fields) and stayed red because nobody set `RUNOPSY_E2E_CAUSAL` | ported to the `failures` contract; prints the 4.47 "flagship chain not exercised" summary every run | E2E |

Spec changes that come with these are recorded in `docs/causal-semantics.md`
§11 (2026-10-28 rows).

### 4.37 counterfactual corpus (adversarial): APPROVE WITH NOTES

Meets the acceptance criteria: conclusion-level assertions, vacuity guards,
the removal-never-strengthens property over all golden fixtures, and pairs
1, 2 and 7–14 on v1 data. Notes:

1. **Statuses barely exercise "never strengthens".** No v1 bundle can reach
   EXPLAINED or AMBIGUOUS, so status comparisons are UNKNOWN versus UNKNOWN. The
   property is real for edge and chain bands but near-vacuous for statuses until
   OOM records exist. That is an honest consequence of v1, not a defect.
2. `statusRank` ranked UNKNOWN above "no anchor", so surfacing an
   unexplained failure counted as "strengthening". Fixed: UNKNOWN makes no causal
   claim and ranks with absence (AMBIGUOUS and EXPLAINED still rank above).
3. The case labelled "pair 3/4-style" deletes the exit; it does not test a
   *normal* exit (pair 3) or a late exit (pair 4). With R13 the normal-exit
   path exists (`exit_state: "normal"` is never an anchor), but v1 cannot
   record it. Keep the label honest ("pair 3/4 analogue") when the OOM
   telemetry lands.
4. Pairs 3–6 and 15 remain blocked on kernel OOM records and Tier B network
   telemetry, as adversarial recorded. The engine-generic halves (MaxGap, order,
   identity) are covered by the reparent negatives and R2.

### Acceptance matrix after this pass

| Scenario | Events | Chain | Root | No false claims |
|---|---|---|---|---|
| OOM | ✅ | ✗ OOM unobservable in v1 (honest) | ✅ UNKNOWN + "OOM suspected" on the exit only | ✅ |
| frozen process | ✅ | n/a | ✅ UNKNOWN | ✅ |
| CPU spin | ✅ | ✗ (no progress telemetry) | ✅ none claimed | ✅ |
| disk exhaustion | ✅ | ✅ escalation chain | ✅ UNKNOWN | ✅ (single-sample reading not a failure) |
| orphan process | ✅ | ✅ exit → reparent | ✅ UNKNOWN, known chain | ✅ |
| process-group kill | ✅ | ✅ members folded into the group anchor | ✅ UNKNOWN (no signal-sender telemetry) | ✅ |
| socket stall | ✅ (open/close + Tier A facts) | ✗ needs Tier B + worker progress | ✅ none claimed | ✅ |
| network failure | ✅ | n/a | ✅ UNKNOWN | ✅ |
| healthy workload | ✅ | ✅ none | ✅ none | ✅ (helper exits, brief dips and recovered cgroups no longer fail) |

**Verdict:** Phase 4 is done for conservative v1. The engine no longer makes a
causal or health claim the evidence does not support, and every claim it
does make is explainable under the eight-question contract. "Chain ✗" rows
are telemetry gaps, stated in every report, not engine defects. Remaining work
is Phase 1 telemetry and one host run; see HANDOFF.
