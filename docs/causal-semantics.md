# Causal semantics: Phase 4 architecture decisions

**Owner:** principal (Phase 4 principal architect)
**Date:** 2026-10-27  
**Status:** BINDING. These decisions replace the provisional engineering decisions
recorded in `HANDOFF.md` under "Phase 4 — engineering slice", items 1–5 ("architecture-REVIEW").
architecture has been removed from the plan, so nothing here waits for architecture.

**Covers:** 4.6 (graph architecture), 4.7 (chronology vs causality), 4.9
(evidence requirements), 4.10 (confidence semantics), 4.11 (root
identification), 4.15 (competing chains), 4.25 (network causality) and 4.43
(explainability invariants).

**Implementation:** engineering owns the code (§10 is the ordered queue). adversarial reviews
each rule change. secondary adjudicates disagreements, owns the CLI and docs
changes, and runs the final re-audit together with adversarial. The executable form
of the findings is `internal/causal/principal_audit_test.go`. When a fix lands,
remove that test's `principalPending` gate.

If a later decision in this file conflicts with code, the code is wrong. If
it conflicts with evidence (a fixture or counterexample shows the rule is
wrong), change this file first, record the reason in §11, and then change
the code.

---

## 0. The one sentence

> Runopsy may draw an arrow only when it can name the mechanism, show the
> observation that the mechanism actually operated, and say what it checked
> that could have proven it wrong.

Everything below follows from that sentence.

---

## 1. Chronology vs causality (4.7)

### 1.1 Evidence classes

Every relation is defined by which evidence classes it requires. A rule's
contract (§3) names the concrete checks that implement each class.

| Class | Name | Meaning | Example |
|---|---|---|---|
| **E1** | Order | `ts(A) < ts(B)` was observed. Equal wall timestamps are not order. | limit sample at T+14, exit event at T+15 |
| **E1′** | Co-occurrence | A and B were observed in the same sampling instant (`ts(A) == ts(B)`). Order is unknown. | both first seen in snapshot 88 |
| **E2** | Linkage | A and B concern the same subject, or subjects joined by a *recorded* relationship (same PID+start time, recorded PPID, same cgroup path, same socket inode, the process owns the socket). Never inferred from names, PID ranges or proximity. | child's recorded `from_ppid` = the exited parent's PID |
| **E3** | Mechanism | The rule declares a known physical or OS mechanism by which A can produce or worsen B. This is the rule's own claim and is documented with the rule. | the kernel reparents orphans when the parent exits |
| **E4** | Discriminator | An observation that *this* mechanism operated, as opposed to merely being possible. It must be something that would usually be absent if A were not the cause. | the kernel OOM record names the victim PID; the child's PPID changed from the dead parent's PID |
| **E5** | Contradiction-clean | Every contradiction check the rule declares was **evaluated** and came back ABSENT. A check that could not be evaluated is UNKNOWN, not ABSENT. | "child reparented before the parent exited": evaluated, absent |

### 1.2 Relation vocabulary

The vocabulary in 4.6 stays as is, with one addition, `ESCALATES_TO` (see
1.3).

| Relation | Requires | Counterfactual reading | It does **not** claim | Root/chain participation |
|---|---|---|---|---|
| `PRECEDES` | E1 + a rule declaring the pair meaningful | none | any dependence at all | Never. Shown in the timeline, never as an arrow in a causal chain. |
| `CORRELATED_WITH` | E1′ or a declared clustering window + E2 | none | order or dependence | Never. |
| `ESCALATES_TO` (new) | E1 + same subject + **same episode** + same measured quantity crossing a higher severity threshold | "the same condition got worse" | that the first crossing caused the second; both share the episode's (possibly unobserved) cause | Traversable: it carries the episode onset to the episode's peak. Contributes no confidence. |
| `CONTRIBUTES_TO` | (E1 or E1′) + E2 + E3 + E5-or-UNKNOWN | "without A, B would likely have been later, rarer or milder; B may still have happened" | sufficiency | Traversable. A path made only of these makes a **contributing factor**, never a root cause (§5). |
| `CAUSES` | (E1 or E1′) + E2 + E3 + **E4** + E5-or-UNKNOWN | "had A not occurred, B would not have occurred when it did" | that A is the *only* explanation (competition is handled in §6) | Traversable. |
| `RECOVERY_OF` | E1 + same subject + same episode | "the condition A started has ended" | that anything downstream was undone | Ends an episode. Never a cause. |
| `CONTRADICTS` | an evaluated contradiction check returned PRESENT | "this observation argues against claim X" | — | Attached to the rejected or demoted claim. |

**The CAUSES vs CONTRIBUTES_TO line is E4, not confidence.** A
well-observed cofactor is still `CONTRIBUTES_TO`. A weakly observed mechanism
with a real discriminator is `CAUSES` at a low band. Confidence (§2) is a
separate question.

### 1.3 Why `ESCALATES_TO` exists

`MEMORY_PRESSURE_STARTED` (≥90%) → `MEMORY_LIMIT_REACHED` (≥98%) on the same
host in the same episode is **one quantity crossing two thresholds**. Crossing
90% does not cause crossing 98%; the allocation growth causes both. Labelling it
`CAUSES` is the textbook error of mistaking a common cause for a causal link.
It also makes the 90% crossing look like a mechanism. But the chain still
needs the episode onset as its head (§5.4), so the relation must be
traversable without being causal. `ESCALATES_TO` is exactly that.

Applies to: memory pressure → memory limit; disk pressure → disk exhausted
(free-space machine only, see review 4.23 note); any future
"started → severe" pair produced by one state machine on one subject.

### 1.4 Promotion ladder

An observed pair can move up only by adding evidence classes:

```text
nothing ──E1 + rule──► PRECEDES ──E2+E3──► CONTRIBUTES_TO ──E4──► CAUSES
                                  (E5 PRESENT at any step ⇒ veto, record CONTRADICTS)
```

No rule may skip from E1 straight to `CAUSES`. A gap bound (MaxGap) is a
precondition, never evidence: being "within 2 s" is still E1.

### 1.5 Prohibitions (engine-enforced, not per rule)

- **P1 — No proximity edges.** No relation other than `PRECEDES` may be
  justified by timing alone, and a `PRECEDES` needs a declaring rule.
- **P2 — No self-explanation.** A derived event (one whose provenance lists
  other events or samples) may not be the source of a causal or
  contributing edge to any event whose evidence it was derived from. If the
  two events share a provenance source, the edge is invalid. This is
  `PROCESS_GROUP_TERMINATED`, which is clustered *from* member exits (audit
  A4).
- **P3 — Episode binding.** A causal, contributing, escalation or recovery
  edge whose endpoints belong to condition episodes must connect events of
  the same episode instance, or (for cross-condition rules) the source
  episode must still be active, unrecovered, at the target's timestamp.
  A recovered episode cannot cause something that happens after its
  recovery (audit A3).
- **P4 — No edge across an unbridged discontinuity.** If a
  `CLOCK_DISCONTINUITY` or timeline gap event lies strictly between source
  and target, the edge is demoted to LOW (D4) and flagged. Recovery
  edges across such a gap are refused.
- **P5 — Unobservable events never originate edges.** Event types the v1
  bundle cannot observe (`OOM_EVENT`, `NETWORK_PROGRESS_*`, `WORKER_*`,
  `RUNNER_*`) are never fabricated (already true; keep it that way).
- **P6 — Same-instant edges are marked.** An edge supported by E1′ only
  carries `same_instant: true`, and its evidence says "order within the
  sampling instant not observed". Its band is capped at MEDIUM (D5).
- **P7 — Canonical order is not evidence.** The canonical tie-break (§4.3)
  exists for determinism. No rule, root ranking or helper may use canonical
  position as order evidence. `Before`/`After` in `compare.go` must be
  renamed `CanonicalBefore`/`CanonicalAfter`, and `ObservedBefore` (strict
  timestamp) added for rules.

---

## 2. Causal confidence semantics (4.10)

### 2.1 What a band means

A band grades **how directly the required evidence was observed**. It is not
a probability, not a likelihood that A caused B, and not comparable across
products. The bands answer one question: *if this arrow is wrong, how
surprised should the reader be?*

| Band | Meaning | All of these hold |
|---|---|---|
| **HIGH** | Wrong would be surprising | Every required check is PRESENT from a **recorded event** (kernel record, recorded exit, recorded PPID). Identity is **exact** (PID + start time, inode, cgroup path). Every contradiction check was evaluated and is ABSENT. No competing CAUSES edge targets the same event. Endpoints are strictly ordered (E1). No discontinuity between them. |
| **MEDIUM** | Wrong is possible but would need an unusual sequence | Every required check is PRESENT, but at least one of: a requirement rests on **sampled state** rather than a recorded event; identity is **weak** (PID only, host scope for a process claim); a contradiction check was **UNKNOWN**; same-instant (E1′); a competing explanation exists. |
| **LOW** | A plausible link worth showing; wrong would not be surprising | Required checks are PRESENT, but the edge spans a timeline discontinuity, or a sampling gap exceeds the rule's MaxGap/2, or two or more MEDIUM conditions stack. |

### 2.2 Computation (uniform; rules do not invent scoring)

```text
edge.band = min(rule.Ceiling, evidenceGrade(edge))
evidenceGrade starts at HIGH and applies every demotion that matches:
  D1  any declared contradiction check UNKNOWN          → cap MEDIUM
  D2  identity weak (PID-only, host-scope)               → cap MEDIUM
  D3  a competing CAUSES edge targets the same event     → cap MEDIUM (both edges)
  D4  discontinuity or gap event between endpoints       → cap LOW
  D5  same-instant only (E1′)                            → cap MEDIUM
  D6  a required check rests on sampled state            → cap MEDIUM
  two or more of D1/D2/D3/D5/D6 apply                    → LOW
```

- Each applied demotion is recorded on the edge (`demotions: ["D1:CHILD_REPARENTED_BEFORE_EXIT unevaluable", ...]`)
  so the band is explainable (§8).
- **Supporting evidence never raises a band.** It is displayed, and that is
  all it does.
- **Ceilings:** `CONTRIBUTES_TO` ceiling is MEDIUM in v1. No cofactor rule
  ships at HIGH until a fixture proves it.
- The internal numeric weights (0.35/0.65/0.90) may stay for sorting, but
  are never rendered, never averaged and never multiplied.

### 2.3 Missing vs contradictory evidence

| Situation | Effect |
|---|---|
| Required check ABSENT | No edge. `RejectedEdge{reason: "required X absent"}` |
| Required check UNKNOWN (telemetry not captured) | No edge. `RejectedEdge{reason: "required X unobservable in this bundle"}`. Surfaced in the unknown-cause report's *missing evidence*. |
| Supporting check ABSENT/UNKNOWN | Edge unaffected; listed under `missing_supporting` |
| Contradiction PRESENT | Veto: no edge; record `CONTRADICTS` in rejections with the observation |
| Contradiction UNKNOWN | Edge allowed, D1 applied, listed as "not checkable" |
| Contradiction ABSENT (evaluated) | Edge allowed; listed as "checked, absent" |

The tri-state (PRESENT/ABSENT/UNKNOWN) is Phase 3's evidence philosophy, and
it is now mandatory in Phase 4 too. The current `ruleContradiction`, which
reads `Data["contradictions"]` (a key that no extractor ever sets), is
replaced by per-code evaluators.

### 2.4 Bands on chains and roots

- **Chain band = weakest link** on the path. `ESCALATES_TO` contributes
  nothing; `PRECEDES` never appears in a chain.
- **Root band, for a given failure anchor = the best chain band** from that
  root to that anchor. Today the root band is the strongest edge *leaving* the
  root (audit A8), which overstates any chain with a weak later link.
- Temporal relations (`PRECEDES`, `RECOVERY_OF`) keep the JSON `confidence`
  field for schema stability, but it means *observation certainty*, and the
  text renderer omits it.

---

## 3. Causal evidence requirements (4.9)

### 3.1 Rule contract (schema)

```go
type Rule struct {
    ID       string        // NAME@VERSION; any semantic change → new version
    Source   EventType
    Target   EventType
    Edge     RelationType
    Ceiling  CausalConfidence

    // Mechanism (E3): one sentence, rendered by explain-edge.
    Mechanism string

    Required      []Check   // E2 + E4 checks; each returns PRESENT|ABSENT|UNKNOWN
    Discriminator []string  // codes within Required that satisfy E4 (CAUSES needs ≥1)
    Supporting    []Check
    Contradicting []Check   // evaluated; PRESENT vetoes, UNKNOWN demotes (D1)

    MinGap, MaxGap time.Duration
    SameInstant    bool          // may E1′ satisfy order? (default false)
    Binding        EpisodeBinding // SameEpisode | SourceActiveAtTarget | NearestOnly | None
    Identity       IdentityStrength // Exact | PIDOnly | Scope ; drives D2
}

type Check struct {
    Code     string
    Evaluate func(g *Graph, src, tgt *Event) CheckResult // PRESENT|ABSENT|UNKNOWN + detail + provenance refs
}
```

Registry invariants, enforced by a test over `Rules()`:

1. `Edge == CAUSES` ⇒ `len(Discriminator) ≥ 1`, and each discriminator code
   is in `Required`.
2. `Edge ∈ {CAUSES, CONTRIBUTES_TO, ESCALATES_TO, RECOVERY_OF}` ⇒
   `Binding != None`, or the rule's documented reason why binding is
   impossible.
3. `Edge == CONTRIBUTES_TO` ⇒ `Ceiling ≤ MEDIUM`.
4. Every code in every list has an evaluator (no "always false" placeholders
   wearing a real name, see 3.3).
5. `Mechanism` non-empty for every non-temporal rule.

### 3.2 The OOM question (the provisional decision #2)

> Is signal lineage the constitutive condition for `OOM_CAUSES_PROCESS_EXIT`,
> or one of several sufficient ones?

Decision: **neither. The constitutive condition (E4) is a kernel OOM record
that identifies the victim.** A SIGKILL exit status is *supporting* evidence,
because many things send SIGKILL: runner cancellation, timeout wrappers,
`docker kill`, operators.

| Evidence available | Relation / band |
|---|---|
| OOM record names victim PID **and** start time (or PID + cgroup + exit within MaxGap) **and** a recorded exit of that identity | `CAUSES` HIGH |
| cgroup `memory.events oom_kill` counter incremented in the sample interval containing the exit, exit is SIGKILL, process in that cgroup, **exactly one** member exited in the interval | `CAUSES` MEDIUM (D6: sampled counter) |
| same, but several members exited in the interval | each `CAUSES` LOW, marked competing (§6) |
| SIGKILL exit + memory at limit + no OOM record/counter | **no causal edge.** The report's unknown-cause section lists "OOM suspected; kernel OOM record not captured" as an *alternative explanation*. This is the 4.37 counterfactual target "memory exhaustion suspected, not definite OOM kill". |
| memory at limit + exit with unknown status | nothing beyond the unknown-cause report |

Telemetry implication for Phase 1 (not v1): read `memory.events` (`oom_kill`
counter) per watched cgroup each sample, and record exit status/signal for
watched processes where available. Both are cheap. Until then the rule stays
dormant, which is correct.

### 3.3 Registry verdicts (current `rules.go`)

| Rule | Verdict | Required change |
|---|---|---|
| `OOM_CAUSES_PROCESS_EXIT@1` | **Change → @2** | E4 = OOM record identifies victim (3.2). Signal → Supporting. Binding: exact identity. Ceiling HIGH. |
| `MEMORY_LIMIT_CAUSES_OOM@1` | **Change → @2** | Applies to **host** limit → host (global) OOM only. Ceiling MEDIUM (host 98% is not proof the OOM killer fired for that reason). Add MaxGap 30 s and Binding `SourceActiveAtTarget`. |
| `CGROUP_LIMIT_PRECEDES_OOM@1` | **Replace** with `CGROUP_LIMIT_CAUSES_OOM@1` | Strength is inverted today: the cgroup at `memory.max` with an OOM record **for that cgroup** is the canonical cgroup-OOM mechanism. `CAUSES`, E4 = OOM record names the same cgroup path, ceiling HIGH, Binding `SourceActiveAtTarget`. |
| `MEMORY_PRESSURE_CAUSES_LIMIT_BREACH@1` | **Retire.** Add `MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1` | `ESCALATES_TO`, Binding `SameEpisode` (fixes A3). |
| `MEMORY_RECOVERY_FOLLOWS_LIMIT@1` | **Change → @2** | Source must be the episode's **onset** event (STARTED/ACTIVE), not the limit, so the recovery closes the whole episode (fixes A2). Binding `SameEpisode`. |
| `PROCESS_EXIT_CAUSES_REPARENT@1` | **Change → @2** | Correct mechanism, weak binding. E4 = recorded `from_ppid` equals the exited PID **and** the exit is the last exit of that PID before the reparent observation **and** after the child was last observed with that PPID (parent-incarnation binding, A22). Identity PIDOnly ⇒ D2 ⇒ MEDIUM. Contradiction `CHILD_REPARENTED_BEFORE_EXIT` gets a real evaluator. Remove the `ruleSupportsEdge` special case that admits `PROCESS_GROUP_TERMINATED` as a source. |
| `PROCESS_GROUP_TERM_CAUSES_GROUP_EXIT@1` | **Retire** | Violates P2 (A4). The group event is an aggregate **failure** (a summary of the effect), not a cause. Member exits are linked through its provenance; no edges are needed. The cause (who signalled the group) is unobserved, so root cause is UNKNOWN with missing evidence "no signal-sender telemetry". |
| `PROCESS_STOP_ENDS_CPU_SATURATION@1` | **Change → @2** | Mechanism is real (a stopped task is not scheduled). Required: same process identity, and saturation ended at the first sample at or after the stop. Drop `MatchStallWindow` (it reads `stall_ms`, which a stop event never carries, so the rule is silently dead). Low value: it explains the *end* of an anomaly, so it never makes a root. |
| `CPU_SATURATION_CONTRIBUTES_TO_FREEZE@1` | **Retire** | Wrong target. `PROCESS_STOPPED` is state T (SIGSTOP or ptrace), and CPU load cannot put a process in T. The 4.24 intent ("CPU saturation contributes to a worker *stall*") needs a progress-loss event the bundle cannot observe. Re-introduce when there is a `WORKER_PROGRESS_STOPPED` event (§7.4). |
| `CPU_SATURATION_RESOLVES@1` | Keep, rename nothing | Add Binding `SameEpisode`. |
| `NETWORK_STALL_PRECEDES_INCIDENT@1` | **Retired (removed from registry).** | Its check reads `SAME_QUANTITY_SAME_EPISODE` against `INCIDENT_TRIGGERED`, which carries no episode and a host subject, so it could never fire. Re-introduce only with a defined incident-to-stall binding. See §7. |
| `NETWORK_RECOVERY_FOLLOWS_STALL@1` | Keep (dormant) | Binding `SameEpisode` (same socket inode). |
| `DISK_PRESSURE_PRECEDES_EXHAUSTION@1` | **Retire.** Add `DISK_PRESSURE_ESCALATES_TO_EXHAUSTION@1` | Same-quantity escalation, so `ESCALATES_TO`. Same filesystem subject required. **IO PSI must stop emitting `DISK_PRESSURE_STARTED`**: give it `IO_PRESSURE_STARTED/ENDED` (host subject). Today the two different quantities share one event type. |
| `DISK_RECOVERY_FOLLOWS_EXHAUSTION@1` | **Change → @2** | Source = episode onset; Binding `SameEpisode`. |
| `WORKER_EXIT_CAUSES_INCIDENT@1` | Keep (dormant) | Fine as written; the trigger linkage is Phase 5 territory. |

Versioning: none of this was released, so the `@1` IDs could legally be
reused. Don't. Retire and re-version as listed, so the history in
`HANDOFF.md` and any stored test output stays interpretable (4.18
discipline).

---

## 4. Event graph architecture (4.6)

### 4.1 Layers

The graph keeps one event set and one edge list, but every consumer must
select edges by **layer**:

| Layer | Relations | Used by |
|---|---|---|
| Temporal | `PRECEDES`, `CORRELATED_WITH` | timeline rendering only |
| Episode | `ESCALATES_TO`, `RECOVERY_OF` | episode reconstruction, chain traversal (escalation only) |
| Causal | `CAUSES`, `CONTRIBUTES_TO` | chains, roots, DAG check |
| Dissent | `CONTRADICTS` | explanations |

The DAG check covers Causal ∪ Episode.

### 4.2 Data model additions (engineering)

```go
type Event struct {
    // existing fields …
    Episode   string        `json:"episode,omitempty"`    // "memory:host:local#2"; set by every state machine
    Class     EventClass    `json:"class"`                // CONDITION | FAILURE | CONTEXT (§5.1)
    OnsetWindow *Window     `json:"onset_window,omitempty"` // (last-known-below, observed-at] for STARTED/crossing events
    // identity fields typed, not in Data:
    PID, PPID, PGID int; StartTicks int64                  // when applicable
}

type CausalEdge struct {
    // existing fields …
    Checks     []CheckRecord `json:"checks"`      // every Required/Contradicting check with PRESENT|ABSENT|UNKNOWN
    Missing    []string      `json:"missing_supporting,omitempty"`
    Demotions  []string      `json:"demotions,omitempty"`
    SameInstant bool         `json:"same_instant,omitempty"`
    Mechanism  string        `json:"mechanism"`
    Competes   []string      `json:"competes_with,omitempty"` // other edge IDs into the same target (§6)
}

type RootCandidate struct {
    Event    EventID          `json:"event"`
    Kind     RootKind         `json:"kind"`     // ROOT_CAUSE | UNEXPLAINED_HEAD | CONTRIBUTING_FACTOR
    Anchor   EventID          `json:"anchor"`   // the failure this candidate explains
    Role     RootRole         `json:"role"`     // PRIMARY | COMPETING | SECONDARY
    Confidence CausalConfidence `json:"confidence"` // weakest-link band to Anchor
    OnsetUnknown bool         `json:"onset_unknown"`
    Effects  int              `json:"downstream_effects"` // distinct events reached (today: path count, A14)
}

type FailureAnalysis struct {           // one per failure anchor; new top-level JSON array "failures"
    Anchor     EventID
    Status     string                  // EXPLAINED | AMBIGUOUS | CONTRIBUTING_ONLY | UNKNOWN
    Candidates []RootCandidate
    MissingEvidence []string
    Alternatives []string              // e.g. "OOM suspected; kernel OOM record not captured"
}
```

`Data map[string]any` remains for display-only facts. **Rules must not read
identity from `Data` by type assertion.** `.(int)` silently fails after any
JSON round-trip, where every number becomes `float64` (audit A18).

### 4.3 Ordering and identity (confirmed with changes, see review 4.4)

- Canonical order = (timestamp, typeRank, subject, type, onset, ID). It is
  deterministic and **not evidence** (P7).
- `Sequence` is the canonical index. Fix the comment that says it
  "preserves original capture order", which is false. If capture order is
  needed (it is, §4.4 of the review), add `CaptureIndex` from the bundle.
- Event IDs are stable per (bundle, extractor version). Document that adding
  a Data key changes IDs. Explanations stored across extractor versions
  must key on rule version + event type + timestamp, not on IDs.

### 4.4 Validate() must additionally enforce

V1: P2 (no shared provenance across a causal edge).
V2: P3 (episode binding).
V3: every non-temporal edge has `Checks`, `Mechanism` and a band equal to
the recomputed band (catches hand-set bands like the ones in the A8 test).
V4: every `CAUSES` edge has ≥1 PRESENT discriminator check.
V5: every root candidate has an anchor of class FAILURE that it reaches.

---

## 5. Root-event identification (4.11)

### 5.1 Event classes

| Class | Types (v1 + reserved) | Meaning |
|---|---|---|
| **CONDITION** | `MEMORY_PRESSURE_*`, `MEMORY_LIMIT_REACHED`, `CGROUP_LIMIT_REACHED`, `DISK_PRESSURE_*`/`DISK_LOW_ACTIVE`/`DISK_EXHAUSTED`, `IO_PRESSURE_*`, `CPU_CONTENTION_*` (reserved: host-level, from PSI cpu), `OOM_EVENT`, `NETWORK_PROGRESS_STOPPED` | A state of the world that can *initiate* a failure. Can be a root cause. |
| **FAILURE** | `PROCESS_EXITED` (not recorded as normal **and** with failure context, see below), `PROCESS_STOPPED` (no `PROCESS_RESUMED` in capture), `PROCESS_GROUP_TERMINATED`, `WORKER_EXITED`, `WORKER_PROGRESS_STOPPED` (reserved), `CONNECTION_CLOSED` (only when a Phase 3 network signature claimed it) | Something went wrong that *needs* an explanation. Can head a known chain; never a root cause by itself. |
| **CONTEXT** | `CPU_SATURATION_*` (process-scoped: a process is CPU-bound, which is its own behaviour — a symptom such as CPU_SPIN, not an external condition), `PROCESS_STARTED`, `PROCESS_RESUMED`, `PROCESS_REPARENTED`, `CONNECTION_OPENED`, all `*_RECOVERED`/`*_ENDED`, `CLOCK_DISCONTINUITY`, `INCIDENT_TRIGGERED` | Facts and consequences; never roots or anchors. |

`PROCESS_REPARENTED` is CONTEXT: an orphan being adopted is a consequence,
and the failure is the parent's exit.

**Exit failure context (2026-10-28, refined 2026-10-30).** The recorder
watches every process by default, so "not recorded as normal" alone would make
every short-lived helper exit a failure. An exit status is recorded
opportunistically (`exit_state` on the timeline event): the kernel exposes the
terminal wait status of a zombie for exactly as long as its parent has not
reaped it, so a sampler that catches the corpse between samples names how the
process died (`exit:<code>` or `signal:<n>`); a vanished, already-reaped PID
records no status and stays UNKNOWN. `exit:0` in particular records the exit
as normal: the graph then treats it as context outright, and identity rules
that tolerate a later normal exit no longer have to guess from absence.

A `PROCESS_EXITED` is a
failure anchor only when at least one of these holds: its recorded status is
non-normal; the incident trigger names that process; a chain edge leads into
or out of it (an OOM kill, orphaned children); or a memory/cgroup limit
episode was unresolved when it exited (the "OOM suspected" case). Member
exits inside a group's coordinated window are the group anchor's evidence,
not anchors. Any other exit is CONTEXT, and the report states how many there
were.

**Severe unresolved condition.** A CONDITION event at its severe level
(`MEMORY_LIMIT_REACHED`, `CGROUP_LIMIT_REACHED`, `DISK_EXHAUSTED`, `OOM_EVENT`)
whose episode has **no** observed recovery by capture end, and which was
observed at the severe level in **at least two samples** (4.27), is *also* a
failure anchor. A single severe reading cannot tell a transient dip from a
full disk; it is reported as an unconfirmed reading, not a failure. Every
resource episode closes with an observed recovery event, including cgroup
limits (`CGROUP_LIMIT_CLEARED`). The disk is still full when recording stops, and that needs
explaining even if no write failure was observed. It can be the anchor of
its own analysis (cause UNKNOWN, known escalation chain), and it can be a root
cause for later anchors. A severe condition that recovered is not an anchor.

### 5.2 Definitions

- **Failure anchor:** an event of class FAILURE, or a severe unresolved
  condition (§5.1). Every anchor gets one
  `FailureAnalysis`, with no exceptions. Today the unknown-cause report is
  suppressed whenever *any* root exists (audit A15).
- **Primary failure:** the earliest anchor that is not reached by a causal
  path from another anchor. If several anchors share the earliest timestamp,
  all are primary (no tie-break by type rank, P7).
- **Root cause candidate** for anchor F: an event R such that
  1. R is **CONDITION** class;
  2. R reaches F through Causal ∪ `ESCALATES_TO` edges, along a path with
     at least one `CAUSES` edge;
  3. R has no incoming Causal edge from another CONDITION or FAILURE
     (it is the earliest supported link). An incoming `ESCALATES_TO` means
     R is not the episode onset; walk back to the onset.
- **Unexplained head** for F: an event H **≠ F** of class FAILURE that
  satisfies (2) and (3), e.g. an upstream worker exit heading a chain to F.
  The report says **"Root cause: UNKNOWN"** and names H as the earliest known
  link whose own cause was not captured (the 4.45 shape). **A failure is
  never its own candidate**: an anchor with no upstream link reports status
  UNKNOWN and its known chain, which also covers its downstream
  consequences (a parent exit → reparent).
- **Contributing factor** for F: a CONDITION event that reaches F through at
  least one Causal-layer edge (`CONTRIBUTES_TO`), but along no path that
  contains a `CAUSES` edge. It is reported under "contributing factors" with
  band ≤ MEDIUM, and it never makes F's status EXPLAINED. **An
  escalation-only path is not contribution**: the 90% crossing does not
  contribute to the 98% crossing of the same episode. That path is F's own
  known chain.
- A CONDITION chain that reaches **no** anchor is **context**: "memory
  pressure observed (no consequence established)". It is never rendered
  under a "ROOT CAUSE" heading (audit A1).

### 5.3 The OOM answer

```text
allocation growth (unobservable)   ← the true root; not observable in v1
      ↓
MEMORY_PRESSURE_STARTED            ← ROOT CAUSE anchor (episode onset)
      ↓ ESCALATES_TO
MEMORY_LIMIT_REACHED
      ↓ CAUSES  (host OOM, MEDIUM) / CGROUP_LIMIT_REACHED ↓ CAUSES (cgroup OOM, HIGH)
OOM_EVENT
      ↓ CAUSES
PROCESS_EXITED                     ← failure anchor
```

Runopsy names the root as **the memory episode, anchored at its earliest
observed event**:

- onset observed → `MEMORY_PRESSURE_STARTED`, "memory pressure began at
  19:43:08";
- onset not observed → `MEMORY_PRESSURE_ACTIVE` (onset_unknown), "memory
  pressure already active when recording began; onset not captured" (4.28);
- no memory data at all, OOM record present → `OOM_EVENT` is the root
  candidate, with the note "upstream memory condition not observed" (4.29).
  Do not fabricate the pressure.

Not `MEMORY_LIMIT_REACHED`: that is a step in the escalation, not a separate
initiating fact. Not `PROCESS_EXITED`: that is the anchor. Not the OOM: that
is the mechanism, except in the 4.29 case.

### 5.4 Ranking and roles

For each anchor:

1. Candidates sorted by chain band (weakest link), then by `CAUSES`-path
   over contributing-only.
2. If exactly one candidate has the top band → it is `PRIMARY`; others
   `SECONDARY`.
3. If two or more **independent** candidates share the top band (neither
   reaches the other) → **all are `COMPETING`, none is `PRIMARY`**, and the
   anchor's status is `AMBIGUOUS` (§6). **Canonical order may break ties
   for display order only**, never for roles (audit A6).
4. The global headline is the primary failure's analysis. Other anchors'
   analyses are listed after it.

### 5.5 Recovery and health

- Recovery of the root condition **after** the anchor does not change
  anything. A memory episode that recovered after it killed the worker is
  still the root cause. (Today `Recovered` is computed only from a
  `RECOVERY_OF` edge leaving the root, and it is reported as "not a terminal
  root cause". Both are wrong for this case.)
- `Healthy()` = **no failure anchors in the capture.** Condition episodes
  that never reached a severe level, or that recovered, and that reached no
  anchor are healthy-but-noteworthy. This makes `high-memory-build`,
  `short-process-stop` and the A1 brief-98% case healthy for the right reason,
  not because of the `Recovered` flag.

### 5.6 Expected fixture outcomes after this change

| Fixture | Today | Required |
|---|---|---|
| oom-chain | PRIMARY root `MEMORY_PRESSURE_STARTED` via CAUSES; exit unexplained; no unknown-cause report | pressure `ESCALATES_TO` limit. Two anchors, both UNKNOWN: the unrecovered `MEMORY_LIMIT_REACHED` (known chain pressure → limit) and `PROCESS_EXITED` (alternative: "OOM suspected; kernel OOM record not captured"). No candidate of kind ROOT_CAUSE. `graph_healthy: false`. |
| orphan-process | PRIMARY root `PROCESS_EXITED` | edge kept (`@2`, MEDIUM via D2); anchor = parent exit; no candidates (a failure is never its own candidate); status UNKNOWN; known chain exit → reparent |
| process-group-kill | PRIMARY root `PROCESS_GROUP_TERMINATED`, 3 CAUSES edges into its own sources | no edges; anchor `PROCESS_GROUP_TERMINATED` (member exits listed via provenance); status UNKNOWN; missing "no signal-sender telemetry" |
| disk-full | PRECEDES only; UNKNOWN; `graph_healthy: true` | `ESCALATES_TO`; anchor = unrecovered `DISK_EXHAUSTED`, status UNKNOWN, known chain pressure → exhausted, missing "write-failure / ENOSPC telemetry". `graph_healthy: **false**`: a disk still full at capture end is not healthy. |
| frozen-worker | UNKNOWN anchored at PROCESS_STOPPED | unchanged (stop never resumed ⇒ FAILURE anchor, UNKNOWN) |
| healthy × 5 | healthy | unchanged |

`expected.json` files are reviewed artifacts. engineering updates them in the same
change that implements the semantics, with notes that cite this file's
section numbers. adversarial reviews the diff.

---

## 6. Competing causal chains (4.15)

### 6.1 Definitions

- Two candidates **compete** for anchor F when both reach F and neither
  reaches the other.
- Two `CAUSES` edges into the same target from non-ancestral sources are
  **alternatives** (each claims sufficiency): both get D3 (cap MEDIUM) and
  reference each other in `competes_with`.
- Several `CONTRIBUTES_TO` edges into one target are **co-factors**, not
  competitors. Show them together.
- Overdetermination (both truly operated) cannot be distinguished from
  alternatives with v1 evidence. Report it as competition. Do not guess.

### 6.2 Resolution rule

Ambiguity is resolved **only by discriminating evidence**, never by
ordering, rule-registry order, confidence arithmetic or "first rule wins".
A discriminator for a competition is an observation whose presence is
expected under one hypothesis and absent under the other (see §7.3 for the
network pair). When the discriminating checks are UNKNOWN:

```text
Root cause: AMBIGUOUS
  Candidate: BROKER_SOCKET_STALL chain     — MEDIUM
  Candidate: NETWORK_PATH_FAILURE chain    — MEDIUM
  Would discriminate (not captured): send-queue state, retransmit timer, other sockets to the same remote
```

When one discriminator is PRESENT for A and contradicts B, then A is
PRIMARY, and B is SECONDARY with its `CONTRADICTS` record shown.

### 6.3 Relation to Phase 3

Phase 3 alternatives (`report.Ambiguous`) and Phase 4 competing candidates
must agree in direction. If Phase 3 says "ambiguous between X and Y" and
Phase 4 promotes one chain to PRIMARY, the report must show **which Phase 4
discriminator** broke the tie, or else downgrade to AMBIGUOUS. secondary owns
this consistency check in 4.44.

---

## 7. Network causality (4.25)

This is the flagship demo (4.47), and today it cannot produce a chain,
because v1 has no progress telemetry. That is honest; it is also the
largest gap between the plan and the product. This section specifies
what to build. The current fixtures and E2E already guard against
fabrication.

### 7.1 Telemetry tiers (Phase 1 extension; Linux)

| Tier | Source | Fields | Cost | Unlocks |
|---|---|---|---|---|
| **A** (do first) | `/proc/net/tcp{,6}`, which is **already read** | `tx_queue`, `rx_queue`, `tr` (timer: 1 = retransmit, 2 = keepalive, 4 = zero-window probe), `retrnsmt` (unrecovered RTO count) — currently parsed past and discarded | ~0 | send/recv queue discriminators, retransmit state |
| **B** | `NETLINK_SOCK_DIAG` / `INET_DIAG` with `tcp_info` for watched-process sockets | `bytes_acked`, `bytes_received`, `tcpi_last_data_recv`, `tcpi_last_data_sent`, `tcpi_retransmits`, `tcpi_rto`, `tcpi_probes` | low (watched sockets only) | **direct progress measurement**: `last_data_recv` gives "ms since data last arrived" in one sample |
| **C** | `/proc/<pid>/wchan`, `/proc/<pid>/syscall` for watched workers | blocked-in-read evidence | low | E4 for "worker blocked on this socket" |

macOS: none of these are available through the current collectors. Network
progress stays UNKNOWN on darwin, which is stated, not hidden.

### 7.2 Derived events (all socket-subject, inode identity)

- `NETWORK_PROGRESS_STOPPED`: ESTABLISHED socket, owned by a watched process,
  that **previously showed progress in this capture** (bytes moved, or
  `last_data_recv` reset), and now has no progress for ≥ `stallThreshold`
  (default 30 s, configurable) across continuously available samples.
  Data: `stall_ms`, `send_q`, `recv_q`, `timer`, `rto_count`, `last_progress_at`.
  A socket that never showed progress is **idle, not stalled** (the
  long-idle-socket healthy fixture) and emits nothing.
- `NETWORK_PROGRESS_RESUMED`: progress observed again on the same inode
  (same episode).
- Each STOPPED event carries a **stall shape** computed from Tier A/B:

| Shape | Observation | Points at |
|---|---|---|
| `PEER_SILENT` | send_q == 0 (everything we sent is acked), recv_q == 0, no retransmit timer | the peer (broker) is not sending: **BROKER_STALL** side |
| `PATH_LOSS` | send_q > 0 and not draining, retransmit timer armed / `retrnsmt` rising | our data is not being acked: **NETWORK_PATH_FAILURE** side (or peer host down) |
| `ZERO_WINDOW` | zero-window probe timer (tr = 4), send_q > 0 | peer not reading: peer-side application stall |
| `LOCAL_NOT_READING` | recv_q > 0 and growing | **our** process is not reading. The network stall is an *effect* of a local stall, so the arrow reverses (N1). |
| `UNKNOWN_SHAPE` | Tier A unavailable | no discrimination |

### 7.3 Discriminators for the 4.15 pair

| Observation | BROKER_SOCKET_STALL | NETWORK_PATH_FAILURE |
|---|---|---|
| stall shape `PEER_SILENT` | supports | contradicts (path loss would show retransmits once we send) |
| stall shape `PATH_LOSS` | contradicts | supports |
| other sockets to **same remote** also stalled | neutral | supports (path to that remote) |
| sockets to **other remotes** progressing during the stall | supports remote-specific (both) | weakly contradicts a host-wide network failure |
| **all** remotes stalled | contradicts | supports (local network) |
| connection closed with RST shortly after | neutral | supports peer/path failure |

Caveat for the reviewers (adversarial): `PEER_SILENT` is also what a healthy idle
long-poll looks like. It becomes a stall only with a downstream failure
anchor (worker progress loss or incident) **and** a prior-progress
requirement. Without an anchor, it is context.

### 7.4 Rules (generic runner/worker abstractions; no GitHub specifics until Phase 5)

| ID | Edge | Required (E4 in bold) | Ceiling |
|---|---|---|---|
| `PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1` (N1) | `PROCESS_STOPPED → NETWORK_PROGRESS_STOPPED`, CAUSES | socket owned by the stopped identity; stop ≤ stall onset; **shape `LOCAL_NOT_READING`** | HIGH |
| `NETWORK_STALL_CAUSES_WORKER_PROGRESS_LOSS@1` (N2) | `NETWORK_PROGRESS_STOPPED → WORKER_PROGRESS_STOPPED`, CAUSES | socket owned by the worker; worker CPU ≈ 0 during the stall (blocked, not spinning); **Tier C: worker blocked in read on that socket's fd** | MEDIUM |
| `NETWORK_STALL_CONTRIBUTES_TO_WORKER_PROGRESS_LOSS@1` (N2′) | same pair, CONTRIBUTES_TO | the same, without Tier C | MEDIUM |
| `NETWORK_RECOVERY_FOLLOWS_STALL@2` | RECOVERY_OF | same inode, same episode | — |

`WORKER_PROGRESS_STOPPED` is the generic "the job stopped making progress"
event (reserved). In v1 it is unobservable. Phase 5 supplies it from runner
logs and job heartbeats. Until then, N2/N2′ cannot fire, and the honest
4.47 outcome remains "no chain".

The **Phase 3 hypotheses** `BROKER_SOCKET_STALL` and `NETWORK_PATH_FAILURE`
are evaluated as *competing explanations of the NETWORK_PROGRESS_STOPPED
condition* using §7.3. They are not separate event types. Phase 4 renders
them as the anchor's alternatives with their discriminator status.

### 7.5 Flagship target graph (4.47), once Tier A/B and worker progress exist

```text
CONNECTION_OPENED (socket:inode-88201, owner worker 5842@…)
      ↓ PRECEDES
NETWORK_PROGRESS_STOPPED  shape=PEER_SILENT  stall=94s   ← ROOT CAUSE (CONDITION)
      ↓ CONTRIBUTES_TO (N2′, MEDIUM) | CAUSES (N2, with Tier C)
WORKER_PROGRESS_STOPPED                                   ← failure anchor
      ↓ PRECEDES
INCIDENT_TRIGGERED
Explanation of the stall: BROKER_SOCKET_STALL (PEER_SILENT supports; PATH_LOSS absent)
Alternative: NETWORK_PATH_FAILURE — contradicted by: send queue empty, no retransmit timer
```

Healthy guards (fixtures adversarial must add, in 4.36 style): idle long-poll with
`PEER_SILENT` and no worker anchor → healthy; temporary pause that resumes
before any anchor → healthy; `LOCAL_NOT_READING` under a CPU-bound worker →
the chain points **local**, never broker.

---

## 8. Explainability invariants (4.43)

### 8.1 The contract

Every **causal conclusion** (a Causal-layer edge, a root candidate, a
chain, a FailureAnalysis status other than UNKNOWN) must be able to answer
all eight questions. The answers are **data on the graph**, not prose
assembled at render time:

| # | Question | Source |
|---|---|---|
| 1 | **Claim**: what is asserted? | rule `Mechanism` + endpoint types/subjects ("worker 5842 exited because the kernel OOM-killed it") |
| 2 | **Evidence**: which observations prove it? | `Checks` with PRESENT status, each with provenance refs (snapshot/event indexes) |
| 3 | **Rule**: which deterministic rule connected them? | `RuleID@version` |
| 4 | **Timing**: when, and how precisely? | endpoint timestamps, gap, `same_instant`, `onset_window`, sampling interval, discontinuities in span |
| 5 | **Confidence**: how strong, and why not higher? | band + `Demotions` |
| 6 | **Contradictions**: what could have disproved it, and was it checked? | every Contradicting check with ABSENT/UNKNOWN status |
| 7 | **Missing evidence**: what would strengthen it but wasn't captured? | `missing_supporting` + UNKNOWN checks |
| 8 | **Alternatives**: what else could explain the target? | `competes_with`, co-factors, Phase 3 alternatives, FailureAnalysis alternatives |

### 8.2 Enforcement

- **I1 (gate):** if 1–4 cannot be produced, the item is **not causal**. The
  renderer shows it as an observation, never under "ROOT CAUSE", and never
  with an arrow.
- **I2 (honesty of absence):** an empty answer to 6, 7 or 8 must say whether
  it is *checked-and-empty* or *not checkable*. The literal "Contradictions:
  none recorded" in `Graph.Explain` today is printed unconditionally while no
  contradiction is ever evaluated (audit A5). Replace it with the per-check
  list.
- **I3 (no orphan claims):** every root candidate names its anchor. Every
  chain ends at an anchor or is labelled context.
- **I4 (stable references):** every claim references stable event IDs and edge
  IDs, so `--explain-edge` can be followed from any report line (4.32).
- **I5 (machine-checkable):** `Validate()` checks 1–5 structurally (V3), and a
  test renders `--explain-edge` for every edge in every golden fixture and
  asserts all eight headings are present with non-placeholder content.

### 8.3 Rendering rule for reports (secondary, 4.44/4.45)

The headline must never be stronger than the weakest of: the Phase 3
band, the Phase 4 FailureAnalysis status, and the chain band. "Root cause:
X (HIGH)" requires EXPLAINED status + HIGH chain + no AMBIGUOUS
alternative. Otherwise use the matching weaker wording: "most likely",
"contributing factor", "ambiguous between", "unknown".

---

## 9. Provisional-decision fallback (when principal quota is exhausted)

As the plan specifies: engineering proposes, adversarial attacks, secondary adjudicates. If they
converge, proceed. If they disagree, implement the conservative choice and
mark it `PROVISIONAL(principal-next)` in a code comment and in §11 below. The
conservative choice is, in order: no edge > `PRECEDES` > `CONTRIBUTES_TO` >
`CAUSES`; UNKNOWN > AMBIGUOUS > a named root; lower band > higher band.

---

## 10. engineering implementation queue (ordered; each item lands with its tests)

| # | Work | Unblocks audit tests | Notes |
|---|---|---|---|
| 1 | Capture-order timeline: process snapshots in **bundle order**; detect backward and forward steps from consecutive pairs **before** any sort; emit `CLOCK_DISCONTINUITY{backward}` or `TIMELINE_GAP` (forward hole) distinctly; events after a backward step keep their wall timestamps but are ordered by capture index; never re-sort samples across a discontinuity | A7 | review 4.19/4.20. The 4.38 "array order is not evidence" property is kept for *recorded events* (which carry their own timestamps) and for test-built incidents via an explicit `CaptureIndex`, not by sorting samples. Coordinate with integration's fuzz suite. |
| 2 | Episode IDs on every state-machine event; Binding enforcement in the engine; `ESCALATES_TO`; retire/re-version rules per §3.3; IO PSI → `IO_PRESSURE_*` | A3, A2 | |
| 3 | Boundary facts on jumps: when one sample crosses both thresholds, emit onset **and** severe event (same timestamp, ESCALATES_TO same-instant allowed); `onset_window` on crossings; onset-unknown for IO and cgroup first observations | A10, A17 | |
| 4 | Tri-state checks: `Check` evaluators, `CheckRecord`s on edges, D1–D6 demotions, `Mechanism` strings, registry invariant test | A5 | |
| 5 | Event classes, failure anchors, `FailureAnalysis`, root kinds/roles, weakest-link bands, AMBIGUOUS, `Healthy()` redefinition, P2 validation | A1, A4, A6, A8, A9 | update the 7 golden `expected.json` per §5.6 in the same change |
| 6 | Reparent incarnation binding; typed identity fields; drop `Data` type assertions in rules | A22, A18 | |
| 7 | Signature links scoped by subject (diagnosis evidence subjects → event subjects) and by type list corrected (FROZEN_PROCESS: stop/resume only) | A11 | secondary co-owns (4.16) |
| 8 | Explain/CLI: eight-question rendering; per-anchor unknown-cause; headline wording rule (§8.3) | A5, A15 | secondary owns rendering |
| 9 | Phase 1 Tier A socket fields (parse what `/proc/net/tcp` already gives) | — | integration can take this; unblocks §7 shapes |

Items 1–5 are the critical path. 6–8 can run in parallel with secondary.
9 is a separate Phase 1 change.

---

## 11. Decision log

| Date | Decision | By | Reason |
|---|---|---|---|
| 2026-10-27 | All of §1–§10 | principal | Phase 4 principal-architect pass; replaces engineering provisional 1–5 |
| 2026-10-28 | §5.2: no self-candidates; escalation-only reach is known chain, not contributing factor | principal (re-audit R5/R6) | rendered as "Root cause: PROCESS_EXITED" and as "pressure contributes to limit", both overclaims |
| 2026-10-28 | §5.1: exit failure context; severe anchors need ≥ 2 severe samples; cgroup episodes close with `CGROUP_LIMIT_CLEARED` | principal (re-audit R11–R13) | every helper exit, every one-sample dip and every recovered cgroup were reported as failures |
| 2026-10-28 | Suspected-kill / write-failure alternatives apply to exit failures only | principal (re-audit R7) | an OOM follows a limit and cannot explain it; a write failure is a consequence of a full disk |
