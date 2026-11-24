# Timeline and causal reasoning

Deprehendo does not infer causation merely from temporal proximity. The Phase 4
engine is deterministic, local, and rule-based: a bundle yields normalized
events, then versioned rules propose edges which the graph validates.

## Relations

- `PRECEDES`: factual canonical order only. It is not a causal statement and
does not qualify an event as a root.
- `CORRELATED_WITH`: a relation for temporal clustering without asserting an
  order. The current rule set does not manufacture correlations from proximity.
- `CONTRIBUTES_TO`: an evidence-bounded cofactor relation, weaker than a
  sufficient causal mechanism. It still requires a rule contract and does not
  follow from order alone.
- `CAUSES`: a mechanism proposed by a versioned rule whose required evidence is
  present. A causal edge must point forward and is rejected if it creates a
  cycle.
- `RECOVERY_OF`: a forward link from a failure/condition event to an observed
  recovery. Recovery is episode history, not a terminal root cause.
- `CONTRADICTS`: evidence against a conclusion. It can be represented without
  changing the factual timestamps or deleting observations.

The binding definitions of every relation (including the new `ESCALATES_TO`),
confidence bands, root anchoring and competing chains are in
[`causal-semantics.md`](causal-semantics.md) (principal decisions, 2026-10-27).
Where this page and the code differ from that spec, the spec wins; the
implementation queue is its §10.

## Rules and evidence

Each rule has a stable `NAME@VERSION`, source and target event types, relation,
confidence band, maximum temporal gap, and required follow-up checks. The
engine indexes events by type rather than trying every rule against every pair.
A missing required fact records a `RejectedEdge`; it never produces an edge.
The validation pass checks event/edge endpoints, provenance, versioned rule IDs,
stable edge IDs, temporal direction, and acyclicity.

Causal confidence is `LOW`, `MEDIUM`, or `HIGH`. These are evidence strength
bands, not probabilities. The internal numeric bases are only for deterministic
ranking and are not rendered as probabilities.

The v1 `OOM_CAUSES_PROCESS_EXIT@1` contract requires explicit signal lineage.
Current bundles have no kernel OOM/signal event stream, so this rule honestly
cannot diagnose an OOM kill from high memory and a later process exit alone.
Likewise, network byte progress and runner/worker roles are unavailable; the
engine does not invent socket stalls or generic job events.

## Roots and chains

A root candidate is an abnormal event with at least one downstream causal edge
and no upstream causal edge. Candidate roles are `PRIMARY` and `SECONDARY`.
Every chain step contains its edge, rule ID, evidence notes, confidence band,
and stable edge ID. Competing chains are retained as separate paths; no
first-rule-wins root selection is performed. An active-at-capture-start event
keeps its `onset_unknown` status in the root candidate.

If effects exist but no causal rule validates a cause, the report states
`UNKNOWN`, lists observed effects, and names missing evidence. It does not
back-fill normal precursors.

## Commands

```sh
deprehendo-agent timeline incident.deprehendo
deprehendo-agent timeline incident.deprehendo --causal
deprehendo-agent timeline incident.deprehendo --json
deprehendo-agent timeline incident.deprehendo --report
deprehendo-agent timeline incident.deprehendo --report --json
deprehendo-agent timeline incident.deprehendo --explain-edge 0
deprehendo-agent timeline incident.deprehendo --explain-edge RULE_ID@1
```

`--json` returns `events`, `edges`, `rejected_edges`, `root_candidates`,
`chains`, and, with `--report`, the Phase 3 diagnosis and signature-to-event
links. Edge explanation accepts the stable edge ID (`ED_...`), index, rule ID,
or `FROM->TO` pair. Text output includes relative and wall-clock event times,
root roles, rule-backed arrows, and confidence bands.

## Phase 3 links and reports

With `--report`, each matching Phase 3 signature includes the IDs of relevant
normalized events. A combined report renders primary/alternative diagnosis,
causal candidates and chains, or the explicit unknown-cause explanation. This
linkage is a cross-reference, not an extra causal inference.

## Conservative interpretation

Phase 4's foundational semantics were decided in the principal architecture pass
([`causal-semantics.md`](causal-semantics.md)), and the current code was audited
against them ([`reviews/phase4-principal-audit.md`](reviews/phase4-principal-audit.md)).
Until the spec's §10 queue lands, root candidates in particular can overstate
what the evidence supports; see audit findings A1–A9. The capture's
observability limits are documented in [`event-model.md`](event-model.md). The
main currently implemented causal contracts focus on resource thresholds,
recorded process exit/reparent observations, process-group termination, and
recovery. Some reserved types/rules are intentionally dormant until the input
bundle has discriminating evidence.
