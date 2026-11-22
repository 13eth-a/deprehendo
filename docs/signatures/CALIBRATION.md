# Phase 3.33 — conservative-v1 confidence calibration

This protocol fixes the meaning and ordering of set-2 heuristic scores. It is
not a probability calibration or a fitted accuracy claim. The tests change
recorded evidence while holding the rest of each trace constant, independently
of fixture labels. No threshold was selected to maximize the existing corpus.

Implementation: `internal/diagnosis/calibration_test.go` and
`internal/diagnosis/implementation_counterexample_test.go`; related temporal cases are in
`architecture_review_test.go`. Reproduce with:

```sh
go test -race -count=1 ./internal/diagnosis
go test -run 'TestConfidenceCalibration|TestCalibration|TestImplementation|TestGroupDepartureWindow|TestCgroupHypothesis' -v ./internal/diagnosis
```

## Reviewed evidence ladders

All numbers below are asserted by tests to within floating-point roundoff.
Missing optional support contributes zero. Hard requirements apply separately
from the sum and cannot be bypassed by reducing `--min-confidence`.

| Hypothesis / condition | Controlled progression | Expected score | Default outcome |
|---|---|---|---|
| OOM hypothesis | Near-limit memory + disappearance; add large candidate RSS; add memory PSI | .35 → .40 → .50 | Always rejected: kernel event/exit cause absent |
| Frozen process | Observed stopped/idle/still stopped; watched identity; all resource sensors known healthy | .70 → .85 → .90 | Factual stopped-process match |
| CPU-spin hypothesis | Sustained high CPU/no child churn/no stop; add complete healthy resource readings | .45 → .50 | Always rejected: application progress absent |
| Disk exhaustion | Sustained low free space through final sample; IO PSI; inode exhaustion | .60 → .75 → .90 | Match; scoped to observed filesystem |
| Orphan tree | Reparented survivor with consistent trigger; substitute trigger naming the child | .80 → .60 | Contradiction reduces score |
| Process-group termination | Coordinated permanent departures with consistent trigger; substitute unrelated trigger | .80 → .60 | Contradiction reduces score |
| Broker-stall hypothesis | Continuous established/live-owner/no churn; add complete healthy resources | .35 → .40 | Always rejected; watching contributes no weight |
| Network-path hypothesis | Single close; add repeated incomplete SYNs on other sockets; complete healthy sensors | .35 → .65 → .75 | Close alone hard rejected; corroborated failures match |
| Resource starvation | Sustained severe some pressure; add severe full pressure | .55 → .70 | Factual resource-pressure match |

Rule ceilings are .50 OOM, .95 frozen, .50 CPU spin, .90 disk, .85 orphan, .85
group, .50 broker, .85 path and .80 starvation. A ceiling need not be reachable
from all evidence combinations. Watch/trigger weights in factual stop/tree/group
rules are explicit prioritization heuristics, not independent kernel witnesses.

## Adversarial controls

- A productive, child-free, single-process CPU workload remains a rejected spin
  hypothesis even with complete healthy PSI. A build driver that spawns children
  is also refused.
- A healthy watched keepalive remains a rejected broker hypothesis. Watching
  never supplies missing byte counters or progress expectations.
- A clean departure with near-limit memory, a large RSS and PSI still does not
  establish OOM. Tests check rejection at thresholds .01, .55 and .99.
- Missing one PSI resource removes healthy-resource support; missing/failed
  telemetry cannot improve a score by being treated as zero pressure.
- Disk recovery records contradictory evidence and lowers the score. A missing
  final disk reading cannot assert persistence through the analysis end.
- A stopped blink, stopped-then-disappeared process and collector gap cannot
  manufacture a sustained stop or an observed resumption.
- Cgroup pressure must belong to the departing identity. It can be used without
  host-memory readings, but not borrowed from an unrelated survivor.
- Three group departures at 4, 8 and 12 seconds provide at most two members in
  a five-second window; pairwise-near events cannot chain into an eight-second
  coordinated episode.
- Normal socket closure is not path failure by itself. Pending attempts at
  capture end and passive `SYN_RECV` bursts do not count as failed attempts.
  A brief connection can still complete and close between samples; observed
  disappearance is not a captured handshake error. A severe PSI peak
  without a sustained interval is not sustained starvation.

## What this establishes

The suite establishes deterministic arithmetic, reviewed evidence-strength
ordering, useful contradiction effects, missing-data behavior and hard limits
for unobservable causes. It does not measure confidence reliability on unseen
production incidents. PSI, observed disappearance, stopped state and socket
state remain factual observations; process intent, exit causes and application
progress are not inferred from them.

The unchanged synthetic corpus reports 16/19 correct top labels, zero false
positives among ten healthy cases, and thirteen UNKNOWN results. Three injected
faults are deliberately left UNKNOWN because their decisive telemetry is absent.
Independent production labels, a broader workload distribution and future direct
OOM/progress instrumentation are required before reporting statistical confidence
or claiming completion of the original full-telemetry acceptance targets.
