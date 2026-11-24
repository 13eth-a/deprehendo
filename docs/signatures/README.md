# Phase 3 signature reference — set 2

Analyzer `0.3.1`, signature set `2`, per-signature version `2`, incident format
v1. The analyzer runs offline over verified bundles. It reports recorded
conditions and bounded hypotheses, not probabilities or inferred intent.

A score is the sum of supporting weights minus contradicting weights, clamped
to `[0, rule cap]`. The default reporting threshold is `0.55`. A hard rejection
is separate from that number: reducing `--min-confidence` cannot supply missing
required evidence. `--explain` retains rejection reasons, supporting facts,
contradictions and missing telemetry. `--disable ID` skips a known signature;
unknown IDs are rejected.

[Calibration protocol and score ladders](CALIBRATION.md) specify the reproducible
Phase 3.33 evidence-strength checks. These are reviewed heuristic scores, not
statistical calibration against independently labeled production incidents.

## Evidence and time

Every evidence item has a stable code, source, weight, observed value and, when
available, timestamp and threshold. Missing or failed telemetry is UNKNOWN,
not healthy or absent. Heavy collector loss (`>=40%` of samples) prevents rules
that require that section from concluding. Valid sensor flags and the particular
required field still matter when a collector returns partial results.

Continuous spans use observed, adjacent usable samples. Gaps, collector failures
and identity changes cannot extend them. CPU smoothing is a five-second trailing
mean with a 90%-of-one-core threshold; its required span is 60 seconds. Sampled
coincidence establishes correlation within recording resolution, not causation.
A process identity is `(PID, start_ticks)`; zero/missing identity and ambiguous
socket ownership reduce what can be inferred.

Healthy-resource support requires valid host memory/disk readings and usable
CPU/memory/IO PSI readings throughout the capture, with no observed stress.
Missing PSI earns no healthy bonus and is recorded as
`RESOURCE_HEALTH_TELEMETRY` when no positive stress reading resolves the question.
Watching a process selects evidence; it does not demonstrate application progress.

## Signature summary

| Signature | Required recorded condition | Optional evidence / cap | Interpretation limit |
|---|---|---|---|
| `OOM_KILL@3` | Host memory >=92%, or the departing process's own cgroup >=95%; permanent observed disappearance within 90s | Large RSS, memory PSI; **kernel evidence:** the victim's own cgroup `memory.events` `oom_kill` counter rising within 5 s after it was last seen (weight .40, lifts the cap from .50 to .85) | Without the counter rise: hard rejected as before (cap .50); the exit signal remains unavailable. The cgroup path never appears in the output |
| `FROZEN_PROCESS@2` | Observed `T`/`t` episode >=5s | Still stopped, actually observed resumption, watched identity, idle CPU, known healthy resources; cap .95 | Describes a stopped process; intentional debugger/job-control stops remain possible |
| `CPU_SPIN@2` | Surviving identity with sustained high CPU >=60s | No observed child churn/stops, known healthy resources; cap .50; **hard rejected in v1** | Productive single-process computation has the same CPU/process observations |
| `DISK_EXHAUSTION@2` | Valid configured-filesystem free space <=10% for >=10s | Observed low at final sample, <=5% free inodes, IO PSI; cap .90; recovery subtracts .30 | Does not establish write failures, quotas, or exhaustion of other mounts |
| `ORPHAN_PROCESS_TREE@2` | Surviving child changes PPID to 1 near its parent's observed permanent disappearance | Persistence, consistent trigger; cap .85 | Intentional daemonization and non-PID-1 reapers limit interpretation |
| `PROCESS_GROUP_TERMINATION@2` | >=2 same-PGID identities permanently absent within one total five-second window | No return, consistent trigger; cap .85 | Does not prove a group signal or unexpected shutdown |
| `BROKER_SOCKET_STALL@2` | Continuous observed ESTABLISHED run >=10s through final sample, with contemporaneously identified surviving owner | No reconnect churn, known healthy resources; cap .50; **hard rejected in v1** | Neither socket bytes nor application progress/job expectations are captured |
| `NETWORK_PATH_FAILURE@2` | Failed connection evidence with >=3 short incomplete SYN handshakes | ESTABLISHED departures, affected sockets, known healthy resources; cap .85 | Normal closes alone are rejected; remote service failure cannot be distinguished from a network-path cause |
| `RESOURCE_STARVATION@2` | PSI some avg10 >=50% sustained >=5s | Full avg10 >=20%, sustained interval; cap .80 | Identifies contention, not its cause or whether the load was expected |

## Rule details

### Memory and departure

`HOST_MEMORY_NEAR_LIMIT` and `CGROUP_MEMORY_NEAR_LIMIT` are alternative memory
anchors. Cgroup-only evidence does not require host memory availability, but
must belong to the departing identity; pressure in an unrelated surviving
process's cgroup cannot be borrowed. A permanent gap contributes
`PROCESS_DEPARTURE_NEAR_MEMORY_PEAK`. Large RSS (`>=30%` of available host total)
and memory PSI some avg10 (`>=20%`) provide additional correlation.

`KERNEL_OOM_EVENT` and `EXIT_SIGNAL_DETAILS` remain missing. The hypothesis is
always rejected in v1, including at a lower user threshold. It must never be
presented as a confirmed OOM kill. Peak-only cgroup recording and the 90-second
correlation window still limit how precisely pressure and departure can be linked.

### Stopped state and CPU

A stopped interval ends at its last observed stopped sample when telemetry is
lost or the process disappears. Only an observed transition to a running state
earns `PROCESS_RESUMED`; disappearance does not. An unknown episode end is
reported as `STOP_EPISODE_END`. A long intentional stop can legitimately produce
the factual frozen-process classification.

CPU quantization can cause short below-threshold readings, so the trailing mean
avoids treating a single dip as recovery. Child churn is evidence of ordinary
pipeline/build work and refuses the spin interpretation. No child churn is not
proof of no useful work. `APPLICATION_PROGRESS_TELEMETRY` is unavailable, so even
a textbook high-CPU trace remains a rejected spin hypothesis.

### Disk

Low disk space must span at least ten observed seconds. Inode exhaustion and
IO PSI strengthen the observation. A low reading that predates a final failed
sensor sample cannot earn `DISK_PERSISTED_TO_ANALYSIS_END`. Recovery to at least
30% free subtracts .30. `WRITE_FAILURE_TELEMETRY` remains missing. The classification
is limited to the configured `--watch-fs` filesystem; inode-only exhaustion with
healthy byte free space is not a standalone matching path in this rule.

### Process trees and groups

Orphan association uses PPID numbers because v1 lacks a child-to-parent start
identity. A parent gap that later closes or starts after adoption is insufficient.
PID recycling near adoption and adoption by a subreaper other than PID 1 remain
limits. Ordinary daemonization is a factual reparenting case, not proof of a leak.

Group departures are sorted chronologically and chosen from a single bounded
five-second window. A chain of pairwise-near departures cannot stretch that window.
Returned identities do not count as permanent terminations. PGID generation and
exit signals are unavailable; normal coordinated shutdown can match the facts.

### Sockets

A broker candidate's current continuous ESTABLISHED run matters, rather than
elapsed time since an initial SYN. An unavailable/absent sample or ambiguous/
changed owner breaks continuity. Ownership resolves against the contemporaneous
PID/start-time table; a later recycled PID cannot inherit the old socket's owner.
This still cannot distinguish a healthy keepalive from a stalled broker, even
when a trigger names the owner. Watching adds no confidence weight.

For path hypotheses, short final `SYN_SENT` attempts subsequently observed absent and observed
ESTABLISHED departures are distinct evidence. Planned replacement connections
can contradict failure. A close without repeated failed handshakes is compatible
with normal peer shutdown and is hard rejected. Address redaction prevents
counting distinct remote peers: `MULTIPLE_CONNECTIONS_HIT` counts sockets;
retained service ports serve only as a coarse reconnect proxy. Retransmission,
DNS, route and interface telemetry are missing. Still-pending attempts at capture
end, attempts followed by an unavailable network sample, and passive `SYN_RECV`
bursts provide no failed-attempt support. A brief connection can still complete
and close between samples; observed disappearance from SYN_SENT is not proof of
a handshake error. This sampling ambiguity remains a limit. A future format must not treat
those fields as observed merely because a socket state changed.

### Pressure

PSI values are percentages of stalled wall time. A single severe reading has
only peak evidence; it is hard rejected if no >=5s severe interval is observed,
even at a low reporting threshold. Full-pressure support and sustained evidence
must be interpreted at sampled resolution. Severe expected builds can meet the
pressure observation, and the rule names only the resource subtype.

## Output and evaluation limits

All nine signatures run in stable order. Other signatures can coexist; the
broker/path pair has an exclusion policy requiring a .15 confidence margin,
but the bundled v1 broker hypothesis is hard rejected, so that conflict is
currently unreachable. Registry-level conflict tests still cover the policy.

The original 19 synthetic fixtures retain their independent injected-fault labels.
Set 2 produces **16/19 correct top labels, 13 UNKNOWN and zero false positives on
10 healthy baselines**. The three false negatives are OOM, CPU spin and broker
stall; their labels were not rewritten to make the matrix look perfect. Run:

```sh
go test -race -count=1 ./internal/diagnosis
go test -run 'TestConfidenceCalibration|TestCalibration|TestImplementation|TestGroupDepartureWindow|TestCgroupHypothesis' -v ./internal/diagnosis
deprehendo-agent evaluate ./testdata/incidents
```

The corpus and calibration variants are authored regression cases, not estimates
of production accuracy. Completing direct OOM/progress telemetry and collecting
independent real incident labels remain necessary for the original full-telemetry
Phase 3 acceptance. Conservative-v1 does not claim those capabilities.
