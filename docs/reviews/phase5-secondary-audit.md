# Phase 5 secondary audit: independent review and acceptance status

**Auditor:** secondary review · **Date:** 2026-11-02
**Scope:** secondary's final-audit share — the items assigned to this lane (5.11 GitHub
API client, 5.27–5.28 timeline/report, 5.44–5.46 cancellation, timeout and
shutdown semantics, provider schemas and CLI, bundle compatibility, offline
analysis, API failure handling), plus an independent check of the B3 real-runner
evidence against `docs/providers/architecture.md` (§9, §10A) and the Phase 5
acceptance gate.
**Not covered here:** the principal share (`docs/reviews/phase5-principal-audit.md`) and
the adversarial attack suite (`docs/reviews/adversarial-phase5-pass.md`).

## Verdict

**Phase 5 is acceptable.** B3 is closed: all twelve real-runner scenarios have a
passing record, S2, S11 and S12 on the binary built from this tree (2026-11-02). Six
findings were reproduced and fixed in this pass (L1–L6), each with a regression
test that fails on the previous code, and every bundle still on the two runner
VMs was re-analyzed offline to confirm the fixes hold on real evidence. The
residual gaps in §5 are documented, not blocking.

## 1. Findings

Severity as in Phase 4: **S1** a wrong conclusion reaches the user or a whole
invariant is dead, **S2** more certainty than the evidence, **S3** latent or
fidelity.

| # | Sev | Where | Finding | Fix | Test |
|---|---|---|---|---|---|
| L1 | S1 | `internal/provider/supervisor.go` | One `Observe` that overran its 2 s deadline abandoned the provider session permanently. On the real runner (`--interval 250ms`) a single slow sample under memory pressure killed the GitHub section for the rest of the watch: every later capture carried `github-actions UNAVAILABLE` with 0 events, and 49,578 queued snapshots were dropped. Two successful runs on 2026-11-02 (`41511306173`, `41518491980`) are in that state. | `SupervisorConfig.OverrunGrace` (10× the call's budget, 2 s floor). An overrun that returns inside the grace marks the section `DEGRADED` and keeps the session; only a call that also overruns the grace is abandoned, and the loop waits for the call to return so the session is never mutated concurrently. | `TestSupervisorSlowCallDegradesOneIncidentAndKeepsTheSession`, `TestSupervisorHungCallIsAbandonedAfterTheGrace` |
| L2 | S1 | `internal/diagnosis/signatures_files.go` | A healthy job's normal teardown was reported as `PROCESS_GROUP_TERMINATION` at HIGH (0.80) / CRITICAL. The runner does not give a job its own process group, so the step's shell, the worker and the listener share the listener's PGID; when the job ends, "several members of one group vanished together" is true of every job. This violated the S2 gate ("no failure claim") and also contaminated the S11 bundle. | A group is only a candidate when no member of it was observed after the last coordinated departure (`groupMemberSurvived`), and an intent that states success covers the worker's tree. A group that merely lost a subtree now rejects with "other members of that group kept running". `SignatureVersion` 4. | `internal/diagnosis/group_subtree_test.go` (replays the real process sequence), `TestGroupKillPositive` unchanged |
| L3 | S1 | `internal/diagnosis/context.go` `kernelOOMRise` | The kernel OOM counter rise was missed whenever it landed in the victim's last-seen sample: a sample reads the process table before the cgroup counters, so that reading can already carry the kill, and the old baseline was "the last reading strictly before the final sample" with the search starting after it. S11 therefore kept rejecting `OOM_KILL` on fresh runs (`inc_2b7295…`) while the host showed 98% memory and the process vanished at its peak. | The final sample's own reading is a candidate, bounded by the same 5 s window as causal rule `CGROUP_OOM_KILLS_MEMBER@1`; an earlier rise is already part of the baseline and is never attributed to this death. | `TestOOMKillCounterRiseInTheVictimsFinalSampleIsEvidence` (plus the earlier-rise, late-rise and other-cgroup cases in the same file) |
| L4 | S2 | `cmd/runopsy-agent/timeline.go` `intentCovers`, `internal/causal/graph.go` | An intent that ends the runner's whole tree (service shutdown, self-update, ephemeral completion) covered only the supervisor. On a real self-update (`inc_571d5d…`) the untagged job processes left with the runner's tree and formed a `PROCESS_GROUP_TERMINATION` failure anchor; the report presented an intentional update as an unexplained failure. | `intentCoversRole` widens runner-level intents to worker/job roles, and `IntentCover.RunnerTree` lets the causal engine treat the exits of the named process's *process group* as context (`Graph.coversGroup`), without silencing an unrelated group in the same window. | `TestIntentCoversResolvesRunnerJobTree`, `TestRunnerTreeCoverCoversTheUntaggedGroup` |
| L5 | S2 | `internal/provider/github/api.go` | The S4 timeout upgrade wrote `outcome=TIMED_OUT` but left `outcome_source=RUNNER_LOG`. No runner-log record ever stated a timeout (all four say `cancelled`); only the check-run annotation does. This breaks 5.47: an offline reader who checks the cited source finds no such statement. | The upgrade also sets `OutcomeSource=PROVIDER_API` and stamps the enrichment time. | `TestAPITimeLimitAnnotationMarksJobTimedOut` (now starts from a log-stated `CANCELLED`, which is the real S4 situation) |
| L6 | S3 | `cmd/runopsy-agent/provider_report.go` | The incident header rendered every job record the section carries. A section keeps the runner's job history, so a capture with no job of its own (idle, shutdown, self-update) printed the previous day's `FAILED` job under `Job outcome`, and a two-job capture printed both blocks with nothing to tell them apart. | Only job records that ran inside the capture window are shown, oldest first, each naming its `ref`; a capture with no job of its own shows no job block. JSON consumers still see the whole section. | `provider_report_test.go` (four tests) |

Observed with no action taken: the S11 bundle records `GITHUB_JOB_COMPLETED
FAILED` twice, one second apart (`20:37:28Z`, `20:37:29Z`). Two distinct runner
log statements can legitimately produce that, and the duplicate affects no
label (the two covers are identical). Deduping would need evidence that they are
the same statement, so it was left alone.

## 2. Reviewed with no finding

- **5.11 API client and failure handling.** Token read per call, cross-origin
  redirects refused, bodies bounded and never stored, every failure mapped to a
  reason code (`UNAUTHORIZED`, `RATE_LIMITED`, `API_UNAVAILABLE`). Enrichment
  never rewrites a log-derived outcome (only an unknown one), and a mismatch is
  recorded as a `JOB_STATE` conflict instead of being resolved.
- **5.44–5.46 intent semantics.** Cancellation, timeout, shutdown, update and
  ephemeral completion all require a stated record; a `TERMINATION_INTENT`
  conflict (statement after the death) removes the cover, so a late statement
  never retroactively explains a kill. A stated failure covers nothing.
- **Offline analysis (5.38).** Fifteen stored bundles analyzed with no network
  and no credentials. Provider interpretation, signatures, intent covers and the
  causal graph all run from the section inside the bundle.
- **Bundle compatibility.** `testdata` v1 bundles still decode; a section whose
  provider vocabulary this binary does not know validates structurally and is
  `UNAVAILABLE` to the interpreter, so unknown evidence never strengthens a
  diagnosis.
- **Privacy (5.12/5.36).** The canary test still passes; no provider code reads
  `.credentials`, `.env` or `/proc/*/environ`. The new report code prints only
  already-redacted fields.
- **5.49 performance.** See §4: the whole per-sample provider cost stays far
  below the sample interval.
- **5.20 on real hardware (S12).** With the assignment seen and no worker ever
  spawned, the label fires at MEDIUM from the assignment alone, leaves the
  generic `BROKER_SOCKET_STALL` at 0.00, and does not promote itself to a root
  cause: the report keeps `ROOT CAUSE Unknown`. The same session reported the
  healthy job after the binary was restored, so the state machine recovers from
  a stall rather than staying latched.

## 3. B3 evidence

| Scenario | Evidence | Date |
|---|---|---|
| S1 idle runner | `inc_7939…`: no signature, `BROKER_SOCKET_STALL` rejected at 0.40 | 2026-10-31 |
| S2 healthy job | run `41520612730`, `inc_9eb4…`: job correlated, `SUCCEEDED`, no failure claim | **2026-11-02** |
| S3 cancel | run `41261769205`, `inc_9c0ade…`; re-analyzed 2026-11-02 | 2026-10-31 |
| S4 timeout | run `41262653679` + `api-enrich` (`s4-enriched`): `TIMED_OUT`, no finding | 2026-10-31 |
| S5 frozen worker | `inc_deac…`: `FROZEN_PROCESS` HIGH (0.75) from a SIGSTOP'd worker | 2026-10-31 |
| S6 intended shutdown | `inc_c0d4…`: `GITHUB_RUNNER_SHUTDOWN`, no `SELF_TERMINATION` | 2026-10-31 |
| S7 listener kill | `SELF_TERMINATION` at MEDIUM | 2026-10-31 |
| S8 orphan job | run `41243213130`, `inc_d2fb…`: `GITHUB_ORPHANED_JOB_PROCESS` HIGH | 2026-10-31 |
| S9 ephemeral exit | run `41245132604`, `inc_752023…`: shutdown recorded, no death claim | 2026-10-31 |
| S10 communication stall | run `41257678327`, `inc_652bdf…`: `GITHUB_COMMUNICATION_STALLED` | 2026-10-31 |
| S11 OOM | run `41520844407`, `inc_11667c…`: `OOM_KILL` HIGH 0.80 + job context | **2026-11-02** |
| S12 assignment stall | run `41528651092`, `inc_013169…`: `GITHUB_JOB_ASSIGNMENT_STALL` MEDIUM, no worker, `BROKER_SOCKET_STALL` 0.00; recovery run `41529045808` `SUCCEEDED` | **2026-11-02** |
| Runner self-update (extra) | `inc_571d5d…`: `UPDATE`→`SHUTDOWN`→stop→restart, no failure anchor | **2026-11-02** |

The S5/S6/S8/S9/S10 bundles are no longer on either VM (the incident directory
keeps recent captures only), so those rows rest on the 2026-10-31 records and on
their regression tests; the S2, S3, S4, S11 and self-update bundles were
re-analyzed on this tree. Full table: `docs/github/real-runner-verification.md`
§7–§8.

## 4. Verification

Run on macOS (darwin/arm64) against the tree after the fixes:

- `go build ./...` and `GOOS=linux GOARCH=arm64 go build ./cmd/runopsy-agent`
  pass; `go vet ./...` is clean and `gofmt -l` reports nothing.
- `go test -count=1 ./...` is green.
- Provider cost per sample (`go test -bench 'BenchmarkObserve|BenchmarkFreeze'
  -benchtime=50x ./internal/provider/github/`): idle runner 77.7 µs, active job
  254.7 µs, multiple runners 312.5 µs, high churn 148.1 µs, `Freeze` 12.9 µs.
  At the 250 ms interval the S11 run used, the active-job case is ~0.1% of the
  interval; the supervisor's deadline plus grace bounds the recorder's exposure
  even when a call is slow.
- Live re-runs on the disposable Linux VM with the rebuilt agent:
  `github watch --interval 250ms --trigger-on-process-exit`, run `41520612730`
  (S2) and run `41520844407` (S11). The S11 capture kept the provider section
  `AVAILABLE` through the memory episode, which is the L1 fix under the exact
  condition that broke it.
- Live S12 on the same VM: the worker binary replaced so that no worker can
  start, capture `inc_013169…` (`GITHUB_JOB_ASSIGNMENT_STALL`, MEDIUM), then the
  binary restored and run `41529045808` captured as `inc_e78d6a…` with
  `Job outcome SUCCEEDED` and no failure label.
- Offline sweep of 15 bundles (12 on the Linux VM, 3 on the older runner VM):
  no false failure claim on any healthy, cancelled, timed-out, update or
  ephemeral capture; the two known-bad pre-fix captures still show the
  `UNAVAILABLE` section they were written with.

## 5. Residual risks

- **macOS runner identity is PID-only** (G3, documented in
  `docs/providers/github-actions.md`); a fast PID reuse can mis-bind a worker.
- **Containerised runners** are linked through docker cgroups plus a witnessed
  docker client, and a job that cannot be verified carries
  `CONTAINER_LINKAGE_UNAVAILABLE`. No real container runner was exercised.
- **The enriched S4 bundle keeps its old attribution.** Bundles are immutable;
  re-running `github api-enrich` with this binary writes `PROVIDER_API`.
- **A second runner self-update was not run.** L4's evidence is the 2026-11-02
  bundle plus the two tests.
- **Windows is unsupported.** Linux is the primary platform; macOS is limited as
  above.
- **An assignment stall names no job.** A job ref is bound to a worker ref
  (C6/C7), so `GITHUB_JOB_ASSIGNMENT_STALL` arrives with `job=` empty; the
  runner and the assignment instant are known, the repository and workflow are
  not. Recovering them needs the API enrichment path, which the capture does
  not call.
- **The report header lists every runner installation discovered on the host**
  (seven on the test VM, from old checkouts). Factual, but when several installs
  exist it buries the runner the incident is about. Not changed in this pass.
- **Fleet scale is untested beyond the provider benchmarks**; a host with many
  runners was exercised only synthetically (`BenchmarkObserveMultipleRunners`).

## 6. Acceptance gate

| Scenario | Expected | Result |
|---|---|---|
| Healthy idle runner | no incident | Pass (S1) |
| Healthy workflow | correct job correlation | Pass (S2, fresh) |
| Worker OOM | `OOM_KILL` + GitHub job context | Pass (S11, fresh) |
| Worker frozen | `FROZEN_PROCESS` + job context | Pass (S5) |
| Assignment stall | GitHub-specific diagnosis | Pass (S12, fresh) |
| Broker/communication stall | provider + systems diagnosis | Pass (S10) |
| Orphan process | GitHub orphan-job diagnosis | Pass (S8) |
| Runner self-kill | process-group causal chain | Pass (S7) |
| Intentional cancellation | not an unexplained failure | Pass (S3) |
| Ephemeral normal shutdown | not a runner death | Pass (S9) |

Every row now has real-runner evidence. The assignment stall (S12) was
injected by replacing `bin/Runner.Worker` with a script that execs `sleep`, so
the listener accepted the job and no worker ever existed; the capture reports
`GITHUB_JOB_ASSIGNMENT_STALL` at MEDIUM without borrowing the socket-stall
label, and the runner was restored and a healthy job re-verified afterwards.
