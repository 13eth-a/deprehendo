# Phase 5 principal audit: GitHub provider review and acceptance status

**Auditor:** principal · **Date:** 2026-10-30
**Scope:** the principal reviewer and invariant items 5.4–5.10, 5.12, 5.15–5.21,
5.23, 5.25, 5.32, 5.36, 5.43–5.46 and 5.48, plus the principal share of the final
Phase 5 audit. Reviewed against `docs/providers/architecture.md` (C1–C12,
T1–T5, P1–P5, §9) after the engineering, integration and secondary slices landed.
**Not covered here:** adversarial's share (5.12/5.20/5.36 implementation and
adversarial review) and secondary's final-audit share.

## Verdict

**Update 2026-10-31 (evening):** F1–F5 are fixed, G1–G4 are closed, and 5.45 (a stated timeout suppresses the kill as a failure) is verified end to end. Phase 5 acceptance now waits only on B3 (the remaining real-runner scenarios) and secondary's final-audit share.

**Update 2026-10-31 (final audit, §5):** B1, B2, G1 and G3 are closed; G2 and G4 are implemented with three open findings (F2–F4, executable under `DEPREHENDO_REVIEW_AUDIT=1`). Acceptance now waits on B3 (a real runner, runbook ready), F2 and F3, and secondary's audit share.

**Update 2026-11-02:** F2–F5 are fixed, B3 is closed on a real runner, and secondary's
final-audit share is delivered with L1–L6 fixed. **Phase 5 is accepted.**

**Phase 5 is not acceptable yet (2026-10-30 verdict, kept for the record).** The 5.1 abstraction holds: the supervisor
isolates every failure, the import-boundary test holds, the conformance kit
passes and no secret reaches a bundle. But the GitHub provider was built and
tested only against the fake runner's invented log format. On a real runner
it would have produced no log-derived fact at all, and several invariants
were inert or wrong. Eighteen findings were reproduced and fixed (R1–R17,
with R7 and R12 in two parts). Each fix has a regression test that fails on
the pre-fix code. Three acceptance blockers remain open (§3).

## 1. Findings (all fixed)

Severity: **S1** means the provider's output is wrong or empty on a real
host, or a whole invariant is dead. **S2** means wrong output in a specific
case. **S3** means a fidelity issue.

| # | Sev | Finding | Fix | Test |
|---|---|---|---|---|
| R1 | S1 | The log reader accepted only the harness shape `2026-… +00:00 [RUNNER 1] msg`. Real `_diag` records are `[2026-09-03 18:34:29Z INFO Terminal] msg` (public runner excerpts), so on a real runner no log-derived fact existed: no assignment, no intent, no log-timing discriminator. | Parses the real trace format (the harness shape is still accepted). Patterns are anchored on phrases the runner writes: `Job request … received.`, `Running job:`, `… completed with result: X`, `Send job cancellation message to worker`. The fake runner now writes the real format, so the gated E2E exercises it. | `TestAuditR1RealRunnerDiagFormatParses` |
| R2 | S1 | The worker-scope `exit code N` pattern turned every step's `Finished process N with exit code 0` into `GITHUB_WORKER_EXITED`, which translates to generic `WORKER_EXITED`. That breaks P1: process exit is LOCAL_PROCESS authority. The worker cancel/timeout patterns matched any line containing "cancel" or "timeout" (T1: intent must be stated). | Exit-code pattern removed. Worker intent patterns now need a statement (`job was cancelled`, `exceeded the maximum execution time`). | `TestAuditR2WorkerTraceNoiseIsNotAFact` |
| R3 | S2 | `Runner connect error: … Retrying until reconnected.` was classified as a *reconnect*, because the reconnect pattern was tried first. | Disconnect patterns now come first. | `TestAuditR3ConnectErrorIsNotAReconnect` |
| R4 | S1 | `.runner` was decoded strictly and any key outside the allowlist failed it. Real files always carry such keys (pool, server and GitHub URLs) and a UTF-8 BOM, so on a real host the runner name and the ephemeral flag were never known. | Allowlisted keys are decoded and everything else is skipped unread. The BOM is stripped and the read is bounded. A mistyped allowlisted key still fails. | `TestAuditR4RealRunnerConfigDecodesAllowlistOnly` |
| R5 | S1 | `EPHEMERAL_COMPLETE` (T1) could never fire. No pattern produced `GITHUB_JOB_COMPLETED`, and `jobOutcome` could never return SUCCEEDED. | The result line yields COMPLETED with SUCCEEDED or FAILED, or a stated CANCELLED. Ephemeral completion accepts any stated result before the exit, and still never fires on an unexplained death. | `TestAuditR5R6StatedResultBindsAndEphemeralCompletes`, `TestAuditR6EphemeralDeathWithoutStatedResultIsNotIntended` |
| R6 | S1 | Log job records were never bound to a worker. As a result `Job.Outcome` never became CANCELLED or TIMED_OUT, and the JOB_STATE and TERMINATION_INTENT conflict code (5.48) never ran. | A job-scoped record names its worker and job only when exactly one worker of that runner was alive at the record's time (C6/C7). Otherwise it is never guessed. | `TestAuditR6StatedCancellationReachesJobOutcome` |
| R7 | S1 | Communication stall was tracked per socket inode. Every normal long-poll reconnect (a new socket) was reported as `GITHUB_COMMUNICATION_STALLED` after 5 s. So was a runner that had simply died, and each runner got one report per session. The C12.3 "re-established" rule waited for the same inode to return, which TCP never does. | The rule is decided per runner: the runner is alive in the sample, it once held a qualifying channel, and no supervisor 443 socket has been open for more than 5 s. The episode ends when a channel returns. A replacement socket opened within 5 s of the old one's close counts as re-established. | `TestAuditR7CommunicationStallNeedsALiveRunnerWithoutAChannel` |
| R7b | S2 | The C12.4(b) "only qualifying socket" test counted every socket ever seen in the window, so one reconnect demoted both sockets to candidates. | Only sockets open at the same time are counted. Closures are processed before new sockets in a sample. | same |
| R8 | S1 | `GITHUB_COMMUNICATION_STALLED` was translated to generic `WORKER_PROGRESS_STOPPED`, which merges the two stall labels that 5.19–5.21 must keep apart. | It has no generic translation. See §10A S1. | `TestAuditR8CommunicationStallHasNoGenericTranslation` |
| R9 | S1 | `internal/agent` did not compile on Linux: `darwinExecutableName` was only defined on darwin. The agent, cmd and tests packages could not build on the primary platform, and it went unnoticed because verification ran on macOS only. | Added `providerview_other.go`. | Linux `go build ./...` and the full suite |
| R10 | S2 | `Worker.Exited` reported the freeze-time clock, not the observed exit. | The exit sample time is recorded per incarnation. | `TestAuditR10WorkerExitTimeIsTheObservedExit` |
| R11 | S3 | A supervisor restart (C9) emitted two `RUNNER_STARTED` events for the new incarnation. | One per incarnation. | `TestAuditR11RestartRecordsOneStartPerIncarnation` |
| R12 | S2 | A supervisor named only by `--github-runner-pids` was reported as a HIGH, layout-verified supervisor. C2 requires MEDIUM with USER_OVERRIDE. | An override that also verifies is tagged as discovery would tag it. Otherwise it gets MEDIUM, USER_OVERRIDE. | `TestAuditR12UnverifiedOverrideIsMedium` |
| R12b | S2 | An override whose install root could not be resolved was tagged with an empty runner, which invalidated the whole section (supervisor → UNAVAILABLE). | Without an identity there is no tag (C1). | same |
| R13 | S2 | API enrichment wrote a local SUCCEEDED or FAILED outcome verbatim as a conflict claim. That value is outside the claim vocabulary, so enriching a finished job failed with "output validation failed". | Outcomes are mapped onto the claim vocabulary. | `TestAuditR13EnrichmentConflictUsesClaimVocabulary` |
| R14 | S2 | `Discover` skipped the C2 executable and layout checks on non-Linux platforms, so a name-only process became a runner. | The same rule now applies on every platform, matching the live session. | covered by the existing discovery tests and the R12 case |
| R15 | S2 | A provider whose `Discover` panicked crashed `deprehendo-agent start`. Only `Detect` was guarded. | `Discover` is guarded for panics and has a 5 s bound. | `TestAuditR15DiscoverPanicDoesNotCrashStart` |
| R16 | S1 | JOB_STATE conflicts counted the worker's exit as a job-state claim (`EXITED`, which is not in the vocabulary). Once R6 made the code reachable, every cancelled job that ended normally produced an invalid section. T4 (an intent that arrives after the death) was not implemented. | Exit is no longer a job-state claim. The same result stated twice is agreement, not conflict. T4 is implemented: a worker that died more than 2 s (up to 60 s) before a cancellation or timeout record gets a TERMINATION_INTENT conflict. `EXITED` is now a registered claim value for that case. | `TestAuditR16TerminationIntentAfterDeathIsAConflict` |
| R17 | S2 | Defect in my 5.1 code: `Section.Validate` rejected any provider not compiled into the reading binary. One bundle with a GitHub section therefore failed in any reader without the GitHub vocabulary, such as an older agent, the `tests` harness or a third-party tool. This surfaced as a flaky `TestPhase2AcceptanceMatrix` when a fake runner from another package was alive on the host. | An unregistered provider is validated structurally (name and token shape, refs, bounds, privacy). `InterpretAll` still reports it UNAVAILABLE, so unknown evidence never strengthens a diagnosis. Writers stay strict. | `TestUnregisteredProviderSectionValidatesStructurally` |

**Privacy (5.12/5.36).** The required whole-provider canary test did not
exist. `TestAuditCanaryNeverLeavesTheHost` plants one token in the
environment, `.credentials`, `.credentials_rsaparams`, `.env`, the `.runner`
URLs, assignment and result log lines, a URL query, an Authorization header
and the worker log. The frozen section and its interpretation contain none
of it at either privacy level, and the allowlisted runner name still appears
at the `identifiers` level. No provider code reads `.credentials`, `.env` or
`/proc/*/environ`. API errors map to reason codes and bodies are never kept.
The token is read per request, cross-origin redirects are refused and token
files must be 0600 and owned by the agent user. No finding.

## 2. Reviewed with no finding

- **C1, C3, C4, C6, C8, C9:** incarnation keys throughout; worker by
  executable plus parent (or install root at MEDIUM); sticky
  first-observation job tree; ±2 s unique binding with a pending retry and
  never a guessed nearest worker. *Note on C6:* the JOB_BINDING conflict
  cannot name its candidates, because the claim has no worker field. This is
  acceptable for v1.
- **5.32 (restart / multiple runners):** the `two-runners` fixture pins
  worker → listener, and R11 covers restart.
- **5.43 (E2E):** `DEPREHENDO_E2E_GITHUB=1` passes on Linux. The harness now
  writes the real record format.
- **5.1 isolation:** supervisor, capture freeze bound and import boundaries
  are unchanged and hold.

## 3. Open: acceptance blockers and gaps

| # | Item | Owner (plan) | Why it blocks |
|---|---|---|---|
| B1 | **Closed 2026-10-31.** Signatures 5.20–5.24 are implemented. The principal review against §10A found one S1 violation (F1, fixed): a connection drop silenced the ASSIGNED and FINALIZING labels and let the IDLE label take an ASSIGNED episode. | engineering, principal review | — |
| B2 | **Closed** (HANDOFF, 2026-10-30): `timeline` and `analyze` build the causal graph with intent covers; a cancelled job's kill is not a failure anchor. | engineering (5.25), principal review | — |
| B3 | **Closed 2026-11-02.** A disposable self-hosted runner exercised all twelve scenarios in `docs/github/real-runner-verification.md` §7, including S12, where the worker binary was replaced so the listener accepted a job that no worker could start: `GITHUB_JOB_ASSIGNMENT_STALL` at MEDIUM, no socket-stall label, `ROOT CAUSE Unknown`. | user | — |
| G1 | **Closed 2026-10-31.** `github api-enrich --repo OWNER/NAME` locates each recorded job by local start time (±30 s) and runner name when known, then enriches it. Unique match or nothing; ambiguity is counted, never resolved. | principal | — |
| G2 | **Closed 2026-10-31.** Container steps link through docker cgroups plus a witnessed docker client; every job whose container membership could not be verified (no cgroup identity, or an unattributed container step while it ran) carries `CONTAINER_LINKAGE_UNAVAILABLE` (F2 fixed). Other runtimes are not linked (documented). | engineering, principal | — |
| G3 | **Closed (documented).** macOS limits now state that identity is the PID alone there (`docs/providers/github-actions.md`). | doc | — |
| G4 | **Closed 2026-10-31.** `DEPREHENDO_GITHUB_STALL_WINDOW` overrides the C11 window with a 10 s floor (F3), and the window in force is recorded in the section (F4). | engineering, principal | — |

## 4. Verification

Linux (sandbox), Go 1.24 local override:
- `go build ./...` and `GOOS=darwin go build ./...` pass. `go vet ./...`
  passes and `gofmt` is clean.
- `go test -count=1 ./...` is green apart from the two sandbox-limited
  platform tests (`/proc/1/fd` permission and no cgroup2), unchanged from
  Phase 4.
- `go test -race` passes on `internal/provider/...` and `internal/agent`.
- The gated runs pass: `DEPREHENDO_E2E_GITHUB=1`, `DEPREHENDO_E2E_CAUSAL=1` and
  `DEPREHENDO_REVIEW_AUDIT=1` (`./tests`, `./internal/causal`).
- **Mutation check:** all 13 positive regression tests fail when run against
  the pre-fix tree (a worktree at the received state, plus only a field shim
  so the test file compiles). R15 panics there. The negative guard R6b passes
  on both, as intended.

Sources for the real record formats: actions/runner issues
[#4670](https://github.com/actions/runner/issues/4670) and
[#2140](https://github.com/actions/runner/issues/2140).

## 5. Final audit (2026-10-31)

Scope: the canonical tree after the engineering, integration, secondary and adversarial slices, and
after B1/B2 landed. Severity as in Phase 4: S1 a wrong conclusion reaches the
user, S2 more certainty than the evidence, S3 latent or documentation.

| ID | Sev | Where | Finding | Status | Test |
|---|---|---|---|---|---|
| F1 | S1 | `signatures.go` | `GITHUB_RUNNER_DISCONNECTED` was in the set of events that silence a stall, and `CommunicationStall` judged IDLE by "no live worker" only. Assignment then broker drop was labelled `GITHUB_RUNNER_COMMUNICATION_STALL`; a finalizing worker whose channel dropped got no label at all. Both violate §10A S1. | **Fixed.** Disconnect is supporting evidence; the IDLE label defers to STOPPING and ASSIGNED per §10A.1. | `TestB1Review*` (3 of 4 fail before the fix; the fourth is a healthy negative) |
| F2 | S2 | `session.go` `jobRecord` | The `CONTAINER_LINKAGE_UNAVAILABLE` marker was set only when no sample ever carried cgroup identity, so on a cgroup host an unattributed docker container step left the job's process list silently incomplete. | **Fixed 2026-10-31.** Every worker alive when an unattributed container step is seen marks its job; a job can carry both the positive linkage and the marker. | `TestPrincipalFinalF2…` |
| F3 | S2 | `session.go` `stallWindowFromEnv` | Any positive override was accepted; `1ms` turned every quiet sample into a C11 progress stall. | **Fixed 2026-10-31.** Overrides below 10 s keep the 2-minute default. | `TestPrincipalFinalF3…` |
| F4 | S3 | provider section | The C11 window in force was not recorded. | **Fixed 2026-10-31.** `Section.StallWindowSeconds` records it; validation bounds it to [10 s, 24 h]. Additive field: a newer bundle is rejected by an older agent's strict decoder. | `TestPrincipalFinalF4…` |
| F5 | S3 | `signatures.go` `SelfTermination` | The finding cited `RUNNER_LOG_RECORD`, but rests on a LOCAL_PROCESS supervisor exit. | **Fixed 2026-10-31.** New registered code `SUPERVISOR_EXIT_OBSERVED`. | `TestPrincipalFinalF5…` |

Reviewed with no finding: 5.20 thresholds and the cancellation suppression;
5.22 tree-empty onset and the stated-result boundary; 5.23 intent windows
(T2); 5.24 grace (10 s, matches §10A.4); G2 ambiguity handling (two
candidate jobs never guess); G4 test coverage; the adversarial attack suite
(`adversarial_attack_test.go`, 11 tests) passes on this tree and is kept as
regression coverage.

**secondary's final-audit share is delivered:** `docs/reviews/phase5-secondary-audit.md`
(2026-11-02), six findings L1–L6 fixed with regression tests. It also closes B3:
all twelve real-runner scenarios have a passing record, S2, S11 and S12 on the
fixed binary (`docs/github/real-runner-verification.md` §7–§8). Phase 5 is
accepted.

5.45 timeout semantics, verified 2026-10-31: `TestTimedOutJobKillIsNotAFailure` (a stated timeout makes the job's SIGKILL context in both `timeline` and `analyze`) and `TestTimeoutStatedLongAfterTheKillDoesNotCover` (T2 bounds the cover). adversarial's share is the attack suite
plus `docs/reviews/adversarial-phase5-pass.md`; its remaining review items are
listed there.

## 6. principal review of secondary's L1–L6 (2026-11-02)

Each of secondary's fixes was diffed against the tree she started from, and the
full suite was rerun with the gated suites on. Two of the fixes needed
corrections. **Phase 5 acceptance stands** once those corrections are in.

| ID | Sev | Where | Finding | Status | Test |
|---|---|---|---|---|---|
| O1 | S1 | `cmd/deprehendo-agent/provider_report.go` (L6) | `jobInWindow` judged a job only by its API timestamps. A capture without API enrichment, which is the default, dropped every job from the report header, including the job the incident is about. `TestPhase5GitHubEndToEnd/healthy-job` failed under `DEPREHENDO_E2E_GITHUB=1`. | **Fixed.** `jobsForSectionWindow` also counts the job's section events and its worker's lifetime. A worker still running at the window start keeps its job in the header. | `TestJobsForSectionWindowUsesLocalEvidence`; the gated E2E passes |
| O2 | S1 | `internal/diagnosis/context.go` `kernelOOMRise` (L2) | L2 let the victim's last sample carry its own kill, which is correct for S11. But the same reading gave a cgroup's kill to any member still listed in that sample. A step shell that outlived the real victim by one sample got `KERNEL_OOM_COUNTER_ROSE`. | **Fixed.** When another member of the same cgroup departed in that interval, the baseline moves to the process's own last sample. A rise read in the victim's final sample still counts. | `TestOOMRiseIsNotGivenToASiblingThatOutlivedTheVictim` (fails on L2), `TestOOMRiseInTheVictimsFinalSampleStillCounts` |
| O3 | S3 | §10A.5, `timeline.go` | `JOB_SUCCEEDED` is a new intent. It covers the job's worker and job processes for exits up to 2 min before the stated success. This extends §10A.5, which listed only cancellation, timeout and runner-stop intents. One consequence: an OOM-killed child inside a step that still succeeds (`|| true`) becomes context, not a causal failure anchor. The diagnosis signature `OOM_KILL` is independent and still reports it. | **Documented** in §10A.5. Kept, because a stated success is the provider's own statement that the job ended as intended. | `intent_cover_test.go` |
| O4 | S3 | `signatures_files.go` `groupMemberSurvived` (L1) | Group survival is judged by PGID. A PGID reused by an unrelated process after the group died would read as a survivor and cancel the group-kill label (a false negative, never a false label). | **Open, accepted.** PGID reuse inside one capture window needs PID wrap. | — |

Reviewed with no finding: L3 (supervisor overrun grace is 30 s, overruns are
notes, counters reset per finish), L4 (the runner-tree cover is limited to
runner-stop intents and to the stopped runner's PGID), L5 (a TIMED_OUT
upgrade records `OutcomeSource=PROVIDER_API`), the `bin.<version>` discovery
layout, and `AnalyzerVersion` 0.3.3 / `SignatureVersion` 4.

Verification on the corrected tree: `go vet ./...` and gofmt are clean.
`go test ./...` and `-race` pass, except the two live-host tests that need a
real cgroup2 mount and `/proc` access, which this review sandbox lacks. The
gated suites (`DEPREHENDO_E2E_GITHUB=1 DEPREHENDO_E2E_CAUSAL=1 DEPREHENDO_REVIEW_AUDIT=1`)
pass, and `GOOS=darwin go build ./...` succeeds.
