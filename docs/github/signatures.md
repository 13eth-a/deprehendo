# GitHub provider signatures and health

GitHub provider observations are currently stored and translated into the
provider-neutral event vocabulary for offline analysis. The generic diagnosis
engine continues to report OS/network mechanisms separately from provider
context. Reports and timelines show provider facts, source, and provenance; an
API disagreement remains explicit as `PROVIDER_STATE_CONFLICT` evidence.

## Current behavior

- Listener, worker, job-process-tree, runner-log, and socket-role observations
  are collected with bounded provider state.
- Job assignment is linked to a worker only when the observed timing window has
  a unique match. Unknown fields remain UNKNOWN.
- A long-lived listener-owned HTTPS socket is not automatically called a
  broker: control-channel classification requires the additional checks in
  [job correlation](job-correlation.md).
- Cancellation, timeout, runner update, service shutdown, and configured
  ephemeral completion are represented as intentional lifecycle facts when
  supported by observed evidence.
- GitHub REST API calls are optional and do not gate recording or offline
  analysis. API outage, rate limiting, invalid credentials, or permission
  failures produce degraded enrichment health while preserving local facts in
  a new, validated bundle. The original bundle is left unchanged.
- `timeline` includes provider evidence even without `--report`; job/run API
  timestamps are shown with their source. `doctor` is discovery-only and
  explicitly reports live worker/communication health as UNKNOWN; it does not
  claim health without a recording sample.

All five provider-specific signatures named in the Phase 5 plan (5.20–5.24)
are implemented. `GITHUB_JOB_ASSIGNMENT_STALL` and `GITHUB_JOB_FINALIZATION_STALL`
are judged offline at the capture end and reported beside the generic events,
with a `SIGNATURE` line in the provider report. The finalization signature also
covers a worker whose job process tree emptied while the worker stayed alive
(`GITHUB_JOB_TREE_EMPTIED`). Both are capped at MEDIUM confidence and are
covered by healthy-negative and failure scenarios.

`GITHUB_RUNNER_SELF_TERMINATION` (5.23) fires when a runner supervisor exits and
no stated intent (shutdown, update, ephemeral completion) lies within the grace
window. It is capped at MEDIUM. `GITHUB_ORPHANED_JOB_PROCESS` (5.24) fires once
per job-tree member that is still alive at least 10 s after its worker's
observed exit. Both are covered by unit tests and the `runner-self-kill` and
`orphan-job` scenarios.

`GITHUB_RUNNER_COMMUNICATION_STALL` (5.21) is implemented: it is the IDLE-onset
label for a communication-stall episode, MEDIUM confidence, and has healthy-negative
tests. Its binding rules (runner phase model, one stall label per episode, confidence
ceilings, and how intended termination covers exits in the causal engine) are in
[architecture §10A](../providers/architecture.md). The generic `BROKER_SOCKET_STALL` rule also remains conservative and
does not establish application-level broker progress from an ESTABLISHED socket
alone.

Each stall episode gets exactly one label, chosen by the runner's phase when
progress stopped (§10A S1). A dropped connection while a job is assigned or
finalizing is supporting evidence for that job's label: it never silences the
assignment or finalization stall, and it is never relabelled as
`GITHUB_RUNNER_COMMUNICATION_STALL`. A drop within 60 s after a stated
shutdown, update or ephemeral completion is the runner going away, not a
communication stall. `TestB1Review*` in `signatures_s1_test.go` pins these
boundaries.

No genuine self-hosted runner has been exercised yet. Fake runner tests
validate parser and correlation invariants, not the real workflow end-to-end
gate. [Real runner verification](real-runner-verification.md) is the runbook
and script that close that gap; see also [runner discovery](runner-discovery.md).
