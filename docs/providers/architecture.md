# CI providers: Phase 5 architecture

**Owner:** principal (Phase 5 principal integration architect)
**Date:** 2026-10-28  
**Status:** BINDING for 5.1. §6–§9 are the binding invariants for the
principal-led items that engineering implements later (5.4–5.10 correlation, 5.15 broker
identification, 5.44–5.46 termination semantics, 5.47/5.48 provenance and
disagreement, 5.12/5.36 privacy). Like `docs/causal-semantics.md`: if code and
this file disagree, the code is wrong; if evidence (a fixture or a real runner)
shows this file is wrong, change this file first and log why in §12.

**Code that implements 5.1** (principal, compiled and tested):

| Package | What it is |
|---|---|
| `internal/provider/evidence` | The bundle's provider section: typed, enumerated, redactable. Leaf package (stdlib only). |
| `internal/provider` | Provider-neutral interfaces (`Provider`, `Session`, `Enricher`, `HostView`), the registry, the failure-isolating `Supervisor`, and the import-boundary test. |
| `internal/provider/providertest` | Conformance kit every concrete provider must pass. |

engineering implements the GitHub provider (`internal/provider/github`) and the wiring
(§11) against these packages.

---

## 0. The one sentence

> The recorder must not know GitHub exists, the bundle must not be able to
> carry a secret, and a provider bug must never cost us the incident.

---

## 1. What 5.1 decides

1. **Two halves.** A provider's live half runs while recording and turns what
   it sees into typed evidence. Its offline half (`Interpret`) is a pure
   function of the bundle. The plan's `Enrich(ctx, *Incident)` is split
   accordingly: local correlation happens live, and remote API enrichment is a
   separate, optional `Enricher`.
2. **Classify live, store roles.** The conservative redactor strips every
   process name, path, command line and address from a bundle. So "PID 5218
   is `Runner.Listener`" and "inode 88201 is the control channel" must be
   decided on the live host and stored as enumerated roles bound to process
   incarnations and socket inodes. A fact not converted while live is lost,
   and offline analysis (5.38) depends on this.
3. **Tri-state with WITHHELD.** Every textual or numeric identifier is
   KNOWN, UNKNOWN (never learned) or WITHHELD (learned, kept out by privacy).
   Reports must say "withheld" and "unknown" differently.
4. **Opaque identity.** Runners, workers and jobs are `Ref`s: salted hashes of
   provider-native identity. Two incidents from one runner share a Ref; the
   bundle never names the runner unless the user opts in.
5. **Closed vocabulary.** Event types, socket roles, evidence codes and
   conflict topics are provider-registered enumerations. `Validate` rejects
   anything else, so neither a parser bug nor a hostile log line can put
   new tokens into a bundle.
6. **Isolation.** The `Supervisor` makes provider failure a health state.
   Panics, errors, hangs and backpressure each become a reason code. None of
   them blocks the recorder, fails a capture, or delays an incident write
   beyond a fixed bound.
7. **Generic translation.** Providers translate their events into a small
   provider-neutral vocabulary (`GenericKind`) that the causal engine can
   reason about. GitHub-specific names stay in the provider section, for
   rendering and for provider signatures.
8. **Multi-provider from day one.** A bundle carries `[]evidence.Section`,
   one per provider, keyed by name, so GitLab/Buildkite/Jenkins need no
   schema change.

---

## 2. Layering (enforced by `TestProviderImportBoundaries`)

```text
cmd/runopsy-agent ──► internal/provider/github ──► internal/provider ──► internal/provider/evidence
        │                                              │                       ▲
        └──► internal/agent ──► internal/collector     └──► internal/incident ─┘
                                internal/platform
internal/causal, internal/diagnosis ──► internal/provider (neutral only)
```

| Rule | Why |
|---|---|
| collector, platform, events import no provider package | recording works with no provider compiled in (5.1 "core recorder remains provider-independent") |
| incident imports only `provider/evidence` | the bundle format knows a provider *section*, never a provider |
| evidence imports only the standard library | it is a schema |
| no `internal/` package imports a concrete provider | concrete providers are wired by `cmd/` only |
| causal and diagnosis use only the neutral package | GitHub signatures register through a neutral extension point (§5.3) |

---

## 3. The bundle provider section (`internal/provider/evidence`)

### 3.1 Shape

`evidence.Section`: provider name, schema version, privacy level, health,
`Runners`, `Workers`, `Jobs`, `ProcessRoles`, `SocketRoles`, `Events`,
`Conflicts`. Every record is typed. There is **no field that can hold a log
line, URL, command line, path, environment variable, header or token**:

- `Event` has no message field. `Provenance` points at the source (file
  *index* in the provider's own list, byte offset, 1-based core sample index)
  without copying it.
- Roles and correlations carry `Sources` (enum) and `Evidence` (registered
  reason codes), never prose.
- Bounds: 64 runners, 4096 workers/jobs, 65536 process roles, 4096 socket
  roles, 50000 events, 1024 conflicts. Text values ≤ 256 bytes.

### 3.2 Identity

- `ProcessRef{PID, StartTicks}` everywhere. PID alone is never an identity.
- `Ref` = `rnr_|wkr_|job_` + 16 hex digits of
  SHA-256(host salt ‖ identity parts). Callers canonicalise parts first
  (realpath, trailing slashes). The salt is per installation: it is stored in
  the agent's state directory, created on first run, and never exported.
- Runner identity parts (5.4): canonical install root + configured runner
  name when readable. If the name is unreadable, the install root alone. Never
  a PID.
- Worker identity: runner Ref + worker `ProcessRef`. Sequential workers are
  distinct.
- Job identity: runner Ref + provider job ID when known, otherwise the
  worker Ref. A job whose native ID is unknown still has a stable Ref for the
  incident.

### 3.3 Incident integration (engineering, §11 item 1)

- `incident.Incident` gains
  `Providers []evidence.Section \`json:"providers,omitempty"\``. This is
  additive, so `SchemaVersion` stays 1 and older readers ignore the field. Bump
  `AgentVersion`.
- `incident.Validate` calls `Section.Validate()` on each section; an invalid
  section fails the bundle (the supervisor never writes one).
- `ConservativeRedactor` calls `Section.Redact(level)` with the capture's
  configured level (default `conservative`). It also sets the
  `PrivacyReport` booleans for provider classes: add `provider_identifiers`.
- `Capture.finalize` asks each supervisor to `Freeze(captureStart,
  captureEnd)` with the supervisor's own bound, before `deriveEvidence`. It
  never waits longer: a provider that cannot answer becomes an UNAVAILABLE
  section with a reason.

---

## 4. The live half

### 4.1 Lifecycle

```text
agent start ─► Registry.All() ─► Detect (each, bounded) ─► present? ─► Supervisor.Start(Attach)
                                                                         │
recorder OnSnapshot ─► Supervisor.Offer (non-blocking, drops counted) ──►│ Session.Observe
incident trigger ─► Capture.finalize ─► Supervisor.Freeze(window) ──────►│ Session.Freeze ─► redact ─► validate ─► bundle
agent stop ─► Supervisor.Close(bounded)
```

- `Detect` and `Discover` are local only: procfs plus the runner's own files.
  No network.
- **Re-discovery** at most every 10 s, and immediately when a supervisor
  incarnation exits. Runners start and stop during recording (5.32, 5.34).
- `--github-runner-pid` (5.2 manual override) feeds
  `AttachOptions.SupervisorPIDs`. Facts derived from it carry
  `SOURCE_USER_OVERRIDE`.
- `runopsy github watch` (5.30) = Discover → set the recorder filter to the
  supervisor PIDs with `Descendants: true` → Start supervisors. It is
  composition in `cmd/`, not new core machinery.

### 4.2 HostView

`Processes` returns the full table; the recorder's own snapshots may be
filtered. `Inspect` returns live-only `ProcessDetail` (resolved executable,
working directory, argv) and **fails if the PID now belongs to a different
incarnation** (it compares `StartTicks`). `ProcessDetail` has no environment
field by design; providers never read `/proc/<pid>/environ`. On macOS,
`Inspect` uses `proc_pidpath`/`ps -o comm=` for the executable and returns
UNKNOWN for the rest.

### 4.3 Supervisor guarantees (`internal/provider/supervisor.go`)

| Guarantee | Test |
|---|---|
| `Offer` never blocks (bounded queue, drops counted, health DEGRADED + `OBSERVATIONS_DROPPED`) | `TestSupervisorOfferNeverBlocks` |
| attach error/panic/hang, observe panic, freeze hang/invalid output → UNAVAILABLE with the matching reason, never an error | `TestSupervisorFailuresBecomeHealthNotErrors` |
| after a panic or a hang no further provider code runs | `TestSupervisorStopsCallingAProviderAfterAPanic` |
| `Freeze` returns within `FreezeTimeout` + 1 s, always a valid section | failure-case timing assertion |
| redaction to the configured level happens in the supervisor, so a provider cannot skip it | `TestSupervisorHealthyPathIsRedactedAndValid`, `...IdentifiersPrivacyStillScrubsSecrets` |

### 4.4 Budgets (5.49)

`DefaultBudget`: 1 MiB/s of log reading, 8 MiB of retained parsed state, and
20000 tracked process incarnations. A provider that hits its budget stops
ingesting (it does not grow), and its section reports DEGRADED with
`LOG_TRUNCATED`. integration benchmarks against these numbers.

---

## 5. The offline half

### 5.1 Interpret is pure

No file, process, network or clock access; deterministic; must not mutate
its input. The conformance kit checks determinism, non-mutation and
well-formed output. Purity is a review rule: `internal/provider/github`'s
`interpret.go` may import only `evidence`, `provider`, `incident` and
the standard library's `sort`/`time`/`fmt`.

### 5.2 Generic translation (5.8 → causal)

| GenericKind | Meaning | Typical GitHub source |
|---|---|---|
| `RUNNER_STARTED` / `RUNNER_STOPPED` | supervisor incarnation began/ended | listener start/exit, log "Listening for Jobs" |
| `WORK_ASSIGNED` | the runner received a job | log job-message received |
| `WORKER_STARTED` / `WORKER_EXITED` | worker incarnation began/ended | `Runner.Worker` child observed / exit observed |
| `WORKER_PROGRESS_STOPPED` | the job stopped making progress (5.18) | derived, see §6 C11. **Only** `GITHUB_JOB_PROGRESS_STOPPED` translates here; `GITHUB_COMMUNICATION_STALLED` has no generic kind (§10A S1) |
| `TERMINATION_INTENDED` + `Intent` | the stop was intended (§7) | cancellation, timeout, service stop, ephemeral completion, update |

The causal engine maps these onto its reserved event types
(`RUNNER_STARTED`, `WORKER_STARTED`, `WORKER_EXITED`,
`WORKER_PROGRESS_STOPPED`) and adds `TERMINATION_INTENDED` as a CONTEXT event
(5.25, engineering). **Privacy independence** (conformance-checked): generic output
must be identical whether the section is conservative or identifiers-level.
Diagnoses never depend on withheld text.

### 5.3 Provider signatures (5.20–5.24)

Provider-specific diagnoses (`GITHUB_JOB_ASSIGNMENT_STALL`, ...) register
through a neutral diagnosis extension point that receives the
`[]provider.Interpretation`. They are reported *alongside* the generic
signature that describes the mechanism (5.26), never instead of it. Their
binding rules are §10A.

---

## 6. Correlation invariants (5.4–5.10, 5.15): principal-defined, engineering implements

**C1. Identity is never a PID.** Runner, worker and job identities are Refs
(§3.2). Process facts bind `ProcessRef` (PID + start ticks). A role tag on a
PID whose start ticks differ is a different process.

**C2. Supervisor classification needs two independent facts.** A process is
tagged `RUNNER_SUPERVISOR` only with (a) executable basename
`Runner.Listener` (resolved exe, not just the 15-byte `comm`) **and** (b) an
install-root layout check: `bin/Runner.Listener` under a root that also has
`.runner` and `config.sh`. Alternatively, (a) plus a user override.
`comm == "Runner.Listener"` alone gives a *candidate*, which is reported by
`discover` but never tagged. Confidence: HIGH with (a)+(b), MEDIUM with
override only.

**C3. Worker = child of a supervisor incarnation.** A process is
`RUNNER_WORKER` when its executable basename is `Runner.Worker` **and** its
PPID is a tagged supervisor whose start ticks ≤ the worker's. A worker whose
parent is unknown (reparented before first observation) is a worker
candidate with MEDIUM confidence, bound to a runner only through the install
root of its executable.

**C4. Job-tree membership is sticky and first-observation-based.** A process
joins a worker's job tree when it is *first observed* as a descendant (PPID
chain, with each ancestor's incarnation verified) of a worker incarnation.
The tag stays with that incarnation for life: when the worker dies and the
job process is reparented, it stays tagged. That is exactly how
`GITHUB_ORPHANED_JOB_PROCESS` (5.24) becomes visible. A process first seen
already outside the tree is never tagged by guess. Session or PGID equality
alone never assigns membership, because jobs call `setsid` and helpers share
sessions.

**C5. Container jobs are not descendants.** Container-step processes run
under `containerd-shim`, not under the worker. Their membership comes from
cgroup linkage (the container's cgroup started within the worker's lifetime
and was created by a `docker` client that is a worker descendant). This is
5.33; until it lands, container-step processes are untagged and the section
says so (`CONTAINER_LINKAGE_UNAVAILABLE` evidence code on the job).

**C6. One worker incarnation ↔ at most one job.** The job Ref binds to the
worker whose start lies within ±2 s of the runner log's job-received
record, and only when that binding is unambiguous: exactly one worker started
in the window. Otherwise the worker keeps a job Ref with UNKNOWN identity, and
a `JOB_BINDING` conflict lists the candidates. Never pick the nearest.

**C7. Log time is not process time.** Runner log timestamps are parsed with
their explicit zone (the files are UTC-named). They are order evidence only
at ≥ 1 s resolution against process observations, and a correlation that
needs finer order is not made. Log events carry `RUNNER_LOG` as source.

**C8. A process belongs to at most one runner.** If two runners' trees claim
one incarnation (a shared `docker` daemon, say), it is untagged, and a
`RUNNER_BINDING` conflict is recorded.

**C9. Restart is the same runner.** A new supervisor incarnation with the
same runner Ref is appended to `Runner.Supervisors` (5.34). It is not a new
runner, and the gap is a `RUNNER_STOPPED` → `RUNNER_STARTED` pair.

**C10. Unknown is always allowed.** Every field and binding may be UNKNOWN.
No step fabricates a value to complete a chain.

**C11. Progress needs two kinds of evidence (5.18).**
`WORKER_PROGRESS_STOPPED` requires *both* (a) no job-tree progress signal
(CPU ticks, child-process creation/exit, job-tree socket bytes) for ≥ the
configured stall window, *and* (b) no runner-side progress (worker log
growth or step transitions) over the same window. Either one alone is LOW and
is not emitted. A long single-process compile has CPU progress, so it is
never a stall.

**C12. Broker / control channel (5.15).** A socket is tagged
`CONTROL_CHANNEL` only when all of these hold:
1. its owner is a tagged supervisor incarnation;
2. it is ESTABLISHED to a remote TCP port 443;
3. it is long-lived: present across ≥ 3 consecutive samples, or
   re-established within 5 s of a previous control-channel socket's close
   (the long-poll cycle);
4. **and at least one discriminator:** (a) runner-log timing, i.e. the
   socket's open falls within ±2 s of a log record of a session/poll
   (re)start, or a progress burst on it within ±2 s of a job-received
   record; or (b) it is the only supervisor socket satisfying 1–3.

Without a discriminator it is a `CONTROL_CHANNEL_CANDIDATE` (MEDIUM),
which signatures may cite as supporting evidence only. "HTTPS socket owned by
the listener" alone is **never** the broker. Worker sockets are never
`CONTROL_CHANNEL`. Their roles (job log upload, action downloads) stay
unclassified until a signature needs them. Remote addresses are redacted in
bundles, so this classification is made live and stored as the role.

---

## 7. Intended termination (5.44–5.46)

**T1. Intent is a positive fact, never an inference from the death.** A
SIGTERM, a process-group kill or a clean exit pattern alone never makes a
termination intended. `TERMINATION_INTENDED` needs a source that *states*
intent:

| Intent | Required evidence (any one) |
|---|---|
| CANCELLED | runner/worker log cancellation record for the job; API conclusion `cancelled` |
| TIMED_OUT | log record of the job/step timeout; API conclusion `timed_out` |
| SERVICE_SHUTDOWN | runner log shutdown record (SIGTERM handler / "Runner service stopped"); host shutdown seen by the agent itself |
| EPHEMERAL_COMPLETE | runner configured ephemeral (§9 allowlist) **and** job completed **and** supervisor exit after completion |
| RUNNER_UPDATE | runner log self-update record, followed by a new supervisor incarnation of the same runner |

**T2. Scope and window.** An intent covers the job tree, the worker and
(for shutdown, ephemeral and update) the supervisor of the runner it names.
It covers exits from 1 s before the intent record (a log may lag the signal) to
the end of a declared grace window (cancellation 30 s, shutdown 60 s).
Exits outside the scope or window keep normal failure semantics.

**T3. Effect.** In the causal engine, covered exits are CONTEXT, not failure
anchors (they extend causal-semantics.md §5.1 "exit failure context" with a
negative case). A covered exit is reported as "ended by job cancellation", not
as a failure. Provider signatures must check intent before claiming
self-termination (5.23) or orphaned jobs (5.24).

**T4. Intent can be contradicted.** If the API says `cancelled` but the
worker died more than the grace window before the cancellation record, the
death is *not* covered. Record a `TERMINATION_INTENT` conflict: the death
may have caused the cancellation, not the other way round.

**T5. Timeout ≠ hang.** A `TIMED_OUT` intent explains the kill, not why the
job ran long. A stall signature may still fire on the pre-timeout evidence,
and the report says both.

---

## 8. Provenance and disagreement (5.47, 5.48)

**P1. Authority depends on the question.**

| Question | Authoritative | Then | Never authoritative |
|---|---|---|---|
| Did this process exist / exit, and when? | `LOCAL_PROCESS` | `RUNNER_LOG` | `PROVIDER_API` |
| Which job was this runner given? | `RUNNER_LOG` | `PROVIDER_API` | inference from timing alone |
| Job identity (repo, workflow, run, attempt) | `PROVIDER_API` | `RUNNER_LOG` | — |
| Job conclusion (succeeded, cancelled, timed out) | `PROVIDER_API` (after completion) | `RUNNER_LOG` | process exit codes |
| Is the runner connected? | `LOCAL_SOCKET` + `RUNNER_LOG` | `PROVIDER_API` (lagging) | — |

**P2. Disagreement is recorded, not resolved.** When two sources answer one
question differently, a `Conflict` is written with each claim, its source and
its observation time. The authoritative source's answer is *used*, but every
conclusion that depends on the answer is capped at MEDIUM (the D3 analogue),
and the report shows the conflict.

**P3. Staleness is a claim property.** Each API claim carries its fetch
time. An API claim older than the local observation it contradicts is
recorded as a conflict with that time, so "the API had not caught up" is
visible rather than silently ignored.

**P4. Enrichment never overrides.** `Enricher` only adds `PROVIDER_API`
facts and conflicts. It never rewrites a local fact.

**P5. Example (the plan's case).** API says *queued*, runner log says
*assigned*, a local worker exists. The process facts and the log win for
"what is happening on this host"; the job is RUNNING. A `JOB_STATE` conflict
records `PROVIDER_API: QUEUED @t1` against `RUNNER_LOG: ASSIGNED @t2`, and
any assignment-stall diagnosis is capped at MEDIUM with the conflict listed.

---

## 9. Credentials and privacy (5.12, 5.36): attack surface first

### 9.1 What the GitHub provider may and may not read

| Never read | Why |
|---|---|
| `.credentials`, `.credentials_rsaparams` (runner root) | runner authentication material |
| `.env` (runner root) | job environment variables, often secrets |
| `/proc/<pid>/environ` of any process | secrets |
| `_diag/pages/`, `_diag/blocks/` | job step output: arbitrary user data |
| `_work/` | checked-out code and job files |

| Read, allowlisted | Rule |
|---|---|
| `.runner` (JSON) | parse into a struct with **only** allowlisted keys (runner name, numeric runner ID, ephemeral flag, work-folder name). Every other key (real files carry pool, server and GitHub URLs) is **skipped unread**, never rejected: rejecting them made the name and the ephemeral flag unreachable on every real host (audit R4). Strip the UTF-8 BOM the runner writes. A mistyped allowlisted key fails the decode. Key names must still be verified on a real runner (5.42). |
| `_diag/Runner_*.log`, `_diag/Worker_*.log` | tail with a bounded reader; match against a closed set of patterns; keep only the derived event and its file index + byte offset. **Raw lines never leave the parser function.** The record shape is the runner's trace format `[YYYY-MM-DD HH:MM:SSZ LEVEL Component] message` (audit R1). Patterns are anchored on phrases the runner itself writes; a phrase taken from anywhere else must be marked unverified until 5.42. |
| resolved executable path and its version-bearing directory | version string only (ClassVersion); the path is used for the Ref hash and then dropped |

### 9.2 Privacy levels

| Class | conservative (default) | identifiers (opt-in `--provider-identifiers`) |
|---|---|---|
| VERSION | KNOWN | KNOWN |
| RUNNER_NAME, LABELS | WITHHELD | KNOWN |
| REPOSITORY, WORKFLOW, JOB_NAME | WITHHELD | KNOWN |
| RUN_ID, JOB_ID, ATTEMPT | WITHHELD | KNOWN |
| URLs, tokens, headers, log text, paths, env | **not representable** | **not representable** |

`Redact` also withholds any KNOWN value that fails the safe-text check
(control/invisible characters, URL schemes, credential markers such as
`ghp_`, `ghs_`, `github_pat_`, `bearer`, `x-access`, `sig=`), even at the
identifiers level. Product decision for the user: whether `identifiers`
should become the default for single-tenant users. Conservative stays the
default until the user says otherwise.

### 9.3 API credentials (5.11, 5.37)

- Sources: `RUNOPSY_GITHUB_TOKEN`, or a token file that must be mode
  `0600` and owned by the agent user (refuse otherwise). Never a CLI flag,
  because argv is world-readable in `/proc`.
- The token is fetched per request through `provider.Credentials` and is
  never stored in a struct field, logged, put in an error string, or
  serialized. API errors are mapped to reason codes
  (`API_UNAUTHORIZED`, `API_RATE_LIMITED`, `API_UNAVAILABLE`); response
  bodies are not kept.
- Required test (adversarial): a canary token `ghp_CANARY…` placed in the
  environment, `.credentials`, `.env`, a runner log line, a URL query string,
  a process argv and an API error body must not appear anywhere in a bundle,
  CLI output, agent log or error message.

---

## 10. Conformance (every concrete provider)

`providertest.Run(t, p, fixtures)` must pass on every fixture under
`testdata/github/` (5.39). It checks: registration, section validity,
deterministic non-mutating `Interpret`, well-formed generic events,
references to existing refs only, and **privacy independence**. GitHub also
needs its own tests for C1–C12, T1–T5 and P1–P5, written from the healthy
scenarios first (5.40).

---

## 10A. State model and provider signatures (5.16–5.25): principal-defined

Status 2026-10-31: **implemented and reviewed**. All five labels (5.20–5.24)
are judged offline in `internal/provider/github/signatures.go`, and the causal
engine honours intent covers (§10A.5). The principal B1 review found and fixed one
S1 violation: a connection drop silenced the ASSIGNED and FINALIZING labels and
let the IDLE label claim an ASSIGNED episode. The phase used for the IDLE
check now follows §10A.1 order (STOPPING and ASSIGNED outrank IDLE). Not
implemented: the RUNNING-phase label is the generic C11 event, as designed.

### 10A.1 Runner phase (5.16, 5.19)

Each runner has exactly one **phase** at any instant, computed offline from
the section alone. The first matching row wins:

| # | Phase | Holds when (at time t) |
|---|---|---|
| 1 | `OFFLINE` | no supervisor incarnation of the runner is alive at t |
| 2 | `STOPPING` | a covering `TERMINATION_INTENDED` (SERVICE_SHUTDOWN, RUNNER_UPDATE, EPHEMERAL_COMPLETE) is within its T2 window |
| 3 | `FINALIZING` | a worker is alive and either its job stated a result, or every sticky job-tree member of that worker has exited |
| 4 | `RUNNING` | a worker is alive with at least one live job-tree member, or its job tree has not yet been observed |
| 5 | `ASSIGNED` | the newest `GITHUB_JOB_ASSIGNED` is unbound (no worker) and newer than the last worker exit |
| 6 | `IDLE` | otherwise (supervisor alive, no worker) |

The **communication state** is orthogonal: `CONNECTED` (an open
`CONTROL_CHANNEL` socket), `STALLED` (a `GITHUB_COMMUNICATION_STALLED`
episode is open), `DISCONNECTED` (newest connection record is a disconnect),
or `UNKNOWN`. A `CONTROL_CHANNEL_CANDIDATE` counts as `UNKNOWN`, never as
`CONNECTED`.

The **job state** (5.17) is the job's `Outcome` plus the phase: `ASSIGNED`,
`RUNNING`, `FINALIZING`, then a stated result. The API's `QUEUED` is a P2
claim, never a phase.

### 10A.2 Stall signatures: one label per episode (5.18, 5.20–5.22)

**S1. Disjointness.** A stall *episode* for a runner gets exactly one stall
label, chosen by the runner's phase when progress first stopped:

| Phase at onset | Label | Fires when (all of) |
|---|---|---|
| `ASSIGNED` | `GITHUB_JOB_ASSIGNMENT_STALL` (5.20) | assignment record unbound for ≥ 30 s; supervisor alive throughout; no stated cancellation for it |
| `RUNNING` | `GITHUB_JOB_PROGRESS_STALL` → generic `WORKER_PROGRESS_STOPPED` (5.18) | the C11 event; both conditions over the same window |
| `FINALIZING` | `GITHUB_JOB_FINALIZATION_STALL` (5.22) | worker alive ≥ 60 s after its job tree emptied or its result was stated; no worker exit; no covering intent |
| `IDLE` | `GITHUB_RUNNER_COMMUNICATION_STALL` (5.21) | a `GITHUB_COMMUNICATION_STALLED` episode, supervisor alive |

A communication drop while a job is running or finalizing is **supporting
evidence** for that phase's label (and is listed in the report), never a
second stall diagnosis. `GITHUB_COMMUNICATION_STALLED` therefore has no
generic translation: it must not reach the causal engine as the job's work
stopping (audit R8). Test: every fixture and every scenario yields at most one
stall label per runner per episode, and a fixture built to sit on each phase
boundary (assignment then worker at +29 s / +31 s; tree empties at the same
sample the channel drops) produces the label of the earlier phase.

**S2. Confidence ceiling.** A stall signature is at most MEDIUM when any input
is log-only (C7), a `CONTROL_CHANNEL_CANDIDATE`, or the subject of a P2
conflict; HIGH needs a LOCAL_PROCESS fact for onset and a direct observation
for the absence (a live supervisor in every sample of the window).

**S3. Healthy negatives first.** `healthy-idle`, `healthy-job`,
`normal-ephemeral-exit`, a long single-process compile and a normal long-poll
reconnect must yield no stall label. Write these tests before the positive
ones.

### 10A.3 Runner termination (5.23)

`GITHUB_RUNNER_SELF_TERMINATION` (name kept from the plan; the report says
"runner terminated without a stated reason", because process evidence cannot
tell a self-exit from an external kill) fires when a supervisor incarnation's
exit is observed (LOCAL_PROCESS) and **no** T1 intent covers it (T2 window,
runner scope). It must not fire when the next sample shows the whole host
recorder stopping, nor for an exit followed within 5 s by a new incarnation
that a `RUNNER_UPDATE` intent covers. A kernel OOM record for the supervisor
yields the generic OOM signature instead; this one is then supporting
evidence. MEDIUM unless the exit was observed within one sample interval.

### 10A.4 Orphaned job process (5.24)

`GITHUB_ORPHANED_JOB_PROCESS` fires for a sticky job-tree member (C4) that is
still alive ≥ 10 s after its worker incarnation's observed exit. It fires
whether or not an intent covers the worker: a cancellation explains the
worker's exit, not a survivor. The report names the survivor's role and PID
incarnation, never its name or command line.

### 10A.5 Causal integration of intent (5.25, T3)

The causal engine consumes generic events only through the neutral package.
For each `TERMINATION_INTENDED` at time t with a runner (and, when present, a
worker or job), the **covered set** is the runner's job-tree members and
worker (CANCELLED, TIMED_OUT), plus its supervisor (SERVICE_SHUTDOWN,
RUNNER_UPDATE, EPHEMERAL_COMPLETE), resolved through `ProcessRoles`. A
`PROCESS_EXITED` or `PROCESS_GROUP_TERMINATED` of a covered process within
[t − 1 s, t + grace] is a CONTEXT event, not a failure anchor (grace: 30 s for
cancellation and timeout, 60 s otherwise). A recorded `TERMINATION_INTENT`
conflict (T4) removes the cover for that worker. Nothing else changes: an
intent never removes an anchor outside its covered set or window, and the
explanation names the intent ("ended by job cancellation"). Test with the
`process-group-kill` causal fixture plus a provider section: covered gives no
failure anchor; the same kill 31 s after the intent keeps it.

**JOB_SUCCEEDED (added 2026-11-02, secondary L1; principal review O3).** A job whose
stated result is SUCCEEDED emits `TERMINATION_INTENDED` with intent
`JOB_SUCCEEDED`. It covers the job's worker, job root and job processes over
[t − 2 min, t + 60 s]. The lead is longer than other intents because the
result is stated when the job ends, not before its processes exit. It never
covers the supervisor and never ends the runner tree. A process killed inside
a step that still succeeded is context for the causal engine. Diagnosis
signatures (e.g. `OOM_KILL`) are unaffected.

---

## 11. engineering queue (ordered)

| # | Work | Notes |
|---|---|---|
| 1 | Incident integration (§3.3): `Providers []evidence.Section`, validation, redaction hook, `Capture.finalize` freeze, `PrivacyReport.provider_identifiers` | bundle round-trip and old-bundle read tests |
| 2 | Agent wiring: `HostView` implementation (procfs `Inspect` with incarnation check, salt file), `Supervisor` per detected provider fed from `OnSnapshot`, clean shutdown | the recorder must behave identically with no provider compiled in |
| 3 | `internal/provider/github`: `Name`, vocabulary, `Detect`, `Discover` (C2, C3, §9.1 `.runner` allowlist), `runopsy github discover` | adversarial reviews C2/C3 and the `.runner` allowlist |
| 4 | GitHub `Session`: process roles (C1–C4, C8, C9), worker/job records, generic translation, `Freeze` | conformance kit + fake-runner harness (5.41) |
| 5 | Log reader (5.7): bounded tailing, rotation, closed pattern set, offsets only | adversarial: "find log lines this parser misreads"; canary test |
| 6 | Control channel (C12), intent (§7), conflicts (§8) | principal reviews (5.15/5.44–46/5.48) |

---

## 12. Decision log

| Date | Decision | By |
|---|---|---|
| 2026-10-28 | All of §1–§11; 5.1 packages implemented and tested | principal |
| 2026-10-28 | §11 queue items 1–6 implemented end to end (agent wiring, github provider, session C1–C9/C11/C12, log reader, conflicts P-rules, `github discover`/`github interpret` commands); fake-runner conformance green | engineering |
| 2026-10-30 | §10A added (state model, stall-label disjointness S1–S3, 5.23/5.24 rules, 5.25 intent cover). §9.1 `.runner` decoding is skip-unread, not reject; the log grammar is the real trace format. Unregistered providers' sections validate structurally (audit R17). Audit: `docs/reviews/phase5-principal-audit.md` | principal |
| 2026-10-31 | B1 reviewed against §10A; S1 fix (disconnect is supporting evidence, phase order for the IDLE label). G1: `api-enrich --repo` locates jobs by time and runner name, unique match or nothing. Final-audit findings F1–F5 in the audit §5 | principal |
