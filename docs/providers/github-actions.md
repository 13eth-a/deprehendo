# GitHub Actions provider

Deprehendo's GitHub Actions integration is local-first. It discovers self-hosted
runner processes, associates verified listener/worker incarnations with sampled
process trees, parses bounded diagnostic-log facts, and stores typed provider
evidence in the `.deprehendo` bundle. The core recorder remains provider-neutral.

## Commands

```sh
deprehendo-agent github discover
deprehendo-agent github doctor
deprehendo-agent github watch --interval 1s --window 2m
deprehendo-agent analyze incident.deprehendo --report
deprehendo-agent timeline incident.deprehendo --report
```

`discover` reports locally verified runner installations; `doctor` reports
what discovery can establish and labels live health as UNKNOWN until a recorder
sample exists. `watch` discovers all eligible runners and records each listener tree in the
foreground. `doctor` is discovery-only today: it deliberately shows worker,
communication and overall health as UNKNOWN unless recording has collected
evidence; it is not a live health probe. To attach to known listener PIDs
explicitly, use
`deprehendo-agent start --github-watch --github-runner-pids 5218,6041`; supplied
PIDs are still checked as listener processes. Stop recording with SIGINT or
SIGTERM. Recording and offline analysis do not require GitHub credentials or
network access. Captured bundles retain local provider events and can be
analyzed later without the original runner, credentials, or network.

Runner name, repository, workflow, job name, and numeric run identifiers are
WITHHELD by default. Add `--provider-identifiers` to `start` to opt into saving
these identifiers. Runner versions and enumerated roles are retained as safe
metadata. Unknown evidence remains UNKNOWN rather than being inferred.

## Optional API enrichment

A saved provider section can be enriched after capture:

```sh
deprehendo-agent github api-enrich --output incident-enriched.deprehendo incident.deprehendo
```

The token is read on demand from `DEPREHENDO_GITHUB_TOKEN` or a mode-0600 file at
`~/.deprehendo/github-token` (or `--token-file`). The API is optional enrichment:
rate limits, permission errors, network failures, and service errors mark
provider health degraded and do not discard the captured local evidence. API
claims do not overwrite local runner-log facts; disagreements are recorded.
The output is a new file and the input is never overwritten. API-derived names
remain WITHHELD unless `--provider-identifiers` is specified for this command.
Tokens and Authorization headers are not represented in incident schemas.
When the API supplies run/job timestamps, text reports and timelines show them
with `PROVIDER_API` provenance; the same fields remain optional for offline
analysis.

Local capture never learns a job's repository or its numeric run and job IDs
(the runner log carries GUIDs), so on a recorded bundle there is nothing to
look up until you name the repository:

```sh
deprehendo-agent github api-enrich --repo acme/service --output incident-enriched.deprehendo incident.deprehendo
```

`--repo` lists the repository's runs created in the 24 hours before each
job's local start, then keeps the API jobs that started within 30 seconds of
it, also matching the runner name when the bundle holds it (identifiers
level). A job gets its repository, run ID, job ID and attempt only when
exactly one API job fits. Otherwise it stays UNKNOWN, and the command prints
how many jobs were located, ambiguous or unmatched. Limits: an attempt of a
re-run whose run was created more than 24 hours earlier is not found; a
window with more than 100 runs, or more than 30 that overlap the job, is
reported as ambiguous rather than paged through. On a conservative bundle the
runner name is withheld, so two jobs starting within 30 seconds of each other
on different runners are ambiguous. The repository named on the command line
is written to the bundle only for located jobs, and only at the identifiers
level.

## Local fake runner (no GitHub required)

`deprehendo-sim github <scenario>` runs a fake runner installation so the provider
path can be exercised offline: it writes a real runner layout
(`bin/Runner.Listener`, `bin/Runner.Worker`, `_work/`, `_diag/`, `.runner`),
starts real processes with those names, writes real diagnostic lines, and holds
a loopback broker-shaped connection.

```sh
deprehendo-sim github healthy-job --root /tmp/runner --keep
# in another terminal, with the listener PID the harness printed:
deprehendo-agent start --github-runner-pids <listener-pid> --provider-identifiers
```

Scenarios: `healthy-idle`, `healthy-job`, `assignment-stall`,
`communication-stall`, `finalization-stall`, `worker-oom`, `runner-self-kill`,
`orphan-job`, `normal-ephemeral-exit`. Each materializes its own failure: an
assignment with no worker, a dropped broker socket, a killed worker with and
without its job tree, a simultaneous listener/worker/job death, and a normal
ephemeral shutdown. The harness idles for a couple of seconds before the job
arrives, so an operator (or a test) can attach recording before the assignment;
it reports each phase change and reaps every process it started on exit or
SIGINT/SIGTERM.

`--github-runner-pids` selects the listener processes to attach to and includes
their descendant trees in the recorded snapshots (a runner is only useful to the
provider together with the worker and job processes it spawns). A runner's
socket is only classified as a control channel when it meets the ownership,
port, lifetime and discriminator rules; the harness's loopback socket is
deliberately not port 443, so live control-channel classification is covered by
the `testdata/github/` fixtures rather than by the harness.

## End-to-end and performance checks

The full local pipeline (fake runner → recorder → stored provider section →
GitHub-aware report) is gated behind `DEPREHENDO_E2E_GITHUB=1`:

```sh
DEPREHENDO_E2E_GITHUB=1 go test ./tests -run TestPhase5GitHubEndToEnd -v
```

It asserts runner identity from the installation, worker→listener→runner
correlation, the job process tree, honest UNKNOWN job fields without API access,
and that a healthy runner produces no failure-shaped claim. Overhead is
measured by `internal/provider/github/bench_test.go` (idle runner, active job,
multiple runners, high process churn); `TestObserveOverheadWithinBudget` fails
if per-sample provider work exceeds a quarter of the fastest documented
sampling interval.

## Platform and privilege requirements

- Runner discovery and process correlation are strongest on Linux, where
  process executable paths, `/proc`, socket ownership, and cgroups are
  available. Other supported platforms may return UNKNOWN or reduced evidence.
- **macOS: process identity is the PID alone (gap G3).** Correlation rule C1
  identifies a process by PID plus start time, so a reused PID is never
  mistaken for the process it replaced. macOS exposes no start-time value to
  the recorder (`StartTicks` is 0), so the incarnation check cannot run there.
  If a runner, worker or job process exits and the OS reuses its PID within
  the capture, the new process can be attributed to the old one's role. The
  macOS build is for development and evaluation; use Linux for incident
  evidence you need to rely on.
- **Container steps (5.33).** A job's container-step processes are linked to
  it only on Linux with cgroup identity, a docker-created container cgroup,
  and exactly one live job running a `docker` client. A job whose container
  membership could not be checked carries `CONTAINER_LINKAGE_UNAVAILABLE`.
  Other runtimes (podman, containerd without docker) are not linked.
- The process table and process details are read locally. Access to other
  users' process metadata, socket ownership, and diagnostic logs depends on OS
  permissions; use the least privilege that can read the target runner.
- No service installation, upload, GitHub-hosted runner support, dashboard, or
  Kubernetes integration is performed by these commands.

See [runner discovery](../github/runner-discovery.md),
[job correlation](../github/job-correlation.md), [privacy](../github/privacy.md),
and [provider signatures](../github/signatures.md) for operational details and
current limits.
