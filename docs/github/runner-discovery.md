# GitHub runner discovery

`deprehendo-agent github discover` reads the local process table and inspects
candidate `Runner.Listener` processes using PID plus process start-time identity.
On every platform, a candidate is accepted only when its resolved executable is
`Runner.Listener` and its installation contains the expected `bin/Runner.Listener`,
`.runner`, and `config.sh` layout. A name-only process is a candidate, not a
verified runner. `--github-runner-pids` is a manual attachment selector, not a
way to bypass process identity validation.

The process name is matched exactly or by its base name: Linux reports a bare
comm, while macOS `ps` reports the executable path (and ` (deleted)` for an
unlinked binary). The base-name match is only the cheap filter; the executable
and install-layout checks still decide whether a process is tagged.

## Identity and metadata

A runner's stable reference is a salted hash of the canonical install root and,
when safely available, configured runner name. The PID is never runner identity;
listener incarnations are recorded separately as `(PID, start_ticks)`, so
restarts can be distinguished and a reused PID cannot inherit old facts.
Multiple installations are discovered independently. Runner version comes from
local version directories or bounded diagnostic-log headers; discovery records
its source as `RUNNER_CONFIG` or `RUNNER_LOG`. The only `.runner`
keys allowlisted by the current parser are `agentId`, `agentName`, `ephemeral`,
and `workFolder`; every other key (real files carry pool, server and GitHub URLs)
is skipped unread, and the UTF-8 byte-order mark the runner writes is stripped.
A mistyped allowlisted key fails the decode. The file is never serialized.

Safe recorded values include versions, lifecycle enum, typed roles, event enums,
opaque references, and process incarnation IDs. Names/labels, installation and
work paths, executable arguments, environment variables, and raw runner log
text are not saved. The configured work directory is not traversed for secrets.

The ephemeral lifecycle is used only when the allowlisted local configuration
says so. A normal process disappearance alone does not prove an error. An
observed completed job followed by an ephemeral listener exit is represented as
an intended lifecycle event.

## Requirements and gaps

Discovery is local and does not call GitHub. On Linux, process details and the
install layout must be readable. Permission failures or a listener that exits
during inspection cause it to be omitted for that discovery pass rather than
fabricating an identity. On non-Linux platforms the evidence can be reduced;
unknown details remain unknown. Container membership is best effort through
available cgroup metadata and does not imply Kubernetes support.

A disposable genuine self-hosted Actions runner is still required to validate
installation-layout assumptions, version parsing, service wrappers, and
real-world runner update/shutdown behavior. Numeric run/job identity, repository,
workflow, and conclusions are not inferred locally when unavailable; optional
API enrichment may add those facts later, with source preserved. Unit tests use generated fake
installations and do not claim that real-runner acceptance gate has passed.
