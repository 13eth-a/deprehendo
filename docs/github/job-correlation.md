# GitHub job correlation

The provider samples existing process observations and correlates by
`(PID, start_ticks)`, never PID alone. A listener requires an executable match
and a verified installation layout (or a checked user override). A worker
requires the `Runner.Worker` executable and a verified parent listener or
installation root. Job descendants are tagged on first observed descendant
lineage and remain associated with that worker incarnation if later reparented.
Session or process-group equality alone is not used to attach a process to a job.

A worker and job have opaque salted references. The runner diagnostic log is
tailed incrementally with bounded bytes and file count. Records use the runner's
trace format, `[YYYY-MM-DD HH:MM:SSZ LEVEL Component] message`; the phrases
matched are ones the runner writes itself (for example `Job request … received.`,
`Running job:`, `Job … completed with result: Succeeded|Failed|Canceled`,
`Send job cancellation message to worker`). A job-scoped record (result,
cancellation, timeout, running) names its worker only when exactly one worker
of that runner was alive at the record's time. A log line that mentions an exit
code is never a worker-exit fact: process exit comes from the process table. Recognized lines become
enumerated events with file index and byte-offset provenance; raw lines are
discarded. Malformed lines are ignored and rotation/truncation degrades provider
health. When log assignment timing has exactly one worker in the configured
correlation window, they can be linked. Ambiguous or absent evidence stays
unbound or records a conflict; the nearest worker is not guessed.

The runner logs the assignment milliseconds before `Runner.Worker` exists, so a
sample can see the record first. Such an assignment stays pending for the
correlation window and binds on the sample where the worker first appears; if
no worker arrives inside the window it stays unbound rather than binding to a
later job's worker.

## Network attribution

A control-channel candidate must be an ESTABLISHED TCP socket on remote port
443 with a contemporaneous owner matching a verified listener incarnation.
Ownership uses socket inode and process start time. A candidate becomes a
`CONTROL_CHANNEL` only with the provider's long-lived/reconnect checks and a
log-timing discriminator or sole qualifying channel for that runner. Other
qualified sockets remain `CONTROL_CHANNEL_CANDIDATE`. A reconnect opens a new
socket; a replacement opened within 5 s of its predecessor's close is the same
long-poll cycle, not a stall. `GITHUB_COMMUNICATION_STALLED` needs a live
listener with no such connection for longer than that. HTTPS ownership by itself
is not enough to call a socket the broker. Remote addresses and traffic content
are not persisted by the provider.

## Causal interpretation limits

The normalized provider timeline is shown alongside generic system events;
co-occurrence and display order do not establish a cross-provider causal edge.
Provider log events include their source and file-index/byte-offset provenance.
API state is optional, may be stale, and is shown as a distinct source. API job
and run start/completion timestamps are also rendered in text timelines with
`PROVIDER_API` provenance; UNKNOWN timestamps stay absent rather than receiving
inferred values. Version evidence identifies whether its source was local runner
configuration/version layout (`RUNNER_CONFIG`) or a diagnostic log (`RUNNER_LOG`). When local and API
claims conflict, both claims are retained instead of silently selecting one.

The current provider does not supply the complete acceptance-level diagnosis
set for assignment stalls, communication stalls, finalization stalls, runner
self-termination, and orphaned job processes. `timeline` renders the combined
provider/system stream by default; JSON output retains the structured provider
evidence. `analyze --report` and `timeline --report` also render generic/provider
context together without implying an unvalidated causal edge. Generic systems
analysis remains available offline. A failure label must not be inferred solely from the fact
that GitHub-specific data exists.
