# Real self-hosted runner: successful job (2026-11-04)

Captured by `deprehendo-agent github watch --tracing proc` on the Lima aarch64 VM
(kernel 7.0.0-34, unprivileged uid 501) while the `selfhosted-e2e` workflow ran
on the registered `deprehendo-linux` self-hosted runner.

- GitHub run `41950041166` (`selfhosted-e2e`, conclusion `success`).
- Tracer state in the bundle: `active` (`proc_connector`), 280 `TRACE_PROCESS_EXIT`
  events, no reported loss.
- The job is correlated (`GITHUB_JOB_ACCEPTED`/`ASSIGNED`/`COMPLETED SUCCEEDED`
  for the listener's worker) and must produce **no** failure claim.

The defect this bundle pins: the job spawned a test process tree of its own;
when the job ended the runner SIGKILLed the leftovers (traced `signal:9`) in
their own process group (pgid 1434733, members 1434733 `JOB_ROOT` and 1434740).
Nothing survived and the exits were signalled, so `PROCESS_GROUP_TERMINATION`
reported the cleanup at 0.80 CRITICAL. Their parent chain reaches the job's
worker (PID 1434428), whose stated `SUCCEEDED` outcome covers that tree.

Provider identifiers are withheld in the bundle (the default privacy policy);
process names are redacted.
