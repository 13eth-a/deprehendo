# Real self-hosted runner verification (5.42, audit blocker B3)

Every GitHub-specific fact in Phase 5 has so far been checked against public
log excerpts and the fake runner, never a live install. This runbook closes
that gap. It needs about an hour, one disposable Linux VM, and a throwaway
repository. **Never run it against a production runner:** several scenarios
kill runner processes on purpose.

**Status: B3 is closed (2026-11-02).** §7 holds the per-scenario results and
§8 the final offline sweep over every bundle still on the VMs.

What it settles:

| Unverified today | Where it is checked |
|---|---|
| `.runner` key names (`agentId`, `agentName`, `ephemeral`, `workFolder`) and the BOM | script section 2 |
| `Runner.Listener` / `Runner.Worker` process names and the install layout (C2) | script sections 1, 3 |
| the `_diag` record header `[YYYY-MM-DD HH:MM:SSZ LEVEL Component]` | script section 4 |
| the shutdown, update, worker-cancel and worker-timeout phrases | script sections 5, 6 after scenarios S3–S6 |
| the Phase 5 acceptance gate on a real runner | the scenario table below |

## 1. Set up (disposable VM only)

1. Create a **private** throwaway repository, for example `you/deprehendo-b3`.
2. On a fresh Linux VM, follow the repository's *Settings → Actions →
   Runners → New self-hosted runner* page to download the runner, then
   configure it with the URL and registration token that page shows:

   ```sh
   ./config.sh --url https://github.com/you/deprehendo-b3 --token <REGISTRATION_TOKEN> --labels deprehendo-b3
   ```
3. Build the agent on the VM from this repository: `go build -o deprehendo-agent ./cmd/deprehendo-agent`.
4. Add the workflow in §3 to the throwaway repository.

## 2. Record

In one terminal start the runner (`./run.sh`). In a second terminal:

```sh
./deprehendo-agent github watch --trigger-on-process-exit --incident-dir ./b3-incidents
```

`github watch` discovers the runner tree and records it. For scenarios that
do not end in a process exit, trigger a capture by hand once the failure is
visible:

```sh
./deprehendo-agent trigger --note "S5 worker frozen"
```

## 3. Workflow

```yaml
# .github/workflows/deprehendo-b3.yml
name: deprehendo-b3
on:
  workflow_dispatch:
    inputs:
      scenario:
        type: choice
        options: [healthy, long, timeout, orphan, cpu, memory]
jobs:
  run:
    runs-on: [self-hosted, deprehendo-b3]
    timeout-minutes: ${{ inputs.scenario == 'timeout' && 1 || 30 }}
    steps:
      - name: scenario
        run: |
          case "${{ inputs.scenario }}" in
            healthy) echo ok; sleep 20 ;;
            long)    sleep 600 ;;                      # cancel it from the UI (S3)
            timeout) sleep 300 ;;                      # job limit is 1 minute (S4)
            orphan)  env -u RUNNER_TRACKING_ID nohup sleep 600 >/dev/null 2>&1 & sleep 5 ;;
            cpu)     timeout 90 sh -c 'while :; do :; done' ;;
            memory)  python3 -c 'import time; b=[bytearray(b"\x01")*(64<<20) for _ in range(64)]; time.sleep(30)' ;;
          esac
```

The `orphan` step starts a process without `RUNNER_TRACKING_ID`. At job end
the runner stops only processes that carry that variable, so this one
outlives the job (see Sources).

## 4. Scenarios and what Deprehendo must say

Run each, capture, then `./deprehendo-agent analyze --report <bundle>` and
`./deprehendo-agent timeline --report <bundle>`.

| # | Do this | Expected (Phase 5 gate) |
|---|---|---|
| S1 | runner idle 10 min, no jobs | no incident; no stall label (idle long-poll is healthy) |
| S2 | dispatch `healthy` | job correlated: listener → worker → job tree; no failure claim |
| S3 | dispatch `long`, cancel it from the Actions UI after ~30 s | cancellation recorded; the kill is **not** an unexplained failure |
| S4 | dispatch `timeout` | timeout recorded; not an unexplained hang |
| S5 | dispatch `long`, then on the VM `kill -STOP $(pgrep -f Runner.Worker)`; trigger after 3 min; then `kill -CONT` | `FROZEN_PROCESS` with job context |
| S6 | with the runner idle, `sudo ./svc.sh stop` (if installed as a service) or Ctrl-C `./run.sh` | intended shutdown; **not** `GITHUB_RUNNER_SELF_TERMINATION` |
| S7 | with the runner idle, `kill -9 $(pgrep -f Runner.Listener)` | `GITHUB_RUNNER_SELF_TERMINATION` ("terminated without a stated reason") |
| S8 | dispatch `orphan` | `GITHUB_ORPHANED_JOB_PROCESS` naming the survivor by role and PID, **only if** the survivor is still alive at least 10 s after its worker exited. A process that exits within that window is not a finding. |
| S9 | re-configure with `--ephemeral`, dispatch `healthy` | normal ephemeral exit; **not** runner death |
| S10 | dispatch `long`; on the VM block GitHub traffic for 3 min (`sudo iptables -I OUTPUT -p tcp --dport 443 -j DROP`, then `-D` to undo) | communication drop recorded; with a job running it is supporting evidence, not a second stall label |
| S11 | dispatch `memory` on a VM small enough to OOM | `OOM_KILL` with job context where the kernel record is captured |
| S12 | make the worker unable to run: `cd actions-runner/bin && cp -p Runner.Worker Runner.Worker.real && printf '#!/bin/sh\nexec sleep 600\n' > Runner.Worker && chmod 0755 Runner.Worker`, dispatch `healthy`, and trigger 40 s after the `Running job:` line. Then `mv Runner.Worker.real Runner.Worker` and kill the leftover `sleep`. | `GITHUB_JOB_ASSIGNMENT_STALL` from the assignment alone, no worker in the timeline, `BROKER_SOCKET_STALL` below threshold |

S10 cuts all HTTPS from the VM, so run it last, and only on the disposable
VM. S12 is the one scenario that edits the runner installation; restore the
binary before the next scenario.

## 5. Collect and send back

```sh
scripts/verify-real-runner.sh /path/to/actions-runner ./runner-verification.txt
```

The script never opens `.credentials`, `.credentials_rsaparams` or `.env`;
from `.runner` it prints key names and value types only, and it masks log
text (URLs, quoted text, hex, numbers, job and runner names) before printing.
**Read the report before sharing it.** Send it with the `analyze --report`
output of each scenario. Bundles keep provider identifiers withheld unless
`--provider-identifiers` was used.

## 6. Clean up

Remove the runner from the repository (`./config.sh remove --token <REMOVAL_TOKEN>`,
token from the same settings page), delete the VM, and delete the throwaway
repository.

## 7. Results (VM run)

| # | Result |
|---|---|
| S6 | Passes. `svc.sh stop` logged `GITHUB_RUNNER_SHUTDOWN` at the same second as the listener exit (bundle `inc_c0d4…`). No `GITHUB_RUNNER_SELF_TERMINATION`. The shutdown regex now matches the real S6 phrasing (`Received Ctrl-C signal`, `Runner will be shutdown for UserCancelled`), and the T2 intent window now covers a log record up to 1 s after the exit. |
| S7 | Passes. `kill -9` on the listener produced `GITHUB_RUNNER_SELF_TERMINATION` at MEDIUM. |
| S3 | **Passes on fresh VM run (2026-10-31).** Run `41261769205` (`long`) was cancelled from the Actions UI (`gh run cancel`) about 30 s in. The watch auto-captured bundle `inc_9c0ade…`: `GITHUB_JOB_CANCELLATION_OBSERVED` with `outcome=CANCELLED`, `Job outcome CANCELLED`, and no unexplained-failure signature. |
| S4 | **Analyzer now reports the timeout (2026-10-31); provenance corrected (2026-11-02).** Run `41262653679` (`timeout`, 1-minute limit) ended `cancelled`. The runner log and jobs API both say `cancelled`, so the analyzer could not tell it from a user cancel. Fix: `api.go` reads the job's check-run annotation and marks the job `TIMED_OUT` only when it says "exceeded the maximum execution time"; any lookup failure keeps `CANCELLED`. The capture does not call the API, so the bundle was enriched with `github api-enrich --repo`. The enriched bundle reports `Job outcome TIMED_OUT`. **Provenance fix (2026-11-02):** the stored bundle `s4-enriched` attributes that `TIMED_OUT` to `RUNNER_LOG`, but every runner-log record for the job says `cancelled` and only the check-run annotation names the limit, so the attribution was wrong. `api.go` now credits `PROVIDER_API` and stamps the enrichment time when the annotation upgrades a cancelled outcome (`TestAPITimeLimitAnnotationMarksJobTimedOut` asserts it); the already-enriched bundle keeps the old attribution. No signature names a timeout yet, so the analyzer still reports no finding. Earlier run `41261933019`: Run `41261933019` (`timeout`, 1-minute job limit) was stopped by GitHub: the job annotation reads "exceeded the maximum execution time of 1m0s", and the step ends `cancelled` at 01:39:55Z. Bundle `inc_4807…` records `Job outcome CANCELLED` and `GITHUB_JOB_CANCELLATION_OBSERVED`; no signature matched. The runner logs show no timeout-specific line, so the analyzer cannot tell a limit-driven stop from a user cancel. Open: add a distinct timeout signal (job annotation or runner log wording), then re-check S4. |
| S5 | Passes. Bundle `inc_deac…`: `FROZEN_PROCESS` at HIGH (0.75), WARNING, from a SIGSTOP'd worker. |
| S8 | **Passes on re-run.** Run `41243213130` (`orphan`) reported `GITHUB_ORPHANED_JOB_PROCESS` at HIGH, naming process 295283 (`sleep 600`) as the survivor, about 11 s after the worker exited. Earlier failure: Run 41242311351 (`orphan`) completed successfully and the `sleep 600` survivor (PID 294804) outlived the job by about 38 s, reparented to PID 1, but bundle `inc_3c5ec99d…` reported no orphan. **Cause (recorder, not the detector):** `github watch` records only the listener's process tree, and the tree filter was re-evaluated from scratch every sample. The step's shell exits first, so the survivor was reparented to PID 1 and dropped out of every later sample before the worker even exited; the provider saw it "exit" and could never see it outlive the worker. That is also why `ORPHAN_PROCESS_TREE` saw no reparenting. **Fix:** tree watching now retains a selected process incarnation (PID and start time) while it lives, after reparenting too (`collector.TreeSelection`). `TestS8OrphanSurvivesTheWatchFilter` replays this run's process sequence through the real filter and session; `TestS8StatelessFilterLosesTheOrphan` pins the old failure. **Re-run:** rebuilt `deprehendo-agent` on the VM, restarted `github watch`, killed the leftover survivor, dispatched `orphan`, and triggered a capture after the job. Bundle `inc_d2fb3c11…`. |
| S1 | Passes. The runner sat idle for 10 minutes, then a manual capture (`inc_7939…`) was analyzed. No signature met the 0.55 threshold and no stall label was raised. The only hint was a rejected `BROKER_SOCKET_STALL` at 0.40, which is below the threshold. |
| S9 | Passes. The runner was re-registered with `--ephemeral`. Run `41245132604` (`healthy`) succeeded and the listener exited on its own. Bundle `inc_752023…` records `GITHUB_RUNNER_SHUTDOWN` (intended) and no `GITHUB_RUNNER_SELF_TERMINATION`. The runner was re-registered as non-ephemeral afterwards for S11. |
| S10 | **Passes on VM re-run (2026-10-31).** Attempt 2 (bundle `inc_f566…`) showed the control socket still `ESTABLISHED` with frozen byte counters, queued send data and an armed timer, so the provider's liveness check (open socket = alive) never fired. `observeProgress` now marks such a socket wedged after `reestablishWindow` without byte progress, and a wedged socket no longer counts as a live control channel, so `COMMUNICATION_STALLED` is raised. An idle long-poll with advancing or idle counters still does not qualify. Unit tests: `TestS10WedgedControlSocketIsCommunicationStall`, `TestS10IdleLongPollIsNotCommunicationStall`. Next: repeat the 3-minute block on the VM and confirm the event. The long run was cancelled, so it must run to completion. **Rerun (run `41250838129`, port 443 blocked 23:08:53–23:11:50 UTC): not confirmed.** The manual capture `inc_393c07d62d9b787bab999a226cd8ecc3` shows the control socket closing and reopening around the block, with no `COMMUNICATION_STALLED` and `BROKER_SOCKET_STALL` rejected as a healthy idle socket. The S10 detector still needs a fix or a different signal. **Cause found (2026-10-31, principal): three defects, all fixed, re-run needed.** (1) The capture window dropped the stall: the event is recorded once at onset, and a capture taken after a 3-minute block with a 90 s pre-window starts after the onset, so the bundle could never hold it. An episode still open at the window start now keeps its onset. (2) The wedge rule counted the keepalive timer (2) as stuck, so a healthy idle long-poll could be reported as a stall; only queued send data, the retransmit timer (1) and the zero-window probe (4) count now. (3) An idle pooled HTTPS connection stays ESTABLISHED with nothing queued through an outbound DROP, so it masked the outage; the runner's own "Runner connect error … Retrying until reconnected", unanswered by "Runner reconnected" for 30 s while the listener lives, now opens the episode. Tests: `TestS10*` in `commstall_test.go` (four fail on the previous code). **To re-run:** rebuild and restart `github watch`, dispatch `long`, block 443 for 3 minutes, and capture either during the block or right after; expect `GITHUB_COMMUNICATION_STALLED` in the provider section. With the job running, no `GITHUB_RUNNER_COMMUNICATION_STALL` label is expected (§10A S1). **Confirmed:** run `41257678327` (`long`, port 443 blocked for 3 minutes, then unblocked) and a manual capture `inc_652bdfd4c789640f0ef1ae478d6aa9d4`. The timeline records `GITHUB_COMMUNICATION_STALLED` (DERIVED, `provenance=sample:133`) at 00:40:34Z. The run was not cancelled from the UI as the runbook asks; it ran to its 10-minute sleep and finished `success`, so the cancel path was not exercised here. |
| S11 | **Passes on VM re-run (2026-10-31).** Run `41245537646` (`memory`) on the 3.9 GB VM failed, and the kernel logged `Out of memory: Killed process … (python3)` in the runner's service cgroup. Deprehendo rejected `OOM_KILL` in every bundle captured after the kill (`inc_36bd3af4…`, `inc_aad05a4…`, `inc_7359f76…`, `inc_7e49c6ec…`) with "host and cgroup memory never approached the exhaustion boundary". The `memory.events` read is correct; it is the 1 s default `--interval` that misses the fast allocation. Next: rerun `memory` with `--interval 250ms` and check that the bundle records a rise in `oom_kill` and `OOM_KILL` with job context. **Rerun (run `41251592204`, watch with `--interval 250ms`): not confirmed.** systemd recorded `Result=oom-kill` for the runner service, and the kernel log shows the python3 kill. The bundle `inc_fd4cda17…` shows the memory spike (host 98.4%) and the process departing near its peak, but `OOM_KILL` is rejected because the kernel OOM event is unavailable (`dmesg` is not permitted for the agent), and the bundle records no `oom_kill` counter. The kernel event source needs to be captured. **Cause found (2026-10-31, principal): fixed, re-run needed.** `OOM_KILL@2` never read the `memory.events` counter: it always listed `KERNEL_OOM_EVENT` as missing and capped itself at .50, below the .55 report threshold, so no bundle could report it. `OOM_KILL@3` uses a rise of the `oom_kill` counter in the victim's own cgroup, read within 5 s after the victim was last seen, as kernel evidence (weight .40, cap .85); without it nothing changes. The rise is readable because the listener and worker stay in the service cgroup for a moment after the kill, so keep `--interval 250ms`. The earlier check "the bundle has no `oom_kills`" was a text search of a compressed bundle and proves nothing. Tests: `oom_counter_test.go`. **To re-run:** rebuild, restart the runner service, dispatch `memory` with `github watch --interval 250ms --trigger-on-process-exit`, then `analyze --report` the auto-captured bundle. If `KERNEL_OOM_COUNTER_ROSE` is still absent, systemd removed the service cgroup before any sample read it; tell principal, and the next step is reading the parent cgroup's hierarchical counter. **Confirmed:** run `41257437173` (`memory`, `github watch --interval 250ms --trigger-on-process-exit`) failed in 19 s with the runner's `python3` OOM-killed. The watch auto-captured `inc_8b5bd6f47d3e513949b0e85ec0867b79`, which records `KERNEL_OOM_COUNTER_ROSE`. Before the fix, `OOM_KILL` was rejected because `signatures.go` always set `Rejected` for this rule, even when the counter rose. The fix leaves `Rejected` empty when the rise is present. Re-analysis of that bundle with the rebuilt binary reports `OOM_KILL` at HIGH (0.80), CRITICAL. This is a re-analysis of the auto-captured bundle, not a fresh run on the fixed binary. **Fresh run on the fixed binary (2026-11-01, run `41264326503`, `memory`, `github watch --interval 250ms --trigger-on-process-exit`): run failed; bundle `inc_2b729576…` records `OOM_EVENT` at 02:14:22.861Z, but `OOM_KILL` is rejected ("kernel OOM event and exit cause are unavailable", scored 0.40), and `KERNEL_OOM_COUNTER_ROSE` is absent.** The earlier pass was a re-analysis of an older bundle, so S11 was not confirmed then. **Cause found and fixed (2026-11-02):** a sample reads the process table before the cgroup counters, so the sample that last listed the victim could already carry the kernel's count for its own kill; `kernelOOMRise` took its baseline as "the last reading strictly before the victim's final sample" and started looking only after it, which missed the rise whenever both landed in one sample. The final sample's own reading is now a candidate, and an earlier rise is never attributed. **Passes on a fresh run (2026-11-02).** Run `41520844407` (`memory`, `--interval 250ms --trigger-on-process-exit`) failed in 26 s; bundle `inc_11667cf2…` reports `OOM_KILL` alone at HIGH (0.80), CRITICAL, with `KERNEL_OOM_COUNTER_ROSE oom_kill_delta=1` at 20:37:27.916Z, `HOST_MEMORY_NEAR_LIMIT 98.84`, the victim `pid 212932 rss 81%`, and the job context (`Job outcome FAILED`, source `RUNNER_LOG`). The provider section stayed `AVAILABLE` through the memory episode (see §8 on the supervisor fix). The 2026-11-01 bundle `inc_2b729576…` now reports `OOM_KILL` at HIGH too. Tests: `internal/diagnosis/oom_counter_test.go`. |
| S2 | **Passes on a fresh run (2026-11-02).** Run `41520612730` (`healthy`), auto-captured bundle `inc_9eb4014c…`: the job correlated (`GITHUB_JOB_ACCEPTED`/`ASSIGNED` at 20:35:31Z, `GITHUB_WORKER_STARTED` at 20:35:31.9Z, `GITHUB_JOB_COMPLETED SUCCEEDED` at 20:35:58Z), `Job outcome SUCCEEDED`, and no failure claim: no signature met 0.55, and the only rejection above zero is `BROKER_SOCKET_STALL` at 0.30 (a healthy idle socket). The false `PROCESS_GROUP_TERMINATION` of 2026-11-01 (`inc_4b51cffb…`, three members of pgid 3297 vanishing as the job ended) is fixed. **Cause:** the runner does not give a job its own process group, so the step's shell, the worker and the listener share one PGID; every normal job teardown is therefore "several members of one group vanished". **Fix:** `PROCESS_GROUP_TERMINATION` also requires that no member of that group was observed after the last coordinated departure (`groupMemberSurvived`), and a stated `SUCCEEDED` result covers the worker's tree. Test: `internal/diagnosis/group_subtree_test.go`. The 2026-11-01 bundle now analyzes clean on this tree. |
| S12 | **Passes on a fresh run (2026-11-02).** Run `41528651092`: `bin/Runner.Worker` was replaced with `#!/bin/sh` / `exec sleep 600`, so the job was accepted at 21:28:57Z (log: `Running job: run`, `Send job request message to worker for job 3334874e-…`) and no `Runner.Worker` process ever existed — the spawned child was `sleep 600`. A manual capture with `--capture-pre 90s` (`inc_0131694611b6913623a49dd9513d918c`) reports `GITHUB_JOB_ASSIGNMENT_STALL` at MEDIUM, onset at the assignment instant, from `WORK_ASSIGNED` + `GITHUB_JOB_ASSIGNED` (both `RUNNER_LOG`); the timeline has no worker event; `BROKER_SOCKET_STALL` is rejected at 0.00; the root cause is left `Unknown` rather than naming the socket. `job=` is empty because a job ref is bound to a worker (5.10 allows `UNKNOWN`). The binary was restored (`sha256 72efd98d78473454`) and the leftover `sleep` killed; run `41529045808` then succeeded (`inc_e78d6a46…`: `GITHUB_WORKER_STARTED` at 21:31:05.8Z, `Job outcome SUCCEEDED`, no failure label), so the injection left nothing behind. Note this is a *host-side* stall: the listener could not start the worker. A listener that stops answering the broker is S10, and the two must not be confused. |

## 8. Final re-analysis sweep (2026-11-02) — B3 closed

Every bundle still on either VM (12 on the Linux runner's host, 3 on the older
runner's host) was re-analyzed offline with the agent built from this tree. No
network and no credentials were used; the analysis reads only the bundle.

| Evidence | Result on this tree |
|---|---|
| S2 fresh `inc_9eb4…` (run `41520612730`) | no finding; job `SUCCEEDED` correlated to worker and tree |
| S11 fresh `inc_11667c…` (run `41520844407`) | `OOM_KILL` alone, HIGH 0.80, CRITICAL, `KERNEL_OOM_COUNTER_ROSE`, job `FAILED` |
| S11 2026-11-01 `inc_2b7295…` | `OOM_KILL` HIGH (was rejected before the counter-window fix) |
| S2 2026-11-01 `inc_4b51cf…` | no finding (was the false `PROCESS_GROUP_TERMINATION`) |
| S3 cancels `inc_9c0ade…`, `inc_57ae9b…` | no finding; `CANCELLED` recorded with provable provenance |
| S4 `inc_480764…` (`CANCELLED`), `s4-enriched` (`TIMED_OUT`) | no finding; the timeout suppresses the kill as a failure |
| Failed Go-test job, healthy host `inc_2e2ace…` (run `41358887434`) | no system diagnosis; `Job outcome FAILED` from the runner log. Correct: the failure is the job's own result, not a host fault |
| `inc_5af60b…`, `inc_ace0ee…` (runs `41511306173`, `41518491980`) | section `UNAVAILABLE`, 0 events, both jobs `SUCCEEDED` — the abandoned-session bug below |
| Runner self-update `inc_571d5d…` (2026-11-02 17:44Z) | "No failure anchor in the capture", no signature; timeline shows `GITHUB_RUNNER_UPDATE` → `GITHUB_RUNNER_SHUTDOWN` → listener stop → restart |
| `inc_095054…`, `inc_d95549…`, `inc_bc27a9…` | no finding; healthy or mixed captures |

**What the sweep found and fixed (two defects, one fidelity fix):**

- **One overrun permanently abandoned a live provider session.** On the
  2026-11-01 memory run the session exceeded its 2 s `Observe` deadline once
  under memory pressure, was abandoned, and stayed dead: every later capture
  carried `github-actions UNAVAILABLE` with 0 events (49,578 queued snapshots
  dropped) although the runs succeeded. This is what makes `inc_5af6…` and
  `inc_ace0…` — both successful jobs — report no provider evidence at all.
  **Fix:** `SupervisorConfig.OverrunGrace` (10× the call's own budget, 2 s
  floor). A call that overruns but returns inside the grace only marks the
  section `DEGRADED`; the session continues and later captures stay
  `AVAILABLE`. Tests: `internal/provider/supervisor_test.go`
  (`TestSupervisorSlowCallDegradesOneIncidentAndKeepsTheSession`,
  `TestSupervisorHungCallIsAbandonedAfterTheGrace`).
- **A runner self-update was reported as a process-group kill.** The update
  intent covered only the supervisor, so the untagged job processes that left
  with the runner's tree formed a `PROCESS_GROUP_TERMINATION` failure anchor
  (`inc_571d…`). **Fix:** an intent that ends a runner's whole tree covers the
  worker and job roles (`intentCoversRole`), and the causal graph treats the
  exits of the named process's group as context (`IntentCover.RunnerTree` +
  `Graph.coversGroup`), without silencing an unrelated group in the same
  window. Tests: `cmd/deprehendo-agent/intent_cover_test.go`,
  `internal/causal/intent_test.go`. A second update was not run; this bundle
  plus the tests are the evidence.
- **The report showed jobs from outside the capture** (S3-class fidelity): a
  section carries the runner's job history, so a capture with no job of its own
  displayed the previous day's `FAILED` job under `Job outcome`. The header now
  lists only job records that ran inside the window, oldest first, each naming
  its `ref` (`cmd/deprehendo-agent/provider_report.go`,
  `provider_report_test.go`).

**B3 is closed.** All twelve scenarios have a passing record; S2, S11 and S12
run on the fixed binary, and the earlier rows were re-confirmed where their
bundles still exist. The bundles for S5, S6, S8, S9 and S10 are no longer on either VM
(the incident directory keeps the most recent captures only), so those rows
rest on the 2026-10-31 records above; their code paths are covered by
`TestS8OrphanSurvivesTheWatchFilter`, `TestS10*`, `TestLogReaderReadsCtrlCShutdown`
and `TestSelfTerminationShutdownLogLagIsSilent`.

## 9. Traced re-verification of S2 (2026-11-04)

The S2 run above predates the kernel tracer. Re-running the same workflow
(`selfhosted-e2e`) with `github watch --tracing proc` on the Lima VM produced
the first traced S2 bundle, and one new false claim:

- **Before:** run `41950041166`, bundle `inc_ea3c017a…`: job `SUCCEEDED` and
  correlated, tracer `active` (`proc_connector`, 280 traced exits, 0 lost),
  yet `PROCESS_GROUP_TERMINATION` at HIGH (0.80) / CRITICAL. The group was the
  job's own pgid 1434733 (`JOB_ROOT` 1434733 and `JOB_PROCESS` 1434740), both
  SIGKILLed by the runner as the job ended. Nothing survived in that group,
  and the exits are `signal:9`, so neither `groupMemberSurvived` nor the
  normal-exit rule could dismiss them. Their parent chain reaches the job's
  worker (1434428), whose provider log states `SUCCEEDED`.
- **Fix:** a stated job outcome (cancel, timeout, success) now covers the job's
  observed tree, not only the role-tagged processes the section names
  (`IntentCover.JobTree`; `AnalysisContext.descendsFrom`). A group the job did
  not start still reports in the same window.
- **After:** run `41950705732`, bundle `inc_5fbe670c…`: tracer `active`,
  280 traced exits, analyzer matches `[]` (rejection: "no process group lost
  multiple members at the same time").

The before-bundle is committed as
`testdata/github/selfhosted-e2e-job-success/` and pinned by
`TestRealRunnerSuccessfulJobIsNotAGroupKill`; the rule is also pinned by
`TestGroupKillJobTreeCoverExplainsTheJobsOwnGroup` and
`TestGroupKillJobTreeCoverDoesNotExplainAnUnrelatedGroup`.

## Sources

- [Configuring the self-hosted runner application as a service](https://docs.github.com/de/enterprise-server@3.4/actions/hosting-your-own-runners/managing-self-hosted-runners/configuring-the-self-hosted-runner-application-as-a-service) (`svc.sh`)
- [How to keep processes running after a GitHub Action job ends](https://www.meziantou.net/how-to-keep-processes-running-after-a-github-action-job-ends.htm) (`RUNNER_TRACKING_ID` cleanup)
- [Uninstalling a self-hosted runner](https://notes.kodekloud.com/docs/GitHub-Actions/Self-Hosted-Runner/Uninstalling-Self-Hosted-Runner) (`config.sh remove`)
