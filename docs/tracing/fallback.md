# Tracing permissions and fallback (6.20/6.52/6.53)

## What the tracer needs, accurately

| backend        | platform    | privilege needed |
|----------------|-------------|------------------|
| proc_connector | Linux       | none on 6.18 (verified with uid 65534, no capabilities); `CAP_NET_ADMIN` on older kernels (Ubuntu 22.04's 5.15 included). Overrun-free bursts need `CAP_NET_ADMIN` or `net.core.rmem_max` ≥ 16 MiB (contract §2.4) |
| proc_connector | non-Linux   | cannot run at all (`capabilities.unsupported = true`) |
| eBPF           | Linux ≥ 5.15 | `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`); grant them to the tracer binary only, never to the agent (contract §2.4). Verified live on kernel 6.18 with these caps |

Phase 6 ships both backends: eBPF primary, proc connector fallback
(`backend::select_backend()`, per-step reasons in each capability's
`*_reason` field). The capability report is honest: a build that cannot
observe something advertises `false`, never a hopeful default (6.14/6.16).

## Degradation ladder, in order of preference

1. **Tracer runs, all claimed capabilities up.** Normal Phase 6 behavior;
   trace events merge with the polling stream, evidence quality benefits
   apply.
2. **Tracer runs, partial capabilities.** Example: subscription fails at
   runtime (group vanished, kernel invalidated the socket). The tracer keeps
   serving, reports degraded status in stderr and on the next handshake, and
   resubscribes with capped backoff. The agent treats the affected event
   classes as unavailable — evidence gaps are losses, not absences (6.27).
3. **Tracer exits / crashed / socket closed.** Agent survives (it must), logs
   the tracer state, downgrades to polling-only, and follows the restart
   policy in `docs/tracing/protocol.md` § Lifecycle: bounded restarts with
   exponential backoff, never a hot loop.
4. **Tracer cannot start at all** (unsupported platform, missing binary,
   refused handshake version). Agent continues in polling-only mode and says
   so plainly:

   ```text
   Tracing unavailable: <reason>. Continuing in polling mode.
   ```

   Never a fatal error (6.52/6.53).

## How the agent is supposed to reason about missing trace evidence

The Phase 3 UNKNOWN discipline applies:

- No trace events for a PID is not evidence of absence; combined with
  `tracing unavailable` it means **that signal/exit evidence does not exist**
  for the incident, and diagnosis confidence must reflect that.
- A received sequence gap is an explicit partial-loss marker: the signals-era
  conclusions drawn from that stream segment are "incomplete evidence", and
  the bundle records the drop count (6.48 reliability metadata).

## Testing the ladder (6.52/6.53 acceptance)

| scenario                          | expected |
|-----------------------------------|----------|
| no tracer binary                  | polling-only mode, no crash |
| unsupported platform (macOS)      | `capabilities.unsupported=true`, polling-only |
| tracer started without privileges | subscribe fails → degraded status, not exit; real kernel EPERM verified (`TestFallbackOnRealPermissionRefusal`) |
| tracer killed mid-session         | agent logs, degrades, restarts with backoff |
| version mismatch at handshake     | session rejected, tracer exits cleanly |
| malformed frame                   | session ends, tracer process stays healthy |

### Reproducing a real permission refusal (H9)

On kernels that accept an unprivileged connector subscribe (7.0 verified), a
non-initial network namespace answers ECONNREFUSED rather than EPERM, so the
connector's own capability check cannot be the source of EPERM there. Two
real kernel refusals are still reachable, and the suite exercises both:

- `unshare -U --map-root-user deprehendo-trace capabilities`: `bpf()` returns
  EPERM (`bpf_object__load: Operation not permitted`), the tracer names it in
  `selection_reason`, and the connector fallback serves the session.
- `TestFallbackOnRealPermissionRefusal` (Linux-only) runs the unmodified
  tracer under a seccomp filter that returns EPERM for `bpf()` and
  `socket(AF_NETLINK)` — the policy a hardened host or container runtime
  applies. Both backends are refused with the kernel's EPERM, the tracer
  classifies it as `insufficient permission: ...`, and the manager degrades
  once to `unavailable` with "continuing in polling mode" and no restarts.
  The filter needs no privilege, so the test runs in CI.
