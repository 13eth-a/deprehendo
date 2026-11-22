# Tracer permissions (6.20/6.52/6.53)

This page states exactly what each backend needs, how to check it, and what the
agent does when the check fails. The degradation ladder itself is in
[`fallback.md`](fallback.md); the backend decision is contract §2.4.

## Matrix

| Backend | Condition | Needs |
|---|---|---|
| `proc_connector` | Linux 6.18 (observed) | **nothing**: uid 65534 with no capabilities subscribed and received events |
| `proc_connector` | Linux older than the 6.6 relaxation (e.g. Ubuntu 22.04, 5.15) | `CAP_NET_ADMIN` |
| `proc_connector` | any | initial network namespace and initial PID namespace |
| `proc_connector` | receive buffer | `net.core.rmem_max` ≥ 16 MiB **or** `CAP_NET_ADMIN` (the tracer asks for 16 MiB; without the capability the kernel caps it at `rmem_max`, 212992 on stock Ubuntu) |
| `proc_connector` | non-Linux | cannot run: `capabilities.unsupported = true` |
| eBPF (not yet implemented) | Linux ≥ 5.8 with BTF | `CAP_BPF` + `CAP_PERFMON`; `CAP_SYS_RESOURCE` below 5.11 (memlock); `CAP_SYS_ADMIN` on older kernels; refused under confidentiality lockdown |

Both backends report PIDs in the **initial** PID namespace. A tracer inside a
container PID namespace reports `unavailable: PID_NAMESPACE` rather than
translating PIDs by guesswork.

## Checking it without guessing

```sh
# What the binary can actually do on this kernel.
runopsy-trace capabilities

# What the agent will do, given its configured mode, and where the binary is.
runopsy-agent trace status                 # mode default: $RUNOPSY_TRACING, then auto
runopsy-agent trace status --tracing proc

# Does the unprivileged case work here? Run as a normal user, not root.
sudo -u nobody runopsy-trace debug         # then, in another shell: echo hello
```

Expected healthy output on a modern kernel:

```text
backend             proc_connector
kernel              6.18.0-…
process exec        yes
process exit        yes
signals             no
stop/resume         no
oom kill            no
unprivileged        yes
non-Linux (unsupported) no
```

`signals`, `stop/resume` and `oom kill` reading `no` is correct for the
proc-connector backend. It is a capability statement, not a bug, and no
diagnosis may present signal evidence as observed when this line says `no`.

## When it fails

```text
Tracing unavailable: insufficient permission. Continuing in polling mode.
```

- The agent keeps recording (`6.52`): a permission failure is never fatal.
- The bundle's reliability metadata records the state and the reason, so later
  analysis knows signal/exit trace evidence **does not exist** for this
  incident (`6.48`).
- Kernel without the mechanism (5.8 floor for eBPF, non-Linux for the proc
  connector) degrades the same way with its own reason (`6.53`).
- A capability lost **mid-session** is a runtime degradation, not a startup
  failure: the tracer reports it and resubscribes with capped backoff while the
  Go recorder continues.

## Deployment guidance

Grant capabilities to the **tracer binary**, not the agent:

```sh
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/runopsy-trace   # future eBPF backend
# or, for the proc connector on an older kernel:
sudo setcap cap_net_admin+ep /usr/local/bin/runopsy-trace
```

Prefer file capabilities or a systemd unit with `AmbientCapabilities=` over
running the whole agent as root. Raising `net.core.rmem_max` to 16 MiB is a
host-level alternative that needs no capability at all, and is the recommended
fix when a burst of short-lived processes shows a non-zero `events lost`
count in the bundle.
