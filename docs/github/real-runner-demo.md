# Real-runner demo (7.62)

Status: **done (November 21, 2026).** Both captures ran and pass the hosted
check. Results are in [Results](#results); the bundles are in
`testdata/github/real-runner-demo/`.

7.62 closes Phase 7's last item: the product working end to end on a real
GitHub runner, and the two headline demos that abstain on synthetic fixtures
(7.42: OOM kill, communication stall) re-captured on real hardware with the
tracer on. The Phase 5 runbook ([real-runner-verification.md](real-runner-verification.md))
proved the detectors on a VM. This one proves the whole path: a real runner,
a traced capture, an upload to the deployed API, and the hosted dashboard.

| Demo | What the real capture should show | Why |
|---|---|---|
| OOM kill | diagnosis `OOM_KILL` | The kernel's OOM counter in the job's cgroup, plus the tracer's OOM record, are the discriminator the synthetic bundle lacks (Phase 5 S11 reached `OOM_KILL` HIGH this way). |
| Communication stall, idle runner | diagnosis `UNKNOWN`, with provider signature `GITHUB_RUNNER_COMMUNICATION_STALL` in the document's `providers` section | The generic `BROKER_SOCKET_STALL` is rejected by design (bundles carry no socket byte counters). The GitHub provider's stall label is the real finding. It is in the analysis document, but the dashboard has no provider panel yet, so the page shows the honest abstention (decided November 20). |

**Use a disposable VM and a throwaway repository only.** The stall capture
cuts all outbound HTTPS from the VM for three minutes. The script always
restores it, including on Ctrl-C.

## 1. Throwaway repository

Reuse the disposable repository from 5.42, `13eth-a/deprehendo-runner-e2e`.
Its `deprehendo-b3` workflow ([real-runner-verification.md](real-runner-verification.md),
step 2) has the `memory` scenario and runs on `[self-hosted, deprehendo-b3]`.
Its old runner was deregistered after Phase 5, so step 4 registers a new one
with the same label. `memory` allocates 4 GiB, more than the VM below has, so
the kernel OOM-kills it.

## 2. The VM (on the Mac)

```sh
brew install lima
limactl start --name deprehendo-demo --cpus 2 --memory 4 --disk 30 template:ubuntu-24.04
limactl shell deprehendo-demo
```

On older Lima versions, use `template://ubuntu-24.04`. Lima mounts your home
folder read-only inside the VM at the same path, so the repository is at
`/Users/<you>/Documents/deprehendo`. The build writes into the VM's own home
folder.

## 3. Build the agent and the tracer (in the VM)

```sh
cd ~   # limactl shell starts in the read-only repo mount; download here instead
sudo apt-get update && sudo apt-get install -y build-essential clang libbpf-dev pkg-config python3 curl
curl -LO https://go.dev/dl/go1.27.4.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.27.4.linux-arm64.tar.gz && export PATH=/usr/local/go/bin:$PATH
curl -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env"

cd /Users/$USER/Documents/deprehendo   # Lima keeps your Mac user name; adjust if not
mkdir -p ~/deprehendo-bin
GOFLAGS=-buildvcs=false go build -o ~/deprehendo-bin/deprehendo-agent ./cmd/deprehendo-agent
GOFLAGS=-buildvcs=false go build -o ~/deprehendo-bin/deprehendo-analyzer ./cmd/deprehendo-analyzer
cargo build --release --locked --manifest-path trace-rs/Cargo.toml --target-dir ~/trace-target
install -m 0755 ~/trace-target/release/deprehendo-trace ~/deprehendo-bin/
```

`-buildvcs=false` is needed because the repository is on a read-only mount
owned by your Mac user. `deprehendo-agent` finds `deprehendo-trace` next to itself.

## 4. Register the runner (in the VM, as your normal user, not root)

On GitHub, open `13eth-a/deprehendo-runner-e2e` and go to **Settings → Actions →
Runners → New self-hosted runner**, and choose **Linux** and **ARM64**. Run the
download commands it shows in `~/actions-runner`, then configure the runner
with the label the workflow uses:

```sh
./config.sh --url https://github.com/13eth-a/deprehendo-runner-e2e --token <REGISTRATION_TOKEN> --labels deprehendo-b3 --name deprehendo-demo-vm
./run.sh
```

Leave `./run.sh` running in this shell. Open a second shell for the captures
(`limactl shell deprehendo-demo`).

## 5. Capture the two demos (in the VM, second shell)

```sh
cd /Users/$USER/Documents/deprehendo
sudo bash scripts/demo-capture.sh oom
```

When the script says so, dispatch **deprehendo-b3** with scenario **memory** on
the repository's Actions tab, or from the Mac with
`gh workflow run deprehendo-b3 -R 13eth-a/deprehendo-runner-e2e -f scenario=memory`. The script ignores captures of healthy exits and
stops at the first capture whose diagnosis is `OOM_KILL`. It ends with `PASS`.

Then, with no job running:

```sh
sudo bash scripts/demo-capture.sh stall
```

This takes about six minutes: a 90-second idle baseline, 3 minutes with HTTPS
blocked, the capture, then HTTPS restored. It ends with `PASS` when the bundle
carries `GITHUB_RUNNER_COMMUNICATION_STALL`.

Both runs print the tracer's status from the report. It should say active (eBPF
or the proc connector), not disabled or unavailable. Results go to
`~/demo-out`: each bundle, its `analyze --report` and `timeline --report`
output, and its analysis document.

## 6. Bring the results to the Mac

On the Mac:

```sh
limactl shell deprehendo-demo -- sh -c 'tar -C "$HOME" -cf - demo-out' | tar -C ~ -xf -
ls ~/demo-out
```

## 7. The hosted check (on the Mac)

Build from the commit Railway is running, so both engines are the same:

```sh
cd ~/Documents/deprehendo && git pull && make build
bash scripts/demo-verify-hosted.sh ~/demo-out/7.62-oom.deprehendo ~/demo-out/7.62-stall.deprehendo
```

The script uploads each bundle with your normal login and requires the hosted
`/analysis` to be byte-identical to the local document. It then prints a
dashboard link for each. Open both links while signed in. The OOM page should
show `OOM_KILL`. The stall page should show the abstention, with the outage in
the timeline.

## 8. Send back

Paste the two scripts' final lines and the dashboard results. **Read
`~/demo-out/*.analyze.txt` before sharing them.** Bundles withhold
provider identifiers by default (no `--provider-identifiers`). The bundles
then go into `testdata/github/real-runner-demo/`, and the demo manifest
(`testdata/demo/manifest.json`) is re-pointed at them.

## 9. Clean up (after the bundles are committed)

In the VM, remove the runner with `./config.sh remove --token <REMOVAL_TOKEN>`
(the token is on the same settings page). Then `limactl delete -f deprehendo-demo`
on the Mac. Delete `13eth-a/deprehendo-runner-e2e` once nothing else needs it;
deleting it with `gh` needs the `delete_repo` scope
(`gh auth refresh -h github.com -s delete_repo`).

## Results

Captured November 21, 2026 on a Lima Ubuntu 24.04 VM (2 CPUs, 4 GiB), runner
label `deprehendo-b3`, repository `13eth-a/deprehendo-runner-e2e`.

| Demo | Local verdict | Hosted check | Dashboard |
|---|---|---|---|
| OOM kill (`7.62-oom.deprehendo`) | `OOM_KILL` HIGH 0.80. Evidence: the job cgroup's `oom_kill` counter rose by 1, host memory peaked at 96.8%, and the killed process held 83% of resident memory. The job failed with exit 137. | PASS, byte-identical | Shows `OOM_KILL` with the causal chain and memory chart |
| Communication stall (`7.62-stall.deprehendo`) | `UNKNOWN` (every generic signature rejected, `BROKER_SOCKET_STALL` by design). The GitHub provider reports `GITHUB_RUNNER_COMMUNICATION_STALL` MEDIUM, onset 07:19:19Z. | PASS, byte-identical | Shows the honest abstention |

Found and fixed on the way:

- The hosted analyzer (`cmd/deprehendo-analyzer`) never registered the GitHub
  provider, so the hosted document had an empty provider section and differed
  from local. It now registers it like the agent does. Test:
  `TestPhase7HostedAnalyzerInterpretsGitHub`. Incidents uploaded before the fix
  need `demo-verify-hosted.sh --replace`, because "Already uploaded" keeps the
  old analysis.
- The capture script needed a 0700 incident folder and a watcher stop that
  escalates from INT to TERM to KILL.

Follow-ups, not gating:

- The tracer ran on the proc-connector fallback, not eBPF. The OOM verdict
  came from the cgroup counter, so it did not need the tracer's OOM record.
- The dashboard has no provider panel, so the stall finding is in the
  document but not on the page.
- The incident list's Confidence column shows "—" for these incidents.
