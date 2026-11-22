# Real-runner demo bundles (7.62)

Traced captures from a self-hosted GitHub runner on a Lima VM, made with
`scripts/demo-capture.sh` on November 21, 2026. The runbook and results are in
`docs/github/real-runner-demo.md`. The dashboard demo manifest
(`testdata/demo/manifest.json`) uses these for its OOM kill and communication
stall scenarios, and `tests/demo_corpus_test.go` checks them.

| Bundle | Fault | Engine verdict | Provider finding |
|---|---|---|---|
| `7.62-oom.runopsy` | A job allocates 4 GiB on a 4 GiB VM; the kernel kills it (exit 137) | `OOM_KILL` HIGH 0.80 | — |
| `7.62-stall.runopsy` | All outbound HTTPS blocked for three minutes on an idle runner | `UNKNOWN` (by design) | `GITHUB_RUNNER_COMMUNICATION_STALL` MEDIUM |

Each bundle has a `.ground-truth.json` with the injected fault, and the
`.analyze.txt` and `.timeline.txt` reports from the capture. Provider
identifiers are withheld (no `--provider-identifiers`), and the files were
checked for IP addresses, paths and names before commit.

The `.document.json` files the capture also writes are not committed: they are
large and the test regenerates them from the bundle.
