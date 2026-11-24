# Phase 7 integration: end-to-end QA and demo fixtures

**Role:** integration · **Date:** 2026-11-05
**Scope:** the integration items in the Phase 7 split — 7.41–7.42 (dashboard
fixtures and demo incidents), 7.44 (dashboard performance), 7.61 (the Phase 0→7
end-to-end and the deliberate breakage matrix) and the reviewer half of 7.40.
7.62 (the real-runner demo) and the traced demo bundles are not reachable from
this machine and are recorded in §6, not claimed.

**Follow-up:** 2026-11-06 — added a real short-deadline analyzer-runner case to
the server failure matrix and aligned contract §5.5 with the tested minimal
rejection-status row behavior.

## 1. Verdict

**The pipeline now runs end to end and agrees from the first byte to the last
rendered value.** A checked-in bundle goes through the real `deprehendo-agent`
binary — `login`, `analyze --document`, `upload` — into the reference cloud
*and* into engineering's real `internal/cloudserver` behind Postgres; the document the
real server serves is byte-identical to the laptop's document, and the web
dashboard's own components render exactly that document's diagnosis, incident
and paging. A repeat upload is a no-op. The failure combinations named in the
QA brief fail cleanly: storage read, document write, analyzer reject/limit/
timeout/crash, a database write lost after storage succeeded, and a user who leaves the
organization.

One correctness defect was found and fixed in `complete`: after an analysis
was stored but the incident row failed to write, a retried `complete` answered
200 with a dashboard URL that returned 404. The §5.5 behavior was also
clarified: refused bundles keep a minimal queryable status row, with no
diagnosis or bundle-derived metadata, so the dashboard can explain the failed
upload. No defect was found in the upload client, storage policy, analyzer
isolation or organization scoping.

## 2. What was built

| Item | Artifact | What it proves |
|---|---|---|
| 7.41 | `testdata/demo/manifest.json` | the seven situations the dashboard must be seedable with, each pointing at a checked-in bundle |
| 7.42 | same file, `headline: true` | the five screenshot demos, chosen as OOM kill, communication stall, runner self-termination, orphaned job, frozen worker |
| 7.41/7.42 guard | `tests/demo_corpus_test.go` | every manifest entry reads, renders through `analysis.Run`, and produces exactly the verdict the manifest promises |
| 7.44 payload | `internal/analysis/scale_test.go` | document size and render time at 100 / 1,000 events, 10,000 opt-in |
| 7.44 render | `web/test/performance.test.tsx` | element count and render time for a full timeline vs a 200-row page, at 100 / 1,000 / 10,000 events |
| 7.61 pipeline | `tests/phase7_e2e_test.go` | bundle → CLI document → client → reference cloud → stored original + document, plus dedupe, network loss, invalid bundle, offline |
| 7.61 dashboard | `tests/phase7_dashboard_render_test.go` + `web/test/render-document.tsx` | the CLI's document, rendered by the dashboard components: same headline, band, unknown flag, incident, timeline total and page size |
| 7.61 server failure matrix | `tests/phase7_failures_test.go` | analyzer reject/limit/timeout/crash, storage read failure, document write failure, DB write lost after storage, membership change across every access path |
| 7.61 SQL invariant | `tests/phase7_server_test.go` | the real server's `/analysis` bytes equal `deprehendo-agent analyze --document` |
| 7.40 review | `tests/phase7_upload_corpus_test.go`, `docs/cloud/upload-corpus.md` | §5.5 cases driven through the worker, with the HTTP answer and the resulting dashboard row asserted |

The demo manifest is deliberately not a second corpus: every entry points into
`testdata/incidents/`, the Phase 3 evaluation corpus, so the dashboard and the
accuracy harness can never disagree about what a bundle contains.

### 2.1 What the reference cloud is, and is not

`tests/phase7_e2e_test.go` contains a small HTTP server implementing create
(with dedupe by SHA-256), presigned POST, complete (recompute digest, run
`incident.Read` + `analysis.Run`, store the document) and one read endpoint. It
is a contract fixture, not engineering's server: its value is that it exercises
`internal/cloudclient` and `cmd/deprehendo-agent cloud.go` without changing
either. The real server is exercised separately by the gated suite, so the
client contract and the deployed behavior are both covered.

## 3. The end-to-end run

Host: the macOS development machine (darwin/arm64, 8 CPUs, `go1.27.1`,
Node 22.23.1). The CLIs are built by the `tests` package's `TestMain` and
driven as subprocesses; nothing about the cloud is mocked inside the CLI.

| Step | Result |
|---|---|
| `deprehendo-agent login -endpoint … -token-file …` | exit 0, credential file `0600` |
| `deprehendo-agent analyze --document local.json frozen-worker.deprehendo` | exit 0, document rendered locally |
| `deprehendo-agent upload -config … frozen-worker.deprehendo` | `Uploading incident inc_…`, `Validated`, `Uploaded` |
| cloud stores the original | bytes equal the file's, digest equal to its SHA-256 (L4) |
| reference cloud stores the document | **byte-identical** to `local.json` (L2, 7.43) |
| real server `/api/incidents/{id}/analysis` | **byte-identical** to `local.json` (7.43, 7.61) |
| dashboard components on that document | same headline, band, incident, 1,001 timeline events, 200-row page (7.61 last leg) |
| second upload of the same bytes | `Already uploaded`; analysis count stays 1 (7.30) |
| storage connection dropped mid-upload | exit 1, `cloud: storage upload: …`; no analysis, no queue file, bundle digest unchanged (L3) |
| truncated bundle (100 bytes) | exit 1, `not a valid bundle`; the server never saw it |
| cloud unreachable (`127.0.0.1:1`) | upload exits 1 without a panic; `analyze --document` still works (L1) |

No token appeared in any output, and the token never reached the storage
endpoint. The server-side matrix runs in `make test-cloud` against a throwaway
Postgres 16 (`ok deprehendo/tests 9.5s` for the gated set, `8.4s` for `make
test-cloud` end to end).

## 4. Findings

### 4.1 A refused bundle keeps a minimal dashboard status row

`complete` records the `analyses` row and the `incidents` view row before it
maps a non-READY status to an HTTP error, so a hostile or broken upload leaves
one organization-scoped row with `analysis_status` `REJECTED` /
`FAILED_LIMIT` / `FAILED_CRASH`, no signature, and `/analysis` answering 202.
Contract §5.5 now specifies the implemented behavior: a minimal organization-
scoped status row, without a diagnosis document or bundle-derived metadata.
This lets the dashboard explain a failed upload (7.31/7.32) without treating
rejected bundle content as trusted incident metadata. Details in
`docs/cloud/upload-corpus.md` §Findings.

### 4.2 Fixed: a retried complete could answer with a URL that 404s

If the analysis row and its document are stored but the incident insert fails
(a transient database error), the upload was left READY with no view row. The
idempotent branch of `complete` answered 200 with the dashboard URL without
looking, so the user was sent to a 404 and the incident never appeared in any
list. `complete` now repairs the view from the already-stored document before
answering (`ensureIncidentRow`). Verified negatively: with the repair removed,
`TestPhase7CompleteRepairsAMissingIncidentRow` fails on the 404; with it
restored, the test passes. No re-analysis and no clock are involved, so the
repair cannot rewrite history.

### 4.3 Four of the seven demo scenarios diagnose, three abstain — honestly

`tests/demo_corpus_test.go` pins each scenario's verdict to the engine's:

| Scenario | Injected fault | Engine verdict |
|---|---|---|
| OOM kill | `OOM_KILL` | **`UNKNOWN`** |
| Frozen worker | `FROZEN_PROCESS` | `FROZEN_PROCESS` |
| Broker / communication stall | `BROKER_SOCKET_STALL` | **`UNKNOWN`** |
| Network path failure | `NETWORK_PATH_FAILURE` | `NETWORK_PATH_FAILURE` |
| Orphaned job | `ORPHAN_PROCESS_TREE` | `ORPHAN_PROCESS_TREE` |
| Runner self-termination | `PROCESS_GROUP_TERMINATION` | `PROCESS_GROUP_TERMINATION` |
| Healthy cancellation | none | **`UNKNOWN`** (correct) |

This is the known v1 abstention: the synthetic corpus has no kernel OOM record
and no socket RX counters, which `testdata/incidents/README.md` records. The
consequence the dashboard cannot avoid: **two of 7.42's five headline
screenshots (OOM kill and communication stall) currently demonstrate
abstention, not diagnosis.** Showing them with a confident diagnosis would
require inventing evidence.

The fix is a new demo set, not a new rule: capture those two incidents with the
Phase 6 tracer present (`oom:mark_victim` for the OOM, socket progress for the
stall) and re-point the manifest. That needs a Linux host with
`CAP_BPF`/`CAP_PERFMON` — the Lima VM — and remains open (§6).

### 4.4 There is no healthy-cancellation fixture

7.41 asks for "healthy cancellation". The nearest baseline is
`healthy-parent-exit`, a watched parent that exits by design while its child
finishes and exits before capture end. A real cancellation fixture is a corpus
addition in `internal/diagnosis/corpus_test.go`; that file is another owner's,
and adding a case changes the published 19-case baseline, so it stays a
follow-up.

## 5. Performance (7.44), measured

### 5.1 The stored document (Go)

120 snapshots (two minutes at 1 Hz), synthetic events, rendered from re-read
bundle bytes:

| Events | Timeline | Series | Bundle | Document | B/event | `analysis.Run` |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 101 | 120 | 4.0 KB | 0.26 MB | 2,552 | 3 ms |
| 1,000 | 1,001 | 120 | 7.3 KB | 1.22 MB | 1,216 | 55 ms |
| 10,000 | 10,001 | 120 | 56 KB | 10.86 MB | 1,086 | 6.95–13.2 s |

The 10,000-event case is opt-in (`DEPREHENDO_SCALE_10K=1`): it spends about seven
seconds of CPU and starves the suite's wall-clock tests when packages run in
parallel. That is a measurement, not a regression guard; CI runs the cheap
sizes.

### 5.2 The rendered page (web)

`web/test/performance.test.tsx`, `renderToStaticMarkup` of the real
`TimelineTable`:

| Events | Full render elements | Full ms | Page of 200 elements | Page ms |
|---:|---:|---:|---:|---:|
| 100 | 812 | 51.6 | 812 | 13.0 |
| 1,000 | 8,012 | 240.3 | 1,612 | 17.5 |
| 10,000 | 80,012 | 785.0 | 1,612 | 8.6 |

Page cost is constant at 1,612 elements once the payload exceeds one page, and
a full 10,000-event render is ~50× that. Paging is therefore a requirement,
not polish, and `pageOf` slices by position with no re-sorting. These are
server-side render numbers; paint, layout and browser memory are still
unmeasured and are not claimed.

## 6. Remaining work, and who it waits on

| Item | State | Waits on |
|---|---|---|
| 7.62 real-runner demo | **not attempted**: no GitHub runner in this environment | a real disposable runner |
| 7.42 traced demos | manifest points at synthetic Phase 3 bundles; two headline demos abstain | a traced capture on the Lima VM |
| healthy cancellation fixture | nearest baseline mapped | the corpus owner (`internal/diagnosis`) |
| browser paint metrics | DOM count and SSR time measured; paint/layout/memory not | a browser harness |
| §5.5 rows 2, 13, 15 | not driven through the worker; reasons in `docs/cloud/upload-corpus.md` | §7.2 decoders / an opt-in heavy run |
| 7.50 notifications | optional, deferred by the roadmap | Phase 9 |

## 7. Verification

Run on 2026-11-05 in this tree, with a follow-up cloud-suite run on 2026-11-06:

- `make test-cloud` — pass: migrations applied twice, then `ok deprehendo/tests`
  (9.5 s for `-run TestPhase7`, including the corpus, the failure matrix and
  the local/cloud byte equality).
- Follow-up `make test-cloud` on 2026-11-06 — pass with the real analyzer
  timeout subcase enabled in `TestPhase7AnalyzerOutcomesKeepAQueryableRow`.
- `go test -count=1 -run 'TestPhase7' -v ./tests` — every case above PASS;
  subtests listed so no case is silently skipped.
- Negative check: with `ensureIncidentRow` removed,
  `TestPhase7CompleteRepairsAMissingIncidentRow` fails; restored, it passes.
- `go test -count=1 -run TestPhase7DashboardRendersTheCLIDocument ./tests` — pass.
- `go test -count=1 -run TestDocumentScalePayload -v ./internal/analysis` — pass
  (100 and 1,000 events).
- `go test -count=1 -run TestDemoCorpusMatchesTheEngine -v ./tests` — pass, all
  seven scenarios.
- `cd web && npm test` — **31 of 31 pass** (6 fixture-contract, 13 unit, 10
  render, 2 performance).
- `cd web && npm run typecheck` — **clean** after adding `@types/node`,
  `@types/react` and `@types/react-dom` and `"types": ["node"]`; the earlier
  "typecheck unverified" caveat is closed.
- `gofmt -l .` clean, `go vet ./...` clean, `go build ./...` clean.

The reference cloud is a test double, so "the upload works" there means "the
contract is implementable and the client honours it". The real-server claims
come from the gated Postgres suite, not the double. No Vercel, S3 or GitHub
runner was involved.
