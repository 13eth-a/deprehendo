# deprehendo web dashboard (Phase 7, adversarial scope)

Status: **route-ready React view layer, not a hosted app.** This directory renders stored
`runopsy.analysis` v1 documents. It does not diagnose: every diagnosis,
confidence, causal link and evidence class comes from the Go analyzer
(`internal/analysis.Run`), and the dashboard only reads and formats them
(checklist 7.43).

## What is here

| Path | Purpose |
| --- | --- |
| `types/analysis.ts` | Wire types for document version 1. Go structs without JSON tags keep their Go field names (`SubjectRef.Kind`, `Snapshot.CaptureIndex`, `RejectedEdge`). |
| `lib/guards.ts` | Rejects unsupported versions and missing sections before any render. |
| `lib/format.ts` | UTC clock times, nanosecond offsets, binary byte sizes, honest "not captured" percentages. |
| `lib/evidence.ts` | Evidence labels and the direct/inferred split. Mirrors Go `Quality.Direct()`. |
| `lib/timeline.ts`, `lib/paging.ts` | Timeline filters and page arithmetic. Order is preserved. |
| `lib/incidents.ts` | Incident list summaries, filters and newest-first sort. |
| `lib/failures.ts` | Fixed copy for the eight failure kinds (checklist 7.32). |
| `lib/processes.ts` | Process tree from stored parent PIDs, and process lifetimes. |
| `lib/series.ts` | CPU series with gaps, trigger marker and SVG paths. |
| `components/*.tsx` | Overview, diagnosis, causal chain, evidence drawer, timeline, process tree, network table, CPU chart, privacy panel, failure state, incident list. |
| `components/LandingPage.tsx` | Minimal product landing and local-first explanation (7.51). |
| `components/DemoIncident.tsx` | Read-only, fixture-backed sample incident presentation (7.54). |
| `styles/dashboard.css` | Keyboard focus, contrast, reduced motion, and narrow-screen layout (7.45). |
| `../docs/cloud/ux-copy.md` | Landing, installation, empty-state, and sample incident copy (7.45, 7.51–7.54). |
| `test/` | Fixture contract, unit tests, render tests, and the 7.44 performance test. |
| `test/render-document.tsx` | Renders one stored document and prints a JSON summary; driven by `tests/phase7_dashboard_render_test.go` (7.61 dashboard leg). Not a test file itself. |

## Running the checks

Requires Node 22.18 or later.

```sh
npm install        # installs react, react-dom, tsx, typescript and @types/*
npm test           # node --import tsx --test test/*.test.ts test/*.test.tsx
npm run typecheck  # tsc -p tsconfig.json
```

## What is verified

- `npm test`: **31 of 31 pass**. The count is 6 fixture-contract tests, 13
  unit tests, 10 render tests and 2 performance tests.
- `npm run typecheck`: **clean**. It was previously unverified because
  `@types/*` could not be installed; those packages are now in
  `devDependencies` and `tsconfig.json` sets `"types": ["node"]` (TypeScript 6
  does not auto-include them).
  - The fixture tests run against the 19 real analysis documents in
    `test/fixtures/analysis/`.
  - A key-shape golden file (`test/fixtures/analysis-keys.golden.json`) fails
    if the Go document changes shape.
  - The render tests use `react-dom/server` `renderToStaticMarkup` with the
    same real fixtures.
- Process tree: a parent cycle (20 and 21 under each other) now terminates.
  `buildProcessTree` refuses any link that would close a loop, so both
  processes still appear, as roots.
- First-run incident list distinguishes a truly empty organization from filters
  with no results, and gives the upload command and sample link.
- The product landing and sample incident are reusable components. The sample
  component requires the host to provide a sanitized fixture and actual routes.

## What is not verified yet

- **No browser run.** The components are checked as static markup only. The
  7.44 numbers measure element count and server-side render time; paint,
  layout, scrolling and browser memory are unmeasured.
- **No live API wiring.** `test/render-document.tsx` renders a document from
  disk; the page shell that fetches `/api/incidents/{id}/analysis` is still the
  host app's job.

## Still open (checklist items)

- **No Next.js app or routes yet.** These components are plain React; routes,
  session auth, live loading, and API wiring still belong to the host app.
- **7.36 and 7.40 need the live API.** Tests against the upload API and the
  authorization matrix require a running cloud service.
- **7.23 GitHub panel.** The provider evidence section
  (`internal/provider/evidence`) has no GitHub fixture yet.
- **Charts beyond CPU.** Memory and I/O charts are not built.
- **7.25 search.** Not built.
- **NO RX highlight (7.21).** Needs per-socket receive counters. The stored
  document does not carry them.
- **Timeline categories (7.18).** Need a category field on the Go side. The
  dashboard does not guess one.
- **Privacy wording (7.27).** Privacy booleans mean "present in the bundle".
  They cannot tell "redacted" from "never collected".
- **Collector per event (evidence drawer).** Events have no `collector` field, so
  the drawer shows "Collector: not recorded in the event".

These components do not yet provide a complete browser application. They have
no live loading/request-error shell; the host app should use `FailureState` and
announce pending requests.

## Findings from building this

- Go nil slices serialize as `null`. `causal.edges` is `null` when a graph has
  no accepted edge. Every consumer must accept both forms.
- `Snapshot.CaptureIndex` is `0` in every v1 bundle. The UI orders samples by
  array position.
- `analyze` has no `--document` flag, so the fixtures were generated with a
  small scratch generator that calls `analysis.Run` and `WriteJSON` directly.
  See `test/fixtures/README.md`.
- Three ground-truth mismatches exist in `testdata/incidents` (oom, cpu-spin,
  socket-stall). The CLI and the analysis document agree with each other on
  all 19 bundles, so both paths produce the same result for these three. The
  mismatch is between that result and the ground-truth files. Not yet
  investigated; it is open for the analyzer owners.
