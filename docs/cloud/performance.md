# Dashboard payload (7.44)

Status: **measured by integration, November 5, 2026** on the macOS development
machine (darwin/arm64, 8 CPUs, `go1.27.1`). Source of the numbers:
`internal/analysis/scale_test.go`; findings and the open items are in
`docs/reviews/phase7-integration-e2e.md` §5–§6.

Reproduce:

```sh
# 100 and 1,000 events (part of the default suite)
go test -count=1 -run TestDocumentScalePayload -v ./internal/analysis

# adds the 10,000-event row (~7 s of CPU; opt-in so it does not starve the
# suite's wall-clock tests when packages run in parallel)
DEPREHENDO_SCALE_10K=1 go test -count=1 -run TestDocumentScalePayload -v ./internal/analysis
```

The dashboard fetches one document per incident (contract
`docs/cloud/contract.md` §3.3), so the size that matters is the analysis
document, not the bundle. The bundle is compressed; the document is indented
JSON and is two orders of magnitude larger.

## Measured

120 snapshots (two minutes at 1 Hz), synthetic process events spread over the
capture, rendered from re-read bundle bytes — the document the worker would
store. Sizes are stable across runs; the render time is wall clock on a shared
laptop and moved between 6.95 s and 13.2 s for the 10,000-event row.

| Events | Timeline | Series | Bundle | Document | B/event | `analysis.Run` |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 101 | 120 | 4.0 KB | 0.26 MB | 2,552 | 3 ms |
| 1,000 | 1,001 | 120 | 7.3 KB | 1.22 MB | 1,216 | 55 ms |
| 10,000 | 10,001 | 120 | 56 KB | 10.86 MB | 1,086 | 6.95–13.2 s |

## Consequences

1. **Paging is required at 1,000 events, not optional.** `timeline` and
   `series` keep capture order with index equal to position
   (`internal/analysis/analysis.go`, `timelineEvents`/`series`), so a page is a
   slice with no re-sorting: `timeline[i*size:(i+1)*size]`. A page of 200
   events is ~220 KB and 200 rows; the dashboard must not fetch 10,000 events
   to draw a list, which is also what 7.44's "do not render 10,000 DOM nodes"
   asks for.
2. **The whole document is fine for the summary panels.** Diagnosis, causal
   chain, process tree and resource charts are small (the 120 snapshots and the
   graph are not the bulk); fetching the full document once per incident is
   acceptable at these sizes, but the event explorer should ask for pages.
3. **Analysis time is not interactive at 10,000 events.** 6.95 s is inside the
   60 s worker budget of contract §5.3, so a synchronous `complete` still
   works; it is not a path to put behind a spinner that must be under a second.
4. **The bounds in the test are drift alarms, not targets.** The test fails if
   the document exceeds 64 MiB (the upload budget) or 4 KB per timeline event.

## Render cost (the dashboard half)

Measured by `web/test/performance.test.tsx` (`npm test`), Node 22.23.1 on the
same machine. Each row renders the real `TimelineTable` with a real fixture's
events cloned to the target size; element count is taken from the markup and
time from `performance.now()`. This is server-side rendering, not a browser.

| Events | Document (Go) | Full render elements | Full render ms | Page of 200 elements | Page ms |
|---:|---:|---:|---:|---:|---:|
| 100 | 0.26 MB | 812 | 51.6 | 812 | 13.0 |
| 1,000 | 1.22 MB | 8,012 | 240.3 | 1,612 | 17.5 |
| 10,000 | 10.86 MB | 80,012 | 785.0 | 1,612 | 8.6 |

- **The page is the bound, not the payload.** 200 rows cost 1,612 elements at
  1,000 events and the same 1,612 at 10,000; rendering all 10,000 costs 80,012
  elements, about 50× the page. `pageOf` slices by position, so nothing is
  re-sorted or filtered to draw a page.
- **Timing is a laptop measurement, not a budget.** The 785 ms full 10,000-event
  render is the cost 7.44 forbids paying per page; the paged render stays
  under 20 ms at every size. Neither number is a paint or interactive metric.
- The test asserts the structural invariant (page markup never contains a row
  beyond the page, page node count is identical at 1,000 and 10,000) and logs
  the table above on every run.

## Not measured

Browser paint, layout, scrolling, memory retention and any Lighthouse-style
metric. The numbers above are `renderToStaticMarkup` output; they bound the
DOM the server hands over, not how a browser lays it out. The dashboard also
reports 7.44's three payload sizes for the *document* and the *timeline page*,
which is what chooses a page size.
