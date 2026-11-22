# Phase 7 — secondary secondary review of the principal security gate (7.60)

Date: November 16, 2026. Reviewer: secondary. Reviewed
`docs/reviews/phase7-principal-security-gate.md` and the current code for its gate
items, plus adversarial's H1 follow-up.

## Method and limits

- Static review of `internal/cloudserver/storage.go`, `server.go`, `incidents.go`,
  `complete.go`, `reanalyze.go`, `usage.go`, `retention.go`,
  `internal/cloudclient/client.go`, `internal/cloudserver/browserauth.go`,
  `cmd/runopsy-cloud/main.go`, and `Dockerfile`.
- Checked cited security-gate test names and read the deletion-failure test.
  No tests or deployment checks were run for this review.

## Verdict

**secondary concurs that the upload/read API is suitable for a private beta**, with
the principal gate's deployment prerequisites and open browser-session/dashboard
items still applying. adversarial's H1 is fixed and covered. One scoped privacy issue
remains in operator-run time-based pruning: if object deletion fails, the sweep
has already deleted the database row and cannot retry from the database. This
does not affect the manual incident-delete endpoint, which now keeps its rows
until all object deletes succeed, but it means the retention sweep does not
guarantee erasure after a storage failure.

## principal gate checks

| Item | secondary result | Evidence / note |
|---|---|---|
| G1 storage POST bounds | Confirmed | Body cap wraps `MultipartReader`; policy fields are bounded; the file part is not read before policy verification. |
| G2 owner-only destructive actions | Confirmed | Delete and activate check organization-scoped existence before `requireOwner`; foreign incidents remain 404 and members receive 403. |
| G3 derived-document cleanup | Confirmed, with H1 correction | Keys are collected before deletion. The manual delete removes objects before rows and returns 503 on storage failure. |
| G4 analyzer concurrency | Confirmed | Both per-org and server-wide limits are checked; waiters observe request cancellation. |
| G5 server timeouts | Confirmed | `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes` are configured in `serve`. |
| G6 client error sanitization | Not independently re-audited | The principal report cites existing client tests; this review did not rerun them. |
| G7 non-root container | Confirmed in source | Final Docker stage uses `USER runopsy`; actual image execution was not checked. |
| Usage limits | Confirmed in source | Rolling 60-minute counter and daily parse-seconds check match the recorded decision. Fail-open database behavior and concurrent read/charge are documented residuals. |
| Browser sessions | Still open for product review | API JWT verification and per-request membership lookup exist. Dashboard cookie flags, host headers, CSP, and deployed browser flow still need review when hosted. |
| Dependency and deployment evidence | Not rerun | The principal report's November 11–12 owner runs remain the evidence; this review did not repeat scans, builds, or production checks. |

## adversarial finding H1 — closed

The current `deleteIncident` reads all document keys, deletes each object, and
returns `503` without deleting rows if any storage delete fails. Only after the
objects are gone does it delete the upload row. `TestPhase7DeleteKeepsRecordWhenStorageFails`
asserts the 503, verifies the incident remains readable, then retries and
checks that no object under the organization prefix remains. This addresses
adversarial's H1 for the manual delete path.

## secondary finding L1 — retention sweep can orphan objects

**Status: fixed November 16, 2026.** `PruneUploadsOlderThan` now deletes objects
before the row, treats a missing object as deleted, and stops on the first other
storage error with the row kept for a rerun; `runopsy-cloud prune` prints partial
progress and exits non-zero. `TestPhase7PruneKeepsRowWhenStorageFails` makes the
bundle delete fail, checks the row and analysis survive, then reruns and checks
nothing is left. `docs/cloud/operations.md` describes the new order. The finding
as originally recorded follows.

**Medium (privacy, scoped to operator-run time-based pruning).**
`PruneUploadsOlderThan` collects document keys and deletes the `uploads` row
before deleting the bundle and documents. A storage-delete error is logged and
the sweep continues. The database no longer names the object, so a later sweep
cannot retry it. The order and failure behavior are also described in
`docs/cloud/operations.md`.

This is separate from manual deletion, which is fixed by H1. It does not block
the private-beta upload/read gate if operators treat pruning as best-effort and
do not represent it as guaranteed erasure. Before relying on time-based
retention for privacy guarantees, delete objects before the row (treating
missing objects as success), stop on the first storage error, and add a test
that proves the row remains retryable after a failed object delete.

## Remaining conditions

- Rotate the exposed Railway bucket credentials before storing real data, as
  the principal gate requires.
- Keep the browser-session cookie and deployed-dashboard checks open until the
  host exists.
- ~~Treat the operator retention sweep as best-effort until L1 is fixed.~~ L1 is
  fixed: both manual deletion and the sweep are retryable on storage failure.
- 7.62's real-runner demo and final review remain blocked as recorded by principal.
