# Phase 7 — adversarial review of the principal security gate (7.60)

Date: November 16, 2026. Reviewer: adversarial. Reviewed:
`docs/reviews/phase7-principal-security-gate.md` (principal, November 9, 2026), against
the code as it is in the repo today.

## Method

- Read the code each fix names, not the summary of it: `internal/cloudserver/storage.go`,
  `incidents.go`, `reanalyze.go` (the owner check), `server.go` (`acquireJob`),
  `usage.go`, `cmd/runopsy-cloud/main.go` (`serve` timeouts) and `Dockerfile`.
- Checked that each test the gate cites exists by name. I did not run the tests in
  this review; the principal run of November 11 is the evidence for that.

## Verdict

**adversarial concurs with the gate for a private beta**, with one new finding (H1) that
should be fixed before real user data is deleted. The principal fixes G1–G7 match the
code. The browser-session row remains OPEN, as the principal doc says.

## Fix-by-fix check

| Item | Result | Note |
|---|---|---|
| G1 storage POST | **Confirmed** | `MaxBytesReader` wraps the body before `MultipartReader`; fields are capped at 4 KiB and 8 in number; `storeFilePart` refuses the file before a valid policy; parts are not `Close()`d. |
| G2 owner-only delete and activate | **Confirmed** | `requireOwner` runs after the org lookup in `deleteIncident` and `activate`, so a foreign org gets 404 and a member gets 403. Reanalyze stays open to members, as the doc says. |
| G3 delete order | **Confirmed** | `documentKeys` is read before `DELETE FROM uploads`, and a read failure stops the delete. |
| G4 server-wide cap | **Confirmed** | `acquireJob` checks `running < MaxConcurrentTotal` and returns on `ctx.Done()`. |
| G5 HTTP timeouts | **Confirmed** | Read 5 m, write 5 m, idle 2 m, header 64 KiB (`cmd/runopsy-cloud/main.go`). |
| G6 sanitized reply body | Not re-read here | Covered by existing client tests per the doc. |
| G7 non-root container | **Confirmed** | `USER runopsy` in the final stage. Needs a `docker build` to prove it runs. |
| Hourly limit (§5.3) | **Confirmed** | Rolling 60-minute sum over `upload_usage_minutes`; `Retry-After` is the time until the oldest minute ages out. Fails open on a database error, as recorded. |
| Test names cited | **Confirmed** | All eight cited test functions exist in `internal/cloudserver/gate_test.go` and `tests/phase7_*_test.go`. |

## New finding

**H1 (Medium, privacy): a failed storage delete is reported as success and can leave the
bundle behind with no record of it.**
`deleteIncident` deletes the `uploads` row first (correct, per G3). It then deletes the
objects, and a storage failure only increments a counter and writes a log line
(`orphan object …`). The handler then answers `200 {"deleted": true}`. Once the row is
gone, nothing in the database names that key, so the retention sweep cannot find it
either. The user is told the incident is deleted while its original bundle or documents
may remain in the bucket.

The gate's privacy row (7.27) says deletion "now removes every derived document". That
holds only when storage succeeds. The principal doc records the orphan as a logged event
rather than a gap, and that is not enough for a deletion promise.

**Fixed November 16, 2026.** `deleteIncident` now deletes objects before rows; any
storage failure other than `ErrNoSuchObject` returns `503` and keeps the rows for a
retry. `TestPhase7DeleteKeepsRecordWhenStorageFails` covers it, and secondary confirmed
the fix. secondary's L1 found the same pattern in the retention sweep; that is fixed the
same way (`TestPhase7PruneKeepsRowWhenStorageFails`).

## Not verified by this review

- The Railway API still needs the new database password (the password was reset on
  November 15). The next database call will fail until the variable is updated.
- The `pgx` v5 password redaction in connection-string errors (principal's secrets row) was
  not re-checked.
- The browser-session headers and cookies on the deployed dashboard (the last OPEN row).
- 7.62 remains blocked, as the principal doc says.

## Recommendation

Accept the gate for the private beta. H1 is fixed, and secondary's secondary review is
complete (`phase7-secondary-gate-review.md`).
