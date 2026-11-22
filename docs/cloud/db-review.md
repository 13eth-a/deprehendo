# Database review: migration 0001, backups and retention (checklist 7.56–7.58)

Status: **reviewed and closed, November 6 and November 8, 2026.** The first
pass proposed four corrections; the second re-ran every probe, accepted two
into the migration, rejected one as an incomplete fix, and resolved one by
correcting the contract instead of adding dead schema. It also ran the backup
and restore drill (7.56) that the first pass listed as not done. The third
pass (MiMo slot, November 8) reviewed the new retention migration and sweep
and fixed four defects in them — see "Retention (7.58): the sweep, second
review".

Migration: `db/migrations/0001_init.up.sql`. Tests: `make test-cloud`.

## What was run

On PostgreSQL 16 (`postgres:16-alpine`, Docker, not a managed service):

| Step | Result |
|---|---|
| `0001_init.up.sql` on an empty database | applies; eight tables including `schema_migrations` |
| `0001_init.down.sql`, then up again | removes every domain table (the runner's `schema_migrations` ledger stays, so re-apply is idempotent); up reapplies cleanly |
| four probes on the as-written schema | P1–P4 confirmed; see below |
| corrected schema (P2, P3 applied) | probes pass; path traversal still rejected |
| gated `TestPhase7SchemaRefusesReadyAnalysisWithoutDocument` | passes: the CHECK refuses `document_key = NULL` on a READY row |
| full upload through the live server | analysis and bundle bytes equal the CLI output |
| `pg_dump -Fc` → fresh database → `pg_restore` | 19,076 bytes, no warnings, identical row counts |
| gated suite against the restored database | `TestPhase7ServerPipeline` passes |
| restored database without its objects | list and metadata 200, analysis and bundle 404 |

## Outcome

| Finding | Decision | Where |
|---|---|---|
| P1 uppercase organization IDs rejected | **Rejected as a schema change; fixed in the docs.** The proposed widening is incomplete and would move the failure to the storage POST. | `docs/cloud/upload-api.md` §1, migration comment |
| P2 `READY` analysis may have no document | **Applied**: `CHECK ((status = 'READY') = (document_key IS NOT NULL))` | `0001_init.up.sql` |
| P3 redundant `uploads_by_search` index | **Applied**: dropped | `0001_init.up.sql` |
| P4 no `state` column | **Resolved in the contract**: readiness is read from `analyses.status`; a column nothing writes would be dead state | `docs/cloud/contract.md` §2.1 |

### P1 (was high): why the schema change was wrong

The review's premise was right — the example in upload-api §1 used a ULID-style
`orgs/org_01J…` that the check would reject — but the proposed remedy was not.
The lowercase shape is enforced in four places, not one:

- `uploads.object_key` CHECK (the schema),
- `policyRE` (`internal/cloudserver/storage.go`) for the signed storage POST,
- `safeKey` (same file) for every store path,
- `mintUploadPolicy`, which builds the key from the organization id,

and `clouddb.NewID` deliberately generates lowercase hex with a comment saying
why. Widening only the CHECK would let `POST /api/uploads` insert a row, mint an
uppercase key, and then have the storage POST answer 403 — a row that can never
complete, which is strictly harder to diagnose than today's create-time error.

Resolution: organization ids are lowercase hex by construction, so the
documentation was wrong, not the constraint. The example now reads
`orgs/org_5f1b…` and the `organizations.id` comment no longer says "ulid". If
ULIDs are wanted later, `NewID` and all three regexes must change together in
one commit; changing the schema alone is a regression.

### P2 and P3: applied

A `READY` analysis without `document_key` passes no code path today, but the
schema allowed it and a 404-on-first-open is the kind of failure a constraint
should prevent. The `CHECK` is in `0001_init.up.sql`; `REJECTED` and the
`FAILED_*` statuses keep `document_key NULL` and satisfy it. The gated suite
pins it (`TestPhase7SchemaRefusesReadyAnalysisWithoutDocument`), so the
invariant cannot silently disappear in a later migration edit.

`uploads_by_search (organization_id, incident_id)` is a prefix of
`uploads_by_incident (organization_id, incident_id, uploaded_at DESC)`; the
longer index serves the shorter query. It was removed, with a comment so it is
not re-added.

### P4: resolved by contract, not by a column

`complete` already answers idempotently from `analyses.status`, and no code
reads an upload state. Adding `state TEXT DEFAULT 'PENDING'` would give the
system a column it never updates: the row would say `PENDING` forever, including
after completion. Contract §2.1 now states the implemented rule (pending until
an analysis reaches `READY`, readiness read from `analyses.status`). Cleaning up
stale, never-completed uploads remains an operations task for when a time-based
retention policy exists (§7.58 optional).

## Backup and restore drill (7.56)

The first pass could only list requirements. This pass ran the drill against a
real corpus row: one organization, one token, one upload of
`testdata/incidents/frozen-worker.runopsy`, one READY analysis and one incident
with `FROZEN_PROCESS`. Storage held the two objects a real upload writes:
`orgs/{org}/bundles/{sha256}.runopsy` and `orgs/{org}/documents/{upload}.json`.

| Check | Result |
|---|---|
| `pg_dump -U postgres -Fc` | 19,076 bytes |
| `pg_restore` into a newly created database | exit 0, no warnings |
| Row counts before vs after | identical: orgs 1, memberships 1, tokens 1, uploads 1, analyses 1, incidents 1, usage 1 |
| `runopsy-cloud migrate` on the restored database | `schema is current` (`schema_migrations` survives the dump) |
| Incident metadata on the restored database | `inc_…002 | FROZEN_PROCESS | READY` |
| `TestPhase7ServerPipeline` against the restored DSN | pass (3.2 s) |
| Copy of the object tree, compared by SHA-256 | byte-identical, 2 of 2 files |
| Restored database + copied objects | `/analysis` 200, `/bundle` 200, analysis bytes equal the CLI document |
| **Restored database without the objects** | list 200, metadata 200, `/analysis` 404, `/bundle` 404 |

The last row is the point of the drill: **a database backup is not a backup of
an incident.** The rows survive and still claim `READY`, but the evidence is
gone and the API answers 404. Requirements that follow:

1. **Back up both stores, as a pair.** Postgres (managed point-in-time recovery
   where available, or `pg_dump -Fc`) and the object bucket/directory. With the
   MVP `LocalStore`, the "bucket" is a directory tree: copy it, do not export
   it, and keep the `orgs/` layout.
2. **Restore objects before rows, or accept a 404 window.** The handlers treat a
   missing object as `NOT_FOUND` (bundle/document), not a crash, so out-of-order
   restore degrades rather than corrupts. Restoring rows first still leaves an
   incident page whose evidence 404s.
3. **Verify after restore.** `runopsy-cloud migrate` must print
   `schema is current` (it also refuses to serve if migrations are recorded but
   missing), then run the gated pipeline test and spot-check a bundle download:
   the server re-hashes the stored bytes against the row's digest and refuses to
   serve a mismatch (7.29), so a corrupted copy is caught on read.
4. **Object durability is the provider's guarantee.** The local store makes no
   such promise; S3-compatible storage does, and versioning/object-lock is what
   makes an immutable original recoverable after a mistaken delete. Not
   configured or tested here.
5. **Not tested here:** managed PITR, cross-region copies, backup encryption,
   and restore time at scale. The PITR mechanics were then rehearsed locally
   (base backup + WAL + restore-to-timestamp, objects restored as a pair) and a
   provider runbook was written: `docs/cloud/pitr-drill.md`. **The managed run
   passed on November 19, 2026.** Neon PITR ran on the production root branch,
   with an **RTO of 5 s** from restore start to the restored state served by
   the deployed API. The post-target canary was excluded, analysis and bundle
   stayed byte-identical, and the schema was current. The history window is
   Free, 6 h, which is too short for real use. Cross-region copies, encryption
   and restore time at scale remain untested.

The drill also found a startup defect: `runopsy-cloud serve` accepted a
relative `-analyzer` path and then failed every job, because the analyzer child
runs in a private temporary directory. `serve` now resolves the path to an
absolute one before validating it; the drill's live upload passes with the
relative form.

## Retention (7.58): the sweep, second review (November 8, 2026)

The optional time-based control is now built: migration `0002_retention_index`
adds `uploads(uploaded_at)`, `Server.PruneUploadsOlderThan` deletes by age, and
`runopsy-cloud prune -older-than 90d` is the operator entry point. This pass
reviewed it as the MiMo slot's retention item. Four real defects were found and
fixed; two behaviours are accepted and recorded.

| Requirement | Support |
|---|---|
| delete manually (the minimum) | yes: delete the `uploads` row; `analyses` and `incidents` cascade; the application then deletes the objects. Tested in the 7.36 suite. |
| delete after N days (optional) | yes: `runopsy-cloud prune`. Dry run first, then apply. Gated by `TestPhase7PruneUploadsOlderThan`. |
| stale never-completed uploads | pruned by the same rule, which is the cleanup contract §2.1 deferred here |
| history preserved while the upload exists | yes: `analyses` is append-only and `original_analysis_id` survives until the upload is deleted |

### Findings

| # | Severity | Finding | Decision |
|---|---|---|---|
| R1 | high | The first version deleted with no preview. `-older-than 90h` where `90d` was meant destroys four days of bundles with no way back. | **Fixed:** `PlanPrune` returns the uploads a sweep would delete (id, org, age, bytes), and `prune -dry-run` prints it and deletes nothing. |
| R2 | high | A failed `analyses.document_key` read was logged and the sweep continued, deleting the rows and stranding documents that nothing could find afterwards. | **Fixed:** `documentKeys` returns the error and the sweep stops before deleting that upload. Failing closed beats a silent leak. |
| R3 | medium | The sweep counted a legacy `documents/{upload}.json` key for every upload, inflating the object count and issuing a delete for an object that post-7.34 uploads never wrote. | **Fixed:** the legacy key is used only when no analysis row exists; otherwise the analysis keys are authoritative. |
| R4 | medium | No test. Destructive SQL with a cascade, an object phase and orphan handling was only reviewed by reading. | **Fixed:** `TestPhase7PruneUploadsOlderThan` (gated) covers dry run, cascade, stale pending upload, object removal, newer-upload survival, and `upload_usage` survival. |
| R5 | note | A concurrent re-analysis can insert between the key read and the row delete. | **Accepted.** The cascade refuses the insert and the request answers `UNAVAILABLE`, leaving one orphan document. It fails closed: no row, no incident, no wrong data. |
| R6 | note | `PruneStats.Bytes` counts original bundles only. | **Accepted and documented.** `Store` has no stat call, so document bytes are not invented; documents are counted as objects. |

### Verified

- `0002_retention_index` applies and re-applies through the real runner
  (`prune` calls `clouddb.Apply` before reading), and `make test-cloud` applies
  the whole directory twice.
- `EXPLAIN` with `enable_seqscan=off` on PostgreSQL 16 picks
  `Index Scan using uploads_by_uploaded_at` with
  `Index Cond: (uploaded_at < now() - '90 days')`, so the index serves the
  sweep's `WHERE … ORDER BY uploaded_at` rather than only the column.
- The CLI was run for real against a throwaway Postgres with two aged uploads:
  `-dry-run` listed `uploads=2 objects=4 bundle_bytes=3882` and deleted nothing;
  the apply printed the same counts; an immediate rerun printed
  `uploads=0 objects=0` (idempotent, because deleted rows no longer match).
- `TestPhase7PruneUploadsOlderThan` passes: after the sweep the aged incident's
  `/analysis` is `404`, the newer incident's is `200`, the aged bundle and
  document are gone from the `Store`, the newer ones remain, and the
  organization's `upload_usage` row survives.

## Other points

- **Objects live outside the database.** `ON DELETE CASCADE` removes rows only.
  The delete handler removes objects after the rows, and a failed object delete
  is logged as an orphan (7.28). The drill shows the reverse failure mode
  (objects lost, rows kept) is a 404, so the pair must be restored together.
- **`upload_usage.day` is a `DATE`** with no stated zone. Quotas are per day;
  the boundary should be UTC in code. Not changed here.
- **Search index.** The list query uses `ILIKE` over the metadata columns; at
  MVP scale the planner can scan `incidents`. No new index is needed yet, and
  none was added.
- **Migration workflow (7.57).** Each file applies in one transaction and is
  recorded; a `.down.sql` is required. `make test-cloud` applies migrations
  twice against a throwaway Postgres, and the gated suite runs against the
  result. Down/up was re-run for this review.

## Recommendation

The migration is ready for a managed Postgres with the P2/P3 changes. Before
first real upload: choose the provider, enable PITR (or schedule `pg_dump`),
mirror the object store's durability/versioning, and rehearse the restore in
staging with steps 1–3 above. Rehearse the *pair*; a database-only restore was
measured to produce an incident that lists but cannot be opened.
