# Managed PITR drill (7.56)

Status: **managed restore drill PASSED on production, November 19, 2026**
(results in the next section). Neon project `empty-truth-18465894`, root
branch `production`, with the Railway bucket as the object store. Run with
`scripts/neon-restore-drill.sh`. **Open: the project is on the Free plan, whose
6-hour history window is too short for real use. Move to Launch and raise the
window before public use** (see "Provider recommendation").

## Managed drill result (November 19, 2026)

Run with `bash scripts/neon-restore-drill.sh` against production. The script
takes the target from the database clock, uploads a canary after it, asks for
confirmation, restores, and then verifies through the deployed API
(`https://runopsy.up.railway.app`).

| Step | Result |
|---|---|
| history window | Free plan, **6 hours** (plan maximum) |
| target (database clock, UTC) | `2026-11-19T07:10:00Z` |
| incidents before the target | 2 (`frozen-worker`, `disk-full`), analysis and bundle 200 |
| canary after the target | `inc_00000000000000000000000000000003` (`cpu-spin.runopsy`), analysis ready |
| restore | `neon branches restore production ^self@2026-11-19T07:10:00Z --preserve-under-name production_pre_drill_20261119_0710` |
| **RTO** (restore start to the restored state served by the API) | **5 s** |
| incident list after restore | identical to before; canary `404` |
| analysis and bundle after restore | `200`, byte-identical to the pre-drill copies |
| `runopsy-cloud migrate` | `schema is current` |
| object store | The bucket is not part of a Neon restore. The canary's bundle and document were deleted, and the bucket listing then matched the pre-drill listing exactly. |
| backup branch | `production_pre_drill_20261119_0710` (retention: see below) |

What this adds to the local rehearsal: Neon's own PITR, on the real root
branch, with the deployed API. That API reconnected on its own, and no restart
was needed. The restore excluded a commit seconds after the target. The pair
rule held because the bucket is append-only (content-addressed, `If-None-Match`)
and nothing was deleted between the target and the restore, so the pre-target
objects were already in place. Only the canary's objects, which nothing names
after the restore, had to be removed.

Not measured: restore time at a larger data size (two incidents), a target
hours back in the window, or a restore after a mistaken delete. That last case
needs the deleted objects back; with no bucket versioning they are gone (see
"Known gaps").

The runbook's `TestPhase7ServerPipeline` check was not run against
production, because its harness creates throwaway organizations and tokens in
the database it is given. The deployed-API checks above cover the same path:
list, analysis and bundle. To run the test as well, point it at a child branch
of the restored `production` and delete the branch afterwards.

The 7.56 review established that a database backup alone is not a backup of an
incident: restored rows still say `READY` while `/analysis` and `/bundle`
answer 404 when the object store was not restored with them. This document
turns that into a rehearsed procedure: first the PITR mechanics on a throwaway
Postgres, then the same steps against a managed provider.

## Provider recommendation: Neon

From the Gravity Index catalog (Database, quality score 92): serverless
Postgres with point-in-time restore built into the storage layer. Facts below
are from Neon's documentation, not memory:

| Fact | Source |
|---|---|
| Instance restore ("instant restore") is point-in-time recovery on **root branches only**; it overwrites the branch and auto-creates a backup branch `<branch>_old_<timestamp>`. | <https://neon.com/docs/guides/backup-restore> |
| History window: **Free 6 hours** (capped at 1 GB of change history), Launch up to **7 days**, Scale up to **30 days**; paid history is $0.20/GB-month. | <https://neon.com/docs/introduction/history-window> |
| Data can be previewed/queried at the restore point before restoring. | <https://neon.com/docs/guides/backup-restore> |
| Snapshots: 1 manual on Free, 100 on paid; scheduled backups on paid; snapshot storage $0.09/GB-month. | <https://neon.com/docs/guides/backup-restore> |
| Restore interrupts existing connections; connection strings stay the same. | <https://neon.com/faqs/postgres-tools-point-in-time-recovery> |

Why it fits this product: a standard Postgres wire connection, so
`internal/clouddb` keeps `sql.Open("pgx", dsn)` and migrations keep using
`pgx.Connect`; no driver or schema change. The schema in `db/migrations/` uses
no extensions or version-specific syntax.

**The Free plan's 6-hour window is too short for this workload.** An incident
is often investigated the next morning, and a mistaken delete may be noticed
days later. Use Launch (7 days) before public use, and snapshots for longer
retention. That is a cost decision for the owner, recorded here rather than
assumed.

Alternatives in the catalog: Supabase (Postgres plus a PITR add-on and BaaS
extras), Crunchy Bridge and Aiven (managed Postgres with provider-run
backups). They were not evaluated in depth because Neon is the closest fit;
the runbook below is provider-shaped but the acceptance checks are not.

## What the local rehearsal proves

`scripts/pitr-drill.sh` (`make pitr-drill`, needs Docker) runs a real
base-backup + WAL-archive + restore-to-timestamp against a throwaway
PostgreSQL 16, with the object store snapshotted at the same logical time.

Measured run, November 6, 2026:

| Step | Result |
|---|---|
| base backup + WAL archiving | primary started, base backup taken; WAL segments archived at each checkpoint |
| pre-target incident | `inc_…002` uploaded through the live server (analysis/bundle byte-identical) |
| recovery target | `2026-11-06 08:01:56.621888+00`, set right after that upload |
| post-target incident | `inc_…006` uploaded two seconds later |
| restore | recovered to the target and promoted |
| restored database | **1** incident, id `inc_…002`; **0** rows from the post-target upload; `migrate` → `schema is current` |
| restored pair (`/analysis`, `/bundle`) | **200 / 200**, analysis byte-identical to `runopsy-agent analyze --document`, bundle byte-identical to the original |
| post-target incident on the restored pair | **404** |
| result | `PITR-DRILL-OK` |

This proves the mechanics this repository depends on: a recovery target
excludes later commits, the schema still migrates cleanly, and **the object
store must be restored with the database** for the evidence to come back. It
does **not** prove a provider's internal PITR, its actual RPO, restore time at
scale, cross-region copies, or billing.

## Managed runbook (Neon)

Prerequisites: a Neon project on a plan with a suitable history window, its
**direct** connection string (not the pooled one) for migrations, and
credentials for the object store.

1. **Record the window.** Note the project's history window and set it to the
   longest the plan allows (Launch: 7 days) before first real upload. A window
   shorter than the incident's age means the drill is impossible, not slow.
2. **Migrate.** `runopsy-cloud migrate -database "$DIRECT_DSN"` →
   `applied 0001_init`. Use the direct endpoint: migrations run multi-statement
   files through `pgx.Connect`, and the pooled (PgBouncer) endpoint is not the
   right place for that.
3. **Establish a target.** After the last known-good upload, record a UTC
   timestamp from the database (`SELECT clock_timestamp()`) and snapshot the
   object store at the same logical moment (S3 versioning or a copy of the
   `orgs/` prefix). Do both; one without the other is the failure measured in
   `db-review.md`.
4. **Create something that must not survive.** A second upload is the canary:
   after the restore, it must be absent.
5. **Preview, then restore.** Query read-only at the target
   (`SELECT count(*) FROM incidents`), then restore the root branch:
   `neon branches restore main ^self@2026-11-06T08:01:56Z --preserve-under-name main_pre_restore`
   (CLI form from Neon's docs). The pre-restore state is kept as a branch;
   decide whether to delete it after verification.
6. **Restore objects first** (or accept a 404 window), to the prefix state that
   matches the target.
7. **Verify.** Run the acceptance checks below, including a byte comparison of
   one analysis document and one original bundle against the CLI output.
8. **Record RTO** — time from restore start to the first 200 — and the observed
   history window, then update `docs/cloud/db-review.md` with the measured
   numbers.

## Acceptance checks

Results from the November 19 managed run:

- [x] target timestamp recorded in UTC before the change to be undone
- [x] object store snapshot taken at the same logical time (bucket listing; the bucket is append-only)
- [x] restore to the target completes
- [x] the pre-target incidents are present; the post-target incident is absent
- [x] `runopsy-cloud migrate` prints `schema is current`
- [x] `/analysis` and `/bundle` return 200 and byte-identical content
- [ ] `RUNOPSY_CLOUD_TEST_DSN=<restored> go test -run TestPhase7ServerPipeline ./tests` passes. Replaced on production by the deployed-API checks; see above.
- [x] RTO (5 s) and history window (Free, 6 h) recorded
- [ ] backup branch retention decided (keep or delete, and who deletes): owner decision pending

## Known gaps

- **Done: the managed run was performed on November 19, 2026** (results above).
  Repeat it after any change to the database, the bucket or the plan.
- **The bucket has no versioning.** A restore brings back rows for a mistaken
  delete, but not the deleted objects: the incident lists but answers 404. Turn
  on bucket versioning or object lock, if Railway offers it, before relying on
  restore to undo deletes.
- **`.env.local` carries Neon's storage settings** (`AWS_ENDPOINT_URL_S3` and
  keys from `neon deploy`). Any tool that loads it and then talks to the
  Railway bucket must clear those variables first, as the drill script does.
- **Neon PITR is root-branch only.** Production is a root branch, so this is
  fine; a staging branch cannot be point-in-time restored.
- **Neon does not back up object storage.** The pair requirement is unchanged,
  and object-store versioning/object-lock is a separate setting.
- **A restore interrupts connections.** `runopsy-agent upload` already fails
  cleanly on a lost connection (tested); queued uploads retry with a bounded
  backoff, so a short restore window is survivable.
- **Free-plan history is 6 hours / 1 GB.** Do not launch publicly on it.

## Reproduce the local rehearsal

```sh
make build
make pitr-drill          # prints PITR-DRILL-OK and the target timestamp
KEEP=1 ./scripts/pitr-drill.sh   # keep the container and volume for inspection
```
