# Cloud operations: migrations, backup, retention, telemetry (7.55–7.58)

Audience: whoever deploys Deprehendo Cloud. Everything here is the MVP-sized
answer: no backup infrastructure of our own, no retention daemon, no metrics
server.

## Migrations (7.57)

`db/migrations/NNNN_name.up.sql` / `.down.sql`, applied by the real binary:

```bash
deprehendo-cloud migrate -database "$DSN"          # apply everything pending
deprehendo-cloud migrate -database "$DSN" -down    # roll back every applied file
```

Rules the runner enforces (`internal/clouddb`):

- applied in filename order, each file in **one transaction**; a failed file is
  never recorded, so a retry re-runs only what did not land;
- applied names are recorded in `schema_migrations` with a checksum; re-running
  is a no-op that prints `schema is current`;
- every `.up.sql` must have a matching `.down.sql` (the runner refuses an
  unpaired up file) — deletion is scoped to Phase 7's own tables;
- `serve` applies pending migrations before listening and **refuses to start**
  if the database records a migration file that is missing from the directory
  (`clouddb.AppliedButMissing`). A schema the code does not match must not
  half-serve.

Migrations are tested, not hand-checked: `make test-cloud` applies them twice
against a throwaway Postgres and then runs the gated suite; the `cloud` CI job
does the same against a `postgres:16-alpine` service.

Adding a migration: create both files, run `make test-cloud`, and if it changes
what the document means, follow contract §7.2 (bump `SchemaVersion`/
`FormatVersion`/policy) in the same change.

## Backup (7.56)

Two stores, two answers:

- **Postgres** holds metadata, tokens (hashes only), analyses and usage
  counters. Use the managed provider's automated backups and point-in-time
  recovery. Nothing here is derivable from the bundles alone, and nothing here
  is large: one incident is one `uploads` row, one `analyses` row, one
  `incidents` row.
- **Object storage** holds the immutable originals and the derived documents.
  Use the provider's durability/versioning; an original is written once under
  `orgs/{org}/bundles/{sha256}.deprehendo` and the store refuses a second write to
  the same key, which is what makes "the original never changes" true.

An inconsistency between them is recoverable in one direction only: a bundle
with no metadata row is invisible (and, with the local store, still on disk);
metadata whose object is missing answers `404`/`500` on the artifact endpoints
and can be deleted. There is no re-derivation of an original from a document.

`LocalStore` (the MVP default, `-storage-root`) is a plain directory with the
same key layout. It is a single-host answer: back it up like any directory, and
do not share it between two `serve` processes.

## Retention (7.58)

Manual deletion is the minimum retention control, and it is real: `DELETE
/api/incidents/{id}` removes every object for that upload — the bundle plus
each engine's document (the legacy per-upload key included) — before removing
the rows. If storage fails, it returns 503 and keeps the rows so deletion can
be retried. The time-based sweep is the operator-run complement (no daemon):

```bash
deprehendo-cloud prune -database "$DSN" -older-than 90d -dry-run   # preview
deprehendo-cloud prune -database "$DSN" -older-than 90d [-limit 1000]
```

The dry run lists each upload it would delete (id, organization, timestamp,
bundle bytes) and touches nothing; run it first every time, because
`-older-than 90h` instead of `90d` is a four-day mistake with no undo. The
apply deletes uploads with `uploaded_at` older than the age, oldest first, up
to the limit. For each upload it deletes the objects first (an object already
gone counts as deleted), then the row (the cascade removes `analyses` and
`incidents`), the same order as manual delete. If a storage delete fails, or
an upload's analysis documents cannot be read, the sweep stops with that
upload's row intact, prints what it finished, and exits non-zero
(`prune stopped: …`). Rerun it once storage is healthy: the kept row still
names every object, so nothing is left behind. Stale never-completed
uploads prune by the same rule, which closes the PENDING-without-state cleanup
contract §2.1 names. `bundle_bytes` in the output counts originals only;
documents have no stat call, so they are counted as objects.

Migration `0002` adds `uploads(uploaded_at)` for the sweep (`EXPLAIN` picks it
for `WHERE uploaded_at < $1 ORDER BY uploaded_at`); the per-incident
`created_at` indexes from 7.6 stay as they are. Deleting by hand remains the
minimum and is always available: `DELETE /api/incidents/{id}`.

On the agent side the equivalent control already exists and is separate from the
cloud: `start --max-incidents N --max-incident-age DUR` prunes local bundles
(`incident.Prune`). Deleting a local bundle never deletes the cloud copy and
vice versa; the upload queue records the path and marks an entry failed once the
file is gone rather than uploading something else.

## Telemetry (7.55)

One log line per `-stats-interval` (default 60s; `0` disables):

```text
telemetry uptime_s=3600.0 uploads_created=12 uploads_duplicate=3 uploads_completed=11
analysis_runs=11 parse_failures=1 analysis_seconds_total=1.284 analysis_seconds_max=0.412
api_errors_client=7 api_errors_server=0 storage_failures=0
```

| counter | what it tells an operator |
|---|---|
| `uploads_created` | accepted create calls; the demand signal |
| `uploads_duplicate` | repeat uploads of the same bytes (7.30) — expected from the CLI's retry-free "already uploaded" path |
| `uploads_completed` | uploads that produced a READY incident |
| `analysis_runs` / `analysis_seconds_total` / `analysis_seconds_max` | parser compute and the worst single bundle against the 60 s job budget |
| `parse_failures` | REJECTED + FAILED_*: hostile or incompatible bundles, not user typos |
| `api_errors_client` / `api_errors_server` | 4xx (bad token, bad bundle, limits) vs 5xx (our fault) |
| `storage_failures` | object reads/writes/deletes that failed |

These are process-local counters, reset on restart, with **no per-user
dimension and no request content**: no token, bundle, document, incident id or
runner log reaches them (`docs/cloud/secrets-audit.md`). The same `logf` carries
handler error lines, which are server-produced error values — see the audit for
the review of those call sites.

## Upload queue on the agent (7.46–7.49)

```bash
deprehendo-agent login -endpoint https://… -auto-upload   # opt in, writes auto_upload
deprehendo-agent queue                                   # report and drain now
deprehendo-agent queue --retry                           # reset failed entries
deprehendo-agent queue --no-drain                        # report only
```

- The queue file lives beside the credential file (`queue.json`, 0600, in a
  0700 directory) and holds three states: `pending`, `uploaded`, `failed`.
- An entry is created **after** the bundle is written (`IncidentPipeline.OnSaved`
  fires on `Complete`), so a queue or network failure cannot cost an incident.
- Retry is bounded exponential backoff: 5 attempts, 30s → 1m → 2m → 4m, then
  `failed` (≈7 minutes). `failed` is terminal until `--retry`; there is no
  unbounded loop.
- A missing local bundle is a terminal `failed` with a reason, and the bundle is
  never modified or deleted by the queue.
- Offline is not an error: `queue` exits 0 with `Upload deferred`, the incident
  stays local, and local recording/diagnosis/analysis never consult the queue.
