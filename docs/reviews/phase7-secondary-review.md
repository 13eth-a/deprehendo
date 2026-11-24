# Phase 7 — secondary review and CLI slice

Status: **updated November 16, 2026.** Covers the contract §9 reviews assigned
to secondary (the `deprehendo.analysis` document schema, §7.1 SQL, and secondary cost
review), the CLI items 7.11/7.12, equality/compatibility work for 7.43 and
7.33, and the route-independent UI slice. The initial findings below remain
the record of those earlier reviews; current status and follow-up work are in
§§5–8.

## 1. What was built

- **`docs/cloud/upload-api.md`** — the client-visible upload contract pinned
  before the server exists: `POST /api/uploads` (create or duplicate),
  presigned POST to storage, `POST /api/uploads/{id}/complete`, one error
  envelope. Without this, engineering's server and secondary's client would each invent a
  shape and the difference would surface as a broken upload.
- **`internal/cloudclient`** — create / `PutObject` / `Complete`, plus
  endpoint validation that refuses plain HTTP except on loopback. The token is
  attached to the two API calls only; the storage POST is already signed and
  gets no `Authorization` header (tested).
- **`deprehendo-agent login` / `deprehendo-agent upload`** (7.11, 7.12) — the
  credential file is `~/.config/deprehendo/config.json`, written atomically at
  0600 in a 0700 directory; a file readable by group or others is refused with
  the fix. `upload` validates the bundle locally with `incident.Read`, hashes
  the **exact bytes sent**, and prints `Uploading incident … / Validated /
  Uploaded / <url>`, or `Already uploaded` for a §6 duplicate. It never puts
  the token inside a bundle and never retries (7.48 belongs to the auto-upload
  queue).
- **`internal/analysis` corpus tests** — 7.43's local half: every fixture
  renders twice to identical bytes and records the digest of the bytes it
  analyzed. 7.33's field pin: `document_version`, engine identity
  (`analyzer_version`, `signature_version`, `signature_set_version`,
  `causal_rules`, `privacy_policy`, `bundle_formats`) and the bundle's
  `sha256`/`schema_version`/`format_version` are present by JSON name.

## 2. Review: the `deprehendo.analysis` document (§3.3)

Verdict: **sound as a viewer format.** The original string-valued `options`
deviation recorded below has since been corrected to a structured object. The
current implementation still omits `options` for default runs and omits an
empty `disabled` list; this matches the cloud default behavior, but differs
from the contract's field listing if consumers require those fields to be
present in every document. Existing Phase 7 documents have been stored in
Neon, so changing that v1 serialization now should be coordinated with the
schema owner.

- The document is a pure function of bundle bytes + engine + options, and both
  readers (`analyze --document`, the worker) call one writer. The corpus test
  now proves determinism across all 19 fixtures, not one.
- Evidence classes are attached per event and per claim
  (`node.evidence_class`, `failure.claim`, timeline `evidence_class`), so 7.22
  can render "DIRECT KERNEL TRACE" vs "INFERRED FROM SNAPSHOTS" without
  re-deriving anything in TypeScript. That is exactly the 7.9 requirement.
- `series` keeps the full snapshot records in capture order and `timeline`
  keeps bundle order; both carry array position as a stable index, which is
  what 7.44 paging needs.
- **Resolved since the initial review:** `options` is now a structured object
  (`min_confidence`, `disabled`) with a matching TypeScript type. Its omission
  when defaults apply is documented in Go and TypeScript comments. If §3.3
  intends the fields to be mandatory even for default runs, the schema owner
  should resolve that separately; Neon now contains stored Phase 7 documents.
- **Not a defect, but worth stating:** the document contains no raw bundle
  bytes and no command lines — only what the Phase 2 redactor already kept.
  The privacy report travels with it, so 7.27 can render what was omitted
  without reconstructing it.

## 3. Review: `db/migrations/0001_init` (§7.1)

Verdict: **the model is right; three defects fixed, three recommendations
left.** Nothing has been applied to a database, so the edits are free.

Fixed here:

1. **Object keys could contain path escapes.** The check was
   `LIKE 'orgs/%.deprehendo'`, which admits `orgs/../../etc/x.deprehendo` and any
   suffix. Now a regex pins `orgs/{org}/bundles/{sha256}.deprehendo` with
   lowercase hex. Even though storage keys are opaque, a filesystem-backed
   store would honour `..`.
2. **Token lookup had no usable index.** `UNIQUE (user_id, token_hash)` cannot
   serve `WHERE token_hash = $1`, which is how a bearer token is resolved
   before the user is known. Added a partial index on `token_hash` for
   unrevoked rows.
3. **`upload_usage` had no foreign key**, so deleting an organization left
   quota rows behind. Now `REFERENCES organizations (id) ON DELETE CASCADE`.

Recommended, not changed:

- **7.6's list columns are split across two tables.** `incidents` lacks
  `bundle_size`, `bundle_object_key`, `schema_version` and
  `analyzer_version`; every list query needs a join to `uploads`, and 7.13's
  table wants bundle size for context. Denormalise them onto the view row
  when the list API lands; they are derived, so the copy is safe.
- **Duplicate races need application handling.** `UNIQUE (organization_id,
  sha256)` turns two concurrent uploads of the same bytes into a constraint
  violation on the second insert. `complete` must catch `23505` and return
  the existing incident (7.30) rather than a 500.
- **`incidents` is keyed by `upload_id`, not `incident_id`.** That is correct
  for §6 (the same incident legitimately exists as two byte sequences), but
  the list must group by `incident_id` in the organization and mark the newest
  — the schema deliberately does not do that grouping for it.

At the time of this review, no Postgres was available, so the migration had
not yet been applied. The later Phase 7 handoff records that migrations were
applied to Neon during the November 7 local end-to-end run.

## 4. Review: the upload client against the contract

- Consent boundary: `login` stores what the user pasted; `upload` sends the
  token only to the two API calls. The client refuses a redirect to another
  host (`sameHostRedirects`, with a test proving the second host is never
  contacted and never sees `Authorization`), so a proxy or hostile endpoint
  cannot walk the bearer token off-site. The server should still not redirect
  `/api/**` at all.
- The client validates locally and refuses corrupt bundles before any network
  call (tested). The server must still validate: a client is not a trust
  boundary (contract §5.1).
- `sha256`/`size_bytes` are claims. The worker must recompute from stored
  bytes and reject a mismatch; `complete` is where that happens.
- The 10-minute storage deadline is a client courtesy, not a server limit;
  §5.3's job wall clock remains 60 s after `complete`.

## 5. secondary follow-up after the dashboard view layer landed

The earlier blocker table above was true before `web/` existed. adversarial's React
view layer is now present, so secondary's route-independent UI and UX share is
complete in the current workspace:

- 7.13–7.17 and 7.20–7.22: reusable incident, diagnosis, causal chain,
  evidence, process, network, and CPU/timeline views are in `web/components/`.
- 7.18 and 7.24: timeline and event evidence are viewable in the existing
  components; event categories and richer raw-event filters still need fields
  not present in the v1 document.
- 7.45: `web/styles/dashboard.css` supplies visible keyboard focus, contrast,
  reduced-motion behavior, and narrow-screen layout. `docs/cloud/ux-copy.md`
  records the accessibility and UX requirements.
- 7.51–7.54: `LandingPage`, first-run/filtered empty states, `DemoIncident`,
  and the product copy now define a route-ready user journey.
- 7.11 and local/cloud equality and schema compatibility checks remain as
  described above.

Still dependent on work outside secondary's view-layer lane:

| Item | Current dependency |
|---|---|
| Next.js pages, API integration, live loading/error behavior | Next.js host app and route wiring (7.3) |
| auth-flow review | Browser session/organization auth (7.4–7.5), not implemented by the token API |
| 7.23 GitHub context and 7.21 no-RX highlight | GitHub fixture and per-socket RX data |
| 7.25 search | Host app integration with the server's search API |
| 7.50 notification hook | Optional and explicitly not a Phase 7 blocker |
| 7.59 cost-measurement review | Completed in §6 after MiMo's measurement pass landed |
| 7.60 final security gate | principal review complete; secondary's secondary review is recorded in §8 |

The TypeScript unit and static-render tests were added with the view layer, but
`npm run typecheck` and a browser run remain unverified because the required
type packages could not be installed from the disconnected environment.

## 6. secondary review of 7.59 cost measurement

**Completed November 9, 2026.** The measurement is now based on the selected
Neon object store and the implemented upload contract:

- Replaced the AWS S3 PUT charge with Neon Object Storage's $0.023/GB-month
  rate and no per-operation fee. The tool retains a configurable operation
  price for comparisons with other providers.
- Counted the three Cloud Run requests in `upload-api.md` (create, `/storage`,
  complete). The analysis runs during complete, so it is not an extra request.
- Removed the stale 6 ms arithmetic and used the latest measured 21 ms median.
  The reported 1,000 fixture-sized incident estimate is now $0.002348 gross at
  list prices, before applicable free allowances.
- Kept the result clearly labeled as a lower-bound estimate: Mac timing does
  not provide deployed CPU billing, and upload handler time, Neon Postgres,
  PITR, transfer, idle time, and actual bills are outside this model.

The corrected command output is recorded in `docs/cloud/cost-measurement.md`.
Neon object storage and Cloud Run rates are linked there to their current
pricing pages. The 7.59 review is closed; actual bills still require the
deployed 1/100/1,000-incident run in the measurement document's next steps.

## 7. Remaining secondary dependencies

- **Deployed browser auth-flow review (7.4–7.5):** the Better Auth JWT verifier,
  per-request organization membership lookup, and local dashboard flow now
  exist. Review the deployed dashboard's cookie flags, browser security
  headers, and hosted sign-in flow when that host is live; the principal gate keeps
  this deployment check OPEN.
- **7.60 security review:** secondary's secondary review is complete; see §8 and
  `phase7-secondary-gate-review.md`.
- **7.50 notification hook:** remains explicitly optional and deferred by the
  Phase 7 status note.

## 8. secondary secondary review of the 7.60 security gate

**Completed November 16, 2026.** secondary reviewed the principal gate against the current
code and closed adversarial's H1 for manual incident deletion. The delete handler now
keeps database rows when object storage fails, returns 503, and supports a
retry; `TestPhase7DeleteKeepsRecordWhenStorageFails` covers that path.

secondary found one scoped follow-up in the operator-run time-based retention sweep:
it deletes rows before objects and logs storage-delete failures, leaving objects
that the database can no longer name. Treat the sweep as best-effort rather
than guaranteed erasure until this is fixed. The upload/read API still passes
the private-beta gate subject to the principal prerequisites and open dashboard/auth
checks. Full review: [phase7-secondary-gate-review.md](phase7-secondary-gate-review.md).
