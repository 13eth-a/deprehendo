# Handoff — Runopsy

The release includes phases 1–7.

## Phase 7 — 7.62 real-runner demo done; Phase 7 complete (November 21, 2026)

- **7.62 passes.** Two traced captures from a self-hosted runner on a Lima VM
  (`13eth-a/runopsy-runner-e2e`, label `runopsy-b3`). Runbook and results:
  `docs/github/real-runner-demo.md`.
  - OOM: a real job allocates 4 GiB on a 4 GiB VM and is killed (exit 137).
    The engine names `OOM_KILL` HIGH 0.80 from the cgroup OOM counter.
  - Stall: three minutes of blocked outbound HTTPS on an idle runner. The
    generic engine abstains (`UNKNOWN`, by design), and the GitHub provider
    reports `GITHUB_RUNNER_COMMUNICATION_STALL` MEDIUM.
  - Both are byte-identical between hosted `/analysis` and local
    `analyze --document`, and the hosted dashboard renders both.
- **Fixed:** the hosted analyzer did not register the GitHub provider.
  `cmd/runopsy-analyzer/main.go` now does. Test:
  `tests/phase7_hosted_provider_test.go`.
- **Demo corpus:** `testdata/demo/manifest.json` is now version 2. The OOM and
  stall scenarios point at the real bundles in
  `testdata/github/real-runner-demo/` (`source: real-runner`), and the stall
  carries `provider_signature`. `tests/demo_corpus_test.go` checks both.
- **New scripts:** `scripts/demo-capture.sh` (VM, `oom` or `stall`) and
  `scripts/demo-verify-hosted.sh [--replace]`.
- **Gate doc:** the 7.62 row is PASS and the final review is closed.
- **Next:**
  - Clean up: remove the VM runner, `limactl delete -f runopsy-demo`, delete
    the stale offline runners `runopsy-b3-vm` and `runopsy-lima-runopsy`.
  - Follow-ups: the tracer fell back to the proc connector, not eBPF; a
    dashboard provider panel; the list's Confidence column shows "—";
    `runopsy-cloud token -org-name` mismatch.

## Phase 7 — Security gate closed; CI green; macOS bundle states fixed (November 18, 2026)

- **Gate (7.60) closed for the private beta.** Every row in
  `docs/reviews/phase7-principal-security-gate.md` passes.
  - The deployed dashboard (`web-production-d673c0ef.up.railway.app`, the
    second Railway service) was checked over https. On November 16,
    `curl -sI /` showed HSTS, CSP, `nosniff`, `Referrer-Policy` and
    `X-Frame-Options`. On November 18 the session cookie showed `Secure`,
    `HttpOnly` and `SameSite=Lax` after sign-in.
  - Public sign-up still waits on custom SMTP and an invite flow.
    So does a nonce-based CSP: `script-src` keeps `'unsafe-inline'` for the
    Next.js bootstrap scripts.
- **Reviews.**
  - adversarial (`phase7-adversarial-gate-review.md`) found H1: a failed storage delete
    was answered `200 deleted` after the rows were gone. Fixed:
    `deleteIncident` deletes objects first and answers `503` with the rows
    kept. Test: `TestPhase7DeleteKeepsRecordWhenStorageFails`.
  - secondary (`phase7-secondary-gate-review.md`, `phase7-secondary-review.md`) found L1:
    the retention sweep had the same row-first order. Fixed:
    `PruneUploadsOlderThan` deletes objects first and stops on a storage error
    with the row kept, and `runopsy-cloud prune` prints partial progress and
    exits non-zero. Test: `TestPhase7PruneKeepsRowWhenStorageFails`.
    `docs/cloud/operations.md` updated.
- **macOS bundle bug (found through CI).** The privacy filter `cleanState`
  accepted only an exact single letter. macOS `ps` appends flags (`T<`, `Ss`),
  so every macOS process state in every bundle became `?`, which erased the
  stopped and zombie evidence. It now keeps the leading letter from the same
  closed alphabet, plus `U`. It is idempotent, so existing bundles still
  verify; macOS bundles written before the fix keep `?`. The policy name stays
  `conservative-v1`. Test: `internal/incident/privacy_state_test.go`.
- **CI repairs.**
  - `trace-live` now installs `clang` and `libbpf-dev` (`build.rs` links
    libbpf by design).
  - `trace-ebpf-live` no longer asks apt for `bpftool`, which Ubuntu 24.04
    lacks. It tries `linux-tools-$(uname -r)` and doesn't fail without it.
    `scripts/ebpf-e2e.sh` skips the optional stats dump when bpftool is
    missing, and `bpfcc-tools` (unused) was dropped.
  - `TestZombieFullCycle` accepts `Z+`, as the rest of `internal/simulator`
    does.
  - The Phase 2 e2e and matrix tests run a private simulator copy
    (`privateSim`, named `rph2-<pid>` / `rpm2-<pid>`). Watching `runopsy-sim`
    by name matched `internal/simulator`'s own stopped worker running in
    parallel. The e2e test now prints the trigger, the PID's recorded states
    and the logs when it fails.
- **Housekeeping.**
  - The `runopsy-smoke-*` users were deleted from `neon_auth."user"`
    (`memberships.user_id` is text, so the subquery casts `id::text`).
  - The untracked `cloud.json` and `local.json` were removed.
  - The Neon `neondb_owner` password was reset after it was printed in a
    terminal error, and `.env.local` and the Railway variables were updated.
  - The Railway bucket credentials were rotated.
- **Verified.** `make test` and `make test-cloud` pass on macOS. Every CI job
  passes on `main` (November 18): `test` (ubuntu and macos), `cloud`,
  `trace-rs`, `trace-live` and `trace-ebpf-live`.
- **GitHub sign-in live (later November 18).**
  - The GitHub OAuth provider is registered in Neon Auth, and the web service
    has `NEXT_PUBLIC_AUTH_GITHUB=1`.
  - `AuthForms.tsx` now passes absolute `callbackURL` and `errorCallbackURL`.
  - The dashboard half of 7.61 is verified on the deployed site: GitHub
    sign-in, owner grant, incident list, analysis, and the sign-out redirect.
    Details in `docs/cloud/browser-auth.md`.
- **7.56 managed restore drill PASSED (November 19).**
  - Ran `scripts/neon-restore-drill.sh` against production: target
    `2026-11-19T07:10:00Z`, canary `cpu-spin` uploaded after it, then
    `neon branches restore production ^self@… --preserve-under-name
    production_pre_drill_20261119_0710`.
  - RTO was 5 s. The incident list was unchanged and the canary answered 404.
    Analysis and bundle were byte-identical, and the schema was current. The
    canary's objects were removed and the bucket listing matched.
  - Found on the way: `.env.local` carries Neon's storage `AWS_*` settings, and
    `.env.railway` had no endpoint, so Railway keys went to Neon's endpoint.
    The script now clears inherited `AWS_*` variables.
  - Open:
    - The Free plan's 6-hour history window is too short; move to Launch
      (7 days) before public use.
    - Decide whether to keep or delete the backup branch.
    - The bucket has no versioning, so a restore can't undo a delete's
      objects.
  - Details in `docs/cloud/pitr-drill.md`.
- **7.59 real bills measured (November 20).**
  - `scripts/cost-load.sh` loaded the deployed API to 1, 100 and 1,000
    incidents. It used 53 throwaway orgs, each holding the 19 fixtures, and
    cleaned up afterwards.
  - Results: 1,000/1,000 uploads ok, with a median end-to-end upload of
    0.92 s. The bucket grew 25,719 B per incident (exactly the model's bundle
    plus document) and the database 1,540 B per incident.
  - The Railway project total stayed at $0.17 for the cycle (API $0.12, web
    $0.05), and Neon Free at 0.23 CU-h and 32 MB. The bill is the always-on
    baseline: on Hobby, the invoice is the flat $5 until usage exceeds $5.
  - Found and fixed on the way: about 1 in 20 Railway bucket writes failed
    with a 5xx, failing the user's upload. `s3store.go` now retries 5xx, 429
    and dropped connections, and a retried PUT that finds its own bytes
    counts as stored. Tests: `s3store_retry_test.go`. The rerun had 0
    failures in 1,000 uploads.
  - Also noted: `runopsy-cloud token -org-name` creates an org with a random
    id, then rejects it as a mismatch. The load script inserts orgs directly
    instead.
  - Details in `docs/cloud/cost-measurement.md`.
- **Next:**

## Phase 7 — Dashboard host built and working end to end (November 14, 2026)

- **Built:** `web/` is a Next.js 16 app (commit `7d3917d`). It covers
  Neon Auth email sign-in and sign-up, protected routes, server-side API calls
  with the session JWT, the incident list and detail using the existing view
  components, the org picker, the public demo and install pages, and security
  headers. Design and steps: `docs/cloud/browser-auth.md`.
- **Checks:** `npm test` (34), typecheck and `next build` pass.
  `make test-cloud` passes, including the gated browser-session test.
- **Verified:** the local dashboard against the deployed Railway API
  (`RUNOPSY_AUTH_URL` set). Sign-up, the owner grant via `runopsy-cloud
  member`, the incident list, the `frozen-worker` analysis from the Railway
  bucket, and the sign-out redirect all work.
- **Next:**
  - Deploy `web/` as a second Railway service (root directory `web`).
  - Allow its domain in Neon Auth.
  - Check the cookies and headers over https; this is the last open gate row.
  - Add GitHub OAuth.
  - Delete the smoke-test users.
  - Rotate the Railway bucket credentials.
  - adversarial and secondary review the gate.

## Phase 7 — Email sign-up live on Neon's managed Better Auth (November 13, 2026)

- **Auth on:** `neon.ts` has `auth: true` (the bucket entry is kept).
  `neon deploy` turned Managed Auth on and wrote `NEON_AUTH_BASE_URL` to
  `.env.local`.
- **Verified with a real user:** `web/scripts/auth-smoke.ts`
  (`npm run auth:smoke`) uses `@neon/auth` to sign up, read the current user,
  sign out, refuse a wrong password (401), sign in, and take the session JWT.
  Then a local `runopsy-cloud serve` with
  `RUNOPSY_AUTH_URL=$NEON_AUTH_BASE_URL` verified that JWT against Neon's real
  JWKS: `GET /api/me` returned the same user, `auth browser`. **ALL PASS.**
- **Next:**
  - Add GitHub OAuth.
  - Set `RUNOPSY_AUTH_URL` on Railway.
  - Build the Next.js host (`docs/cloud/browser-auth.md`).
  - Run `make test-cloud` for the gated browser-session test.
  - Delete the `runopsy-smoke-*` test users when done (SQL in
    `browser-auth.md`).

## Phase 7 — Browser sign-in decided and API side built (November 12, 2026)

- **§8.2 decided:** Neon's managed Better Auth, with GitHub as the main sign-in
  method. Design and dashboard build plan: `docs/cloud/browser-auth.md`.
- **API side built:**
  - `internal/cloudserver/browserauth.go`: Ed25519/EdDSA-only JWT
    verification, standard library only. JWKS cached for 10 minutes;
    unknown key ids refetched at most every 30 s; last good keys kept through
    an outage. `iss`/`aud` must equal the auth URL origin; `exp` required.
  - `requireToken` accepts a session JWT beside personal tokens.
    `X-Runopsy-Organization` picks the membership (optional with exactly one),
    and roles apply as for tokens.
  - New `GET /api/me` lists the caller's organizations.
  - New `runopsy-cloud member` grants or revokes memberships.
  - Configured by `RUNOPSY_AUTH_URL` (unset means token-only, so the current
    Railway deploy is unaffected).
- **Tests:**
  - `browserauth_test.go` (6 tests, including 16 refusal cases, key rotation,
    outage, and refusal before any database call) passes under `-race` in the
    offline module copy.
  - The gated `TestPhase7BrowserSessionsUseMembershipsAndOrganizationHeader`
    typechecks. **Run `make test-cloud` on the Mac** before deploying.
- **Next:**
  - Enable Neon Auth with GitHub, then set `RUNOPSY_AUTH_URL` on Railway.
  - Build the Next.js host: server-side proxy route, org picker, cookie and
    security headers (`browser-auth.md` steps 1–6).

## Phase 7 — principal security gate (7.60) and review roles (November 9, 2026)

The principal items on the Phase 7 roster are done: the 7.60 gate, plus the principal
review roles for 7.4–7.6, 7.8, 7.9/7.38, 7.12, 7.27, 7.34, 7.36, 7.37, 7.39,
7.43 and 7.46–7.49. Full record: `docs/reviews/phase7-principal-security-gate.md`.

- **Verdict:** the API passes for a private beta on Railway + Neon once
  `make test-cloud`, `govulncheck`/`npm audit` and the Railway bucket
  immutability test pass. It does **not** pass for public sign-up: browser
  auth and session cookies are not built, and the dashboard has no host
  (§8.2).
- **G1 (high), fixed:** the unauthenticated `POST /storage` parsed the whole
  multipart form, up to about 66 MiB in memory plus temp files, before
  checking the policy. It now streams with a capped body, accepts at most 8
  fields of 4 KiB each, and refuses the file part unless a valid policy came
  before it.
- **G2 (high), fixed:** delete and activate are owner-only. A member token,
  such as a CI runner's, gets 403; other organizations still get 404.
- **G3 (high, privacy), fixed:** delete read document keys after the cascade
  had removed the rows naming them, so every per-engine analysis document
  survived a user delete. Keys are now read first, and a failed read stops
  the delete.
- **G4–G7, fixed:**
  - A server-wide analyzer cap, `MaxConcurrentTotal` (default 2). All
    analyzer children now share the Railway container.
  - Job-slot waits end when the request does (503).
  - HTTP read, write and idle timeouts.
  - The F3 sanitizing gap on the client's storage-failure path is closed.
  - The container now runs as non-root (`USER runopsy`).
- **Recorded, not changed:**
  - The analysis limit is now **60 per org per hour** (owner decision §8.3):
    a rolling window over per-minute counters (migration
    `0003_hourly_usage`), with `Retry-After` on the 429. It was effectively
    60 per day. Covered by `TestPhase7AnalysisLimitIsPerOrganizationPerHour`;
    the SQL and migration were checked on PostgreSQL 16.
  - `create` has no rate limit.
  - A single replica is required until `SigningSecret` is configured.
- **Tests:** new `internal/cloudserver/gate_test.go` covers storage streaming
  (an 8 MiB policy-less body reads under 1 MiB) and the job slots. New
  `tests/phase7_security_gate_test.go` (gated) covers owner-only actions and
  delete removing every object. Verified here in an offline module copy with
  Go 1.24 and a `pgx` stub: build, `go vet`, `gofmt`, and the unit tests for
  `cloudserver`/`cloudclient` (including `-race`). **On the Mac, November 11
  (Go 1.27.1):** `go vet ./...` clean, unit tests pass, and `make test-cloud`
  applied `0001`–`0003` (`schema is current`) with `ok runopsy/tests` for the
  whole gated suite.
- **Dependency scan (November 11):** `govulncheck` found 12 standard-library
  vulnerabilities in Go 1.27.1. Two hit the gate's own code:
  - GO-2026-6859, a server crash from a `MaxBytesReader` race;
  - GO-2026-6608, a MIME header memory-limit bypass in the multipart reader.

  `go.mod` now requires **go 1.27.4**. On 1.27.4, `go vet`, the unit tests and
  `make test-cloud` pass, `govulncheck ./...` reports no vulnerabilities, and
  `npm audit` (`web/`) reports 0. **The Railway image must be rebuilt** to pick
  up 1.27.4.
- **Still open in Phase 7:**
  - 7.61: the server half **passes on Railway + Neon** (November 12). The
    stale `frozen-worker` row was deleted and re-uploaded fresh (`Uploaded`,
    with its bundle and document in the Railway bucket), and the deployed
    `/analysis` for `disk-full` is byte-for-byte `IDENTICAL` to a local
    `analyze --document`. The hosted-dashboard half is still open.
  - **Deployed (November 12):** commit `eab5d70` (gate fixes, hourly limit,
    Go 1.27.4) is live on Railway. A storage POST with an oversized policy
    field now gets `400` from the new streaming path; the old build answered
    `403`.
  - Rotate the Railway bucket credentials again. The secret was exposed in
    pasted terminal output three times during testing; keep it only in the
    gitignored `.env.railway`.
  - 7.62 real-runner demo (Lima traced captures, hosted dashboard).
  - 7.50 notifications (optional).
  - The managed Neon PITR run.
  - Provider bills.
  - On Railway, `frozen-worker` is recorded in Neon but its bytes are only in
    the old Neon `assets` bucket, so delete it or re-upload it after the
    redeploy.

## Phase 7 — secondary cost review complete (November 9, 2026)

secondary completed the remaining reviewable Phase 7 cost work after the MiMo 7.59
measurement landed. The original measurement remains useful, but its provider
assumptions and totals are superseded in `docs/cloud/cost-measurement.md`:

- The selected Neon Object Storage rate is $0.023/GB-month with no
  per-operation charge; the tool default no longer applies S3 PUT fees.
- The upload contract performs three Cloud Run requests (create, storage,
  complete), rather than the one request in the original estimate.
- The model uses the latest measured 21 ms median, not the earlier 13 ms or
  stale 6 ms figure. For 1,000 fixture-sized incidents, the revised gross
  list-price total is $0.002348 before free allowances; database compute, PITR, egress, and
  measured Cloud Run upload/handler time remain excluded.
- `docs/reviews/phase7-secondary-review.md` records the review. Browser-auth review
  still has no implementation to inspect, 7.60 remains downstream of principal,
  and 7.50 remains optional.

The cost command built successfully with a writable Go cache and completed a
fresh five-run measurement; no test suite was run.

## Phase 7 — MiMo slot completed: cost tool, retention review, prune verified (November 8, 2026)

The items the Phase 7 roster assigns to MiMo 2.6 Pro are closed: 7.59 cost
measurement, and the 7.56–7.58 database/migration/retention review. Detail in
`docs/cloud/cost-measurement.md` and `docs/cloud/db-review.md`.

- **7.59 is now reproducible, not a copied table.** New `cmd/runopsy-cost`
  reads the 19 real bundles, runs the real analyzer child five times each,
  takes per-bundle medians, optionally measures real row bytes with
  `pg_column_size`, and prints the 1/100/1,000 table with every price as a
  flag. At the November 8 run: bundle 1,965 B mean, document 23,754 B mean,
  analysis 13 ms median (8–85 ms), **1,098 B of database rows per incident**.
  The $0.0113 estimate used AWS PUT pricing and one request per incident; the
  November 9 secondary review above supersedes that cost figure.
- **Defect fixed in the shared runner, not a third caller.**
  `analyzer.NewRunner` accepted a relative child path while `Run` starts the
  child in a private temp directory; `serve` was patched locally during the
  7.56 drill and `runopsy-cost` then hit the same wall. `NewRunner` now
  resolves the path itself, so no caller can repeat it.
- **7.58 retention reviewed, four defects fixed.** `prune` deletes by age with
  no preview → added `PlanPrune` and `prune -dry-run` (a mistyped `90h` for
  `90d` was silent data loss). A failed analysis-document read let the sweep
  continue and strand documents → it now stops before that upload's rows go.
  The sweep invented a legacy document key for every upload, inflating object
  counts → the legacy key is used only when no analysis row exists. And the
  destructive path had no test → `TestPhase7PruneUploadsOlderThan` now covers
  dry run, cascade, stale pending upload, object removal, newer-upload survival
  and `upload_usage` survival.
- **Verified for real:** `prune -dry-run` listed `uploads=2 objects=4
  bundle_bytes=3882` and deleted nothing; the apply printed the same counts; a
  rerun printed `uploads=0 objects=0`. `EXPLAIN` with `enable_seqscan=off`
  picks `Index Scan using uploads_by_uploaded_at`, so `0002` serves the sweep's
  `WHERE … ORDER BY uploaded_at`.
- **Still not done, and not doable here:** actual provider bills (needs a
  deployment), the managed Neon PITR restore (overwrites the root branch;
  needs an operator window — the runbook in `docs/cloud/pitr-drill.md` is
  ready), and the real-runner demo (needs hardware this machine lacks).

## Phase 7 — Neon object store and end-to-end local run (November 7, 2026)

The cloud server now has a real S3-compatible object store, and the local
stack ran end to end against a Neon project. Credentials are in `.env.local`
(gitignored); nothing secret is recorded here.

- **Store:** `internal/cloudserver/s3store.go` implements `Store` over
  S3-compatible HTTP with AWS SigV4, using only the standard library. Puts are
  conditional (`If-None-Match: *`), so a stored original cannot be overwritten.
  Selected by `RUNOPSY_S3_BUCKET`; the local store is used when it is unset.
  Endpoint must be https (plain http only for loopback). Tests in
  `s3store_test.go` cover the AWS signing vector, round trip, immutability,
  wrong secret, unsafe keys, and config validation. `go vet` and
  `go test ./internal/cloudserver/ ./cmd/runopsy-cloud/` pass on the Mac.
- **Neon:** Postgres via `DATABASE_URL_UNPOOLED` (migrations applied by
  `runopsy-cloud serve`); private bucket `assets` for objects, configured
  with `AWS_ENDPOINT_URL_S3` and `AWS_REGION` from `.env.local`.
- **Run result:** an org and token were created, and `runopsy-agent login` and
  `upload` succeeded against `http://127.0.0.1:6080`. Telemetry showed
  `uploads_completed=1`, `analysis_runs=1`, `storage_failures=0`,
  `parse_failures=0`. The bundle and analysis document are in `s3://assets/`
  under `orgs/<org>/bundles/` and `orgs/<org>/documents/`.
- **Immutability on Neon:** a second conditional PUT to the same key returned
  `PreconditionFailed`, so Neon honours `If-None-Match`. The test key was
  deleted afterwards.
- **Not yet checked:** reading the incident back through the server, and
  whether the stored analysis document matches a local `analysis.Run` byte
  for byte. The dashboard read path is still unverified against Neon.
- **Contract clarification:** `docs/cloud/upload-api.md` now describes the real
  upload flow. `upload.url` is the server's own `/storage` route, and the
  policy is an HMAC-signed token minted by the server, not a provider presigned
  POST. The bytes pass through the server into the object store.
- **Error codes:** a bundle outside the accepted size range now returns `413
  TOO_LARGE` from `create` (below 22 bytes: `422 INVALID_BUNDLE`), matching
  `upload-api.md` §4 and `complete`.
- **Repo root:** the Node files from `neon init` (`package.json`,
  `package-lock.json`, `node_modules`, `skills-lock.json`, `.agents`, `neon.ts`)
  are kept.

## Phase 7 — PITR rehearsal passes; managed runbook written (November 6, 2026)

The 7.56 backup work is now drilled, not just documented. `make pitr-drill`
(`scripts/pitr-drill.sh`) runs a real base backup + WAL archive + restore to a
chosen timestamp against a throwaway PostgreSQL 16, with the object store
snapshotted at the same moment.

- **Result:** two incidents uploaded; the target was recorded after the first.
  Recovery to that timestamp (2026-11-06 08:01:56.621888+00) left exactly one
  incident, the pre-target one; the post-target upload was absent;
  `runopsy-cloud migrate` printed `schema is current`; the restored pair served
  `/analysis` and `/bundle` with 200, byte-identical to the CLI document and the
  original bundle; the post-target incident answered 404. Printed
  `PITR-DRILL-OK`.
- **Provider:** Neon is recommended (`docs/cloud/pitr-drill.md`): serverless
  Postgres with instant restore on root branches; history window 6 hours on
  Free (1 GB cap), up to 7 days on Launch, 30 on Scale; snapshots $0.09/GB-month.
  The 6-hour Free window is too short for this workload — Launch before public
  use. The app needs no change: `internal/clouddb` already speaks plain
  Postgres over `pgx`.
- **Managed runbook:** a step-by-step Neon procedure with acceptance checks
  (target recorded in UTC, objects snapshotted at the same logical time, restore,
  post-target rows absent, byte-identical evidence, schema current, RTO
  recorded). **The managed run itself is not done:** it needs a Neon account,
  which this environment does not have. The runbook says to paste the measured
  results back into the file.
- **Drill defects fixed while building it** (all in the script, not the app):
  the container must listen on all interfaces and trust the Docker gateway, the
  restored data directory must be `0700`, and a recovering server must not be
  started with `pg_ctl -w`.

## Phase 7 — MiMo slot closed: review applied, backup drill run (November 6, 2026)

The MiMo-slot documents from the first pass are now reviewed and closed. Full
detail: `docs/cloud/db-review.md` and `docs/cloud/cost-measurement.md`.

- **Database review decided, not just proposed.** P1 was **rejected as a schema
  change**: widening the `object_key` check to uppercase would only move the
  failure, because `policyRE`, `safeKey` and `mintUploadPolicy` also require
  lowercase and `clouddb.NewID` generates lowercase hex by design. The real
  defect was the ULID-style example in upload-api §1, now corrected. P2
  (`READY` iff `document_key`) and P3 (redundant `uploads_by_search` index) were
  **applied to `0001_init.up.sql`**. P4 (`state` column) was **resolved in the
  contract**: readiness is read from `analyses.status`, and a column nothing
  writes would be dead state.
- **7.56 backup and restore drill run for real.** On PostgreSQL 16: migrated,
  uploaded `frozen-worker.runopsy` through the live server (`/analysis` and
  `/bundle` byte-identical to the CLI/original), `pg_dump -Fc` = 19,076 bytes,
  `pg_restore` into a fresh database with no warnings and identical row counts,
  `migrate` → `schema is current`, and the gated `TestPhase7ServerPipeline`
  passes against the restored DSN. Copying the object tree is byte-identical and
  `/analysis` serves the same bytes. **Restoring the database without the
  objects leaves rows that list (200) but 404 on analysis and bundle**, so the
  two stores must be backed up and restored as a pair. Managed PITR remains
  untested (no provider chosen).
- **7.59 cost review: inputs verified.** Re-measured on this tree: 19 bundles
  mean 1,965 B, 19 documents mean 23,754 B (min 19,487 / max 27,907), matching
  the document. The arithmetic for all nine rows was re-derived, and the
  "Compute" column was noted to include request charges. Price provenance was
  made honest: the AWS page confirms the tier but renders the number
  client-side, so storage and PUT prices still need invoice confirmation.
- **Defect found by the drill, fixed:** `runopsy-cloud serve -analyzer
  ./bin/runopsy-analyzer` passed its startup stat but failed every job, because
  the analyzer child runs in a private temp dir. `serve` now resolves the path to
  an absolute one first; the relative form was re-run through a live upload.

### Verification

`make test-cloud` passes after the migration changes (migrations applied twice;
`ok runopsy/tests`), including the new
`TestPhase7SchemaRefusesReadyAnalysisWithoutDocument` that pins P2. Down then up
was re-run on a scratch Postgres; the gated suite passed against the restored
database. `gofmt -l` clean, `go vet ./...`
and `go build ./...` clean. Still open for a deployed system: managed-backup
PITR rehearsal, real provider bills, and the time-based retention sweep (not
built; manual delete is the supported path).

## Phase 7 — MiMo slot: cloud cost (7.59) and database review (7.56–7.58) (November 6, 2026)

MiMo 2.6 Pro was unavailable, so adversarial covered its Phase 7 items. Its review
is still needed; this entry names what to check.

- **7.59 cost measurement** (`docs/cloud/cost-measurement.md`): an estimate, not
  a bill. Measured on the 19 real bundles: about 2 KB per bundle and 24 KB per
  document, analysis median 6 ms on the sandbox. Priced at list rates: storage
  $0.023 per GB-month (third-party guide, October 2026; confirm against AWS) and
  Cloud Run request-based rates (Google's pricing page). 1,000 real-sized
  incidents cost about one cent. The 10,000-event profile costs about $0.44–0.61
  for 1,000 incidents, mostly compute. Database, egress and backup costs are not
  priced. Those need a deployed system.
- **7.56–7.58 database review** (`docs/cloud/db-review.md`): migration
  `0001_init` was run on PostgreSQL 16.15 (scratch): up, down and up again all
  pass, which is the 7.57 "migrations tested" evidence. Four findings:
  - P1 (high): the `object_key` check accepts only lowercase organization IDs,
    but upload-api §1 uses uppercase ULID-style IDs. An upload for such an
    organization would fail at insert.
  - P2 (medium): a `READY` analysis can have no `document_key`.
  - P3 (low): `uploads_by_search` duplicates a prefix of `uploads_by_incident`.
  - P4 (medium): the `uploads` table has no `state` column, so the PENDING
    semantics in contract §2.1 cannot be enforced.
  - Proposed corrections: `docs/cloud/proposed-0001-fixes.sql`. Verified on
    Postgres; not applied. engineering owns the migration.
- **Not done:** the managed-database backup and restore test (7.56) needs a
  chosen provider. The MiMo backend API review was not in the Phase 7 slot list
  and was not started.

## Phase 7 — integration QA closed: dashboard leg, failure matrix, upload corpus (November 5, 2026)

The integration items left open by the earlier review are done except the ones
that need hardware this machine does not have. Full record and measurements:
`docs/reviews/phase7-integration-e2e.md`.

- **7.61 dashboard leg.** `tests/phase7_dashboard_render_test.go` hands the
  document `runopsy-agent analyze --document` wrote to
  `web/test/render-document.tsx`, which renders it through the real
  `Overview`/`DiagnosisPanel`/`CausalChain`/`TimelineTable`/process/network/
  privacy components. The test asserts the page's headline, confidence band,
  unknown flag, incident id, timeline total and page size all equal the
  document's, and that `document_version` 99 is reported rather than rendered
  blank (7.32). Skips with instructions when `node` or `web/node_modules` is
  absent.
- **7.61 server failure matrix** (`tests/phase7_failures_test.go`, gated on
  `RUNOPSY_CLOUD_TEST_DSN`): analyzer `REJECTED`/`FAILED_LIMIT`/`FAILED_CRASH`
  each answer their pinned status and leave one queryable row with the status
  and no invented signature. The timeout case runs the real child-process
  runner with an expired wall-clock deadline. A failing bundle read and a failing document
  failing document write leave no incident and are retryable; leaving the
  organization returns 403 on list, read, analysis, bundle and delete, while
  another organization's token keeps returning 404.
- **Real-server local/cloud equality.** `TestPhase7ServerPipeline` now asserts
  `GET /api/incidents/{id}/analysis` is byte-identical to
  `runopsy-agent analyze --document` for the same bundle, so 7.43 holds against
  engineering's server, not only against the reference fixture.
- **7.44 rendered half.** `web/test/performance.test.tsx` measures the real
  timeline table at 100/1,000/10,000 events: a 200-row page is 1,612 elements
  at both 1,000 and 10,000 events, while a full 10,000-event render is 80,012
  (~50×). Numbers and caveats in `docs/cloud/performance.md`.
- **7.40 worker-level review.** `tests/phase7_upload_corpus_test.go` drives
  ten §5.5 cases through the real worker (valid, truncated, duplicate member,
  sixth member, symlink, ZIP64, bumped schema, forged identity, 65 MiB
  declared bomb, replaced stored object) and asserts the HTTP answer plus the
  dashboard row. `docs/cloud/upload-corpus.md` was rewritten from a guessed
  name map into executed results, with the three undriven cases and why.
- **Defect found and fixed.** If the analysis row and document were stored but
  the incident view insert failed, a retried `complete` answered 200 with a
  dashboard URL that 404'd, and the incident never appeared in a list. The
  idempotent branch now repairs the view from the already-stored document
  (`ensureIncidentRow`) with no re-analysis and no clock. Verified negatively:
  removing the repair makes `TestPhase7CompleteRepairsAMissingIncidentRow`
  fail on the 404.

### Findings for the owner

- **§5.5 now matches rejection handling.** Rejected uploads keep a minimal
  organization-scoped row (`analysis_status` `REJECTED`/`FAILED_*`, no
  signature, `/analysis` 202), but no diagnosis document or bundle-derived
  metadata. This lets the dashboard explain a failed upload (7.31/7.32).
- **Two of 7.42's five headline demos still abstain** (OOM kill, broker
  stall) because the synthetic corpus has no kernel OOM record or socket RX
  counters. A confident screenshot would require invented evidence, so the
  manifest stays honest; the fix needs a traced capture on the Lima VM.

### Verification

`make test-cloud` passes (migrations twice, then `ok runopsy/tests`, 9.5 s for
`-run TestPhase7`); `go test -run TestPhase7DashboardRendersTheCLIDocument`
passes; `npm test` is 31/31 and **`npm run typecheck` is clean** now that
`@types/*` install and `tsconfig` sets `"types": ["node"]`; `gofmt -l` clean,
`go vet ./...` and `go build ./...` clean. Still open: 7.62 (real runner),
traced demo bundles (Lima), browser paint metrics, and the healthy-cancellation
fixture (corpus owner).

## Phase 7 — secondary UX follow-up (November 5, 2026)

Completed secondary's remaining route-independent product UX work after the React
view layer landed:

- Added keyboard-visible focus, high-contrast colors, reduced-motion support,
  responsive landing steps/filters, and a keyboard-scrollable incident table in
  `web/styles/dashboard.css` and `IncidentList`.
- Empty incident lists now distinguish first-run from an empty filtered result;
  first-run includes the upload command and a sample-incident link.
- Added route-ready `LandingPage` and `DemoIncident` components, plus the
  installation, local-first, sample-data, and accessibility copy in
  `docs/cloud/ux-copy.md`.
- Updated the secondary review and web notes to reflect current work. The old
  statement that `web/` did not exist was an earlier blocker and is superseded.

The host still needs to supply the Next.js routes, auth session, live API
loading/error shell, demo fixture, and stylesheet import. These components do
not claim those integrations are complete. UI typecheck/browser verification
also remains open; the earlier environment could not fetch the required React
and Node type packages. Optional 7.50 notifications remain deferred. At the
time of this entry, the 7.59 cost review still depended on the measurement
pass; that review was completed on November 9 (see the latest Phase 7 entry).

---

## Phase 7 — engineering backend completion: server, search, telemetry, auto-upload (November 5, 2026)

engineering's remaining queue (§9 items 4–5) and the rest of its Phase 7 ownership.
The cloud still stores, indexes and shows; it never diagnoses. Detail lives in
`docs/cloud/read-api.md`, `docs/cloud/operations.md` and
`docs/cloud/authz-matrix.md`.

### The backend is now a real server, not a schema

- **`internal/cloudserver`** implements `docs/cloud/upload-api.md` v1 and the
  read endpoints: `POST /api/uploads` (create-or-duplicate), `POST /storage`
  (policy verification, digest check, immutable `LocalStore` write),
  `POST /api/uploads/{id}/complete` (recompute digest from stored bytes →
  analyzer child → append-only `analyses` row → `incidents` view → URL), and
  `GET /api/incidents`, `GET /api/incidents/{id}`, `…/analysis`, `…/bundle`,
  `DELETE /api/incidents/{id}`. `cmd/runopsy-cloud serve` wires it to Postgres,
  the analyzer child and the store; `… token` mints personal tokens (hashes
  only) and `… migrate` applies the migrations.
- **Organization scoping is structural**: every query starts from the token's
  `organization_id`, and another organization's incident is 404 (never 403).
- **Hostile input**: create validates its claim (hex digest, size bounds,
  incident-id shape); complete ignores the client's digest and re-hashes the
  stored object; the analyzer runs as a resource-limited child; storage
  policies are HMAC-signed, bound to one key under
  `orgs/{org}/bundles/{sha256}.runopsy`, and refuse a mismatched digest.
- **Migrations are tested, not hand-checked**: `runopsy-cloud migrate` applies
  each file in one transaction and records it; a paired `.down.sql` is
  required. `make test-cloud` applies them twice against a throwaway Postgres
  and then runs the gated suite; a new `cloud` CI job does the same against a
  `postgres:16-alpine` service.

### This session's additions

- **Search and filters (7.25/7.13)**: `GET /api/incidents` now takes `q`
  (case-insensitive across incident id, signature, runner/version, repository,
  workflow, job, with LIKE metacharacters escaped), exact filters
  (`id`, `signature`, `severity`, `runner`, `repository`, `workflow`, `job`,
  `platform`), `from`/`to` date bounds and bounded paging. A malformed filter is
  400, not silently ignored. Query building is a pure function with its own
  unit tests; the org predicate is always argument 1 and always first.
- **Telemetry (7.55)**: `internal/cloudserver/telemetry.go` counts uploads
  (created/duplicate/completed), analyzer runs and latencies (total + worst),
  parse failures, 4xx/5xx API errors, and storage failures. `serve` prints one
  fixed-shape count line per `-stats-interval` (default 1m, 0 disables) and now
  passes a stderr `logf` at all — previously production handler errors were
  discarded. No per-user dimension, no request content, no metrics endpoint.
- **Auto-upload and the local queue (7.46–7.49)**: new `internal/uploadqueue`
  (three states, atomic 0600 JSON file beside the credential file, bounded to
  500 entries) with exponential backoff 30s→1m→2m→4m and a hard 5-attempt cap,
  then `failed` until `queue --retry`. The agent hook is
  `IncidentPipeline.OnSaved`, which fires only after a bundle is `Complete`, so
  local persistence always precedes any network attempt. `login -auto-upload`
  opts in; `queue [--retry|--no-drain]` reports and drains. `runUpload` and the
  queue now share one `sendBundle` implementation.
- **Fixes found by running it for real**: Makefile published Postgres on host
  port 5432, which collides with a developer's local server (the migration then
  hit that server and failed with "role postgres does not exist") — now
  `CLOUD_TEST_PORT` (default 55432); the readiness probe used the unix socket,
  which initdb's temporary server also answers, so the first migration raced a
  "database system is starting up" (57P03) — the probe now goes over TCP.

### Verification

`make test-cloud` (Postgres 16 in docker, migrations applied twice, then the
suite) passes: `applied 0001_init` / `schema is current` / `ok runopsy/tests`.
The gated suite now also asserts search results and non-results from two
organizations, the telemetry counters after a real flow, the 7.36 matrix per
read path, dedupe (7.30), delete removing rows and objects, a byte-identical
download and hostile-storage refusal. `go test ./internal/uploadqueue` covers
offline-first, backoff bounding/terminal state, idempotent enqueue, missing
bundle, file permissions and the queue-size bound;
`go test ./internal/cloudserver` covers the filter renderer and the counters;
`go test ./cmd/runopsy-agent -run 'TestLogin|TestUpload|TestAutoUpload|TestQueue'`
covers the opt-in, the offline `queue` path and unchanged bundle bytes.
`gofmt -l .` clean, `go build ./...`, `go vet ./...` clean.

### Still open on engineering's list

- **Worker over HTTP / hosting** (contract §2.2): analysis runs in-process in
  `serve` today via the `JobRunner` seam; a separate worker service is the
  §8.1 hosting decision, not correctness work.
- **Re-analysis endpoint** (7.34): history model (`original_analysis_id`,
  `active_analysis_id`, `UNIQUE(upload_id, engine_key)`) exists; the endpoint
  does not.
- **Retention sweep** (7.58): manual delete is real and tested; time-based
  deletion is deliberately not built.
- **S3-compatible `Store`** (7.7): `LocalStore` only; the handlers are
  storage-agnostic.

## Phase 7 — adversarial slice (November 5, 2026)

adversarial's dashboard scaffold and its test-only and documentation items are in
`web/` and `docs/cloud/`. No Go code changed, and nothing is committed to git.

- **`web/`**: a React and TypeScript view layer over the `runopsy.analysis` v1
  documents. It only formats and filters; it does not diagnose (7.43). Types,
  guards, formatting, the timeline, incident and process lib, and 12 components.
  `npm test` passes 29 of 29: 6 fixture-contract tests against the 19 real
  documents, 13 unit tests, and 10 render tests. The key-shape golden file
  fails on any Go document shape change. Read `web/README.md` first.
- **Not verified:** the typecheck. The npm registry is unreachable from the
  scratch environment, so `@types/react` and `@types/node` were not installed.
  Run `npm install && npm run typecheck` on a machine with registry access.
- **Blocked or deferred:** the Next.js app and its routes; 7.36 and 7.40 need
  the live API; 7.23 needs a GitHub provider fixture; memory and I/O charts; 7.25
  search; the NO RX highlight needs socket receive counters the document lacks.
- **`docs/cloud/secrets-audit.md` (7.39):** three findings to fix on the Go
  side. (F1) `NormalizeEndpoint` echoes the raw endpoint, so userinfo in it
  reaches stderr. (F2) The storage-upload error wraps a transport error whose
  message can include the presigned URL and its signature. (F3) Server message
  text is printed to the terminal without filtering control characters.
- **`docs/cloud/authz-matrix.md` (7.36):** the access paths, the proposed 404
  for other organizations' objects, and eight two-organization cases. Design
  only; nothing has run.
- **`docs/cloud/upload-corpus.md` (7.40):** maps the sixteen contract §5.5
  cases to existing Go test names. Only names were read, so every mapping is a
  candidate. Six cases have no test by name, and two are only partly covered
  (old schema, forged identity). Schema-version decoders (§7.2) are not
  built, so the old-schema case cannot pass yet.
- **Open for the owners:** the privacy booleans cannot tell "redacted" from
  "never collected"; `causal.edges` is `null` when there are no accepted edges;
  `Snapshot.CaptureIndex` is 0 in every v1 bundle; three ground-truth
  mismatches (oom, cpu-spin, socket-stall) remain, and the CLI and the document
  agree with each other on all three. `analyze --document` is not in the CLI
  yet, so the fixtures were made with a scratch generator, and regenerating
  them is not reproducible from the repo.
- **Not done:** `docs/cloud/ux-copy.md` (7.45, 7.51–7.54). The checklist text
  for those items was not re-read in this session, so no copy was written
  from memory.

## Phase 7 status: contract + engineering backend slice 1–4 (November 5, 2026)

principal's design items are written up in `docs/cloud/contract.md`: 7.1 (cloud
boundary), 7.2 (architecture), 7.9 (parsing architecture), 7.38 (parser
isolation) and 7.34 (re-analysis), plus the constraints they put on 7.7, 7.8,
7.30, 7.33, 7.36, 7.37 and 7.43. The full design rationale is in the original
design entry below; engineering's implementation of queue items 1–4 is in the
"Phase 7 — engineering backend slice" section near the end of this file.

Still open from §9, in dependency order: adversarial scaffolds 7.3 (needs nothing);
**owner decisions §8** (worker hosting, auth provider, rate defaults) gate
engineering items 4-completion (migrations against live Postgres) and 5 (upload flow
+ dedupe) plus the worker's HTTP job endpoint. Items 1–3 landed this session;
item 4 is written as SQL in `db/migrations/` but has never been applied.

**Superseded November 5, 2026:** items 4 and 5 are now implemented and tested
against a real Postgres, together with search, telemetry and auto-upload — see
"Phase 7 — engineering backend completion" at the top of this file. The worker's HTTP
job endpoint and the hosting decision remain open.

### What the design decided (unchanged)

- **The cloud never diagnoses.** The Go analyzer produces a versioned
  *analysis document*; TypeScript only renders it. Today's `analyze --json`
  lacks the timeline, series, graph and evidence classes the dashboard needs,
  and the wiring that builds them lives in package `main`, so engineering's first
  task is `internal/analysis` + `analyze --document` (§3.3).
- **Engine identity is broken today.** `AnalyzerVersion` is still `0.3.3`
  although `SignatureVersion` went 4 → 5 on November 4, and the causal rule
  set has no version. Re-analysis (7.34) cannot name its engine until §4's
  identity and golden fingerprint test land.
- **Uploads go straight to storage** (Vercel Functions cap request bodies at
  4.5 MB; valid bundles reach 65 MiB). **Analysis runs in a separate worker**,
  one process per job: Fluid compute shares one process across concurrent
  invocations, so parsing inside the web app would mix organizations.
- **Measured costs** (§5.2): a 456 KB upload expanded to 30 MB and took
  7.5 s and 421 MB to analyze; reading, not diagnosis, dominates (duplicate-key
  scan 45 %, privacy re-check clones 29 %). Limits are therefore on parse time
  and memory, not bytes.
- **Isolation facts measured:** `RLIMIT_AS` cannot bound Go (1.5 GiB killed
  the analyzer at ~50 MB heap), so memory is bounded by the container cgroup;
  `RLIMIT_CPU` and `RLIMIT_NOFILE` work; a `CGO_ENABLED=0` build gives
  byte-identical output.
- **Compatibility hazards for later:** `Read` accepts only the current schema
  and re-applies the current redaction policy, so a version bump or a
  tightened policy would make stored bundles unreadable (§7.2).

**Owner decisions needed (§8):** where the analyzer worker runs (recommended:
container host, one request per container), the auth library or provider,
and the per-organization rate defaults.

**Next:** adversarial scaffold and §5.5 corpus through the worker; principal review
of engineering 1–3 (§9). engineering waits on §8 decisions for migrations, upload flow,
Docker/operator run notes.

### What engineering landed (contract items 1–4, full detail in the slice section)

All four landed; the completion entry at the top of this file supersedes the
"not yet applied" caveat for the migrations.

## Phase 6: real-runner job correlation closes (November 4, 2026)

The last Phase 6 gate row — GitHub job correlation on a real runner — is
closed, and the run found one remaining false claim.

- **Reproduction, traced.** `selfhosted-e2e` run `41950041166` on the Lima
  self-hosted runner (`runopsy-linux`), watched with `github watch --tracing
  proc`: the job correlated (`GITHUB_JOB_*` accepted/assigned/completed
  `SUCCEEDED`), the tracer was `active` (`proc_connector`, 280 traced exits,
  0 reported loss), and the analyzer still reported `PROCESS_GROUP_TERMINATION`
  at HIGH (0.80) / CRITICAL. The group was the job's own pgid 1434733
  (`JOB_ROOT` 1434733 plus `JOB_PROCESS` 1434740), both SIGKILLed by the
  runner as the job ended.
- **Why the earlier fixes missed it.** The job's tree sits in its own process
  group, so nothing survived and `groupMemberSurvived` never applied; the
  traced exits are `signal:9`, so `dropTracedNormalExits` (normal exits only)
  did not apply either. The job's stated success is the authority for the tree
  it started, but the cover named only the role-tagged worker/job processes.
- **Fix.** `IntentCover.JobTree` (cancel, timeout, success) plus
  `AnalysisContext.descendsFrom`: a stated job outcome covers the job's
  observed descendants, resolved from the capture's PPID lineage. A group the
  job did not start still reports in the same window.
- **Re-run, fixed.** `selfhosted-e2e` run `41950705732` on the same runner with
  the same watch flags: tracer `active`, 280 traced exits, analyzer matches
  `[]`.
- **Regression fixture.** The before-bundle is committed at
  `testdata/github/selfhosted-e2e-job-success/incident.runopsy` (provider
  identifiers withheld) with `TestRealRunnerSuccessfulJobIsNotAGroupKill`;
  the rule is pinned by `TestGroupKillJobTreeCoverExplainsTheJobsOwnGroup` and
  `TestGroupKillJobTreeCoverDoesNotExplainAnUnrelatedGroup`.
- **Checks:** `gofmt` clean, `go vet ./...` clean, `go build ./...` clean, full
  `go test -count=1 ./...` green. `-race` was not run for this change.

## Phase 6: arm64 VM check — live capture race found and fixed (November 4, 2026)

Running the full check on the Lima VM (kernel 7.0.0-34-generic, aarch64, Go
1.27.1, as root) instead of the skip-only default `go test ./...` surfaced one
real defect in the eBPF path. The e2e and the rest of the suite were green.

- **The defect: the watch ACK raced the kernel map.** With a tracer binary
  actually configured (`RUNOPSY_TRACE_BINARY`),
  `TestLiveShortLivedProcessCapture` and `TestLiveTracerOverhead` captured 0
  events (0/24 and 0/400 edges). The transport ACKed ADD/REMOVE/RESET as soon
  as `WatchSet::apply` returned; the eBPF pump only mirrored the set into the
  kernel `watched` map on its next loop iteration, after a ring poll that
  blocks first (up to `POLL_TIMEOUT_MS` = 100 ms). Any process that execed in
  that window was filtered as unwatched, and because the kernel never saw the
  watch, no loss counter moved either: silent absence, the failure mode
  6.23/§5.6 forbids.
- **The fix.** `WatchSet` tracks the highest version a backend has confirmed
  (`mark_synced`/`wait_synced`, Condvar-backed). The eBPF pump marks after
  each `sync_watch_map`; the transport waits for that mark before writing the
  ACK; a mirror that does not complete within 2 s produces an error ACK
  (`watch set not applied in the kernel: ...`) instead of `watches`. The proc
  connector filters in user space and is unchanged
  (`TraceBackend::watch_sync_is_kernel_visible`, default false).
- **Checks on the VM, as root:** `scripts/ebpf-e2e.sh` → `EBPF-E2E-OK`;
  `internal/trace` with `RUNOPSY_TRACE_BINARY` → ok (27.6 s; 24/24, 400/400,
  zero loss); `go test -race -count=1 ./...` → every package ok; `cargo fmt
  --check` clean and `cargo test --all-targets` green (one proc-connector
  short-lived test flaked once under load, 3/3 on rerun and covered by the
  full-suite pass). On macOS: `go build ./...`, `go vet ./...` and
  `internal/trace` green.
- **Why the earlier "green" claim missed it:** without a tracer binary every
  live test skips, so `go test ./...` on the VM exercised no kernel capture
  at all.
- **100k live churn (contract §14), both backends, same fixed tracer.**
  Unprivileged (uid 501, proc_connector): 52.4 s, 200,002 events, 0 lost,
  100,000/100,000 lifecycles, p50 44.5 ms, 5.5 MiB peak RSS, 40.8% of one CPU.
  Root (eBPF, all five capabilities attached): 51.9 s, 200,001 events, 0 lost,
  100,000 exec / 100,001 exit, p50 134.5 ms, 11.5 MiB peak RSS, 45.2% of one
  CPU. Both PASS. These are debug-build numbers (`make trace-churn-live`).
- **Two earlier churn runs lost events and accounted for them:** 199,999 and
  199,998 of 200,000 received; the session reported 2 and 3 missing sequence
  numbers (1 exec / 1 exec+1 exit missing). The invariant held, but the test
  failed both runs on two flawed gates: it treated *any* sequence gap as
  unaccounted even when the loss counters named it, and it failed reported
  loss whenever all 100,000 processes were captured (the watched driver
  shell's own exit lies outside the count, so `exit_pids` is `n+1`). Both
  gates now compare sink-observed missing sequence numbers with the session's
  accounting. The wait loop also stopped burning the full `30 s + n*3 ms`
  deadline whenever one edge was missing (it reported 5m30s for a ~105s
  burst); it now ends 2 s after the stream goes quiet.

Still open: GitHub correlation on a real runner.

## Phase 6: arm64 eBPF verified as root; signal/OOM evidence reaches Phase 3/4 (November 4, 2026)

Two items the principal re-review left open are closed.

- **Root eBPF on arm64.** On the Lima VM (Ubuntu, kernel 7.0.0-34-generic,
  aarch64) the release tracer built with the system clang and libbpf 1.6.3 and
  `sudo -n scripts/ebpf-e2e.sh` printed `EBPF-E2E-OK`: `capabilities` reported
  backend `ebpf` with exec/exit/signals/stop-resume/oom-kill all `attached`,
  and the live session captured `PROCESS_EXEC`/`PROCESS_EXIT exit=7`, an
  in-kernel `SIGNAL_SENT signal=15 fact=1` followed by `PROCESS_EXIT
  signal=15 fact=2`, the stop/resume pair, and a `tgkill`-delivered send.
  Every eBPF claim is now verified on both x86_64 and arm64.
- **H12: op 7 on the Go control decoder.** `OpAddCgroup` (ADD_CGROUP) is
  accepted by `decodeControl`/`decodeAck` and labelled `ADD_CGROUP`; the Rust
  test mirror accepts the same op. Unknown ops still end the session. The
  agent does not send it yet (cgroup watches are later), and a backend that
  cannot filter by cgroup refuses it in the ack.
- **Signal and OOM evidence feed Phase 4.** `SIGNAL_SENT` and `OOM_KILL` trace
  events now enter the causal timeline with exact identity and bundle
  provenance. New rule `SIGNAL_TERMINATES_PROCESS@1` (HIGH) pairs a send with
  an exit whose own wait status says it exited by that same signal; group
  sends bind through the member's PGID. `OOM_CAUSES_PROCESS_EXIT@2`, dormant
  in v1, now fires on the tracer's `oom:mark_victim` record: the victim
  discriminator answers PRESENT only for a record that names an identity, so
  the sampled cgroup counter still stays with `CGROUP_OOM_KILLS_MEMBER@1`.
- **Signal/OOM evidence feeds Phase 3 diagnosis.** `OOM_KILL@5`: a direct
  victim record is its own evidence code (`KERNEL_OOM_VICTIM_OBSERVED`, weight
  0.60, cap 0.95), lifting the cap that exists for the counter/no-evidence
  case. A record naming another incarnation of the same PID changes nothing.
- **A real permission refusal (H9) reproduced.** Kernel 7.0 allows an
  unprivileged connector subscribe and answers ECONNREFUSED in a non-initial
  netns, so EPERM cannot come from the connector's capability check there. A
  seccomp filter denying `bpf()` and `socket(AF_NETLINK)` produces the real
  kernel EPERM instead: the unmodified tracer classifies it as `insufficient
  permission: ...`, and the agent degrades once to `unavailable` with
  "continuing in polling mode" and no restarts
  (`TestFallbackOnRealPermissionRefusal`, Linux-only). An unforced EPERM is
  also visible under `unshare -U --map-root-user`, where `bpf_object__load`
  fails and the tracer falls back to the connector.
- **Checks:** `gofmt`/`go vet`/`go build` clean; full `go test ./...` green;
  `cargo test` green; the arm64 e2e script passes.

Still open: GitHub correlation on a real runner.

## Phase 6: principal re-review done, §11.1 complete — Phase 6 queue closed (November 3, 2026)

The last items in contract §14 are done. Findings in
`docs/reviews/phase6-principal-rereview.md`; contract §11.1, §13 and §14 updated.

- **eBPF run live as root** on Linux 6.18/x86_64 (libbpf built from source
  in the sandbox). That is also where engineering's E2E ran: the eBPF backend has
  **still never run as root on the arm64 Lima VM**.
- **Six eBPF defects fixed**, each failing the extended
  `scripts/ebpf-e2e.sh` on the old tracer: stop/resume named the parent
  and never reported a resume; unwatched stops leaked; a pidfd send was a
  "group 13" send (and `kill(-1)` would be "group 1"); a dead watched PID
  produced fake WATCH_FULL loss and an any-identity entry. Also: full kernel
  watch map now counted, stale fork entries overwritten, callback panics
  contained, `build.rs` derives the BPF arch, debug output shows sender and
  pgid for sends.
- **Merge:** a pair with both identities unknown is refused when polling saw
  the PID reused in the window; `Merge` no longer reorders its inputs;
  bundles keep a send's `sender_pid` and `target_pgid`.
- **§11.1 complete, two real defects fixed:** a crashed tracer's
  already-written events were discarded (114 of 100,000 in the new test;
  now drained); a re-push after a restart carried bare PIDs, so a reused PID
  was adopted. The agent now pushes `(pid, start_ticks)`; the tracer refuses
  stale PIDs one by one in a new optional ACK field `stale`, and the agent
  drops and counts them (`watches_stale`). The tracer used to refuse the
  whole ADD, which would have looped restarts.
- **Checks:** Rust fmt/clippy clean, 27+8+5 tests; full Go suite green
  except three environmental tests (same with the old tracer); live trace
  tests pass on eBPF and the proc connector. Two load-only flakes seen once,
  not reproduced (details in the review).

Still open, outside the Phase 6 queue: a root eBPF run on arm64 (Lima), a
real EPERM (H9), op 7 on the Go decoder (H12), Phase 3/4 consumption of
`SIGNAL_SENT`/`OOM_KILL`, GitHub correlation on a real runner. The new
agent and tracer must ship together (the per-PID `stale` refusal).

## Phase 6: integration 100k churn run complete on the Lima VM (November 3, 2026)

The last integration item in contract §14 is measured. On the Lima Ubuntu VM
(kernel 7.0.0-34-generic, 4 vCPU) as **uid 501 with no capabilities**, eBPF
was refused for lack of `CAP_BPF`/`CAP_PERFMON` and the proc connector was
selected with that reason. A watched shell ran **100,000** back-to-back
`/bin/true` processes, each child watched through fork inheritance:

| `net.core.rmem_max` | Wall | EXEC pids | EXIT pids | Loss | Tracer CPU | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| 212992 (stock) | 56.2 s | 100,000 | 100,001 | 0 | 12.63 s (22.5%) | 5,164 KiB |
| 4,194,304 | 52.8 s | 100,000 | 100,001 | 0 | 12.36 s (23.4%) | 5,168 KiB |

- **Complete coverage at stock `rmem_max`**, so steady churn at ~1,800
  processes/s fits the 208 KiB buffer; the 20% loss principal measured was a
  200-process *burst*, which this run does not re-measure.
- **Memory is flat** at 1k and 100k processes, so neither the identity cache
  nor the watch set grows with churn.
- **The run found a real defect:** `Session.Err()` consumed the publish-once
  that closes `Done()`, so a status reader polling a healthy session left
  `Close()` blocked forever. Fixed (`errMu` guards the value; `errOnce` only
  publishes), with `TestErrOnLiveSessionDoesNotWedgeShutdown`.
- **Harness added:** `TestLiveChurn` (`RUNOPSY_LIVE_CHURN=N`, opt-in) plus
  `make trace-churn-live`; it asserts accounted loss, flat memory, one stream,
  and the 6.50 CPU budget. Numbers: `docs/tracing/benchmarks.md`. Findings:
  `docs/reviews/phase6-integration-churn.md`.

Still open for Phase 6: the principal re-review (merge + eBPF sources) and the
§11.1 cases the isolation suite does not reach (queue fill, 100k events
queued at a crash, PID reuse across a restart).

## Phase 6: remaining engineering items closed — §9.1 merge identity, Go-side §6.3 b enforcement, H10 (November 3, 2026)

Three items from the phase-6 review ledger are closed in this sweep:

- **§9.1 merge identities (H7, contract §14 item 5 tail).** The merge no
  longer pairs a zero `start_ticks` with a known identity on PID and time
  alone. A pair merges only when the identities are compatible (contract
  §4): equal known start times; and when one side is unknown, only when the
  known identity's observed lifetime — built from the polling stream itself
  — covers the event time (first sighting relaxed by one dedup window,
  because differ observations are stamped after the fact) with no other
  identity of that PID plausibly owning the event. Otherwise both facts
  survive and `Event.Conflicts` records why
  (`merge_identity_mismatch/uncovered/ambiguous`, closed vocabulary, bundle
  validation enforces it). The skipped adversarial test
  `TestMergeUnknownIdentityGapKnownToday` was replaced by four unskipped
  tests (refusal, covered pair, already-exited identity, PID-reuse
  ambiguity). The snapshot interval half of §9.1 stays an approximation by
  the dedup window; the identity half is enforced exactly.
- **Go-side §6.3 b identity enforcement (H11).** `internal/trace` decodes
  `boot_id`, `pid_namespace_inode` and `event_clock` plus the per-capability
  `{state, reason}` pairs the Rust handshake already sends, and enforces
  them: a tracer from another boot (stale socket surviving reboot), another
  PID namespace, or another event clock is refused with `ErrIdentityMismatch`
  at `Connect`; capability states that contradict their booleans are
  protocol violations. Each irreversible fact check uses only when both
  sides know ("unknown", never guessed). The supervisor treats an identity
  refusal as machine-permanent: it degrades once to unavailable with the
  GaveUp flag and a polling-mode reason instead of spending the restart
  budget. Agent identity is read the same way the Rust tracer reads its own
  (`internal/trace/identity.go`); the source is a seam so the refusals are
  testable on any host. Tests: refusal per cause, coherent handshake,
  unknown-not-guessed, vocabulary forward-compatibility, and a manager-level
  degrade test using the re-exec fake tracer with a foreign `boot_id`.
- **Acceptance-matrix flake (H10).** Two causes, both fixed. (1)
  `tests/phase2_matrix_test.go` asserted the process-exit case on
  `PROCESS_EXITED` only; with the tracer on PATH the §9.1 merge lets
  `TRACE_PROCESS_EXIT` own that entry when it arrives inside the capture
  window, so the assertion passed/failed depending on tracer arrival timing.
  Both sources of the same fact are now accepted. (2) Reproduced on the Lima
  VM on 2026-11-04: every case watches the same process name, so a leftover
  simulator from an earlier case can exit first and trigger a bundle;
  `waitForBundle` returned whichever bundle appeared first, and the
  process-exit assertions then ran against an incident that had no event for
  this case's PID. The case now waits for the bundle that carries its own
  simulator's exit (`waitForBundleOfProcess`). Verified with two race-enabled
  matrix runs, and the full `go test -race ./...` plus
  `cargo test --all-targets` passed on the VM afterwards.

Still open, as before: the Rust eBPF live path needs the Lima toolchain
(host covered by the November 3 entry), H9's real EPERM needs a host where
the connector is restricted, and H12 (op 7 on the Go control decoder) stays
latent until cgroup watches land.

## Phase 6: 100k churn reproduced at stock `rmem_max` (November 4, 2026)

The unprivileged 100k churn was re-run on the Lima VM (kernel 7.0.0, 4 vCPU)
as uid 501 with `net.core.rmem_max` set to the stock 212,992 bytes (the VM's
4 MiB sysctl was restored afterwards), against a **release** tracer built
from the current tree:

- run 1: 53.2 s, 200,001 events, 100,000/100,000 exec and 100,001 exit pids,
  0 gaps, 0 upstream drops, p50 48.4 ms, 11.91 s CPU (22.4%), 5,160 KiB peak
- run 2: 50.6 s, 200,001 events, same coverage, 0 gaps, 0 upstream drops,
  p50 62.3 ms, 11.62 s CPU (23.0%), 5,116 KiB peak

Both exited 0. At ~3,800–4,000 events/s the 208 KiB socket buffer is
sufficient, so the burst loss principal measured is a burst property, not steady
churn; the accounted-loss gate from the previous entry still holds. Numbers
and caveats: `docs/tracing/benchmarks.md`.

A full `go test -race -count=1 ./...` on the VM then passed every package,
and `cargo test --all-targets` passed all five suites. That run also exposed
a second, separate silence-watchdog test flake:
`TestIsolationSilentTracerIsRestarted` required a single health snapshot with
`ConsecutiveFailures > 0`, the "silent" reason, and `Attempts >= 2`, but a
successful reconnect resets the streak and keeps the stale reason, so the
condition only existed in a ~10 ms backoff window of the *second* 5 s silence
cycle and timed out under `-race` with a slow re-exec. The test now observes
the teardown and the rebuild as two separate states; the supervisor's
behaviour is unchanged (three race-enabled runs pass).

## Phase 6: real-runner correlation and kernel-evidence follow-ups (November 4, 2026)

The last ◐ row — GitHub job correlation with tracing active — was executed on
the live self-hosted runner (`runopsy-lima-runopsy`, label `runopsy-linux`,
`selfhosted-e2e` workflow), as uid 501 with `--tracing auto`:
`proc_connector`, 490 events, 0 lost. **Correlation holds:** the job was
accepted, assigned and completed `SUCCEEDED`, the worker and its tree were
linked, and the report's trace section read `active (proc_connector)` with
complete coverage. **One failure claim is still wrong:** GitHub's runner
SIGKILLs leftover job processes as normal cleanup when a job ends, so the
kernel records `TRACE_PROCESS_EXIT signal:9` for both members of the job's
process group (pids 1431156/1431163, start_ticks 33838040/33838041 in bundle
`inc_64905f…`) and `PROCESS_GROUP_TERMINATION` fires at 0.60 CRITICAL on a
`SUCCEEDED` job. The signature now treats a traced *normal* exit (`exit:<code>`)
as an explained departure (`dropTracedNormalExits`; tests cover normal and
signalled exits), but this case is a genuine SIGKILL, so the remaining fix is
for a stated job completion to cover its whole tree — the rule the Phase 5 S2
notes describe, which does not fire because the job's processes are in their
own process group rather than the listener's.

A third 100k churn run at stock `rmem_max` (release tracer, host also running
the Go race suite) delivered 98,048/100,000 processes with 3,904 gaps and
3,905 upstream drops, all at stage `queue`; `/proc/net/netlink` reported 0
drops and `Rmem` peaked at 37,440 bytes. The loss was the tracer's bounded
queue, accounted and reported, and the test now puts both numbers in its
notes. The two quiet stock-buffer runs were lossless (100,000/100,000, 0
gaps). The churn harness also records the driver's own spawn count and skips
with it when the driver could not produce the burst, so an environment limit
is no longer reported as silent tracer loss.

`go test -race ./...` passed on macOS (exit 0), and the Linux VM's full race
suite plus `cargo test --all-targets` passed earlier in the same sweep.

## Phase 6: engineering item 4 closed — eBPF backend live against a real kernel (November 3, 2026)

The eBPF backend (contract §2, engineering queue item 4) is implemented, compiles
with the real toolchain, and passed a live E2E on the Lima VM's kernel
6.18/x86_64: `scripts/ebpf-e2e.sh` drives a watched shell subtree through
`exit(7)`, a child exec, `kill -TERM $$`, and the tracer reports the full
ordered chain — `PROCESS_EXEC /bin/sh`, `PROCESS_EXIT exit=7`, child
`PROCESS_EXEC /bin/sleep`/`exit=0`, `SIGNAL_SENT signal=15 fact=1`,
`PROCESS_EXIT signal=15 fact=2` — with clean sequence numbers and zero
unrelated-sender leakage. Unprivileged, `runopsy-trace capabilities`
refuses with the privilege reason and selects the proc connector; as root
all five capability rows report `attached`.

- **BPF programs** (`trace-rs/src/ebpf/runopsy.bpf.c`, CO-RE with the
  committed vmlinux.h): `sched_process_exec`, `sched_process_exit`
  (`group_dead`), raw `sched_process_fork` (in-kernel watch inheritance),
  the six kill-family enter tracepoints + six exit tracepoints for
  `SIGNAL_SENT` (sender-gated by identity, answered by rule-1 `si_code`
  marking in `signal_generate`), stop/resume confirmations via
  `SIGCHLD`/`SIGCONT`, and `oom:mark_victim`. Kernel-side adaptations that
  only a real BTF can teach: 6.18's `signal_struct` carries the group pid
  as `pids[PIDTYPE_PGID]->numbers[0].nr` (there is no `pgrp`, and `struct
  pid` has no numeric field), and the raw-fork context is the raw args
  array, so child resolution reads `args[1]`, not pointer arithmetic.
- **Loader/FFI** (`trace-rs/src/libbpf.rs`): hand-rolled FFI against the
  system `libbpf-dev` 1.x — no new crates.io dependency and the crate
  builds dependency-free as before. `build.rs` compiles the C package with
  `clang -target bpf` and refuses quietly when the toolchain is absent:
  the binary then reports the backend unavailable with the reason and the
  proc connector serves, instead of failing to build.
- **Rust pump** (`trace-rs/src/ebpf_backend.rs`): attach with per-capability
  honesty (a capability is `true` only when its program linked), ring-buffer
  pump through the same bounded publish path as the proc connector (source
  `SOURCE_EBPF`, sequence stamped before the bounded enqueue), watch-set
  control mirroring the agent's set into the kernel map, and gofmt-equivalent
  hygiene: `cargo fmt` clean, `cargo clippy` zero warnings, `cargo test`
  green on Linux; no Rust source change touched the wire format.
- **Toolchain honesty note:** libbpf 1.x exports the ring-buffer API
  *without* the `bpf_` prefix; the FFI symbol names were fixed against the
  installed header (`ring_buffer__new/poll/free`). The `Reviewed-by:`-style
  stats map (`STAT_*_SEEN/WATCHED`) is for bpftool diagnosis and never
  crosses the wire.
- **Checks:** BPF C compiles under `clang -target bpf` (0 errors); Linux
  `cargo fmt --check`/`clippy -D warnings`/`cargo test` green; live E2E
  green as above; Go side unchanged and green (`gofmt -l` empty, `go vet`,
  `go build`, full `go test ./...`). CI gains the `clang`/`libbpf-dev`
  toolchain in the `trace-rs` job, an embedded-object check, and a new
  `trace-ebpf-live` job (capabilities + `scripts/ebpf-e2e.sh` on
  `ubuntu-24.04`).
- **Docs:** `docs/tracing/ebpf.md` status block now describes what the
  binary does; `docs/tracing/fallback.md` carries the real privilege
  requirements; `docs/tracing/contract.md` §2 has an implementation-status
  note.

## Phase 6: engineering protocol/supervision sweep closed (November 2, 2026)

Contract §6.3 a–f are implemented in both languages, verified against the
production binary. engineering queue items 2 and 3 are done; the eBPF backend
(item 4) is closed too (see the November 3 entry above), which completes
the queue.

- **Supervised tracer mode (§6.3 a, 6.39/6.40).** `runopsy-trace
  --supervised` arms `PR_SET_PDEATHSIG(SIGKILL)` (plus the fork→prctl race
  check), serves exactly one session, and dies with the agent; a refused
  pdeathsig or a dead-at-startup parent is a hard refusal. `Tracer.serve` is
  standalone-only. Fixed in the sweep: a SHUTDOWN now ends the pump even
  when the client keeps the socket open — previously the tracer hung in
  accept after a clean shutdown ack if the agent did not disconnect.
- **Handshake identity + negotiation (§6.3 b, §6.4).** The reply carries
  `boot_id`, the PID-namespace inode and `event_clock`; the Go manager
  refuses a tracer from another boot. Negotiation is a range overlap on
  both sides (a 1..1 agent meets the 2..1 tracer at protocol 1 and never
  sees protocol-2 frames).
- **LOSS/HEALTH frames (§6.3 d/e, 6.25–6.27).** Rust emits LOSS on every
  stage-counter move and HEALTH once a second; the Go session decodes both,
  surfaces loss stages in session status, and treats 5 s of frame silence
  as a hung tracer, which the manager supervises.
- **Control-path bounds + identity (§6.3 c/f, 6.23).** The pump forces a
  control read at least every 256 drained events (acks cannot starve under
  backlog); ADD is identity-keyed — the agent sends `start_ticks`, the
  tracer verifies against `/proc` and answers `STALE_IDENTITY: pid ...` in
  the ack when a watch would adopt a dead or recycled process. The Go
  watch tracker carries start-ticks and treats the error ack as a
  counted refusal, never a silent drop.
- **Crate is library + binary (finding O17).** `src/lib.rs` exports the
  schema/framing/transport, and the integration tests speak to the
  production `runopsy-trace` server: Go's exact control framing, ack field
  names, null-vs-absent `pids`, refused-handshake survival, and SHUTDOWN
  semantics, end to end (`trace-rs/tests/wire_compat_test.rs`).
- **Verified:** `cargo fmt` clean, `cargo clippy --all-targets` zero
  warnings, full `cargo test` green (20 tests incl. the live-server ones);
  `gofmt -l` empty, `go vet` clean, `go build ./...`, and `go test
  -count=1 ./...` green (16 packages with tests).

## Phase 6: engineering item 5 closed — merge and causal integration live (November 2, 2026)

The tracer→bundle→causality loop is now wired end to end; the eBPF backend
(contract §2) landed on November 3 (see the top entry), completing Phase 6's
engineering queue.

- **Agent wiring completed (O5 remainder, 6.21/6.23/6.29/6.47).** The `start`
  event sink feeds `capture.ObserveTrace`; the desired watch set is the
  filter's own selection — the same processes the bundle records — synced on
  change through `Manager.Watches()` (Rust inherits children at fork and
  forgets exits, so no per-child round trip). The stale "not merged yet"
  warning is replaced by a watch-set warning when tracing is on with no
  filter selected (6.22).
- **Causal extraction consumes the merged stream (O22, §6.33/6.34).**
  `TRACE_PROCESS_EXEC/EXIT/STOPPED/RESUMED` map onto the existing
  `PROCESS_*` vocabulary with tracer start-tick identity, recorded wait
  status (`exit_state`) and typed PGID, so signal-bound rules, group folding
  and frozen-episode recovery work on kernel-direct evidence. Provenance
  refs are unchanged (`event:<index>`), so the direct-vs-inferred report
  classifies these as kernel trace with no new plumbing. `SIGNAL_SENT` and
  `OOM_KILL` stay bundle-viewport facts until rules consume a standalone
  sender fact and the tracer carries cgroup identity.
- **Connect-time watch gate (6.23).** A fresh session is driven from RESET
  only when the desired set is non-empty: a new tracer process owns an empty
  set by construction, so "nothing to apply" no longer blocks activation.
  A set that becomes empty later is still cleared through the watchCh drive.
  Regressions: `TestActiveSessionWithEmptyWatchSet`,
  `TestWatchSetRefusalIsVisibleAndKeepsSupervision`.
- **Recorder honesty in the bundle (6.27/6.48).** The capture's own
  refusals (closed buffer, out-of-order delivery, section bounds) now land
  in the tracing section as `capture_lost`, reported separately from the
  tracer's wire losses, and the analyzer prints \"Recorder dropped\" and the
  incomplete-coverage consequence when it is non-zero.
- **Verified:** gofmt/vet clean, `go build ./...`, full `go test -count=1
  ./...` green (18 packages), plus a start smoke run: tracing auto-resolved,
  watch filter applied, honest Linux-only degradation, recording intact,
  exit 0.

## Phase 6: secondary's lane complete (November 2, 2026)

**secondary's Phase 6 items are done and green; Phase 6 as a whole is still not
acceptable** (eBPF backend and the timeline/bundle merge remain). Findings and
verification: `docs/reviews/phase6-secondary-audit.md`.

- **Two S1 cross-language defects found and fixed.** `Control.PIDs` lacked
  `omitempty`, so Go sent `"pids":null` and the Rust decoder (which takes a
  `Vec`) rejected it: PING, SHUTDOWN, FLUSH and empty RESET would have ended
  the session on first use. Go now omits the field and Rust accepts *and*
  normalizes `null`/absent. The reason it survived four reviews: the Rust
  "cross-language" suite decoded its own mirror structs, never the shipped
  code. `trace-rs/tests/wire_compat_test.rs` now drives the production binary
  (`replay` and `--socket`) with Go's exact bytes, and Go pins the same golden
  literals, header and control bytes.
- **Replay policy unified (S2).** Rust replay aborted on the first undecodable
  event payload while Go counted it and continued; both now count and continue
  on a bad *sample* and abort on a broken *frame*.
- **`start` now runs the tracer (6.21/6.46).** `--tracing MODE` and
  `--trace-debug-output FILE`, supervisor restarts/backoff, debug recording in
  the replayable frame format, `tracing` reliability section stamped from
  health after the tracer stops, and a final tracer log line. Trace events are
  counted, **not** merged into the timeline or bundle stream yet — that is
  6.29/6.47 (engineering), and start warns about it rather than implying otherwise.
- **Also delivered:** 6.44 fixtures (production encoder + Go decode),
  6.55 Rust CI (fmt, clippy `-D warnings`, all targets, live job),
  6.58 `runopsy-agent trace status|capabilities|replay`, 6.62 direct-vs-inferred
  report, and 6.63 docs including `docs/tracing/ebpf.md` and
  `docs/tracing/permissions.md`.
- **Residuals, recorded not hidden:** the agent's handshake `monotonic_ns` is a
  wall-clock reading (ordering is safe, the 6.49–6.51 latency anchor is not,
  across a clock step), and `runopsy-agent status` still does not show tracer
  health (6.38).

## Phase 6: principal decisions and review (November 2, 2026)

**Phase 6 is not acceptable yet.** The slice that landed is well structured,
but it had never met a real kernel, and nothing in the agent uses it.

- **Decisions** are in `docs/tracing/contract.md`:
  - **scope (6.2):** exec, process exit, signals sent/generated/delivered,
    stop/resume and OOM; with explicit non-goals.
  - **backend (6.17):** eBPF is required for acceptance, with the proc
    connector as fallback, using `libbpf-rs`.
  - **encoding:** JSON stays for Phase 6; protobuf would be the Go module's
    first dependency.
  - **signal semantics:** sent, queued and delivered are three facts, never
    interchangeable.
  - **identity, watch-set, loss/coverage and clock rules.**
  - **evidence quality (6.32)** and **compatibility policy (6.57).**
- **Fixed in the tracer, verified on a live 6.18 kernel:**
  - exits are decoded now. The exit constant was wrong (O1) and so was the
    field layout (O2); no exit was ever recognized before.
  - thread exits are no longer process exits (O3).
  - children of watched processes are watched from fork; before this, nothing
    born after the agent's last update was seen (O4).
  - kernel-side drops are now visible gaps, and the receive buffer is raised
    to 16 MiB; a 200-process burst used to lose about 20% of its exits (O7).
  - a session's first event is sequence 1, on both sides (O8).
  - events carry the process identity, with a check against PID reuse (O9).
  - events carry the kernel's own timestamp (O10).
  - the watch set is reset per session (O12).
  - a missing binary degrades at once instead of spending 3.75 s of restart
    backoff (O16).
  - Ctrl-C works in debug mode (O19).
- **Measured:** 100,000/100,000 short-lived processes captured with no loss,
  about 7% of one CPU and 2.6 MiB that does not grow. The Go live tests pass
  against the real tracer for the first time.
- **Next, for engineering:** wire the tracer into the agent, with `--tracing`, the
  watch-set push, trace events into bundles, and `TracingSource` (O5). Then
  the protocol items (O13–O15), the crate as a library plus a binary (O17),
  and the eBPF backend. Full queue: contract §14. Findings:
  `docs/reviews/phase6-principal-review.md`.

## principal review of secondary's L1–L6 (November 2, 2026)

Phase 5 acceptance stands, with two corrections to secondary's fixes
(`docs/reviews/phase5-principal-audit.md` §6):

- **O1 (L6 regression).** The report header dropped every job that had no API
  timestamps, so the gated `TestPhase5GitHubEndToEnd` failed. The header now
  also uses the job's events and its worker's lifetime.
- **O2 (L2 misattribution).** A cgroup OOM rise was given to a sibling still
  listed one sample after the real victim left. The rise is now attributed to
  the victim.
- **O3.** `JOB_SUCCEEDED` is documented in architecture §10A.5.
- **O4.** PGID reuse in `groupMemberSurvived` is noted and accepted.

The full suite, race, the gated suites and the darwin build all pass.

## Phase 5 closed: B3 and secondary's audit (November 2, 2026)

**Phase 5 is accepted.** B3 passes on the disposable real runner and secondary's
final-audit share is delivered (`docs/reviews/phase5-secondary-audit.md`). The next
phase can start; nothing in Phase 5 is waiting on a model.

- **B3 complete, S2 and S11 fresh on the fixed binary.** S2: run `41520612730`,
  bundle `inc_9eb4…` — job correlated, `SUCCEEDED`, no failure claim. S11: run
  `41520844407`, bundle `inc_11667c…` — `OOM_KILL` alone at HIGH (0.80),
  CRITICAL, `KERNEL_OOM_COUNTER_ROSE oom_kill_delta=1`, host memory 98.84%,
  victim `pid 212932 rss 81%`, job context `FAILED`. The other ten scenarios
  keep their records, and the 15 bundles still on the two VMs were
  re-analyzed offline (`docs/github/real-runner-verification.md` §8).
  `SignatureVersion` is 4.
- **S12 assignment stall, injected for real (2026-11-02).** Run `41528651092`:
  `bin/Runner.Worker` was replaced with a script that never becomes a worker
  process, so the listener accepted the job at 21:28:57Z and no worker ever
  appeared. A manual capture (`inc_013169…`, 90 s pre-window) reports
  `GITHUB_JOB_ASSIGNMENT_STALL` at MEDIUM from `WORK_ASSIGNED` +
  `GITHUB_JOB_ASSIGNED`, no worker event in the timeline, and
  `BROKER_SOCKET_STALL` at 0.00 — the assignment label 5.20 promises, not the
  generic socket stall. Job identity stays `UNKNOWN` because a job ref is
  worker-bound (5.10 allows it). The binary was restored (`sha256 72efd98d…`)
  and run `41529045808` succeeded afterwards (`inc_e78d6a…`: worker bound at
  21:31:05.8Z, `Job outcome SUCCEEDED`), so the injection left no residue.
- **Four defects, each reproduced from a real bundle:**
  1. **S2 false group kill.** GitHub does not put a job in its own process
     group, so a job's shell, the worker and the listener share one PGID; any
     normal teardown looked like `PROCESS_GROUP_TERMINATION` (HIGH 0.80,
     CRITICAL) on a successful job. The rule now also requires that no member
     of the group survives the coordinated departure, and a stated success
     covers the worker's tree (`signatures_files.go`,
     `internal/diagnosis/group_subtree_test.go`).
  2. **S11 missed the OOM counter rise.** A sample reads the process table
     before the cgroup counters, so the victim's last-seen sample can already
     carry its own kill; the old baseline skipped that reading
     (`kernelOOMRise`, `internal/diagnosis/oom_counter_test.go`).
  3. **One slow `Observe` killed the provider session for good.** A single
     overrun under memory pressure abandoned the GitHub session, and every
     later capture carried `UNAVAILABLE` with 0 events — 49,578 snapshots
     dropped, including two successful runs on 2026-11-02. `OverrunGrace`
     (10× the budget, 2 s floor) now degrades that section only; a call that
     also overruns the grace is still abandoned (`internal/provider/supervisor.go`).
  4. **A runner self-update was a group kill.** The tree-ending intents
     (shutdown, update, ephemeral completion) covered only the supervisor, so
     the untagged job processes that left with the tree formed a failure
     anchor. `intentCoversRole` widens those intents to worker/job roles, and
     the causal engine covers the named process's group
     (`IntentCover.RunnerTree`, `Graph.coversGroup`) without silencing an
     unrelated group.
- **Two fidelity fixes:** a `TIMED_OUT` outcome upgraded from the check-run
  annotation is now attributed to `PROVIDER_API` (it used to claim
  `RUNNER_LOG`, which only ever said `cancelled`), and the report shows only job
  records that ran inside the capture, each with its `ref` (a capture with no
  job of its own used to print the previous day's `FAILED` job).
- **Verification:** `go build ./...`, `GOOS=linux GOARCH=arm64 go build
  ./cmd/runopsy-agent`, `go vet ./...`, `gofmt -l` clean, `go test -count=1
  ./...` green (macOS). Provider cost per sample: idle 77.7 µs, active job
  254.7 µs, multiple runners 312.5 µs, churn 148.1 µs, `Freeze` 12.9 µs.
- **Residual risks (documented, not blocking):** macOS runner identity is
  PID-only; no real container runner was exercised; the stored `s4-enriched`
  bundle keeps its old provenance until it is re-enriched; no second self-update
  run (the 2026-11-02 bundle is the evidence); an assignment stall
  (`GITHUB_JOB_ASSIGNMENT_STALL`, S12) names no job, because a job ref is bound
  to a worker and a stall has none; the report header lists every runner
  installation on the host, which is noisy on a VM with old checkouts.
- **Cleanup owed:** the throwaway repo `13eth-a/runopsy-runner-e2e` still
  exists (`gh` lacks the `delete_repo` scope), and both Lima VMs still run
  runners (`linux` = `runopsy-b3-vm`, `runopsy` = the earlier runner).

## Phase 5 code items closed (principal, October 31, 2026, evening): only B3 and secondary's share remain

- **F2 fixed:** a docker container step that cannot be attributed to one job
  now marks every job that was running then with
  `CONTAINER_LINKAGE_UNAVAILABLE`, instead of leaving the process list silently
  incomplete on cgroup hosts.
- **F3 fixed:** `RUNOPSY_GITHUB_STALL_WINDOW` below 10 s keeps the 2-minute
  default.
- **F4 fixed:** the window in force is recorded as
  `stall_window_seconds` in the provider section (bounded 10 s to 24 h). Older
  agent binaries reject the new field, so rebuild every agent that reads new
  bundles.
- **F5 fixed:** `GITHUB_RUNNER_SELF_TERMINATION` cites the new
  `SUPERVISOR_EXIT_OBSERVED` code.
- **5.45 verified:** `cmd/runopsy-agent/timeout_e2e_test.go` proves a stated
  timeout covers the job's SIGKILL in `timeline` and `analyze`, and that a
  statement minutes later does not.

The `principal_final_audit_test.go` gates are removed; the tests run in the default
suite. **Remaining for Phase 5 acceptance:** B3, the scenarios in
`docs/github/real-runner-verification.md` not yet run or passed on the VM, and
secondary's final-audit share.

## B3 re-run: S2 fails, S11 not confirmed on a fresh run (November 1, 2026)

- **S2 (healthy) fails.** The job correlates and succeeds, but the analyzer reports `PROCESS_GROUP_TERMINATION` at HIGH/CRITICAL on a successful job (bundle `inc_4b51cffb…`). It treats the normal exit of three processes in one pgid as a termination. Needs a fix in the process-group signature, then a re-run.
- **S11 (memory) is not confirmed on a fresh run.** Run `41264326503` failed and the bundle has `OOM_EVENT`, but `OOM_KILL` is rejected with "kernel OOM event and exit cause are unavailable", and `KERNEL_OOM_COUNTER_ROSE` is absent. The earlier pass was a re-analysis of an older bundle. The same false `PROCESS_GROUP_TERMINATION` also appears.
- The VM agent was rebuilt from the Mac source. The runner is registered, and the watch was restarted with `--interval 250ms --trigger-on-process-exit`.
- S1, S3–S10 were not re-run in this pass. Earlier results in §7 of the runbook still stand as recorded there.

## B3 finished on the VM (October 31, 2026)

- **S3 (cancel) passes** on a fresh run: `41261769205` cancelled from the UI; bundle `inc_9c0ade…` records `CANCELLED` with no false failure signature.
- **S4 (timeout) now reported as `TIMED_OUT`:** `api.go` fetches the job's check-run annotation and marks a job `TIMED_OUT` only on "exceeded the maximum execution time"; any lookup failure keeps `CANCELLED`. Run `41262653679` was enriched with `github api-enrich --repo`, which reports `Job outcome TIMED_OUT` (source `PROVIDER_API`). The capture itself does not call the API. Still open: no signature names a timeout.
- The runner is deregistered and its service is removed. The throwaway repo `13eth-a/runopsy-runner-e2e` still exists: `gh` lacks the `delete_repo` scope (`gh auth refresh -h github.com -s delete_repo`, then delete it).

## S10 and S11 causes found, fixed, and confirmed on the VM (October 31, 2026)

Details and re-run steps: `docs/github/real-runner-verification.md` §7.

- **S10 (communication stall), three defects:** (1) `sectionEvents` dropped
  the stall onset whenever the capture started after it, which a capture
  following a 3-minute block always does; an episode still open at the window
  start now keeps its onset. (2) The wedge rule treated the keepalive timer as
  stuck, which could report a healthy idle long-poll as a stall. (3) Idle pooled
  HTTPS sockets stay ESTABLISHED through an outbound DROP and masked the
  outage; the runner's own unanswered "Runner connect error" (30 s grace) now
  opens the episode. Code: `commstall.go`, small edits in `controlchannel.go`
  and `session.go`. Tests: `commstall_test.go` (four fail on the old code).
- **S11 (OOM):** `OOM_KILL@2` never read the `memory.events` counter and was
  capped below the report threshold by design. `OOM_KILL@3` uses a counter
  rise in the victim's own cgroup as kernel evidence; `SignatureVersion` is now
  3. Tests: `internal/diagnosis/oom_counter_test.go`. Residual risk: if systemd
  removes the service cgroup before any sample reads it, the rise is still
  unseen; the next step would be the parent cgroup's hierarchical counter.

## B3 partial: healthy job binds on a live runner (October 31, 2026)

**B3 is NOT complete.** S2 (`healthy`), S6 (intended shutdown) and S7 (listener kill) have run. S1 and S3–S5 are untested, and S8 (orphan) is blocked because the VM has no `gh` and no `runopsy-b3` workflow in its checkout. Phase 5 acceptance stays blocked on B3.

- **Fixed the job-assignment binding bug.** A worker was bound against the time it was first sampled, not when it started, so a worker that started more than ±2 s earlier stayed unbound. On Linux the session now uses the process start time (`platform.ProcessStartTime`, from `/proc/<pid>/stat` and `btime`). macOS still uses the sample time, so the same lag can affect darwin. Regression test: `TestSessionAssignmentBindsWhenWorkerSampledLate`.
- **Verified live (S2):** the Lima Linux runner `runopsy-lima-linux` ran `runopsy-b3` on `13eth-a/runopsy-runner-e2e` (run 41177394588). The bundle `inc_77ada79e899d0e34bf3f96b76ce01a8c.runopsy` shows `GITHUB_JOB_ASSIGNED` with `job=job_40063c66…` and `worker=wkr_fb70ece7…`. The job was SUCCEEDED with no failure claim.
- **Setup notes:** the agent was built from a copy in `~/src` in the VM (Go at `/usr/local/go/bin`). The incident directory must be mode 0700 or the recorder refuses to start. `selfhosted.yml` in the disposable repo only runs the gated Go test, so `runopsy-b3.yml` (healthy only) was added there for S2. Remove it when cleaning up.
- **S6 (intended shutdown) passes.** `svc.sh stop` logged `GITHUB_RUNNER_SHUTDOWN` at the same second as the listener exit (bundle `inc_c0d4e99be2fd5685900f945a9f45b307.runopsy`), and no `GITHUB_RUNNER_SELF_TERMINATION` was raised. Two fixes made it pass: the shutdown regex in `logreader.go` now matches the real phrasing (`Received Ctrl-C signal`, `Runner will be shutdown for UserCancelled`), and `intentCovers` in `signatures.go` had its T2 window reversed, so a log record up to 1 s after the exit was not counted. Regression tests: `TestLogReaderReadsCtrlCShutdown` and `TestSelfTerminationShutdownLogLagIsSilent`.
- **S7 (listener kill) passes.** `kill -9` on `Runner.Listener` produced `GITHUB_RUNNER_SELF_TERMINATION` at MEDIUM.
- **Still to do for B3:** S1, S3 (cancel), S4 (timeout), S5 (SIGSTOP worker), S8 (orphan, needs a dispatch from GitHub or `gh` in the VM). Then run `analyze` and `timeline` on each bundle.

## Phase 5 final audit (principal, October 31, 2026): B1, G1, G3 closed; B3 and two findings remain

Details: `docs/reviews/phase5-principal-audit.md` §5 and the updated §3 table.

- **B1 reviewed and closed.** One S1 defect fixed (F1): a broker
  disconnect silenced the assignment and finalization stalls, and an
  assignment-then-disconnect episode was labelled
  `GITHUB_RUNNER_COMMUNICATION_STALL`. Disconnect is now supporting evidence,
  and the IDLE label defers to STOPPING and ASSIGNED. Tests:
  `signatures_s1_test.go`.
- **G1 closed.** `runopsy-agent github api-enrich --repo OWNER/NAME` locates
  recorded jobs by local start time (±30 s) and runner name when known. Unique
  match or nothing. Code: `api_locate.go`; the shared client setup moved into
  `apiClient()`/`apiGet()` in `api.go`.
- **G3 closed** (macOS identity is PID-only, documented in
  `docs/providers/github-actions.md`).
- **G2 and G4 were already implemented** (by another model); reviewed. Open
  findings for engineering, executable with `RUNOPSY_REVIEW_AUDIT=1`
  (`principal_final_audit_test.go`): **F2**, an unattributed container step on a
  cgroup host leaves no `CONTAINER_LINKAGE_UNAVAILABLE` marker; **F3**, the
  stall-window override has no floor. Also F4 (window not recorded in the
  bundle) and F5 (self-termination cites a log evidence code for a process
  exit), both S3.
- **B3 runbook ready:** `docs/github/real-runner-verification.md` (11
  scenarios on a disposable VM) and `scripts/verify-real-runner.sh` (collects
  `.runner` key names, process names, the record header and the intent phrases;
  never reads credentials).
- **adversarial share:** `adversarial_attack_test.go` (11 attacks, all pass on this tree)
  and `docs/reviews/adversarial-phase5-pass.md`.

**Next:** the user runs the B3 runbook; engineering fixes F2 and F3 (delete each
`principalFinalPending` call with its fix) and F4/F5; secondary delivers her
final-audit share. Phase 5 is accepted when B3 passes and F2/F3 are fixed.

## Phase 5 principal review and final-audit share (October 30, 2026): not accepted yet

Full report: `docs/reviews/phase5-principal-audit.md`. Spec additions:
`docs/providers/architecture.md` §10A (runner phase model, one stall label per
episode, the 5.23/5.24 rules, and how intended termination covers exits in the
causal engine) and the 2026-10-30 decision-log row.

**Fixed (18 findings, R1–R17 incl. R7b/R12b, each with a regression test that
fails on the pre-fix tree):**
- **The log reader parsed only the fake harness's invented record shape (R1).**
  Real `_diag` lines are `[2026-09-03 18:34:29Z INFO Terminal] …`, so on a real
  runner the provider produced no log facts at all.
- **The strict `.runner` decoder rejected every real file (R4),** because real
  files carry extra keys and a BOM. The runner name and the ephemeral flag were
  never known.
- **`EPHEMERAL_COMPLETE`, job outcomes and the 5.48 conflicts were unreachable
  (R5, R6, R16).**
- **`GITHUB_COMMUNICATION_STALLED` fired on every normal reconnect and on dead
  runners (R7),** and it was translated to the job-progress generic kind (R8).
- **The agent did not build on Linux (R9).**

Also fixed: R2, R3, R10–R15 and R17. The fake runner now writes the real
record format. A whole-provider canary test was added (no leak found).

**Open acceptance blockers:**
- **B1:** closed. Signatures 5.20–5.24 are implemented and tested against §10A,
  with healthy negatives first; 5.21 (`CommunicationStall`) was verified on
  October 30 and its docs corrected.
- **B2:** closed for the `timeline` path. The causal graph honours intent covers
  (`timeline.go` → `SetIntentCovers` → `failureAnchors`), and
  `TestCancelledJobKillIsNotAFailureEndToEnd` proves a cancelled job's SIGKILL
  stops being a PROCESS_EXITED anchor on a real bundle. `analyze` now builds the
  same causal graph through the shared `buildCausalGraph`, and
  `TestCancelledJobKillIsNotAFailureThroughAnalyze` covers it.
- **B3:** no real self-hosted runner has been exercised (5.42). The `.runner`
  keys, the shutdown/update/worker-intent log phrases and the macOS behaviour
  are unverified.

Gaps: G1, API enrichment can never fire on a recorded bundle (no local
repository or run/job IDs); G2, container linkage (5.33); G3, no macOS
incarnation check; G4, a fixed C11 window.

**Next:** adversarial/engineering for B1 and B2; the user (with a disposable runner) for B3;
then principal reviews B1/B2 and adversarial and secondary finish their final-audit shares.

## Phase 5 started: 5.1 provider abstraction (principal, October 28, 2026). Next owner: engineering. 5.1 reviewer: secondary

### integration-owned Phase 5 slice — completed October 29, 2026 (5.39–5.41, 5.43, 5.49; review of 5.31)

- **5.39/5.40 fixtures and healthy scenarios**: `testdata/github/` holds ten
declarative scenarios (the nine planned cases plus `two-runners`) with
sanitized runner logs, process and socket tables; `internal/provider/github/fixtures`
materializes each as a real installation and drives the real session.
`internal/provider/github/scenarios_test.go` asserts the contract per scenario,
proves the assignment stays unbound in the stall case, proves the healthy cases
carry no stall/cancellation/termination-intent fact, and requires the stored
section to be interpretable offline.
- **5.41 fake runner harness**: `runopsy-sim github <scenario>` plus
`internal/simhelper/github.go` run a real runner shape — installation layout,
`Runner.Listener`/`Runner.Worker`/job processes, diagnostic logs, a loopback
broker socket — and fail in each scenario's own way. `GitHubPlan`/`PlanFor`
export the choreography so tests pin it. The harness now reports phase changes,
idles two seconds before the assignment so a recorder can attach first, logs an
assignment for `assignment-stall` with no worker, kills the job tree with the
worker for `worker-oom` but not for `orphan-job`, and reaps the whole runner on
SIGINT/SIGTERM. Tests: `internal/simulator/github_test.go`.
- **5.43 real E2E correlation**: `tests/phase5_e2e_test.go` (gated by
`RUNOPSY_E2E_GITHUB=1`) runs harness → recorder → bundle → shipped
`timeline --report`. It asserts installation-derived identity, worker → listener
→ runner binding, the job process tree, honest UNKNOWN job identity without API
access, no failure claim for a healthy job, an unbound assignment for the stall,
and worker-exit-without-runner-death for the OOM shape.
- **5.49 performance**: `internal/provider/github/bench_test.go` measures
`Observe` and `Freeze` for idle, active-job, four-runner and high-churn shapes;
`TestObserveOverheadWithinBudget` and `TestChurnKeepsProviderStateBounded` are
the guardrails (per-sample work must stay under a quarter of the fastest
documented interval, and the second half of a 1500-sample run may not cost more
than 3× the first). Apple M1 Pro: 100 µs/sample idle, 310 µs active job,
293 µs for four runners, 132 µs with 20 new processes per sample; `Freeze`
≈15 µs.
- **5.31 review (integration Fast)**: the `two-runners` fixture now pins each
worker to its own listener (`worker_listener`); a swapped-expectation mutation
check fails as it should, so cross-runner attribution is actually asserted
rather than implied by a runner count.

**Two defects found and fixed while building the E2E:** (1) discovery and
correlation compared the recorded process name only against the bare
`Runner.Listener`/`Runner.Worker` strings, which never match macOS `ps`, where
the name is the executable path; the provider now matches the base name as the
cheap filter and still requires the executable/layout checks before tagging.
(2) C6 bound a job only on the snapshot that read the `Received job message`
record, so a recorder that saw the log one sample before `Runner.Worker`
appeared left the assignment unbound forever; assignments now stay pending for
the ±2 s C6 window and bind on the sample where the worker first appears.

This is completion of the integration slice, **not Phase 5 acceptance**: no real
self-hosted runner has been exercised (5.42), no provider-specific diagnosis
signature is implemented (5.20–5.25), and the gated E2E uses the fake runner.

### secondary-owned Phase 5 slice — completed October 29, 2026

Completed the assigned API/report/CLI/provenance/documentation work (5.11,
5.26–5.30, 5.35, 5.37–5.38, 5.47, 5.50): API failures remain degraded
provider health instead of capture failures; offline bundles remain analyzable;
provider timestamps and their sources appear in text reports/timelines; runner
version evidence carries its actual config/log source; and the five required
GitHub provider docs describe current behavior and limits. Added regression
coverage for API-unavailable CLI enrichment preserving the input and producing
an offline-readable output, and for report/timeline provider context.

Verification on darwin/arm64: `go test -count=1 ./...`, `go vet ./...`, and
`gofmt` on the changed Go files pass. This is completion of secondary's assigned
slice, **not Phase 5 acceptance**: the self-hosted runner, real workflow E2E,
and provider-specific diagnosis signatures remain unverified/not implemented
as noted in `docs/github/signatures.md` and the open items below.

The binding spec is `docs/providers/architecture.md`. Read §0–§3, then work the engineering
queue in §11 in order.

**New code (compiled, `go test -race` green, `go vet`/`gofmt` clean):**
- `internal/provider/evidence`: the bundle's provider section. It is a stdlib-only leaf schema. Text
  values are tri-state (KNOWN/UNKNOWN/WITHHELD) and carry privacy classes. Runner, worker and job
  refs are opaque salted hashes. The vocabulary is closed and provider-registered. `Validate` bounds
  and checks everything. `Redact(level)` scrubs credential-looking text even at the
  `identifiers` level.
- `internal/provider`: the `Provider` interface (live Detect/Discover/Attach/Session plus pure
  offline `Interpret`), `HostView` (which has no env field), the optional `Enricher`, the
  `GenericKind`/`Intent` translation, and the `Registry`. The `Supervisor` turns provider
  panics, errors, hangs and backpressure into section health, so a provider fault never reaches
  the recorder or capture. `TestProviderImportBoundaries` enforces the layering over the
  transitive import graph.
- `internal/provider/providertest`: the conformance kit. It checks validity, determinism,
  non-mutation, well-formed generic events and privacy independence (generic output must not
  depend on withheld identifiers).

**principal-led invariants are already written** for engineering to implement: correlation C1–C12 (§6, covering
5.4–5.10 and the 5.15 broker rule), intended termination T1–T5 (§7, 5.44–5.46), source
authority and conflicts P1–P5 (§8, 5.47/5.48), and credentials and privacy (§9, 5.12/5.36).

**Open:**
- The allowlisted `.runner` key names were not verified against a real runner. Verify them first
  (5.42).
- Product call for the user: should `identifiers` become the default privacy level? It stays
  `conservative` until the user decides.
- Stage-host verification of Discover/Session on a real GitHub Actions runner (5.42): the
  fake-runner fixtures (5.41) exercise the C1–C4/C6/C12 paths and the conformance kit passes, but
  comm/exe/layout observations for a real runner install were never confirmed on a live host.

**2026-10-28 update (engineering):** the §11 queue items 1–6 are implemented and the agent is command-
documented for `github discover` / `github interpret`. New packages: `internal/incident` provider
sections with redaction hooks and bundle round-trip tests; `internal/agent` HostView,
`ProviderSet`, salt file, and the provider panic/backpressure isolation; `internal/provider/github`
(vocabulary, Discover/C2/C3, live session with worker/job records C1–C4/C6/C9, bounded `_diag` log
reader with a closed pattern set and offsets-only provenance, C12 control-channel classification,
C11 progress stalls, C6 JOB_BINDING and JOB_STATE/TERMINATION_INTENT conflicts, generic
translation and conformance fixtures). `go vet` and the full `go test ./...` suite are green.

## Phase 4 closed for conservative v1: principal re-audit + residuals (October 28, 2026)

**Network follow-up (October 28, 2026):** `internal/causal/network_progress.go` emits
`NETWORK_PROGRESS_STOPPED`/`RESUMED` from Tier B byte counters. `STALL_SHAPE_LOCAL_NOT_READING`
is a real evaluator. `SOCKET_OWNED_BY_STOPPED_IDENTITY` is now real too: the collector keeps the
owner's start-time on `ConnectionSnapshot`, the stall event records the owner's PID and start-time,
and the check binds the stopped process incarnation (reused PIDs are ABSENT). Verified: `go vet`,
full `go test ./...` on the Lima Linux VM, and the gated `RUNOPSY_E2E_CAUSAL=1` /
`RUNOPSY_REVIEW_AUDIT=1` runs.

**Live socket stall (October 28, 2026, Lima Linux VM):** a sender/reader TCP pair with the reader
SIGSTOPed for 50 s, recorded and triggered mid-stall. The bundle surfaced `PROCESS_STOPPED` on the
reader and `NETWORK_PROGRESS_STOPPED` on the socket (`stall_ms` 30006, ~30 MB unread).
`PROCESS_STOP_CAUSES_NETWORK_PROGRESS_LOSS@1` fired with both required checks PRESENT, and the
owner matched the stopped incarnation. Two defects found and fixed along the way:
`NETWORK_PROGRESS@1` was missing from `derivedRuleIDs`, so every live socket stall failed graph
validation (regression test `TestValidateAcceptsNetworkProgressDerivedRule`); and the socket-owner
scan treated a process exiting mid-scan (`ESRCH`) as a failure. Full suite passes as root.
The project mount is read-only inside the VM, so the build ran from a copy in `~/src`.

Supersedes the "next owner: adversarial" list below. principal ran the post-remediation
final audit, reviewed the 4.37 corpus and closed the open non-telemetry items.
Details: `docs/reviews/phase4-principal-audit.md` Part 3. Spec changes:
`docs/causal-semantics.md` §11 (2026-10-28 rows).

**Re-audit:** all 23 Part 2 findings stay closed. 15 new findings (R1–R15) were
reproduced and fixed in this pass, each with an ungated regression test. The
S1s: R1 (`timeline` failed with "invalid graph" when reparent edges competed),
R5 ("Root cause: PROCESS_EXITED" rendered under UNKNOWN), R11 (recovered
cgroups stayed failures), R13 (every helper-process exit became a failure).
Also notable: R10 (a 4.41 performance regression, 10k-sample end-to-end
analysis 1.96 s → 92 ms), R15 (the gated Phase 4 E2E was broken by the
remediation and never re-run; now ported to the `failures` contract), and the
adapted A8 test could not catch its own bug (new A8b, mutation-checked).

**Semantics decided (principal):** a failure is never its own candidate;
escalation-only reach is the known chain, not a contributing factor; an exit is
a failure only with context (trigger names it, causal edge in or out, unresolved
memory/cgroup limit, or non-normal recorded status), and other exits are
counted; a severe condition needs ≥ 2 severe samples to be a failure;
suspected OOM/write-failure alternatives explain exit failures only.

**Residuals closed:** §8.3 headline wording and A15 (per-anchor analysis,
"Root cause: UNKNOWN" / "Most likely" / "Possible" / "AMBIGUOUS"), A19
(`--explain-edge RULE@n` errors on ambiguity), A16 (rules README rewritten from
the registry, plus a drift test), the 4.47 "flagship chain not exercised"
summary, §10 item 9 Tier A socket facts (`tx_queue`, `rx_queue`, `timer`,
`retransmits` parsed from `/proc/net/tcp` into connection snapshots), and
`event-model.md` updated (capture order, episodes, `CGROUP_LIMIT_CLEARED`,
`severe_samples`, typed identity, exit context).

**Verified (linux/amd64 sandbox, Go 1.24 with a local `go` directive override
that was not written back):** gofmt and vet clean; `go test -race` green for
causal, cmd, collector, incident, diagnosis and agent;
`RUNOPSY_REVIEW_AUDIT=1` green; `RUNOPSY_E2E_CAUSAL=1` Phase 4 E2E green (socket
half saw 7 socket facts); `RUNOPSY_E2E_DIAGNOSIS=1` Phase 2 matrix and Phase 3
E2E green. Still failing only on sandbox limits, identical before and after:
`TestLinuxLiveIdentitySocketAndFD`, `TestLinuxLiveCgroupAndPressure` (no
cgroup2) and `TestProcessScenariosRespectShortDurationAndCleanChildren` (PID 1
reaping).

**Still open (none blocks conservative v1):**
1. One run on a real Linux host with cgroup2 for the three sandbox-limited
   tests above.
2. Phase 1 telemetry that unlocks the dormant rules: cgroup `memory.events`
   `oom_kill` + exit status/signal (OOM chain, 4.37 pairs 3–6, the first
   reachable EXPLAINED); Tier B `tcp_info` + a generic worker-progress event
   (flagship 4.47 chain, pair 15); the recorder writing `CaptureIndex` and a
   monotonic offset per snapshot.
3. Wire the Tier A fields into extraction as §7.2 stall shapes once Tier B
   gives progress (the fields are parsed; nothing consumes them yet).
4. secondary: diagnosis-side subject scoping for signature links (A11's second
   half: `SignatureMatch` has no subject in v1) and the §6.3 Phase 3 ↔ Phase 4
   consistency check (low risk while EXPLAINED is unreachable in v1).

## Phase 4 principal-audit remediation closed — next owner: adversarial (October 28, 2026)

This section supersedes the "Next owner: engineering" pointer in the principal pass entry
below. The engineering §10 implementation queue is done: every audit finding from
`docs/reviews/phase4-principal-audit.md` Part 2 is implemented, and the gated suite
is fully green.

State of the check in this workspace (macOS/darwin — Linux re-run still owed):

- `RUNOPSY_REVIEW_AUDIT=1 go test ./internal/causal` passes all 14 principal-audit
  tests and all 13 `TestGoldenFixtureRemovalNeverStrengthens` subtests,
  including the previously open a3, a5, a6, a8 and a11 fixtures.
- `go vet ./...` and the full `go test ./...` (all 10 packages) pass.

What closed the findings:

- **A3:** the per-machine episode counters (`memoryMachine`, `diskMachine`,
  `ioPressureMachine`) no longer reset `episodeN` to zero, so a post-recovery
  episode cannot collide with a pre-recovery episode ID and
  `MEMORY_PRESSURE_ESCALATES_TO_LIMIT@1` no longer binds across a recovered
  boundary; its check evaluator veto is what the contract now observes.
- **A6:** `markCompetingEdges` (D3, §6.1) compares the two **sources** of the
  same-target CAUSES pair instead of judging source→shared-target, which was
  vacuous; tied candidates stay COMPETING with none PRIMARY, anchor AMBIGUOUS.
- **A8:** root-eligibility is enforced for every condition candidate on a
  chain (an upstream condition with incoming causal edges is excluded and its
  onset/limit resolves instead) and the root band is the weakest-link band of
  the best chain, not the strongest link.
- **A11:** `signature_link.go` scopes FROZEN_PROCESS to stop/resume event
  types only; the subject-scoping half of item 7 stays open for secondary (4.16)
  because diagnosis `Match`/`SignatureMatch` has no subject field in v1.
- **A5 / test layer:** the reparent rule binds on typed PPID lineage; the
  contradiction section of the explanation reports each declared check's
  status; the blanket whole-text `"none recorded"` test scan was removed (it
  false-matched the honest Alternatives boilerplate; assertions are now
  section-scoped) and the events-mode injection harness re-runs the idempotent
  D3 pass over the post-injection edge set, so injected audited hypotheses
  obey the same demotion contract as production edges.

**Next owner: adversarial.** Work in this order:

1. **Final re-audit with secondary**, starting from `principal_audit_test.go`. Note the
   audit is no longer gated-only: the `principalPending` calls are deleted for the
   landed findings, so the default suite pins them; `RUNOPSY_REVIEW_AUDIT=1` is
   now belt-and-braces, not the primary switch.
2. **4.37 counterfactual corpus residual** (acceptance criteria and the
   15 required pairs are in the audit file). Pairs 1, 2 and 7–14 already run
   on v1. Still open: pairs 3, 4, 5 and 6 need a kernel OOM record whose
   checks evaluate real recorded data — `EventOOM` is on
   `unobservableEventTypes`, so nothing v1 can produce it; the pairs stay
   dormant (and a pass would be vacuous) until the OOM constitutive checks
   read real records. Pair 15 needs Tier A network telemetry. Replace the
   weak `TestCounterfactualOomRemovalChangesConclusion` rather than keeping
   it alongside the pairs.
3. **Status (adversarial pass, October 28):** the weak OOM counterfactual test is removed; `TestRuleNegativesReparentIdentity` is added; the golden removal property is reviewed and holds on the gated run (11 fixtures). Verdicts are in `docs/reviews/phase4-principal-audit.md`. Still open: the reparent gap (no `MaxGap`), OOM timing negatives (blocked until OOM records exist), and the rule-by-rule review of recovery, CPU, network and disk rules.
   **Rule-level negatives residual:** timing-boundary negatives for the
   reparent rule and OOM rule (`MaxGap` and identity boundaries); the
   golden-fixture removal property drafted in
   `TestGoldenFixtureRemovalNeverStrengthens` should be reviewed against the
   4.37 property criterion ("removing PRESENT evidence never raises an edge
   or chain band") and extended if it under-covers.

Still assigned elsewhere, unchanged:

- **integration:** §10 item 9 (parse `tx_queue`/`rx_queue`/`tr`/`retrnsmt` from
  `/proc/net/tcp` — Tier A socket facts), the A21 rejection-volume cap, and
  capture-order handling in the fuzz suite.
- **secondary:** §8.3 headline wording and explain rendering (item 8), the A15
  items, diagnosis-side subject scoping for signature links (4.16 co-owner,
  the half of A11 above), and the docs half of the pass.
- **Everyone:** the socket-stall E2E acceptance row is NOT MET with v1
  telemetry (4.47): do not describe the flagship demo as working, and when
  the environment yields no socket facts the test must print a `"flagship
  chain not exercised"` summary instead of a bare pass.
- Platform debt from the previous entries still stands: run the race suites,
  `RUNOPSY_E2E_CAUSAL=1`, the socket-stall E2E and the gated matrix on a real
  Linux host with cgroup2 before calling Phase 4 done.

## Phase 4 principal pass: architecture decisions, reviews, audit (October 27, 2026)

This section supersedes the provisional "Conservative semantics for the
architecture-owned conceptual items" in the Phase 4 engineering slice below. architecture is out
of the plan, and those items are now decided.

principal completed every principal-assigned Phase 4 role:

- **Design (binding):** `docs/causal-semantics.md` covers 4.6 graph
  architecture, 4.7 chronology vs causality (evidence ladder E1–E5, new
  `ESCALATES_TO` relation, prohibitions P1–P7), 4.9 rule contracts (tri-state
  checks, discriminators, episode binding; the OOM constitutive condition is
  a kernel OOM record naming the victim, and signal lineage is only
  supporting), 4.10 confidence bands (uniform demotions D1–D6;
  weakest-link chains), 4.11 roots (event classes, failure anchors, ROOT_CAUSE
  vs UNEXPLAINED_HEAD vs CONTRIBUTING_FACTOR), 4.15 competing chains
  (AMBIGUOUS, never tie-broken by canonical order), 4.25 network causality
  (telemetry tiers, stall shapes, broker-vs-path discriminators, rules
  N1/N2), and 4.43 explainability (the eight-question contract).
- **Reviews:** 4.1, 4.4, 4.19, 4.22, 4.24, 4.28, 4.29, 4.37 and 4.47 are in
  `docs/reviews/phase4-principal-audit.md` Part 1. 4.37 is NOT REVIEWABLE: adversarial's
  counterfactual corpus is not delivered; the acceptance criteria and 15
  required pairs are listed there.
- **Final audit:** same file, Part 2. 23 findings: 5 S1 (wrong
  root/health conclusion reaches the user), 9 S2, 9 S3. Each S1/S2 finding was
  reproduced. Fourteen are executable in `internal/causal/principal_audit_test.go`;
  they skip by default and fail with `RUNOPSY_REVIEW_AUDIT=1`.

Headline S1 findings: (A1) "root cause" reported for a chain that reaches no
failure (oom-chain fixture); (A2) a healthy build that touches 98% and recovers
is reported as an unhealthy PRIMARY root; (A3) a recovered memory episode CAUSES
a later episode's limit; (A4) `PROCESS_GROUP_TERMINATED`, derived *from* the
member exits, is said to CAUSE them; (A7) a 5 s backward clock step is
silently re-sorted, which fabricates a pre-capture episode and a recovery.

**Next owner: engineering**, following `docs/causal-semantics.md` §10 in order (items 1–5
are the critical path; update the golden `expected.json` files per §5.6 in the
same change; adversarial reviews each rule change; delete each test's
`principalPending` call as its fix lands). secondary: §8.3 headline wording, A11/A15/A16/A19,
docs. integration: §10 item 9 (parse `tx_queue`/`rx_queue`/`tr`/`retrnsmt` from
`/proc/net/tcp`), the A21 rejection-volume cap, and capture-order handling in
the fuzz suite. adversarial: the 4.37 counterfactual corpus, then the final re-audit
with secondary.

Verification in this pass (linux/amd64 sandbox; the first Linux run of Phase 4):
race tests green for `internal/causal`, `cmd/runopsy-agent`, `internal/diagnosis`;
`RUNOPSY_E2E_CAUSAL=1` Phase 4 E2E passed. Socket facts did not surface in the
sandbox, so that half is inconclusive and needs a real Linux host. Platform and
simulator failures in the full suite are sandbox limits (no cgroup2,
restricted `/proc`). No production code was changed in this pass: only docs,
the gated audit tests and this entry.

## Phase 3 final implementation/architecture review (October 27, 2026)

This section supersedes the older review-availability and completion statements
below. The actual delegated implementation and architecture reviewers have now completed their
Phase 3 assignments, including **3.33 evidence-strength calibration**. independent
was not used. The reviewed target is conservative v1, analyzer 0.3.1 / signature
set 2 / rule version 2; it is not the original full-telemetry acceptance target.

architecture reviewed context construction, tri-state evidence, temporal continuity,
identity, registry/result validation and conflict semantics. Fixes prevent
failed/missing samples from extending CPU/stopped/resource episodes or creating
socket state transitions, use contemporaneous socket-owner identities, and
reject invalid score/weight/threshold values. implementation reviewed the signatures and
calibration independently, adding counterexamples for productive CPU, watched
idle sockets, clean exits under memory pressure, normal closes, passive and
unfinished handshakes, returned parent/group members and missing final disk data.

Item 3.33 is specified in `docs/signatures/CALIBRATION.md`: controlled evidence
ladders for all nine hypotheses, contradiction effects, missing support and hard
requirements. The tests verify heuristic score ordering, not statistical
probabilities. OOM/CPU-spin/broker-stall remain hard rejections with v1 telemetry,
including at lowered thresholds. The original fixture labels are unchanged:
16/19 correct top labels, zero false positives on ten healthy fixtures, thirteen
UNKNOWN (ten healthy and three explicit false negatives).

The CLI now renders supporting observations for rejected hypotheses under
`--explain`/`--report`, so users can see the observed CPU/memory/socket facts as
well as the missing evidence. Ambiguity remains visible without `--explain`.

Verification: full macOS and Linux race suites passed; final changed-package
race checks cover diagnosis and CLI on both platforms. Vet, builds and formatting
are clean. The gated Linux recorder → bundle → analyzer matrix passed all three
cases (freeze, clean exit, sustained CPU). Its first concurrent run lacked a
continuous CPU span while competing with other tests; the isolated run passed
in 79.93 seconds. Run this timing-sensitive matrix separately from load tests.
The Phase 2 seven-scenario Linux capture matrix and bounded bundle-reader fuzz
smoke also passed during this review cycle. Hosted CI was not run.

Performance smoke (one iteration, Apple M1 Pro under concurrent load): small
1.36 ms, medium 28.0 ms, large 97.2 ms; context-only large 128.4 ms. These are
observations, not latency guarantees or a statistically controlled comparison.

The requested implementation/architecture review and 3.33 are complete for conservative v1.
Remaining broader goals: direct OOM/progress evidence for the three abstaining
rules; production calibration and broader fault E2E coverage; optional separate
independent audit. Broker/network exclusion is tested with synthetic rival results;
it cannot select a broker diagnosis from today's v1 input. Normal process-group
shutdown, intentional reparenting and expected resource pressure remain possible
interpretations of factual symptom matches. Existing Phase 4 work in this shared
workspace is outside this review's scope.

## Phase 3 completion (October 27, 2026, conservative v1)

Phase 3 was completed on the user-selected conservative path (implementation, architecture and
independent remained unavailable throughout; nothing in this section is independent
sign-off). All 45 checklist items are implemented or explicitly resolved as
follows:

- Core engine (3.1-3.24, 3.34-3.40): as described in the engineering pass below.
- CLI (3.25-3.27, 3.39, 3.42, 3.44): `analyze` text / `--json` / `--explain` /
  `--report` / `--min-confidence`, plus `evaluate DIR [--json]`.
- NEW in this pass: user-facing `--disable SIG1,SIG2` on `analyze` and
  `evaluate` (3.20 enable/disable), with table-driven tests for disabled
  emission, flag-before-path ordering, unknown-ID rejection (nonzero exit) and
  empty-token rejection (exit 2).
- Corpus and evaluation (3.28-3.33, 3.41, 3.43): 19 deterministic fixtures,
  out-of-band ground truth, confusion matrix, false-positive harness, and
  benchmarks (small 0.7 ms / medium 7.4 ms / large 47 ms, M1 Pro).
- Docs (3.45): `docs/signatures/README.md` now carries the conservative v1
  acceptance matrix plus per-signature required/supporting/contradicting
  evidence, limits and false-positive risks.
- Conservative acceptance matrix (recorded in docs/signatures/README.md):
  16/19 correct top results, 0 false positives on 10 healthy baselines, 13
  UNKNOWN. FROZEN_PROCESS, DISK_EXHAUSTION, ORPHAN_PROCESS_TREE,
  PROCESS_GROUP_TERMINATION, NETWORK_PATH_FAILURE and RESOURCE_STARVATION
  diagnose. OOM, CPU_SPIN and BROKER_SOCKET_STALL faults report UNKNOWN with
  evidence-backed rejections; this is deliberate under conservative v1, and the
  broker/network exclusion pair is therefore unreachable (path failure wins by
  default). These rows are recorded as honest false negatives, not passings.
- Verification (this pass): gofmt clean, `go vet ./...` clean, full
  `go test -race -count=1 -timeout=9m ./...` green on macOS/arm64, the corpus
  evaluation via the CLI (16/19, 0 FP, 13 UNKNOWN), and the gated E2E suite
  (`RUNOPSY_E2E_DIAGNOSIS=1`) green on macOS (frozen-worker diagnosed,
  watched clean exit UNKNOWN). NOT rerun: the Linux container matrix and the
  Linux-only CPU-spin E2E case.
- Remaining epistemology work for implementation/architecture/independent is in the sections below;
  Phase 4 must not silently re-decide the three conservative boundaries.

## Phase 3 implementation/architecture review pass (October 26, 2026)

Scope: the implementation and architecture portions of the Phase 3 model plan, run while those
models were unavailable. This was a partial pass by the coding agent, not an
independent architecture or implementation review. independent review and the final audit remain open.

- **Doc/code mismatch fixed**: `docs/signatures/README.md` listed caps of 0.90
  (OOM_KILL, BROKER_SOCKET_STALL) and 0.75 (CPU_SPIN). The code and calibration
  tests use 0.50 for all three, which is below the 0.55 default threshold, so
  these rules are reported only as rejections. The docs now match the code.
  Open question for architecture: whether these three should ever become diagnoses
  without a kernel OOM event, application progress telemetry, or socket byte
  counters.
- **implementation counterexamples added** (`internal/diagnosis/implementation_counterexample_test.go`):
  productive single-process compute is not CPU_SPIN; a compile driver with
  children is refused; an idle keepalive with a manual trigger is not a stall;
  a clean exit near the memory limit is not OOM_KILL and stays under the cap;
  a brief SIGSTOP is not FROZEN_PROCESS. All pass under `-race`.
- **Self-review (not independent sign-off; implementation, architecture and independent were all
  unavailable)**:
  - Tri-state: `observationFalse` is returned only when host memory was observed
    below the boundary. Missing telemetry is UNKNOWN. No defect found.
  - Broker vs network: `BROKER_SOCKET_STALL` is capped at 0.50, below the 0.55
    threshold, so it can never be a match. The `BROKER_SOCKET_STALL` /
    `NETWORK_PATH_FAILURE` exclusion only fires when both are matches, so it is
    unreachable in v1. Any network-path match is reported uncontested. The
    broker-vs-network distinction is therefore not enforced. Open for architecture:
    either raise the stall cap with new evidence or define a rejection-side
    exclusion.
  - Caps: OOM, CPU_SPIN and BROKER_SOCKET_STALL can never be diagnoses with v1
    bundles. This is recorded as an open calibration question, not changed.
- **Still open**: independent's review of the whole model, the architecture semantics review
  above, and the final architecture → implementation → independent audit.

## Phase 3 status (October 26, 2026, engineering pass)

The Phase 3 diagnosis engine exists and is tested: `internal/diagnosis`
(tri-state evidence model, analysis context, nine signatures, exclusion
semantics) and the offline `runopsy-agent analyze` CLI (text/`--json`/
`--explain`/`--min-confidence`). Confidence is a declared-weight sum with
per-rule caps, never a probability; missing telemetry is UNKNOWN, never FALSE,
and failed collector sections carry coverage so rules refuse thin evidence.
Race-enabled tests, vet, gofmt and builds pass on macOS/arm64 and
Linux/arm64 (`golang:1.27.1` container). The package has positive/negative
unit tests for all nine signatures, PID-recycle identity, gap inference
boundaries, exclusion ambiguity, thresholds and determinism.

Key new-package semantics reviewers should re-check:

- `BROKER_SOCKET_STALL` vs `NETWORK_PATH_FAILURE` exclusion with a 0.15
  margin and an explicit `Ambiguous` list; tie-breaks are ID-ordered and the
  same bundle always produces the same report.
- V1 bundles carry no socket byte counters, so RX progress is structurally
  UNKNOWN and the stall rule is capped; a manual trigger + healthy host + un-
  watched identity cannot score above 0.55 (`WORKER_LIFECYCLE_EXPECTATION`
  recorded) — this gate protects the healthy-corpus row but may undertrigger
  genuine unwatched stalls and needs independent calibration review.
- OOM requires a memory condition (host >= 92% or cgroup >= 95% of limit) plus
  an unclosed departure gap near that reading; kernel OOM events are
  unobservable, capping the rule at 0.90.
- `ResolveExclusions` is unexported engine logic; conflict metadata is a fixed
  v1 pairs table, not an extensible registry yet.

The integration slice (3.29, 3.31, 3.32, 3.40, 3.41, 3.42, 3.43) is now present:
see the integration Phase 3 section below. Still outstanding: independently
reviewed labels, independent confidence calibration (3.33), and the independent
architecture → implementation → independent final audit. Registry is a stable ordered slice with per-ID
disable and custom registry support; a user-facing config file/CLI disable
syntax is still absent.

## Phase 3 integration slice (October 26, 2026)

Assignments **3.29, 3.31, 3.32, 3.40, 3.41, 3.42 and 3.43** are implemented on
top of the engineering/secondary analyzer:

- **3.29/3.30/3.43 corpus and labels**: `internal/diagnosis/corpus_test.go`
defines 19 deterministic incidents — 9 single-cause faults (one per signature)
and 10 healthy-but-weird baselines (CPU-heavy and memory-heavy compiles, long
idle socket, intended parent exit, brief stop, brief disk dip, reconnects,
large writes, busy co-tenant CPU pressure). Git-tracked bundles live in
`testdata/incidents/` with out-of-band `.ground-truth.json` sidecars;
`RUNOPSY_WRITE_FIXTURES=1` regenerates them and deletes strays.
- **3.31 confusion matrix**: `TestIncidentCorpusConfusionMatrix` and
`runopsy-agent evaluate DIR [--json]` report 19/19 correct top diagnoses, 0
false positives, 10 UNKNOWN, plus the full matrix. `TestHealthyCorpusFalsePositiveHarness`
requires every healthy fixture to produce zero matches, `Unknown`, and a
explained rejection for each signature.
- **3.32 false-positive harness**: the healthy half of the corpus (above).
- **3.40 performance**: `internal/diagnosis/bench_test.go` covers small (60
snapshots/20 processes/5 sockets), medium (300/80/20) and large (800/200/60),
plus context construction in isolation.
- **3.41 E2E fault evaluation**: `tests/phase3_e2e_test.go`, gated by
`RUNOPSY_E2E_DIAGNOSIS=1`, runs simulator → live recorder → automatic bundle →
`runopsy-agent analyze`. Cases: frozen worker (must report `FROZEN_PROCESS`), a
watched clean `exit --code 7` (must stay `UNKNOWN` with no matches), and CPU
spin (Linux only; 60 s sustained window). The harness watches a private copy of
the simulator under a per-test-process name because `--watch-name runopsy-sim`
also captures simulators from other packages' tests running in parallel; that
cross-talk produced a spurious `PROCESS_GROUP_TERMINATION` under `go test
./...` before isolation. There is deliberately no live orphan case: the
simulator's `orphan-process` scenario group-kills the reparented tasks about
100 ms after observing them, so a manual capture contains the coordinated
kill, not a surviving orphan. That classifier path stays covered by the
synthetic corpus (`healthy-parent-exit` plus the orphan fault).
- **3.42 batch evaluator**: already landed with secondary's work and is exercised by
the corpus tests.

Two real calibration defects were found and fixed while building the harness:

1. `RESOURCE_STARVATION` treated PSI `some avg10=10` (10% stalled time) as
   severe. A live CPU-spin capture on a multi-core container diagnosed routine
   load as starvation at 0.55. Boundaries are now 50% some / 20% full, with a
   corpus baseline for 35% CPU some pressure that must stay UNKNOWN.
2. `CPU_SPIN` required every 100 ms sample >= 90%, but 10 ms tick
   quantization makes a fully busy core read 89-128%. A real 64 s spin failed
   on a single 89.6% sample. `identitySustainedCPU` now uses a 5 s trailing
   mean; `TestCPUSpinToleratesTickQuantizationDips` locks this in.

Verification: gofmt, `go vet ./...`, the full `go test -race ./...` suite on
macOS/arm64, the diagnosis/CLI corpus tests in the Linux `golang:1.27`
container, and the gated E2E suite on macOS (frozen + exit) and Linux (all
three). Benchmarks on Apple M1 Pro: small 0.7 ms, medium 7.4 ms, large 47 ms;
`BenchmarkBuildContextLarge` 49 ms of that shape's cost. Corpus fixtures and
labels are authored by the implementers, so none of this is independent
validation.

## Phase 2 completion pass (October 26, 2026)

The interrupted review changes are present: per-ID capture status retains bounded
terminal results, the reader rejects Unicode case-folded JSON aliases, and the
agent locks its incident directory during cleanup, retention and writing. A
follow-up review covered capture transitions and ownership, the v1 reader and
privacy policy, and persistence/crash semantics; no additional confirmed defect
was fixed in this pass. This was not an independent architecture, implementation or independent review,
and any unreported findings from the interrupted sessions remain unavailable.
The independent artifact/privacy audit remains outstanding before a public v1
contract is claimed.

The seven-scenario Phase 2 CLI acceptance matrix passed on Linux/arm64 in the
`golang:1.27.1` container (`docker run --rm --init ... go test -count=1
-run '^TestPhase2AcceptanceMatrix$' -v ./tests`). Captured bundle sizes were
4,306–6,409 bytes with shortened test windows. The memory case uses a low host
threshold to exercise automatic capture and checks simulated RSS growth; it does
not establish that the workload caused the host threshold crossing. Vet and the
full race suite passed on macOS/arm64 and Linux/arm64, and the bundle-reader
10-second fuzz smoke, macOS build and formatting check passed. No real full-disk
mount or power-loss test was performed; fault injection is not a substitute.
Notes are user-supplied and not secret-scanned; integrity hashes are not
signatures. V1 rejects unknown fields rather than providing forward compatibility.

The status in this section supersedes the older Phase 2 statements below about
the acceptance matrix not having been recorded.

## Phase 2 integration slice (completed)

integration assignments **2.2, 2.7, 2.13, 2.15, 2.19, 2.22, 2.31, 2.34 and 2.35**
are implemented on top of the engineering/implementation core. The agent now exposes the incident
pipeline end to end:

- **2.2 manual trigger**: `POST /trigger` and `GET /incident` on the private
  control socket, plus `runopsy-agent trigger`. It prints the incident ID,
  waits for publication and reports the saved path; the recorder continues.
- **2.7 host metadata**: `HostMetadata.MemoryTotal` is populated from
  `/proc/meminfo` (Linux) or `hw.memsize` (darwin), with zero meaning unknown.
  OS/architecture/CPU count were already present. Hostname/kernel version remain
  deliberately uncollected under conservative-v1.
- **2.13 / 2.15 / 2.16 triggers**: `incident.ResourceRules` (memory used >=,
  disk free <=, continuous `Debounce`) and `incident.StoppedProcessRule` (once
  per PID+start-tick stopped episode). Start flags are
  `--trigger-memory-percent`, `--trigger-disk-free-percent`,
  `--trigger-duration`, `--trigger-on-stop`, and `--trigger-on-process-exit`
  (the process rules require a watch selector).
- **2.19 compression**: measured Store vs Deflate on a dense 120-snapshot,
  2,322-event payload. Deflate: 46,398 B / 25.1 ms encode / 50.3 ms decode;
  Store: 1,291,842 B / 22.0 ms / 48.3 ms (darwin/arm64, allocations in README).
- **2.22 timeline inspection**: `runopsy-agent inspect FILE --timeline` reads
  bundles offline, prints a factual summary and event timeline, and never
  diagnoses. Bundle validation (layout/schema/checksums/privacy) happens in
  `incident.ReadFile` before output.
- **2.31 retention**: `incident.RetentionPolicy` + `Prune`, `DefaultDir`,
  `EnsureDir`, and a `pruningWriter` used by the agent. Defaults: 50 bundles,
  no age limit; startup also removes writer temps older than one hour.
- **2.34 size budget**: env-gated live matrix (`RUNOPSY_INCIDENT_SIZES=1`) for
  normal, cpu-spin, memory-pressure, frozen-worker, orphan-process and
  socket-stall. Linux/container at ~124 snapshots: 14.4–18.5 KB stored,
  281–431 KB uncompressed. The target is met with room to spare.
- **2.35 end to end**: `TestPhase2IncidentEndToEnd` starts the real agent with
  `--watch-name runopsy-sim --trigger-on-stop`, runs `frozen-worker`, waits for
  the automatic bundle, validates stopped-process/post-trigger evidence, runs
  `inspect --timeline`, performs a manual trigger with `--max-incidents 1` to
  verify retention and continued recording, then checks graceful shutdown and
  socket cleanup.

Verification for this slice: `gofmt -l .` clean, `go vet ./...` clean,
`go test -race -count=1 -timeout=8m ./...` passed on darwin/arm64. The live
Linux bundle-size matrix passed in the `golang:1.27.1` container, and the full
race suite passed there as well. Three existing integration checks were made
less timing-sensitive after race-enabled macOS runs exposed their short
margins: 10s capture prehistory, a 4s frozen window, and a bounded poll for
post-save sampling. No assertions were weakened.

## Phase 2 secondary CLI + remaining integration/engineering integration (implemented)

- Offline commands: `incidents list [--incident-dir DIR]`, `validate FILE`, and
  `extract FILE [--output DIR]`. Listing verifies each complete bundle; extract
  verifies the full archive first, then writes fixed component names with 0600
  files into a new 0700 directory without overwriting existing destinations.
- `inspect FILE` now supports `--timeline`, `--privacy`, `--snapshot N` (zero
  based), and `--at -10s` or an RFC3339 timestamp, selecting the nearest sample.
- `trigger --note TEXT` passes a bounded UTF-8 annotation through the private
  control socket, normalizes control characters, persists it in the incident,
  and reports its presence in the privacy manifest.
- `--trigger-on-process-exit` integrates the watched-identity exit rule. It is
  opt-in, requires a selector and process collector, ignores unavailable samples
  and resets its baseline across gaps. Graceful exit is still an exit; this rule
  makes no diagnosis or expected/unexpected classification.
- Unknown bundle schema/format/encoding versions now have specific unsupported
  version errors.

Targeted tests cover offline command behavior, private extraction, snapshot and
privacy output, version rejection, note persistence, watched-process exit,
collector gaps, and process-metric-backed availability.

## Phase 2 engineering / implementation core slice (superseded headline)

The earlier core remains as described next. `internal/incident` and
`agent.Options.OnSnapshot` provided the ZIP + compressed JSON,
conservative-privacy core. Package README defines capture/writer/reader APIs,
state transitions, v1 wire format and limits. Full race/vet/build checks passed
on macOS and live Linux; reader fuzz smoke passed. Tests include live
simulator-to-bundle/offline validation, ENOSPC stage injection, abrupt subprocess
crash boundaries and forged hostile archives. **Phase 2 still needs the independent architecture/independent artifact/privacy review and
full seven-scenario CLI acceptance matrix.** The remaining secondary CLI items and
process-exit trigger adapter are implemented below; the review and acceptance
matrix are not claimed as complete.

## Phase 1 completion review

Phase 1 is implemented and acceptance-tested on darwin/arm64 and live
linux/arm64 (Docker `--init`, Go 1.27.1). Full race suites, vet and builds pass;
the Linux matrix observes normal, CPU spin, memory growth, stopped children,
orphan reparenting, process hierarchy, stalled ESTABLISHED socket ownership,
and exit/fatal-signal disappearance. Live PSI/cgroups and CLI control-socket
cleanup are tested too. README contains commands, benchmark results and limits.

The completion pass added CLI collector enable/disable flags and coverage,
retained valid socket FD zero in JSON, corrected a live inspection test whose
160ms retention expired before collection completed, and strengthened overhead
measurement reporting. Measurement also exposed shutdown cancellation being
retained as an empty failed cycle: cancelled cycles are now discarded and
context cancellation does not count as a collector failure, with regression
coverage. Existing live Unix-socket status/history, age and byte
retention, identity checks and per-target cgroups were already present.

Resource overhead is measured rather than promised: the initial container run
used about 15 MiB RSS and 0.5 MiB retained payload. Three final valid repeats
retained 120 snapshots with no collector errors, 13.7–15.2 MiB RSS, about
0.45 MiB retained payload, and 2.66–7.00% of one core. CPU results exceeded the
aspirational 1% target. See README for measured results and reproduction. The
64 MiB default budget is an estimated retained-payload bound, not an RSS cap.
Cgroups are direct v2 limits only; network reads stay in the agent namespace.
macOS is for development with explicitly unavailable Linux-only sensors.
No diagnosis, persistence, service installation, SaaS or GitHub API is included.

The Phase 0 notes below are historical; their pending Phase 1 references and
Linux-verification gaps are superseded by the completion results above.

# Historical Phase 0 implementation slices (integration + engineering Flash)

Two implementation passes so far:

* **integration**: 0.1 (bootstrap), 0.4 (normal), 0.10 (socket stall),
  0.13 (structured events), plus the shared scaffolding (Scenario contract,
  registry, CLI shell, Makefile/CI/README).
* **engineering Flash**: 0.5 (cpu-spin), 0.6 (memory-pressure), 0.7 (frozen-worker),
  0.8 (orphan-process), 0.9 (process-tree), 0.11 (exit/signal), plus the
  `internal/platform` process primitives and the hidden helper processes that
  the tree scenarios needed, and Makefile/README extensions.

This file records the contract so the next model does not have to
reverse-engineer it.

Status: Phase 0 completion review is finished. The full race-enabled unit and
CLI acceptance suites pass on `darwin/arm64` and `linux/arm64` (Docker with
`--init`) using Go 1.27.1. STOP/CONT also passed five repeated race-enabled
regression runs on each system. Vet and build checks passed on both systems; formatting is clean.
Nothing is committed yet; no Git remote is configured, so hosted CI has not run.
CI is configured for Ubuntu and macOS.

## implementation + architecture completion review (October 24, 2026)

The final review found bugs beyond the original passing macOS matrix:

- implementation fixed STOP/CONT ordering: the watcher starts after the hold and waits for
  an observed stopped state before counting the resume delay.
- implementation fixed memory allocations exceeding the requested limit when rate > limit,
  cancellation before another allocation, and byte-count overflow validation.
- implementation made socket cancellation unblock reads immediately, made server close stop
  recovery timers, and counted actual responses for `--stall-after`. Invalid
  timing combinations are rejected; uncapped incomplete cycles now fail.
- architecture added an independent `_guard` for frozen workers, because stopped
  processes cannot run their own parent-liveness checks. Helpers now recognize
  zombie runners as dead. `worker_guard_spawned` records the guard PID.
- architecture enforced short frozen-worker deadlines, cleanup on signal-error paths,
  verification of entire process groups even before children are recorded, and
  nonzero status for failed observations or unexpected worker exits.
- Linux runtime testing exposed asynchronous SIGSTOP delivery: the parent now
  waits for the resume helper to finish before emitting `resumed` or reaping it.
  Signal integration tests have deadlines so a stopped process fails promptly.
  The process snapshot test now works in small container PID namespaces.
- Integration work rejects negative CLI durations, restores default handlers
  after the first interrupt, and reports event-output errors even for `exit`.
  JSON acceptance now validates timestamps. CI covers Ubuntu and macOS.
- Added automated hard-kill regressions with an unreaped runner, covering
  frozen workers, orphan trees, process trees, and the independent guard.

The small `Scenario` and optional `Flagged` interfaces remain appropriate for
this CLI. `Config` by value with a shared emitter is retained; no extra
abstraction is needed for Phase 0. This is the completion review, not an independent
review. The event field remains `type`, matching the supplied struct contract.
The socket state describes the controlled local peer and application progress;
kernel TCP-state recording remains Phase 1 work.

The earlier implementation reports below are historical; the completion review
supersedes their cleanup claims and pending reviewer questions.

## What exists

| Path | Contents |
|---|---|
| `cmd/runopsy` | placeholder that prints `Runopsy` |
| `cmd/runopsy-sim` | entrypoint; all logic lives in `internal/simulator.RunCLI` so it is testable |
| `internal/events` | `Event`, `Emitter` (text + NDJSON), concurrency-safe, first-write-error tracking |
| `internal/simulator` | `Scenario`, `Flagged`, `Config`, registry, CLI, all nine scenarios, shared process utilities and tests |
| `internal/platform` | process snapshot (`/proc` or `ps`), `SignalProcess`, `KillGroup`, `Children`, `Find`, `Alive` |
| `internal/simhelper` | hidden `_node` (task / w(children) trees) and `_cont` (SIGCONT watcher) helpers |
| `Makefile`, `.github/workflows/ci.yml`, `README.md`, `LICENSE`, `.gitignore` | bootstrap, scenario targets, acceptance target and Phase 0 docs |

`runopsy-sim --help` lists only what is registered, by design: it must never
advertise a scenario that cannot run. Scenarios register themselves in `init()`;
no CLI edits are required to add another one.

## Contract for the other models

### Scenario (0.12 — still needs independent's review)

```go
type Scenario interface {
    Name() string
    Description() string
    Run(ctx context.Context, cfg Config) error
}

// optional, for scenario-specific flags
type Flagged interface {
    RegisterFlags(fs *flag.FlagSet)
}
```

* Register in `init()`: `Register(&CPUSpin{})`. Duplicate names panic, on purpose.
* Flags: the CLI already registers `--duration`, `--verbose`, `--json` before
  calling `RegisterFlags`. Do not redefine those three. Scenario flags appear in
  `runopsy-sim <name> --help` automatically.
* Cancellation: clean up children/sockets/goroutines, then return `nil`.
  Returning `ctx.Err()` is for genuine interruption failures only, because a
  clean Ctrl+C must exit 0.
* Duration: `cfg.Duration == 0` means "your default". A scenario must terminate
  on its own even with no `--duration` (0.10 computes a bounded budget; copy that
  idea rather than running forever).
* Output: `cfg.Emit(type, data)` for observations, `cfg.Say(msg)` for narration.
  Never write to stdout directly — the emitter owns the stream.
  * text mode: narration + one formatted event line per record, on stdout.
  * `--json`: NDJSON only, narration suppressed, stdout stays parseable.
  * errors: stderr, prefixed `runopsy-sim: <scenario>:`.
* Exit codes: `0` success (including Ctrl+C), `1` scenario returned an error,
  `2` usage error. *Exception:* a scenario may return `exitCodeError{code}`
  (unexported, in `exit.go`) to choose the process exit code; the `exit`
  scenario uses it for `exit --code 7`.
* Spawning children: use the package-local helpers in `procutil.go`
  (`spawn(bin, args, spec, group)`, `reap(cmd)`, `SimBinary()`,
  `HelperArgs(spec, hold)`), which route through `simBinaryOverride` in tests.
  A tree-building child must be spawned with `group=true` so its subtree is
  killable by process group without touching the runner's group.

### Event schema (0.13 — this is the Phase 1 interface, pin it early)

```go
type Event struct {
    Timestamp time.Time      `json:"timestamp"`
    Scenario  string         `json:"scenario"`
    Type      string         `json:"type"`
    Data      map[string]any `json:"data,omitempty"`
}
```

* Timestamps are UTC, RFC 3339 with sub-second precision.
* One JSON object per line; `data` is omitted when empty.
* Naming: lowercase snake_case, past-participle observations (`worker_frozen`,
  `stall_detected`). Frame every run with `started` and `exited`; include
  `code`/`reason` in `exited`.
* 0.10's state changes use `conn_state` with `{"from","to"}`; reuse that shape if
  another scenario has an explicit state machine.

### Socket-stall specifics

`internal/simulator/stallstate.go` enforces
`CONNECTING -> HEALTHY -> STALLED -> RECOVERED -> CLOSED`, with `* -> CLOSED`
allowed from any state and every other edge rejected (including a second stall:
that would be a different condition). `socketstall.go` documents the server's
"read and drop, never close" behaviour that keeps the socket open without
applying backpressure.

Defaults: 200ms pings, 1s stall threshold, 6s stall, stall after 3 responses.
A default run lasts ~7s and always ends `CLOSED` + `exited{reason:
"cycle_complete"}`.

## engineering slices — process scenarios (0.5-0.9, 0.11) and helpers

### What the new scenarios emit

All frame runs with `started`/`exited` as documented. Observation types worth
pinning for Phase 1:

* frozen-worker: `worker_spawned`, `worker_state`(raw ps state + `kind`),
  `worker_frozen`, `worker_resumed`, `worker_exited_early`, `worker_killed`
  (with the reaper's `exit_code`/`exit_kind`), `cleanup_incomplete` (only if a
  child survived SIGKILL — treat as a red flag). Cleanup failure returns an
  error and CLI status 1, rather than reporting a clean exit.
* orphan-process: `tree_recorded`(worker pgid, task pids), `worker_reaped`,
  `orphan_report`(per task: `ppid_before`, `ppid_after`, `pgid`, `state`,
  `alive`), `orphan_summary`(survival/reparent counts),
  `tree_cleaned`(`targeted`, `still_alive`). Cleanup failure returns an error.
* process-tree: two `branch_killed` events (`worker` by `process_group`, then
  `helper` by `single_process`) and `branch_survey` events showing that group
  kill removes descendants while PID-only kill leaves the helper's children
  alive/reparented; final cleanup group-kills and verifies both trees. Cleanup
  failure returns an error instead of reporting `exited` success.
* exit: `exited` with the requested `code`, `reason=exit_code_requested`.
* signal: `signal_sent` is the last event for TERM/INT/KILL — a dead process
  cannot emit its own `exited`; the **caller** observes 143/130/137. STOP runs
  emit `watcher_spawned`, then `resumed` + `exited` after the `_cont` helper's
  SIGCONT. INT and TERM call `signal.Reset` first, so the death is by kernel
  default disposition, not intercepted by the CLI's Ctrl+C handler.

### Design decisions (do not silently re-decide in Phase 1)

1. **Helpers are real processes, not goroutines.** `simhelper._node` grows
   leaf or n-ary trees (`task`, `w(task,task)`) from the sim binary itself, so
   PPID/PGID relationships are kernel facts. The runner always spawns top-level
   children with `Setpgid` (own group); nested children inherit, which is what
   makes group-kill semantics demonstrable branch-by-branch. Helpers receive
   the scenario runner PID and self-exit if it disappears, bounding residue
   after an external SIGKILL.
2. **orphan vs process-tree are the two halves of one lesson.** Orphan-process
   kills only the worker PID and observes its tasks alive/reparented, then
   group-kills them for cleanup. Process-tree contrasts a worker PGID kill with
   a helper PID kill and then group-cleans the helper's surviving tasks. If
   either scenario changes those signal targets, the pair loses its meaning.
3. **`sig == SIGSTOP` cannot self-resume.** A frozen process's timers are
   frozen too, so the signal scenario pre-spawns a `_cont` watcher child before
   stopping itself. On cancel, the watcher is killed and reaped.
4. **Fatal self-kill stops the event stream deliberately.** After raising a
   fatal signal the scenario blocks forever (`select{}`) so that no racy, lying
   `exited` event is emitted between the kill syscall and delivery. Do not add a
   trailing exit event for TERM/INT/KILL runs.
5. **`--duration` clips, never truncates cleanup.** Every parent/child scenario
   derives a run deadline, funnels expiry into the same teardown an interrupt
   takes, and reaps its own children; grandchildren are verified
   `goneOrZombie` (zombies are the adopter's business, not the scenario's).
6. **Scaled phases, one shape.** frozen-worker scales freeze-after/freeze-for/
   grace proportionally when `--duration` is shorter than the default cycle, so
   tests exercise the same shape in less time.

### Verification performed (engineering slices, darwin/arm64, Go 1.27.1)

```text
gofmt -l .                  clean
go vet ./...                clean
go test -race -count=1 ./... ok
```

Manual, via the built binary: cpu-spin with 4 workers shows steady `work_report`
and ends cleanly; memory-pressure retains up to the limit; frozen-worker shows
`worker_state kind=stopped` in the process table, freeze -> resume -> kill(137);
orphan-process reports tasks alive with a new `ppid_after` and the dead
worker's pgid, then `tree_cleaned still_alive=0`; process-tree kills the worker
branch by group (tasks gone, helper untouched) then the helper by pid; `exit
--code 7` exits 7; `signal TERM/KILL/INT` produce 143/137/130 as observed by a
wait(2)ing caller; STOP runs are resumed by the watcher and exit 0.

The real-binary hard-kill audit was run on macOS for orphan-process,
process-tree, frozen-worker, and signal STOP: SIGKILLing the scenario runner
left no `_node`, `_cont`, or worker processes. Helpers now carry the runner PID
and self-terminate when it is no longer signalable, with their `--hold` timer as
a final bound.

Known gap: verified on macOS only (no Linux host here; CI has not run because
the repo has no remote). Linux `/proc`, signal, and group behavior still needs
an Ubuntu run.

## Questions for the reviewers (do not silently re-decide these)

1. **independent / 0.12** — Is `Flagged` the idiomatic Go answer, or should each
   scenario own a typed options struct parsed by a per-scenario `flag.FlagSet`
   built in `cmd/`? Is a value `Config` carrying a pointer `*Emitter` the right
   shape, or should `Run` take the emitter as a second parameter?
2. **architecture / 0.10** — The scenario claims ESTABLISHED from *read timeout with no
   EOF*, not from the kernel. Is that the right operational definition of "socket
   still established while application-level progress has stopped"? Should the
   server also model the opposite failure (stopped reading -> backpressure), or
   is that a separate scenario? Check `stallstate.go` for any edge that will
   bite when the recorder starts driving state transitions.
3. **implementation** — Concurrency review of `socketstall.go`: `sync.Once` shutdown,
   `WaitGroup.Add` from the connection handler while `Close` may be waiting
   (legal only because the counter is non-zero), ping writer vs. reader on one
   `net.Conn`, and the absence of a reader-unblocking goroutine (cancellation is
   bounded by the read deadline instead).
4. **Event key, decide before Phase 1** — The Phase 0 prose shows
   `"event": "worker_frozen"` in the example JSON, while the `Event` struct spec
   names the field `Type`. I implemented `type` (the struct is the authoritative
   contract). If the recorder wants `event`, change it now — it is the one part
   of this schema that is expensive to migrate later.
5. **LICENSE** — MIT with "Runopsy contributors" as holder. Replace with a legal
   entity if this will be commercialized.

## Original remaining checks (superseded by completion review)

| Item | Owner | Notes |
|---|---|---|
| 0.2 empty dirs | — | `pkg/`, `testdata/`, `scripts/` exist locally but have no tracked contents; intentionally reserved |
| 0.12 interface review | independent | `Flagged` is used by all scenario-specific options; review question 1 above remains open |
| 0.14 Linux hard-kill audit | architecture/implementation | macOS hard-kill test passed for orphan, tree, frozen-worker, and signal STOP; repeat under Ubuntu CI to verify Linux adoption/reaping |
| Linux runtime verification | implementation/architecture | Linux `/proc` and signal/group behavior should be exercised on Ubuntu CI/host; this local host is macOS |
| Final acceptance review | implementation + architecture | Run `make acceptance` and the full matrix on Linux and macOS |

## Verification performed

```text
gofmt -l .                  clean
go vet ./...                clean
go test -count=1 ./...      ok  internal/events, internal/simulator
go test -race -count=1 ./... ok  (no data races, no goroutine leaks)
make build                  bin/runopsy, bin/runopsy-sim
```

Manual, on `darwin/arm64` / Go 1.27.1:

* `runopsy-sim normal --duration 1s` -> `started` + heartbeats + `exited code=0`,
  exactly 1s, exit 0.
* `runopsy-sim normal --json --duration 1s | python3 -m json.tool`-style check ->
  4 well-formed records, all with `timestamp`/`scenario`/`type`.
* `runopsy-sim socket-stall` (defaults) -> 7.0s,
  `HEALTHY -> STALLED -> RECOVERED -> CLOSED`, `stall_detected silent_ms=1000
  socket=open progress=none`, `recovered stall_ms=6203`, exit 0.
* `SIGINT` and `SIGTERM` during `normal` -> exit 0, `exited reason=interrupted`.
* `SIGTERM` during `socket-stall`'s stall -> exit 0,
  `HEALTHY -> STALLED -> CLOSED` (no false recovery).
* 5 back-to-back short socket-stall runs -> all exit 0 with `CLOSED`; no
  leftover `runopsy-sim` processes, zombies, or listening sockets afterwards.
* `runopsy-sim --help` lists all registered scenarios; `definitely-unknown` exits 2 with an unknown-scenario message.
* `go test ./tests` exercises all scenarios through the built CLI, validates JSON event records and checks signal statuses and process cleanup.
* `make acceptance` runs the repeatable full-binary integration matrix.
* `go test -race -count=1 ./...`, `go vet ./...`, `go build ./...`, and
  `gofmt -l .` pass after the secondary acceptance/cleanup work.

Not verified: Linux (no Linux host available here; CI is `ubuntu-latest` but has
not run because the repo has no remote yet). All Phase 0 scenarios are
implemented on macOS; Linux paths in `internal/platform` (the `/proc` snapshot)
are written but only exercised by unit tests, not on a live Linux box.

## Phase 4 — engineering slice (timeline + causal engine core), self-review only

Status: implemented and verified on `darwin/arm64`, 2026-10-27. **Self-review,
not independent sign-off** — implementation and independent are unavailable this session, so
nothing here was reviewed by a second model.

New package `internal/causal` (all offline, deterministic for a given bundle):

| File | Contents |
|---|---|
| `events.go` | Event model (4.1), SubjectRef (4.2), provenance (4.17), relation vocabulary + tri-band causal confidence (4.6/4.7/4.10), canonical ordering (4.4), typed-explicit v1 observability: OOM_EVENT, socket progress, runner/worker roles are declared and **never fabricated** |
| `extract.go` | BuildTimeline: recorded events as authoritative, state machines for memory/disk/IO/CG-/CPU episodes with hysteresis + threshold-once (4.3/4.27), onset-unknown ACTIVE semantics (4.28), clock-discontinuity events (4.20), process reparent from PPID deltas, group-termination clustering, sensor-gap honesty (UNKNOWN never bridges an episode) |
| `compare.go` | Temporal helpers (4.5): Before/After/Within/Overlaps/DurationBetween/ImmediatelyPrecedes/SustainedAbove/Below/ChangedWithin; NoProgressFor **always false** in v1 because bundles carry no progress telemetry — call sites encode intent rather than silently substitute evidence |
| `graph.go` | Graph/edges/roots/chains (4.6/4.11-4.14/4.26): direction-validated proposals, cycle rejection naming the offending rule, DAG check over CAUSES/CONTRIBUTES only (PRECEDES stays a temporal fat), primary/secondary roles, recovered-chain semantics, Explain(edge) rendering |
| `rules.go` | Versioned rule registry (4.18): source/target pairs are the rule index (4.42); each rule declares Required/Supporting/Contradicting codes and a MaxGap (4.9) |
| `engine.go` | Rule application with contract enforcement: an edge whose required codes the bundle cannot verify is recorded as a `RejectedEdge` with the missing code - never an edge |
| `signature_link.go` | Phase-3 signature id -> emitted event types (4.16); `SignatureMatch.RelatedEvents` field added in `internal/diagnosis/diagnosis.go`, populated only by the caller that owns both report and timeline |

Conservative semantics for the architecture-owned conceptual items
(4.7/4.9/4.10/4.11/4.15), decided by engineering alone and recorded as provisional:

1. **Chronology vs causality (4.7)**: PRECEDES = canonical observed order
   only, always drawable, never counts for root eligibility; CORRELATED_WITH
   = equal-wall-timestamp clustering (explicitly *not* order claim);
   CONTRIBUTES_TO = cofactor with required evidence but weaker mechanism;
   CAUSES = declared mechanism whose required evidence the bundle actually
   shows. architecture-REVIEW: this distinction and CONTRIBUTES_TO's exact strength.
2. **Evidence requirements (4.9)**: rules declare Followup contract codes;
   the engine refuses edges whose required codes cannot be verified. The
   shipped OOM rule requires signal lineage, which v1 bundles do not record,
   so OOM_CAUSES_PROCESS_EXIT @1 can never fire on v1 data (honest by
   construction). architecture-REVIEW: whether signal lineage is the right
   constitutive condition, or one of several sufficient ones.
3. **Causal confidence (4.10)**: LOW/MEDIUM/HIGH bands over internal base
   weights 0.35/0.65/0.90, rendered only as bands, never as probabilities.
4. **Root definition (4.11)**: a root candidate = abnormal event type + has
   at least one downstream CAUSES/CONTRIBUTES edge + no upstream causal edge.
   Ranking: strongest outgoing edge weight, then downstream-effect count,
   then canonical order. A recovered failure chain is never a root. architecture-REVIEW:
   "limit reached" vs "pressure started" as anchor when both are present.
5. **Competing chains (4.15)**: ambiguity is represented, never resolved
   silently - all accepted chains are preserved with distinct roots; the
   broker-stall vs network-failure problem stays structurally expressible
   because chains are lists, not a single chosen path.
6. **Incomplete observation (4.28) and missing precursors (4.29)**: a
   condition already in effect at its first observation is ACTIVE with
   `OnsetUnknown`, never STARTED at an invented time; missing precursor
   telemetry is never back-filled. No fabrication is possible by the
   extraction code paths (sensor UNKNOWN gaps end episodes silently).

**Verified here**: `gofmt -l .` clean; `go vet ./...` clean; `go test -race
-count=1 ./...` green across all 10 packages; `go build ./...` clean. Direct CLI
checks covered text/causal output, JSON graph shape, combined diagnosis and
signature links, stable-edge explanation, and effect-only unknown-cause output.
New tests cover: threshold-once/hysteresis, onset-unknown, sensor-gap honesty,
clock discontinuity, cgroup crossing once per episode, CPU sustain minimum,
healthy-timeline emits no failure events, determinism (byte-identical
timelines), tie-breaks with equal timestamps, cycle prevention + rejection
records, direction validation, rule gap bounds, signal-contract non-firing,
lineage-verified reparent edge, roots/roles, competing-chain preservation,
recovered-episode Healthy(), counterfactual OOM-removal, disabled-rule
exclusion, rule-version lock, structural graph comparisons, edge evidence,
rule contract negatives, and unknown/mismatched provenance validation.

**secondary-owned work completed in this pass** (self-review, not independent
sign-off):

- 4.30-4.33 CLI: `runopsy-agent timeline FILE` renders normalized events;
  `--causal` adds rule-backed chains and root candidates; `--json` serializes
  the graph; `--explain-edge` accepts a stable `ED_...` ID, numeric index,
  rule ID, or endpoint pair. `--report` combines Phase 3 matches with causal
  graph output and `related_events` links.
- 4.39-4.40: graph-structure comparison checks nodes, endpoints, relation,
  rule, roots, chains, and IDs rather than rendered strings; validation tests
  reject dangling/duplicate nodes, missing provenance/evidence, unknown or
  mismatched rules, invalid stable event/edge IDs, backwards temporal claims,
  and cycles.
  Rule tests cover positive lineage/threshold, unrelated-subject negative,
  missing OOM signal evidence, and maximum-gap boundaries.
- 4.44-4.45: combined diagnosis/causal output and an unknown-cause report
  listing observed effects and missing telemetry. The unknown state is explicit
  and does not imply a causal root.
- 4.41 benchmark added and run once per size on darwin/arm64 / Apple M1 Pro:
  100 events: 132 us, 59.6 KB, 212 allocs; 1,000: 932 us, 760 KB, 1,151
  allocs; 10,000: 5.62 ms, 6.95 MB, 10,410 allocs. Single-iteration baseline,
  not a performance guarantee.
- 4.48 docs: `docs/causality.md`, `docs/event-model.md`, and
  `docs/causal-rules/README.md` record relation semantics, evidence contracts,
  provenance, event observability, CLI, and provisional architecture decisions.

**Not completed in secondary's assignment** (other owners): 4.37 counterfactual
corpus (adversarial) and architecture/adversarial/Terra independent semantics and adversarial
reviews. The integration slice (4.35/4.36 fixtures, 4.38 fuzzing, 4.41 performance,
4.46/4.47 end-to-end) landed afterwards; see the section below. The Phase 4 root
semantics remain provisional; do not describe the causal decisions as
independently reviewed.

## Phase 4 — integration slice (fixtures, fuzzing, performance, E2E), self-review only

Status: implemented and verified on `darwin/arm64`, 2026-10-27. Assignments
4.35, 4.36, 4.38, 4.41, 4.46 and 4.47. 4.37 counterfactuals and the independent
semantics/adversarial reviews remain with adversarial/Terra/architecture. Nothing in this
section is an independent sign-off.

### 4.35/4.36 — golden and healthy causal fixtures

Twelve committed fixtures under `testdata/causal/<name>/`, each a decoded
`incident.json` plus a reviewed `expected.json` (`class`, exact event multiset,
exact rule-backed edge multiset, root roles and onsets, unknown-cause anchor,
`graph_healthy`):

- **GOLDEN**: `oom-chain` (pressure → limit CAUSES, unexplained exit left
  unconnected), `frozen-worker` (onset-unknown stop, empty graph),
  `disk-full` (PRECEDES only, exhaustion anchored as UNKNOWN root),
  `orphan-process` (recorded PPID lineage → reparent CAUSES),
  `process-group-kill` (derived group termination → three member exits),
  `socket-stall` (flagship: established socket, no fabricated progress stall),
  `network-failure` (recorded close, no invented cause).
- **HEALTHY**: `high-cpu-build`, `long-idle-socket`, `high-memory-build`,
  `short-process-stop`, `temporary-network-pause`; each asserts zero causal
  edges, zero roots, and a healthy graph.

Harness: `internal/causal/fixture_defs_test.go` (definitions, builders, loader,
writer) and `internal/causal/fixture_compare_test.go` (structure comparison,
draft printer). Regenerate inputs with `RUNOPSY_WRITE_CAUSAL_FIXTURES=create`
(`force` overwrites); draft expectations with `RUNOPSY_PRINT_CAUSAL_FIXTURES=write`
and review before committing — the suite never regenerates `expected.json`, so a
behavior change fails the build. Every fixture also rejects the v1-unobservable
events (`OOM_EVENT`, `NETWORK_PROGRESS_*`, `RUNNER_*`, `WORKER_*`).

### 4.38 — temporal fuzzing

`internal/causal/temporal_fuzz_test.go`: deterministic jitter (±800 ms),
equal wall timestamps, dropped samples and recorded events, duplicated
samples/events, a 35 s sampling hole, reversed input arrays, 30-process churn,
and 60 seeded combined mutations. Each case asserts byte-identical repeated
analysis, unique stable IDs, dense sequence, canonical order (identical
duplicate facts treated as unordered), a validated acyclic graph, strict
observed order for PRECEDES/RECOVERY_OF, no backwards causal edge, at most one
PRIMARY root, and no unobservable event.

### 4.41 — performance, and three real defects found

New benchmarks cover 100/1,000/10,000 events and samples:
`BenchmarkGraphEngine`, `BenchmarkTimelineBuild`, `BenchmarkEndToEndAnalysis`.
darwin/arm64, Apple M1 Pro, `-benchtime=1s`, single run (indicative, not a
contract):

| Size | Timeline build | Graph+apply+validate | End-to-end |
|---|---|---|---|
| 100 events / 100 samples | 128 µs | 118 µs | 261 µs |
| 1,000 / 1,000 | 1.34 ms | 1.11 ms | 2.63 ms |
| 10,000 / 10,000 | 12.8 ms | 12.7 ms | 56.0 ms |

Roughly linear-to-`n log n` growth; edge generation is now 17 / 172 / 1,722
edges for 59 / 592 / 5,930 events. Three defects this work exposed, all fixed:

1. **Quadratic edge explosion / false episode history**: episode-recovery and
disk-pressure rules paired every source with every later target. The 10k-sample
stress capture produced **624,019** edges before the fix (and every early limit
"recovered" by every later recovery). `causal.Rule.NearestOnly` now accepts at
most one edge per source, to the nearest validated target; the same capture
produces 1,722 edges. Regression tests cover both recovery and PRECEDES rules.
2. **O(n²) validation**: `Graph.Validate` recomputed each event's duplicate
ordinal by re-hashing the whole order. It now assigns ordinals in one pass.
3. **Cycle check rebuilt the causal index per proposal**: `addEdge` now lazily
builds the index once and maintains it incrementally; `Validate` also hoists the
rule registry instead of rebuilding it per edge.

Extraction gaps found by fixture work (also fixed): a capture whose first
usable sample is already at the memory limit / disk exhaustion now records the
boundary fact with `onset_unknown` instead of losing it (4.28); input array
order is no longer evidence (samples and recorded events are processed in
timestamp order, provenance keeps the original index); and the engine now honors
the graph's documented direction contract, allowing CAUSES/CONTRIBUTES_TO at
equal sampling instants while PRECEDES/RECOVERY_OF still require observed order.

### 4.46/4.47 — end-to-end tests

`tests/phase4_e2e_test.go`, gated by `RUNOPSY_E2E_CAUSAL=1`: live simulator →
recorder → persisted bundle → `runopsy-agent timeline --report --json`.

- **4.46 memory pressure**: allocates in the simulator and freezes the capture.
  The test asserts the report's honesty invariants: no fabricated OOM/progress
  events, every edge directional/versioned/evidenced, every memory claim tied to
  its ≥90%/≥98% reading, limit edges only from
  `MEMORY_PRESSURE_CAUSES_LIMIT_BREACH@1`, and an explicit UNKNOWN root when no
  chain exists. On this host the simulated allocation never raises host memory
  above 90%, so the honest outcome is "no memory episode claimed" and the test
  records that. The observable half of the target chain (pressure → limit) is
  covered deterministically by the `oom-chain` fixture; the OOM step is not
  observable in v1 and is never invented.
- **4.47 socket stall**: asserts no `NETWORK_PROGRESS_*`, no network causal edge,
  no `BROKER_SOCKET_STALL`/`OOM_KILL` diagnosis without telemetry, and that the
  human-readable `--causal` output says "No validated causal root" when the
  graph is empty. Socket facts are collector-dependent; on hosts without a TCP
  table the test still enforces the no-fabrication contract.

Verified commands and results: `gofmt -l .` clean; `go vet ./...` clean;
`go test -race -count=1 ./...` green across all packages;
`RUNOPSY_E2E_CAUSAL=1 go test ./tests -run TestPhase4CausalEndToEnd` green in
~11 s. Fixture drift was checked by mutating an expectation (fails, then
restored). Not verified: Linux (no Linux host this session; CI is
`ubuntu-latest` but has not run — the repo has no remote yet).

## Phase 7 — engineering backend slice (November 5, 2026)

Scope from `docs/cloud/contract.md` §9, items 1–3 of engineering's queue plus the
initial SQL for item 4. The cloud stores, indexes and shows; diagnosis never
moves into it.

### 1 — internal/analysis + document v1 (§3.3)

New package `internal/analysis`: `Run(bundle, sha256hex, Options) (*Document,
error)` and `WriteJSON`. The document (`runopsy.analysis` v1) carries the
engine identity, evaluation options, bundle manifest + sha256 of the original
bytes, the bundle's privacy report, the diagnosis report, provider
interpretations, the causal graph (canonical-order nodes with per-event
evidence class, accepted edges, rejected edges, per-anchor failure analyses
with claim-level evidence class), the normalized timeline with per-event
evidence class, and the full snapshot series in capture order.

The orchestration that lived in `package main` (`buildCausalGraph`,
`diagnosisOptions`, `intentCovers`…, `linkDiagnoses`) moved verbatim into
`internal/analysis/wiring.go`; the CLI functions are thin wrappers, so CLI,
timeline renderer and worker run the same code (the "one Runopsy" rule).

`runopsy-agent analyze --document FILE` (value flag; `-` = stdout) writes the
document. Existing `--json`/text output is unchanged.

### 2 — engine identity + golden fingerprint (§4)

`diagnosis.AnalyzerVersion` 0.3.3 → **0.4.0** (same-engine drift: the
`SignatureVersion` moved 4→5 in November without a bump). New
`analysis.Engine` names analyzer version, signature version + set version,
sha256 of the sorted causal rule-ID list, the privacy policy
(`incident.PrivacyPolicy`, new constant `conservative-v1`, now used by the
redactor itself), and supported bundle formats. The golden fingerprint test
pins the engine identity and the sorted signature set; the causal rule hash
today is
`5167716d106987cd77cc0da5247f1f883afc1ed432ee8efe77ddf93bde719c70` —
bumping requires updating the pin and the analyzer version.

### 3 — analyzer worker (§5.4)

`cmd/runopsy-analyzer` + `internal/analyzer`. Child: stdin → `incident.Read`
(unmodified hostile-input reader) → `analysis.Run` → document on stdout;
self-limits (`RLIMIT_CPU` 70 s, `RLIMIT_NOFILE` 16), no inherited
environment (only `GOMEMLIMIT=1GiB`), bounded stdin read, exit codes
0/3/4 = READY/REJECTED/FAILED_LIMIT. Parent (`Runner.Run`): one child per job
in a fresh private directory, 60 s wall clock, statuses READY, REJECTED
(first-line reason), FAILED_LIMIT, FAILED_CRASH, stderr truncated to 4 KiB.
`-parent -bundle FILE` runs one job locally; `bin/runopsy-analyzer` and
`runopsy-agent analyze --document` produce **byte-identical** documents for
the same fixture (checked with cmp), which is the 7.43 precondition.

### 4 — Postgres schema (§7.1) — written, NOT yet applied

`db/migrations/0001_init.{up,down}.sql`: organizations, memberships
(owner/member), personal tokens (hashes only), uploads with
`UNIQUE (organization_id, sha256)` duplicate rule, append-only analyses with
`UNIQUE (upload_id, engine_key)`, the incidents view model, and the §5.3
upload-usage counters. Not applied or tested against a live Postgres — that
is the remaining part of engineering item 4 (needs a Postgres + a migration runner;
SQL was hand-checked, nothing executed it).

### Tests and checks (this session, darwin/arm64, Go 1.27.1)

`internal/analysis`: golden fingerprint, determinism (double render + TZ
change, byte-equal), digest contract, option recording, privacy-report
passthrough, nil-bundle guards. `cmd/runopsy-agent`:
`TestAnalyzeDocumentMatchesWorkerPath` (CLI document == analysis package
document). `internal/analyzer`: READY/REJECTED/FAILED_LIMIT/FAILED_CRASH
statuses via the real built binary, schedule/stdin budgets, stderr
truncation. `gofmt -l .` clean, `go vet ./...` clean,
`go test ./...` green (full run at the bottom of this entry).

### Remaining engineering items (after the other models land their pieces)

1. **Queue item 4 (7.5–7.6, 7.57): apply + test the migrations** against a
   real Postgres once hosted Postgres is chosen; add a migration runner to CI.
2. **Queue item 5 (§2.1/§6): upload flow + dedupe** needs web's Next.js
   scaffold (adversarial, 7.3) and object storage; the Go side then implements
   presigned-POST handling, the complete → worker job call with the
   dedupe/verify order, and the org-scoped read endpoints (7.35).
3. **Worker service shell**: the storage-facing HTTP worker receiving
   `{upload_id, object_key, expected_sha256}` (one request per container)
   around the existing `analyzer.Runner`; contract §8.1's [user] hosting
   choice gates deployment.
4. **Auto-upload + local queue (7.46–7.49)** after manual upload works: agent
   config, bounded-backoff queue, offline-first test.
5. **§7.2 reader work**: when anyone bumps `SchemaVersion`, `FormatVersion`
   or the redaction policy, the retained-decoder and declared-policy rules in
   contract §7.2 apply before that change lands.

Verification log: `gofmt -l .` clean; `go vet ./...` clean; `go build ./...`
plus both binaries; `go test ./...` twice with one flake each in the two
pre-existing live tests — `TestGitHubRunnerTraceCorrelation` (listener pid
left the process table under suite concurrency) and
`TestChurnKeepsProviderStateBounded` (wall-clock growth ratio, ran green at
`-count=3` standalone); both packages pass on rerun, and every other package
was green both runs.

## Phase 7 — secondary CLI slice and independent review (November 5, 2026)

secondary's unblocked Phase 7 work. Full detail: `docs/reviews/phase7-secondary-review.md`.

- **Upload API pinned** (`docs/cloud/upload-api.md`): create-or-duplicate
  `POST /api/uploads`, presigned POST to storage, `POST
  /api/uploads/{id}/complete`, one error envelope. This is the wire shape
  engineering's server must satisfy; the client is tested against it.
- **`internal/cloudclient`**: create/`PutObject`/`Complete`; https-only
  endpoints except loopback; the token goes to the API calls only and never
  to the signed storage POST; cross-host redirects are refused so the bearer
  token cannot follow one.
- **`runopsy-agent login` / `upload`** (7.11/7.12): credentials at
  `~/.config/runopsy/config.json`, written atomically 0600 inside a 0700
  directory, and refused if group/other-readable. `upload` validates the
  bundle locally with `incident.Read`, hashes the exact bytes sent, prints
  `Uploading incident … / Validated / Uploaded / <url>`, reports a §6
  duplicate as `Already uploaded`, maps 401 to the login command and never
  retries. `-config` is a test seam (`upload [-config FILE] PATH`; flags
  precede the path, matching the other commands).
- **Tests for 7.43/7.33**: every fixture renders twice to identical bytes and
  records the digest of the bytes it analyzed (19 bundles); the document's
  compatibility fields (`document_version`, engine identity, bundle
  `sha256`/`schema_version`/`format_version`) are pinned by JSON name.
- **Review findings fixed in the §7.1 SQL**: the object-key check now pins
  `orgs/{org}/bundles/{sha256}.runopsy` (the old `LIKE` admitted `..`), added
  the missing `token_hash` partial index used to resolve bearer tokens, and
  gave `upload_usage` its organization foreign key. Left as recommendations:
  denormalising 7.6's list columns onto `incidents`, catching `23505` as a
  duplicate at complete, and grouping by `incident_id` in the list. The
  migration is still unapplied — no Postgres here.
- **Deviations reported, not changed**: the document's `options` is a
  rendered string although contract §3.3 specifies `min_confidence` +
  `disabled`; fixing it is cheap before the first stored analysis and belongs
  to engineering's schema.

Blocked secondary work (no `web/` yet, so nothing renders a document): 7.13–7.22
UI, 7.45 accessibility, TypeScript document types and dashboard tests,
Next.js API review, auth-flow review, 7.50 (deferred), 7.51–7.54, and the
7.59 cost review.

## Phase 7 — integration end-to-end QA, demo fixtures and payload measurement (November 5, 2026)

Full detail in `docs/reviews/phase7-integration-e2e.md`; the numbers are in
`docs/cloud/performance.md`.

- **7.41/7.42 demo corpus**: `testdata/demo/manifest.json` maps the seven
  situations the dashboard must be seedable with onto the checked-in Phase 3
  bundles, and marks 7.42's five screenshot incidents. It points into
  `testdata/incidents/` rather than duplicating a corpus.
  `tests/demo_corpus_test.go` renders every entry through `analysis.Run` and
  fails if the manifest's promised verdict, panel list or ground-truth label
  drifts. Finding: OOM kill and broker stall (two of the five headline demos)
  abstain on these synthetic bundles because the discriminating telemetry is
  absent, so a dashboard must render `UNKNOWN` honestly; traced demo captures
  are remaining work.
- **7.44 payload**: `internal/analysis/scale_test.go` measures the stored
  document at 100 / 1,000 / 10,000 events: 0.26 MB / 1.22 MB / 10.86 MB, i.e.
  ~1.1 KB per event, with `analysis.Run` at 3 ms / 55 ms / 6.95 s. Paging the
  `timeline` and `series` arrays is therefore required above ~1,000 events; a
  200-event page is ~220 KB. Browser/DOM metrics are not measured and need
  `web/`. The 10,000-event case is opt-in (`RUNOPSY_SCALE_10K=1`): run in the
  parallel suite, it starves two wall-clock tests; see the review §5.1.
- **7.61 pipeline**: `tests/phase7_e2e_test.go` drives the real binary
  (`login`, `analyze --document`, `upload`) into a reference cloud that
  implements `docs/cloud/upload-api.md` v1, and asserts the stored original
  equals the file byte for byte, the stored document equals the laptop's
  document byte for byte, the read endpoint serves those bytes, a repeat upload
  is `Already uploaded` with no second analysis, a dropped storage connection
  and a truncated bundle both fail cleanly without touching the local artifact,
  and local analysis still works with the cloud unreachable. No change was
  needed in `internal/cloudclient` or `cmd/runopsy-agent/cloud.go`.
- **Not done**: 7.62 (no real GitHub runner here; also waits on the open Phase
  6 real-runner correlation row), the rendering leg of 7.61 and browser metrics
  (wait on `web/`), the server-side breakage matrix (waits on engineering's upload flow
  and worker endpoint), the worker-level upload corpus review (waits on adversarial's
  7.40 tests), and a dedicated healthy-cancellation fixture (corpus owner).
