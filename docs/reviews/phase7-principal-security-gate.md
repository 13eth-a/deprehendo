# Phase 7 — principal security gate (7.60) and principal review roles

Date: November 9, 2026. Reviewer: principal (roster: 7.60 owner; reviewer for
7.4–7.6, 7.8, 7.12, 7.27, 7.36, 7.37, 7.39, 7.43, 7.46–7.49, 7.61; final
review for 7.62, closed November 21).

## Verdict

**The upload/read API passes the gate for a private beta**, meaning your own
organization on the Railway + Neon deployment, once the three checks under
"Before the first real upload" are done. That covers the fixes below plus
`make test-cloud`, the dependency scan and the Railway bucket immutability
test.

**It does not pass for public sign-up.** When this review was written,
browser authentication, session cookies and the dashboard host did not exist,
so those rows were **OPEN**. They have since been built and checked: the
deployed dashboard's headers and session cookies passed on November 16–18 (see
the session row). Public sign-up still waits on custom SMTP for verification
and reset email (Neon's production checklist) and an invite flow.

## Method and limits of this review

- The review was static, reading the code as it is in the repo today:
  `internal/cloudserver`, `internal/clouddb`, `internal/cloudclient`,
  `internal/uploadqueue`, `internal/analyzer`, the reader limits in
  `internal/incident/bundle.go`, `cmd/deprehendo-cloud`, `cmd/deprehendo-agent/cloud.go`,
  `db/migrations`, the `Dockerfile`, and the Phase 7 tests.
- What was run: an offline copy of the module (Go 1.24, with a compile-only
  `pgx` stub; the real toolchain is 1.27.1) built `./internal/... ./cmd/...`.
  `go vet` was clean, `gofmt -l` was clean, and `go test` passed for
  `internal/cloudserver` and `internal/cloudclient`, including the new gate
  tests under `-race`. The `tests` package typechecks.
- **On the Mac, November 11, 2026 (owner run, Go 1.27.1):** `go vet ./...`
  was clean. `go test -count=1 ./internal/cloudserver/ ./internal/cloudclient/`
  passed. `make test-cloud` applied `0001_init`, `0002_retention_index` and
  `0003_hourly_usage`, reported `schema is current`, and `ok deprehendo/tests`
  for the whole Postgres-gated suite, including the three new gated tests.

## 7.60 checklist

| Item | Status | Evidence |
|---|---|---|
| Authorization tests | **PASS after fix** | Org scoping is structural (`organization_id` is the first predicate everywhere; other orgs get 404). Membership loss gives 403 on every path (`TestPhase7OrganizationChangeRevokesEveryPath`). New: owner-only delete and activate (G2), covered by `TestPhase7MemberCannotDeleteOrActivate`. |
| Upload size limits | **PASS after fix** | `create` takes 22 B to the archive budget (`422`/`413`). The storage POST was the gap (G1). It now has a capped body, capped fields, and a policy check before the file part is read. |
| Decompression limits | PASS | `incident.Read`: exactly five regular members, no ZIP64, encryption or symlinks, Store/Deflate only, declared *and* actual uncompressed sizes capped, `LimitReader` on every member. integration's corpus drives a 65 MiB declared bomb (`tests/phase7_upload_corpus_test.go`). |
| Path-traversal protection | PASS | The reader never extracts. Storage keys pass `safeKey` (local and S3) and `policyRE`. Incident ids match `^[A-Za-z0-9_-]{3,64}$` before they reach a URL or `Content-Disposition`. |
| Parser timeouts | PASS | One child per job, 60 s wall clock (`exec.CommandContext` + `WaitDelay`), `RLIMIT_CPU` 70 s, `RLIMIT_NOFILE` 16, empty environment, private temp dir. New: HTTP `ReadTimeout`/`WriteTimeout`/`IdleTimeout` (G5). |
| Token redaction | PASS | Tokens are 32 random bytes, stored only as SHA-256, never logged, and the bearer header is never echoed. The agent config file is 0600 and refused if wider. The client redacts endpoint userinfo (F1) and the storage URL (F2). |
| Secrets not logged | **PASS after fix** | Server log lines carry error text and fixed-shape counters only. pgx v5 redacts the password in connection-string errors; that was not re-verified against v5.12.0 here. New: the client's storage-failure path now sanitizes the reply body like every other server message (F3 was incomplete, G6). |
| Immutable original bundles | PASS (Neon and Railway) | Conditional PUT (`If-None-Match: *`). `409` is now also treated as already-exists (7.7 fix), and redirects are not followed. A second conditional PUT to the same key returned `PreconditionFailed` on Neon (November 7) and on the Railway bucket `deprehendo-0uz5hzbri3moxaaaa` (November 11). The test key was deleted afterwards. |
| Secure object storage | PASS | Buckets are private and reached only by the server with SigV4. Credentials live in Railway variables. https is required unless the endpoint is loopback. An unsigned request to the Railway bucket returns `403`, so it is not public (November 11). The bucket credentials were exposed during testing; they were rotated and the server variables updated (November 16). |
| HTTPS | PASS for the API | The client refuses plain http except on loopback and refuses cross-host redirects. TLS is terminated at the Railway edge. The dashboard host sends HSTS (see the session row, November 16). |
| Secure session cookies | **PASS (November 16–18)** | §8.2 decided November 12: Neon's managed Better Auth. The API side is built: EdDSA-only JWT verification against the JWKS, membership-based org selection, and unit and gated tests (`docs/cloud/browser-auth.md`). The dashboard is deployed on Railway (`web-production-d673c0ef.up.railway.app`). On November 16, `curl -sI /` returned `Strict-Transport-Security: max-age=31536000; includeSubDomains`, a `Content-Security-Policy` (`default-src 'self'`, `connect-src 'self'`, `frame-src` limited to the app and the Neon Auth origin, `frame-ancestors 'none'`, `object-src 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and `X-Frame-Options: DENY`. `script-src` keeps `'unsafe-inline'` for the Next.js bootstrap scripts. On November 18, after sign-in on the deployed site, the browser showed the session cookie as `Secure`, `HttpOnly` and `SameSite=Lax`. |
| Dependency scan | **PASS after fix** | The first `govulncheck` run (November 11, Go 1.27.1) found 12 reachable standard-library vulnerabilities. Two hit gate code directly: GO-2026-6859, an HTTP/1 server crash via a `MaxBytesReader` race (the storage POST now uses `MaxBytesReader`), and GO-2026-6608, a MIME header memory-limit bypass (the storage POST's multipart reader). `go.mod` now requires **go 1.27.4**, which fixes all twelve. After the bump, `govulncheck ./...` reports **No vulnerabilities found**, and `npm audit` in `web/` reports **0 vulnerabilities** (npm's registry setting was changed from plain http to https first). Three findings in imported or required modules are not called by our code. |

## Findings and fixes

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| G1 | High | `POST /storage` is unauthenticated until its policy verifies, but it called `ParseMultipartForm` (holding up to ~66 MiB in memory, plus temp files on disk, with no body cap) **before** looking at the policy. Anyone could pin memory and disk with junk POSTs. | The whole body is capped with `MaxBytesReader` and the form is read as a stream. Each field is capped at 4 KiB, and at most 8 fields are accepted. The file part is refused unless a valid policy came before it (every client sends the fields first). Parts are never `Close()`d on refusal, because `Close` drains the part. | `TestStoragePostReadsNothingPastAMissingPolicy` (8 MiB body, under 1 MiB read), `…StopsReadingAnOversizedField`, `…RefusesFileBeforePolicy`, `…BoundsPolicyFields` |
| G2 | High | Delete (which destroys the immutable original) and activate (which changes the diagnosis every member sees) had no role check. `deprehendo-cloud token` defaults to `member`, which is what an agent token on a CI runner would be, so a leaked runner token could wipe the organization's evidence. The authz matrix already called for owner-only. | `requireOwner` runs after the org lookup, so other organizations still get 404 and members get 403. Reads, upload and re-analysis stay open to members. | `TestPhase7MemberCannotDeleteOrActivate` (gated) |
| G3 | High (privacy) | `deleteIncident` deleted the `uploads` row (cascading `analyses`) **before** querying `analyses` for document keys. The query then always came back empty, so every per-engine analysis document survived the user's delete. Only the legacy key, which current builds never write, was removed. | Document keys are read first through the same `documentKeys` the retention sweep uses. A failed read stops the delete instead of stranding documents. | `TestPhase7DeleteRemovesEveryStoredObject` (gated: no object under the org prefix survives) |
| G4 | Medium | Job slots were per-organization only. Waiting used a `sync.Cond` that ignored the request context, so the queue was unbounded and abandoned requests still ran. The contract's memory bound assumes one job per container, but on Railway every analyzer child runs inside the server's container. | Added `MaxConcurrentTotal` (default 2; each child may use about 1 GiB). The wait now returns when the request context ends, and the handler answers `503 UNAVAILABLE`. | `TestAcquireJobHonoursTheServerWideCap`, `…PerOrganizationCap` (`-race`) |
| G5 | Medium | `serve` set only `ReadHeaderTimeout`, so a slow body could hold a connection indefinitely. | `ReadTimeout` 5 m (enough for 65 MiB over a slow link), `WriteTimeout` 5 m (covers the 60 s analysis), `IdleTimeout` 2 m, `MaxHeaderBytes` 64 KiB. | none; it is server configuration |
| G6 | Low | Secrets-audit F3 was incomplete: the storage-failure path printed the reply body without filtering. | Wrapped in `sanitizeServerText`. | existing client tests |
| G7 | Low | The container ran the server and every analyzer child as root. | `USER deprehendo` (uid 10001). `/app/storage` is the only writable app path; children write only under `/tmp`. | needs a `docker build` and run |

### Recorded, not changed

- **The rate-limit unit disagreed with the contract. Resolved November 9,
  2026, per the owner's decision.** §5.3 says 60 analyses per organization
  per *hour*, but `checkUsage` compared `MaxAnalysesPerHour` against a
  *daily* counter (effectively 60 per day). The limit is now a rolling
  60-minute window. Migration `0003_hourly_usage` adds per-minute counters
  (`upload_usage_minutes`), `checkUsage` sums the last 60 minutes, and the
  429 carries `Retry-After` (when the oldest minute ages out) with the
  message `60 analyses per hour` (upload-api §4). Parse seconds stay per day.
  Minute rows older than a day are trimmed on each charge. Covered by
  `TestPhase7AnalysisLimitIsPerOrganizationPerHour` (gated). The migration and
  the exact SQL were checked against PostgreSQL 16: the window sum, the
  `Retry-After` value, an empty org, the trim, the cascade on org delete, and
  down/up.
- **`create` is not rate limited.** A member token can insert unbounded
  pending `uploads` rows. They are cheap, and the retention sweep removes
  stale pending rows.
- **`checkUsage` fails open on a database error**, and its read-then-charge is
  racy under concurrent completes. Both are deliberate and documented. The
  concurrency caps still bound the damage.
- **Pending storage policies die on restart**, and a second replica would
  reject the first replica's policies. The `Dockerfile` already says to run
  one replica. Set `SigningSecret` from a variable before scaling out.
- **Without `-external-url`, link host and scheme come from the request's
  `Host` and `X-Forwarded-Proto` headers.** This only affects links in the
  caller's own response, and Railway sets `EXTERNAL_URL`.

## principal review roles

| Item | Verdict |
|---|---|
| 7.4–7.5 auth and organizations | Accepted for tokens. Memberships grant access and roles now gate destructive actions (G2). Browser sign-in is not built (§8.2). |
| 7.6 incident database model | Accepted. Constraints were reviewed earlier (`db-review.md`). The delete-path defect was in the handler, not the schema (G3). |
| 7.8 hostile bundle validation | Accepted (see the decompression and path rows). The server re-hashes the stored bytes and never trusts the client's digest. |
| 7.9 / 7.38 parsing architecture and isolation | Accepted as built. On Railway the server-wide cap (G4) is now the only cross-org memory bound. The contract's one-job-per-container worker is still the §8.1 hosting decision. |
| 7.12 API-token auth | Accepted (token redaction row). No token expiry, which is acceptable for personal tokens with revocation. |
| 7.27 privacy controls | Accepted after G3. Deletion now removes every derived document. The reader re-applies the redaction policy. |
| 7.34 re-analysis | Accepted. Append-only history. Activate is now owner-only. Re-analysis consumes the org's quota and slots. |
| 7.36 org authorization tests | Accepted. The two-org matrix and membership-change tests exist. Role cases 7 and 9 are now enforced and tested. Case 8 (switching organizations with one user) still has no fixture. |
| 7.37 abuse protection | Accepted with G1, G4 and G5 fixed and the hourly analysis window in place. |
| 7.39 secrets audit | Accepted. F1 and F2 were confirmed fixed. F3 was completed (G6). |
| 7.43 local/cloud consistency | Accepted. `TestPhase7ServerPipeline` asserts the server's `/analysis` bytes equal `analyze --document`. |
| 7.46–7.49 auto-upload and offline queue | Accepted. Opt-in, 0600 queue file, no token in the queue, bounded to 500 entries, capped backoff. Bundles persist locally before any network attempt. |
| 7.61 full end-to-end | **Both halves pass against production data; the dashboard is not yet hosted.** Server half on Railway + Neon (November 12): fresh upload, objects in the Railway bucket, and deployed `/analysis` byte-identical to local `analyze --document`. Dashboard half (November 14): the Next.js host, run locally against the deployed API, covers sign-up, the owner grant, the incident list, the `frozen-worker` analysis from the Railway bucket, and the sign-out redirect. Still to do: run the same check once the dashboard itself is deployed on https, and the sim → trace leg on real hardware (7.62). |
| 7.62 real-runner demo | **PASS (November 21).** Two traced captures from a self-hosted runner on a Lima VM, registered to `13eth-a/deprehendo-runner-e2e`. OOM: a real job allocates 4 GiB on a 4 GiB VM, the kernel kills it (exit 137), and the engine names `OOM_KILL` HIGH 0.80 from the job cgroup's OOM counter. Stall: three minutes of blocked outbound HTTPS on an idle runner. The generic engine abstains (`UNKNOWN`, by design) and the GitHub provider reports `GITHUB_RUNNER_COMMUNICATION_STALL` MEDIUM. Both bundles uploaded to the deployed API, and the hosted `/analysis` is byte-identical to local `analyze --document`. That needed one fix: the hosted analyzer had not registered the GitHub provider (`cmd/deprehendo-analyzer`, test `TestPhase7HostedAnalyzerInterpretsGitHub`). The hosted dashboard renders both. The bundles replace the synthetic OOM and stall demos (`testdata/demo/manifest.json` v2). Follow-ups, not gating: the tracer ran on the proc-connector fallback, not eBPF; the dashboard has no provider panel; the incident list's Confidence column shows "—". |

## Before the first real upload

1. ~~`go test` and `make test-cloud` on the Mac~~: **done November 11, all
   passing.**
2. ~~Dependency scan~~: **done November 11.** Clean on Go 1.27.4 (see the table).
3. ~~Railway bucket immutability and public-access check~~: **done November 11**
   (`PreconditionFailed`, and unsigned access returns `403`). The bucket
   credentials exposed during testing were rotated on November 16.
4. ~~Rebuild and redeploy the Railway image~~: **done November 12.** Commit
   `eab5d70` (Go 1.27.4) is live. A storage POST with a 5,000-byte policy
   field gets `400 form field exceeds its size bound`; the previous build
   answered `403`. So the streaming storage fix is serving in production.

## Owner decisions this gate depends on

- §8.2: the browser auth provider. It unblocks the session-cookie row and the
  dashboard host.
- §8.3: the rate defaults. **Decided November 9:** 60 analyses per org per hour,
  with the 1,800 parse seconds per day unchanged.
- §8.1: whether the analyzer moves to its own one-job-per-container worker.
  Until then, `MaxConcurrentTotal` must be sized to the Railway container's
  memory.

## secondary secondary review

secondary's secondary review was completed November 16, 2026. It confirms the
private-beta upload/read verdict subject to the prerequisites and open dashboard
items above. adversarial's H1 on manual deletion is fixed and tested. secondary also
records a scoped privacy follow-up (L1): the operator-run retention sweep
deleted rows before objects, so a storage failure could leave an untracked
object. L1 was fixed and tested on November 16. See
[the secondary review](phase7-secondary-gate-review.md) for scope and recommendation.
