# Phase 7 cloud contract (principal)

Status: **design, November 5, 2026.** Covers checklist items 7.1, 7.2, 7.9,
7.34 and 7.38, plus the constraints 7.7, 7.8, 7.30, 7.33, 7.36, 7.37 and 7.43
inherit from them. Every claim about current code names the file it comes
from; every number in §5 was measured on this tree (2-vCPU x86_64 sandbox,
Go 1.24, `deprehendo-agent` built from the November 4 tree).

Decisions marked **[user]** need the owner's answer before engineering builds the
piece that depends on them. Everything else is decided here; changing it
needs a reason written into this file.

---

## 1. Cloud boundary (7.1)

**The cloud stores, indexes and shows. It never diagnoses.**

| Cloud does | Cloud does not |
|---|---|
| accounts, sessions, personal API tokens | run or provision runners |
| organizations and memberships (owner, member) | remote execution or remediation |
| receive `.deprehendo` uploads and keep the original bytes | fleet orchestration, CI compute |
| run the **unmodified Go analyzer** on an upload and store its output | its own interpretation of a bundle in TypeScript |
| list, filter and search incident metadata (Postgres) | billing, plans, RBAC beyond owner/member |
| render the stored analysis | changing a stored diagnosis in the dashboard |
| delete and download | notifications beyond an optional webhook (7.50) |

Local-first invariants. Each is a test, not a principle:

- **L1.** The agent records, freezes, diagnoses and writes a bundle with the
  network down. Nothing in `cmd/deprehendo-agent` or `internal/agent` may import
  cloud code on the capture path.
- **L2.** `deprehendo-agent analyze` on a laptop and the cloud produce the same
  analysis document, byte for byte, for the same bundle and engine (§3.4).
- **L3.** Upload is a separate step after the local write succeeded (7.46:
  "local persistence happens first"). An upload failure never deletes,
  rewrites or blocks a local bundle.
- **L4.** A bundle is never re-encoded by the cloud. What a user downloads
  (7.29) is the exact bytes they uploaded; the SHA-256 shown is of those bytes.

---

## 2. Architecture (7.2)

```text
 deprehendo-agent (CLI)                       browser
   │ 1. POST /api/uploads  (token)            │
   │ ◄── upload id + presigned PUT URL         │
   │ 2. PUT bundle ──────────────┐             │
   │ 3. POST /api/uploads/:id/complete         │
   ▼                             ▼             ▼
 ┌──────────────────────────┐  ┌──────────────────┐
 │ web: Next.js (one app)   │  │ object storage   │
 │  UI + /api routes        │  │  originals +     │
 │  auth, orgs, metadata    │  │  analysis docs   │
 └──────┬──────────────┬────┘  └────────▲─────────┘
        │ SQL          │ analyze(job)    │ read by key
        ▼              ▼                 │
 ┌────────────┐  ┌───────────────────────┴──┐
 │ Postgres   │  │ analyzer worker (Go)     │
 │ metadata   │  │  one process per job     │
 └────────────┘  └──────────────────────────┘
```

Three deployable pieces, no queue system, no microservices beyond the worker:

1. **web** — Next.js + TypeScript (strict), UI and API routes. Owns auth,
   organizations, tokens, metadata reads, signed download URLs.
2. **analyzer worker** — a small Go HTTP service built from this repo. It
   accepts `{upload_id, object_key, expected_sha256}` from web only, fetches
   the bytes, runs one child process per job (§5.4), writes the analysis
   document to storage and returns the extracted metadata row. It has no
   database credentials and no user-facing routes.
3. **Postgres** (managed) for metadata, and **S3-compatible object storage**
   for originals and analysis documents.

### 2.1 Why the upload goes straight to storage

Vercel Functions accept at most a **4.5 MB request body** (larger payloads
fail with 413 `FUNCTION_PAYLOAD_TOO_LARGE`). A valid bundle can be up to
`maxArchiveBytes` (`MaxPayloadBytes` 64 MiB + 1 MiB, `internal/incident/bundle.go`),
and the writer can produce uncompressed bundles (`Writer.Uncompressed`,
`writer.go`). So the CLI never sends bundle bytes through a web function:

1. `POST /api/uploads` (authenticated) creates an `uploads` row — pending
   until an analysis of it reaches `READY`; v1 keeps no separate state column
   and reads readiness from `analyses.status` — chooses the object key (§6),
   and returns a presigned **POST policy** with `content-length-range`
   22..`maxArchiveBytes` and a short expiry (10 min). The client-declared
   SHA-256 is recorded but not trusted.
2. The client uploads directly to storage.
3. `POST /api/uploads/:id/complete` hands the job to the worker. The worker
   recomputes SHA-256 from the stored bytes; a mismatch fails the upload.

### 2.2 Why the worker is not a web function **[user: hosting]**

Analysis must not run inside the web app's functions:

- Fluid compute, on by default for new Vercel projects, lets **multiple
  invocations share one instance and process** concurrently. A hostile
  bundle that drives memory to the ceiling would take other organizations'
  requests with it.
- Vercel's Go runtime is in **beta**, and functions give no control over
  per-request rlimits.

Recommendation: run the worker on a container host where **one request gets
one container** (e.g. Cloud Run with `concurrency=1`, 2 GiB, 120 s request
timeout), web on Vercel, Postgres and storage managed. This adds one platform;
the alternative that keeps everything on Vercel is the Go runtime with
concurrency limited to 1 and the self-limits of §5.4, accepted as weaker. The
contract below holds for either; only §5.4's outer layer differs.

### 2.3 Authorization shape (constraint for 7.4–7.5, 7.35, 7.36)

- Every query that touches incident data is built from
  `organization_id = <session or token's active org>`; there is no code path
  that loads an incident by id alone and checks ownership afterwards.
- **Bundle contents never grant access.** Checksums detect corruption, not
  authenticity (`bundle.go`, `Read`): `incident_id`, repository, runner name
  and hostname are whatever the uploader wrote. They are display and search
  fields inside one organization, never keys across organizations, never a
  reason to attach an upload to an organization.
- Storage object keys are never sent to the browser. Downloads are 60-second
  signed GET URLs minted by web after the org check.
- The worker trusts only web's job call (shared secret or platform identity),
  and only reads the one key it was given.

---

## 3. Parsing architecture (7.9): one interpretation, in Go

### 3.1 Decision

TypeScript never opens a `.deprehendo` archive and never decides what an event,
signature or edge means. The Go analyzer turns a verified bundle into an
**analysis document**; web stores and renders that document. The dashboard
may filter, sort, paginate and format; it may not derive a diagnosis,
confidence, causal link or evidence class.

### 3.2 What exists and what is missing

`deprehendo-agent analyze --json` (`cmd/deprehendo-agent/analyze.go`) emits the
diagnosis report, provider interpretations and `causal.FailureAnalysis` list.
It does **not** emit what 7.13–7.24 render: the timeline, snapshots (resource
series, process tree, connections), the causal graph's nodes and edges with
their checks, per-link evidence class (`newQualityResolver`), the privacy
report, or the manifest.

The orchestration that produces these lives in package `main`:
`buildCausalGraph` and `diagnosisOptions` (`cmd/deprehendo-agent/timeline.go`)
wire provider intent covers into both the causal graph and the diagnosis
engine. A second caller that re-implemented that wiring would be the "two
Deprehendos" 7.9 forbids.

### 3.3 Required change (engineering, first)

1. Move the orchestration into **`internal/analysis`**:
   `analysis.Run(bundle *incident.Bundle, opts Options) (*Document, error)`.
   `analyze`, `timeline` and the worker all call it. The CLI keeps its text
   renderers; they read from the `Document`.
2. `deprehendo-agent analyze --document FILE` writes the document as JSON. The
   existing `--json` output stays as it is for compatibility.
3. The document, `deprehendo.analysis` v1:

   | field | content |
   |---|---|
   | `document_version` | `1` |
   | `engine` | §4 engine identity |
   | `options` | `min_confidence`, `disabled` (cloud always uses defaults) |
   | `bundle` | manifest fields + `sha256` of the original bytes |
   | `privacy` | the bundle's `privacy.json` as read |
   | `diagnosis` | `diagnosis.Report` as today |
   | `providers` | provider interpretations as today |
   | `causal` | nodes, edges (rule id, band, checks with detail), `failures` |
   | `timeline` | normalized events with provenance and evidence class |
   | `series` | per-snapshot system/process/connection data the charts need |

   Large arrays (`timeline`, `series`) keep their bundle order and carry a
   stable index so web can page them without re-sorting (7.44).
4. Determinism: the document is a pure function of (bundle bytes, engine,
   options). Measured today: three runs of `analyze --json` on the same bundle
   give the same SHA-256, a `CGO_ENABLED=0` build gives the same bytes as the
   default build, and the analysis path reads no clock, environment or host
   (`time.Now` appears only in GitHub API fetching, `internal/provider/github/api.go`).
   `internal/analysis` must keep that: add a test that runs `Run` twice and
   under a different `TZ` and compares bytes.

### 3.4 Local/cloud equality (feeds 7.43)

The equality test is mechanical: for every fixture in `testdata/incidents/`,
`deprehendo-agent analyze --document` output must equal the document the worker
stored, byte for byte, when both report the same engine identity. If they
differ, the cloud is wrong by definition.

---

## 4. Engine identity (prerequisite for 7.33 and 7.34)

A stored analysis must name the exact engine that produced it. Today it
cannot:

- `AnalyzerVersion` is still `"0.3.3"` (`internal/diagnosis/diagnosis.go`),
  though its own comment says it is bumped "whenever matching behavior changes"
  and `SignatureVersion` moved 4 → 5 on November 4 (OOM_KILL accepts the
  tracer's `oom:mark_victim` record). Two engines that diagnose the same
  bundle differently both report `analyzer_version: 0.3.3`.
- The report carries `signature_set_version` (2) but not `SignatureVersion`
  at the top level (only per match), and causal rules have no set version at
  all: each rule carries `@N` in its id, but adding or removing a rule changes
  nothing a report records.

Required (engineering, with the §3.3 work):

```json
"engine": {
  "analyzer_version": "0.4.0",
  "signature_version": 5,
  "signature_set_version": 2,
  "causal_rules": "sha256 of the sorted rule-id list",
  "privacy_policy": "conservative-v1",
  "bundle_formats": [{"format_version": 1, "schema_version": 1}]
}
```

and a **golden fingerprint test**: the test holds the expected
`causal_rules` hash and the sorted list of `SignatureID@version`; changing a
rule or signature without updating the golden, and bumping
`AnalyzerVersion`, fails CI. That turns the drift above into a build error.

---

## 5. Hostile uploads and parser isolation (7.8, 7.37, 7.38)

### 5.1 What the reader already guarantees

`incident.Read` (`internal/incident/bundle.go`) was built for hostile input
in Phase 2, and the cloud reuses it unchanged:

| attack | disposition today |
|---|---|
| path traversal, absolute paths, temp-file escape | **cannot occur**: `Read` never extracts; it decodes five fixed member names in memory. `Extract` writes only those five names through `os.OpenRoot`. The worker never calls `Extract`. |
| extra or duplicate members, huge file counts | end-of-central-directory parsed by hand **before** `archive/zip` allocates entries: exactly 5 entries, central directory ≤ 64 KiB, no extra entries |
| symlinks, encrypted members, odd compression | rejected: regular mode only, encryption flag rejected, Store/Deflate only |
| ZIP64, multi-disk | rejected (sentinel sizes, disk fields, ZIP64 extra) |
| decompression bomb | declared sizes checked against the 64 MiB budget before reading; every read through `LimitReader`; actual size must equal declared (`TestDecompressionBombBound`) |
| malformed or ambiguous JSON | UTF-8 required; duplicate keys (with Unicode case folding) rejected; nesting ≤ 64; ≤ 256 fields per object; ≤ 250,000 records; unknown fields rejected; trailing content rejected |
| forged checksums with bad content | semantic `Validate` runs after checksums (`TestForgedValidChecksumsStillRejectInvalidEvidence`) |
| unexpected schema or format version | rejected: `SchemaVersion`, `FormatVersion`, `SnapshotEncoding` must match |
| secrets a modified bundle tries to smuggle in | the redaction policy is re-applied and must change nothing |

The worker adds nothing to this list except the outer limits below. It must
not add a second ZIP or JSON parser.

### 5.2 What it costs: measured

Valid bundles built with `incident.Encode` (repeating snapshots of 50–100
processes), then `deprehendo-agent analyze --json`:

| expanded payload | upload (compressed) | `validate` only | `analyze --json` | peak RSS |
|---:|---:|---:|---:|---:|
| 1.3 MB | 21 KB | — | 0.48 s | 28 MB |
| 12.5 MB | 192 KB | — | 3.08 s | 179 MB |
| 24.9 MB | 380 KB | — | 6.17 s | 345 MB |
| 29.9 MB (240k records) | 456 KB | 7.85 s / 296 MB | 7.53 s | 421 MB |

Conclusions:

- **Compressed size is not a cost proxy.** A 456 KB upload expanded to 30 MB
  and cost 7.5 s of CPU and 421 MB. Rate limits on bytes alone would not
  bound work; the limits below are on parse time and memory.
- **Cost is linear and already bounded** by the reader's budgets. At the
  64 MiB ceiling, extrapolation gives ~17 s and ~0.9 GB; not measured, because
  the record cap is reached first with this shape.
- **Reading dominates, not diagnosis.** CPU profile of `ReadFile`:
  duplicate-key scan 45 %, the two JSON round-trip `clone`s of the privacy
  re-check 29 %. Worth optimizing later; not a security issue.

### 5.3 Limits

| limit | value | enforced by |
|---|---|---|
| stored object size | 22 B .. `maxArchiveBytes` | presigned POST policy; worker re-checks |
| expanded payload, records, JSON shape | as §5.1 | `incident.Read` |
| job wall time | 60 s (≈3.5× the extrapolated worst case) | worker parent kills the child |
| job memory | 1.5–2 GiB hard, `GOMEMLIMIT` 1 GiB | container cgroup limit (not `RLIMIT_AS`, §5.4) |
| concurrent jobs per organization | 2 | web, at `complete` |
| analyses per organization per hour | 60, then 429 | web |
| parse-seconds per organization per day | 1,800 s | web, from job durations |

The rate numbers are MVP defaults for the owner to adjust; the per-job limits
come from §5.2.

### 5.4 Isolation of one job

The threat is not code execution (memory-safe Go, no extraction); it is a
job that exhausts the machine or wedges, and state leaking between
organizations through a shared process. So:

1. **One child process per job**, started by the worker parent with a fresh
   private temp dir as its only writable path, an empty environment except
   `GOMEMLIMIT=1GiB`, and the bundle on stdin. Output is the document on
   stdout, errors on stderr (truncated to 4 KiB, never containing bundle
   content).
2. The child binary is built with **`CGO_ENABLED=0`**. The default build of
   `deprehendo-agent` links `runtime/cgo` through `net` (GitHub API code), which
   the analysis path does not need. Measured: the static build produces
   byte-identical output.
3. Limits on the child: `RLIMIT_CPU` 70 s and `RLIMIT_NOFILE` 16 (both
   measured: a 30 MB bundle analyzes normally under them; `RLIMIT_CPU` 2 s
   kills it). **Not `RLIMIT_AS`**: Go reserves far more address space than it
   uses, and measured, `RLIMIT_AS` 1.5 GiB kills the analyzer with ~50 MB of
   heap in use. The hard memory bound is the container's cgroup limit
   (1.5–2 GiB, one job per container); `GOMEMLIMIT` only makes the GC work
   harder before that.
4. The parent enforces the 60 s wall clock with `exec.CommandContext` and
   records exit status: success, `REJECTED` (reader refused the bundle; the
   error class is stored), `FAILED_LIMIT` (killed by a limit), `FAILED_CRASH`
   (panic or other exit).
5. No network from the child. On a container host, the worker's egress is
   limited to the storage endpoint.
6. One request per container (§2.2). The parent holds no bundle data after
   the job returns.

### 5.5 Required tests (adversarial, with principal review)

The upload integration corpus (7.40), each with its expected status and error
class: valid; old schema; truncated; checksum mismatch; duplicate member;
sixth member; symlink member; ZIP64 sizes; declared-size bomb; actual-size
mismatch; duplicate JSON key via case folding; nesting 65; 250,001 records;
privacy-violating payload; 60 MiB expanded valid bundle (must succeed under
the limits); forged manifest identity. Most already exist as Go tests in
`internal/incident`; the new work is driving them through the worker and
asserting the job status, the resulting dashboard state, and that nothing is
logged from the bundle. A rejected bundle leaves a minimal organization-scoped
incident status row (`REJECTED`/`FAILED_*`) so the dashboard can explain the
failure; it does not produce a diagnosis document or bundle-derived metadata.

---

## 6. Storage, identity and duplicates (constraints for 7.7, 7.28–7.30)

- Original key: `orgs/{organization_id}/bundles/{sha256}.deprehendo`. Analysis
  document key: `orgs/{organization_id}/analyses/{analysis_id}.json`. Object
  ACLs private; content-type `application/octet-stream` and
  `Content-Disposition: attachment` on download; never served inline.
- **Duplicate = same organization, same SHA-256 of the bytes.** `complete`
  returns the existing incident (7.30's preference). The same bytes in two
  organizations are two independent uploads.
- **`incident_id` is not unique.** `deprehendo-agent github locate` re-encodes
  an enriched bundle (`github_api_cli.go` calls `incident.Encode`), so one
  incident legitimately exists as two different byte sequences with the same
  `incident_id`. Store both; the list groups uploads by `incident_id` within
  the organization and marks the newest. Never merge them.
- Delete (7.28) removes the metadata rows, every analysis document and the
  original object for that upload, in that order, and is not soft.

---

## 7. Re-analysis and history (7.34) and schema compatibility (7.33)

### 7.1 Model

```text
uploads    (immutable)  id, organization_id, sha256, object_key, size,
                        incident_id, schema_version, format_version,
                        uploaded_by, uploaded_at
analyses   (append-only) id, upload_id, engine (jsonb, §4), engine_key,
                        status, error_class, document_key, duration_ms,
                        created_at
incidents  (view model) upload_id, active_analysis_id, original_analysis_id,
                        + the searchable columns of 7.6, copied from the
                        active analysis
```

- The **original analysis** is the first analysis that reached `READY`. It is
  never updated or deleted while the upload exists.
- **Re-analysis** inserts a new `analyses` row with the current engine. It
  never edits an existing document. `UNIQUE(upload_id, engine_key)`: running
  the same engine twice is a no-op.
- **Active analysis** changes only by an explicit action (user or an admin
  backfill), and the change is recorded with who and when. The incident page
  shows which engine produced the view, the original verdict when it differs,
  and whether a newer engine exists.
- Search columns follow the active analysis; history stays queryable.

### 7.2 Old bundles must stay readable

Two current behaviours would break 7.33 the first time the format moves:

- `Read` accepts only the **current** `SchemaVersion`/`FormatVersion`. When
  either is bumped, the reader must dispatch to a retained decoder for every
  version ever written; a bundle the engine cannot read gets an analysis row
  with status `UNSUPPORTED`, never a deletion.
- `Read` re-applies the **current** redaction policy and rejects any payload
  it would change. If the policy is tightened, every older stored bundle
  becomes unreadable. The privacy report already names its policy
  (`"conservative-v1"`, `privacy.go`); the check must use the policy the
  bundle declares, and old policies stay in the code.

Both are queued for whoever bumps a version (§9); neither changes anything
today.

---

## 8. Decisions for the owner

1. **[user] Worker hosting.** Recommended: container host with one request
   per container (e.g. Cloud Run, `concurrency=1`). Alternative: Vercel Go
   runtime (beta) with weaker isolation (§2.2).
2. **Authentication. Decided November 12, 2026: Neon's managed Better
   Auth**, with GitHub as the main sign-in method. (Auth.js, the example
   named earlier, has been maintained for security fixes only since September
   2025.) The dashboard sends Better Auth's session JWT (EdDSA) as a Bearer
   token. The API verifies it against the auth service's JWKS and maps `sub`
   to `memberships`; `X-Deprehendo-Organization` selects the organization.
   Personal API tokens for the CLI stay in our own table, stored as hashes.
   Design and build plan: `docs/cloud/browser-auth.md`.
3. **Rate defaults** in §5.3. **Decided November 9, 2026:** keep the §5.3
   numbers: 60 analyses per organization per hour (a rolling 60-minute
   window, migration `0003_hourly_usage`), 1,800 parse seconds per day, and
   2 concurrent jobs per organization (plus a server-wide cap,
   `MaxConcurrentTotal`).

---

## 9. Work queue

**engineering (backend), in order:**

1. `internal/analysis` + `analyze --document` + document v1 (§3.3).
2. Engine identity + golden fingerprint test; bump `AnalyzerVersion` (§4).
3. Analyzer worker: parent/child, limits, statuses (§5.4), local Docker run.
4. Postgres schema and migrations for §7.1 plus organizations, memberships,
   tokens (7.5–7.6, 7.57).
5. Upload flow §2.1 and dedupe §6.

All five items are done (HANDOFF, "Phase 7 — engineering backend slice" and "Phase 7 —
engineering backend completion"): `internal/analysis` + document v1, engine identity
with the golden fingerprint, the analyzer worker with its limits, the §7.1
schema, and the upload flow with dedupe — implemented as the Go server
`internal/cloudserver` (`POST /api/uploads`, `POST /storage`, `POST
/api/uploads/{id}/complete`) behind `deprehendo-cloud serve`, with migrations
applied by `deprehendo-cloud migrate` (real runner, tested twice against Postgres).

Also landed with it: the org-scoped read endpoints (7.35, `docs/cloud/read-api.md`),
metadata search and filters (7.25/7.13), delete/download with digest
verification (7.28/7.29), per-organization abuse limits (7.37), the local
object store with immutable keys (7.7), operational telemetry (7.55,
`docs/cloud/operations.md`), and auto-upload with a bounded local queue
(7.46–7.49). The 7.36 matrix is executed against Postgres.

Still open for someone else:

- **Worker over HTTP / hosting** (§2.2, item: hosting decision) — the analyzer
  runs in-process in `serve` today (`JobRunner`), which is the controlled
  server-side process §3.1 allows; a separate worker service is a hosting
  choice, not a correctness one.
- **Browser auth + organizations UI** (7.4–7.5): the server consumes personal
  tokens only; sign-up/session belongs to the auth provider decision (§8.2).
- **Re-analysis endpoint** (7.34): schema and history model are in place, the
  endpoint is not built.
- **Object storage backend** (7.7): `LocalStore` is the MVP; an S3-compatible
  `Store` replaces it without handler changes.

**adversarial:** 7.3 scaffold after 1 lands; the §5.5 corpus through the worker.

**secondary:** independent review of the document schema (§3.3) and §7.1 schema
before migrations land, plus a secondary review of 7.59 after the measurement
pass. The schema and cost reviews are recorded in
`docs/reviews/phase7-secondary-review.md`.

**integration (done, see `docs/reviews/phase7-integration-e2e.md`):** 7.41–7.42
demo corpus (`testdata/demo/manifest.json`, `tests/demo_corpus_test.go`),
7.44 payload measurement (`internal/analysis/scale_test.go`) and rendered-DOM
measurement (`web/test/performance.test.tsx`), 7.61 (`tests/phase7_e2e_test.go`,
`tests/phase7_dashboard_render_test.go`, `tests/phase7_failures_test.go`) and
the worker-level 7.40 review (`tests/phase7_upload_corpus_test.go`,
`docs/cloud/upload-corpus.md`). The dashboard leg now renders the CLI's
document through the real components; the failure matrix covers analyzer
reject/limit/timeout/crash, storage read and write failures, a DB write lost
after storage, and a membership change on every access path. One defect was found
and fixed: a retried `complete` could answer 200 with an incident URL that
404'd when the view insert had failed (`ensureIncidentRow`).

7.62 passed on November 21: traced real-runner captures replace the two
headline demos that abstained (OOM now reaches `OOM_KILL`; the stall abstains in
the generic engine and carries the GitHub provider's stall signature), and the
hosted analysis is byte-identical to local. Still open, and not
correctness-gated: browser paint metrics, and §5.5 rows 2/13/15 (old schema needs §7.2
decoders; the other two are documented as reader-covered or deliberately not
worker-driven). §5.5 now matches the implemented behavior: rejected uploads
leave a minimal status row so the dashboard can explain the failure.

**principal (next):** the final security gate (7.60) over the now-existing API:
`internal/cloudserver` (auth, scoping, storage, parsing) and
`internal/uploadqueue`; the authorization audit (2.3, 7.36) can now read the
handlers and the executed matrix in `docs/cloud/authz-matrix.md`.

**Version bumps (whoever makes them):** §7.2 before the first change to
`SchemaVersion`, `FormatVersion` or the redaction policy.

---

Sources for platform facts: Vercel Functions limits
(<https://vercel.com/docs/functions/limitations>), Vercel Go runtime
(<https://vercel.com/docs/functions/runtimes/go>), Vercel Fluid compute
(<https://vercel.com/docs/fluid-compute>), all read November 5, 2026.
