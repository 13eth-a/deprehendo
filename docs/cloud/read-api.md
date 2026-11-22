# Read API (server contract, v1)

Status: **implemented by engineering in `internal/cloudserver` (November 5, 2026)** and
exercised by the gated server suite (`tests/phase7_server_test.go`, run by
`make test-cloud` and the `cloud` CI job). The upload half is
`docs/cloud/upload-api.md`; this document covers what the dashboard and the
CLI read back.

Scope: the endpoints the bundled dashboard needs (7.35), the metadata search
and filters it needs (7.25, 7.13), and the two artifact endpoints (7.28, 7.29).
There is deliberately no public API, no sharing and no cross-organization
access.

## Authentication and scope

Every endpoint below requires `Authorization: Bearer <personal token>` (7.12).
The token row carries the user and the organization; each query is built with
`organization_id` as its first predicate (contract §2.3). An incident that
belongs to another organization is **404**, the same answer as an incident that
does not exist: a 403 would confirm the id exists.

| failure | status | body code |
|---|---|---|
| missing or malformed `Authorization` | 401 | `UNAUTHENTICATED` |
| unknown or revoked token | 401 | `UNAUTHENTICATED` |
| token's user is no longer a member of its organization | 403 | `FORBIDDEN` |
| other organization's incident, or no such incident | 404 | `NOT_FOUND` |
| malformed query parameter | 400 | `BAD_REQUEST` |

All errors use the upload API's single envelope (`upload-api.md` §4).

## `GET /api/incidents`

Metadata only, newest first. The archive is never opened to answer it.

Query parameters (all optional, all combinable):

| parameter | meaning |
|---|---|
| `q` | free-text search, case-insensitive, at most 128 characters. Matched against the external incident id, primary signature, runner name, runner version, repository, workflow and job. `%` and `_` are literal, not wildcards. |
| `id` | exact external incident id (`inc_…`) |
| `signature` | exact primary signature |
| `severity` | exact severity |
| `runner` | exact runner name |
| `repository` | exact repository |
| `workflow` | exact workflow |
| `job` | exact job name |
| `platform` | exact platform |
| `from` | `created_at` lower bound: RFC 3339 or `YYYY-MM-DD` |
| `to` | `created_at` upper bound (exclusive): RFC 3339, or a date whose whole day is included |
| `limit` | page size, default 50, clamped to 1..200 |
| `offset` | page offset, clamped to `>= 0` |

A malformed value (`limit=abc`, `from=yesterday`, an over-long `q`) is a 400:
silently ignoring a filter would show the user incidents that do not match
what they asked for.

Response: an array of summaries.

```json
[
  {
    "incident_id": "inc_01J…",
    "created_at": "2026-11-05T12:01:07Z",
    "triggered_at": "2026-11-05T12:00:58Z",
    "primary_signature": "GITHUB_RUNNER_COMMUNICATION_STALL",
    "confidence": 0.82,
    "confidence_band": "HIGH",
    "severity": "high",
    "runner_name": "linux-prod-03",
    "repository": "acme/infra",
    "workflow": "CI",
    "job": "integration-tests",
    "platform": "linux",
    "analysis_status": "READY"
  }
]
```

`confidence_band` is the engine's band for the top match (`VERY_HIGH`,
`HIGH`, `MODERATE` or `NONE`), copied from the analysis document when it was
stored; it is omitted when there is no match.

`analysis_status` is `READY`, `REJECTED`, `FAILED_LIMIT` or `FAILED_CRASH`.
A non-ready incident still appears: it has a row, a reason, and no document
(7.32's "no blank page").

## `GET /api/incidents/{id}`

One incident's metadata, including the fields the list omits:
`upload_id`, `runner_version`, `run_id`, `hostname_hash`, `architecture`,
`bundle_size`.

## `GET /api/incidents/{id}/analysis`

The stored `runopsy.analysis` document, served **byte for byte** as the engine
wrote it (7.43). The server never re-renders or re-derives it; the dashboard
reads the same bytes `runopsy-agent analyze --document` produces locally.

- `200` with `Content-Type: application/json` and the document body.
- `202 PROCESSING` with the status as the message when the analysis is not
  ready and there is no document.
- `404 NOT_FOUND` when the document object is missing (metadata without its
  derived artifact is a storage incident, not an empty page).

## `GET /api/incidents/{id}/bundle`

The original `.runopsy` file (7.29).

Before serving, the server re-hashes the stored object and compares it with the
digest recorded at upload. A mismatch is **500 `UNAVAILABLE`**: unreproducible
evidence is refused rather than served. A successful response is
`application/octet-stream` with
`Content-Disposition: attachment; filename="<incident id>.runopsy"` and
`X-Content-Type-Options: nosniff`.

## `DELETE /api/incidents/{id}`

Removes the incident for real (7.28): the bundle object and every analysis
document are deleted first, then the `uploads` row (which cascades to
`analyses` and `incidents`). If storage cannot delete an object, the endpoint
returns `503` and keeps the database rows so the owner can retry. Missing
objects count as already deleted.

Response: `{"deleted": true, "incident_id": "inc_01J…"}`.

The analysis rows are append-only by design (7.34); deletion is the only way a
row disappears, and it removes the whole upload rather than editing history.

## Re-analysis history (7.34)

Implemented in `internal/cloudserver/reanalyze.go`; the schema already kept
the pointers, these endpoints use them. Nothing here edits a stored document:
a re-analysis appends an `analyses` row and moves `active_analysis_id`, while
`original_analysis_id` never moves while the upload exists.

- `GET /api/incidents/{id}/analyses` — every analysis row for the incident's
  upload, oldest first: `analysis_id`, `engine`/`engine_key`, `status`,
  `error_class`, `created_at`, and `active`/`original` flags.
- `POST /api/incidents/{id}/reanalyze` — run the server's current engine over
  the stored bytes. Same engine twice is a no-op (`{"reanalyzed": false}`
  with the existing analysis); a new engine appends a row and moves the
  active pointer (`{"reanalyzed": true}`). Usage limits, the digest
  re-check, the 60 s job budget and telemetry charge are identical to
  `complete`. Each engine's document lives under its own key
  (`orgs/{org}/documents/{upload}-{enginehash}.json`), so history never
  overwrites itself; the original per-upload key from earlier builds is still
  read and still deleted.
- `POST /api/incidents/{id}/activate` with `{"analysis_id": "ana_…"}` —
  move the active pointer to an existing analysis of the same upload
  (explicit action, 7.34). The body is strict JSON; an id from another
  upload or organization is `404`.

## Not in this version

- Organizations, membership changes, sessions and token management are CLI/
  library work behind the dashboard's auth provider (contract §8.2, decided in
  `docs/cloud/owner-decisions.md`), not part of this API.
- Events and timeline endpoints are served by the analysis document itself;
  a separate `GET /api/incidents/{id}/events` is deliberately not built while
  the document is the canonical result (7.9's "one Runopsy").
