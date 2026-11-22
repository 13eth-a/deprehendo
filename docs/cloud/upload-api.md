# Upload API (client contract, v1)

Status: **pinned by secondary, November 5, 2026.** This is the wire shape the
`runopsy-agent` CLI implements (`internal/cloudclient`, `docs/cloud/contract.md`
§2.1/§6). The server is engineering's to build; when the server and this document
disagree, one of them is wrong and the difference must be resolved here rather
than in two clients.

Scope: exactly three calls and one error envelope. Authentication is the
personal token of checklist 7.12, sent as `Authorization: Bearer <token>` on
the two API calls only — never to the storage endpoint, never inside a bundle,
never logged.

## 1. Create an upload

```http
POST {endpoint}/api/uploads
Authorization: Bearer <token>
Content-Type: application/json

{
  "sha256": "9f2c…",          // hex of the exact bytes, lowercase
  "size_bytes": 184320,        // length of the file
  "incident_id": "inc_01J…",   // display data from the bundle (§2.3)
  "schema_version": 1,
  "format_version": 1
}
```

`201 Created` with a target to upload into:

```json
{
  "upload_id": "upl_01J…",
  "object_key": "orgs/org_5f1b…/bundles/9f2c….runopsy",
  "upload": {
    "url": "https://app.example.com/storage",
    "fields": {"key": "orgs/…", "policy": "…", "x-amz-signature": "…"}
  }
}
```

`200 OK` when the same organization already holds these bytes (§6 dedupe):
the CLI must not upload anything, and reports the existing incident.

```json
{
  "upload_id": "upl_01J…",
  "duplicate": true,
  "incident_id": "inc_01J…",
  "url": "https://app.example.com/incidents/inc_01J…"
}
```

The `upload` object is a **server-signed storage policy**, not a provider's
presigned POST. `upload.url` is this server's own `/storage` route; the bytes
go through the server, which writes them to the object store (S3-compatible or
local) after checking the policy. The `policy` field is a base64url payload
and `x-amz-signature` is an HMAC over it, both made with the server secret.
The payload binds the object `key`, the `sha256` the policy was issued for,
the organization, a size range of 22 to `maxArchiveBytes`, and a lifetime of
15 minutes. The `key` and `x-amz-signature` field names follow the S3 form
convention so the client needs no special case; no AWS credential is involved.

`sha256` and `size_bytes` here are client claims, recorded but not trusted:
the storage step recomputes the digest from the received bytes, and the server
rejects any digest that does not match the policy's `sha256`.

## 2. Upload the bytes

```http
POST {upload.url}
Content-Type: multipart/form-data
```

Parts: every key of `upload.fields` (the client sends them in alphabetical
order), then the file as the last part. The file part is named `file`, content
type `application/octet-stream`. Success is `2xx` with no body the client needs.

Storage responses are plain-text `http.Error` replies, not the JSON envelope in
§4: `403` for a refused policy, `413` for a body outside the policy's size
bounds, `400` for a digest mismatch or a missing file part.

No `Authorization` header is sent here. A bundle is never re-encoded: the
bytes uploaded are exactly the bytes the CLI validated, so a later download
(7.29) and the stored `SHA-256` describe the same file.

## 3. Complete

```http
POST {endpoint}/api/uploads/{upload_id}/complete
Authorization: Bearer <token>
```

`200 OK`:

```json
{
  "upload_id": "upl_01J…",
  "incident_id": "inc_01J…",
  "url": "https://app.example.com/incidents/inc_01J…",
  "duplicate": false
}
```

This is where the server verifies the stored SHA-256, hands the job to the
analyzer worker, stores the metadata row and returns the dashboard URL. The
CLI treats a non-2xx as a failed upload and prints the error class; a
`duplicate: true` here is also success (§6: return the existing incident).

## 4. Errors

Every non-2xx API response uses one envelope:

```json
{"error": {"code": "RATE_LIMITED", "message": "60 analyses per hour"}}
```

| status | code (recommended) | CLI behaviour |
|---|---|---|
| 401 | `UNAUTHENTICATED` | "run `runopsy-agent login`" |
| 403 | `FORBIDDEN` | print message, no retry |
| 413 | `TOO_LARGE` | print the server's limit |
| 422 | `INVALID_BUNDLE` | print the reader's rejection reason |
| 429 | `RATE_LIMITED` | print retry-after when present |
| 5xx | `UNAVAILABLE` | print message; the auto-upload queue retries later (7.46–7.48) |

The manual command never retries (bounded backoff belongs to the auto-upload
queue, not to an interactive `upload`) and never prints the token or the
bundle's contents. When the credential file opts into auto-upload, a completed
incident is queued after it is saved locally and retried there.

## 5. Outside this contract

The read half has its own document: **`docs/cloud/read-api.md`** (list with
search and filters, one incident, the analysis document, the original bundle,
delete). Token creation is `runopsy-cloud token`; there is no `GET /api/me`, so
`login` stores an endpoint and a token after a format check and correctness is
proven by the first upload (`401` is unambiguous). Re-analysis is designed but
not built (contract §7.1).

The server implementing this contract is `internal/cloudserver`, wired up by
`runopsy-cloud serve`; the reference server in `tests/phase7_e2e_test.go`
remains the client's independent fixture.
