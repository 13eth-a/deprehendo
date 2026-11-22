# Authorization matrix (checklist 7.36)

Status: **implemented in the Go server, partially exercised.**

Updated November 5, 2026: the API is `internal/cloudserver` (not `web/`
routes); every row below is implemented there, and the rows marked ✅ are
asserted by `tests/phase7_server_test.go` against a real Postgres
(`make test-cloud`, plus the `cloud` CI job). Rows marked ⏳ are implemented but
not yet covered by an executable test: they need the browser session (adversarial's
`web/` work) or a second role/member fixture.

| # | path | handler | test |
|---|---|---|---|
| 1 | `POST /api/uploads` | `create.go` | ✅ pipeline (dedupe) |
| 2 | storage POST | `storage.go` | ✅ hostile-storage test |
| 3 | `POST /api/uploads/{id}/complete` | `complete.go` | ✅ org-B 404 is implied by the read rows; not asked directly |
| 4 | list incidents | `incidents.go` (list) | ✅ search test (org B sees nothing) |
| 5 | read incident / analysis | `incidents.go` | ✅ 404 for org B, 401 without a token |
| 6 | re-analysis | — | ⏳ not built (contract §7.1 design only) |
| 7 | set active analysis | — | ⏳ not built |
| 8 | download original | `getBundle` | ✅ org-B 404 + byte-identical download |
| 9 | delete | `deleteIncident` | ✅ org-B 404, owner 200, rows and objects gone |
| 10 | token create / revoke | `clouddb` + `runopsy-cloud token` | ⏳ unit-level only |
| 11 | worker job call | in-process `JobRunner` | ⏳ no HTTP worker yet (contract §2.2, hosting decision) |
| 12 | storage object direct access | `LocalStore` | ✅ no route exposes a key; forged policy refused |

Each row is an access path the contract requires, the check it must make, and
the response for a request from another organization. Source of truth:
`docs/cloud/contract.md` §2.3 and §6, `docs/cloud/upload-api.md` §1–§4.

Principle (contract §2.3): every query that touches incident data is scoped by
`organization_id` taken from the session or token. No path loads an incident
by id and checks ownership afterwards. Bundle contents never grant access.

## Cross-organization response (proposed)

When a caller asks for an object that exists in another organization, the
server returns **404 Not Found** with the same body as a missing object. It
does not return 403, because a 403 confirms that the id exists.

This is proposed, not yet decided. The upload API's `403 FORBIDDEN` (upload-api
§4) applies to a token that is valid but lacks permission in the current
organization, for example a member trying an owner-only action. It is not used
for another organization's objects.

## Access paths

| # | Path | Caller | Required check | Other org's object |
|---|---|---|---|---|
| 1 | `POST /api/uploads` | CLI with personal token | token valid (else 401); `organization_id` from the token's active org; dedupe scoped to that org | No cross-org input: the body names no object. A `sha256` that exists only in another org is **not** a duplicate (contract §6) and is stored as a new upload. |
| 2 | presigned POST to storage | CLI, no token | policy issued by path 1 for that org; key fixed by the server | Policy is bound to one object key. A key from another org is never issued. |
| 3 | `POST /api/uploads/{id}/complete` | CLI with token | `upload.organization_id` equals the token's org; state is `PENDING`; server recomputes SHA-256 (§2.1 step 3) | **404** for another org's `upload_id`. Mismatch of the stored digest → failed upload, not 404. |
| 4 | list incidents (7.6 filters) | browser session | query built from session org; filters cannot widen scope | Other orgs' rows are never selected, so there is nothing to 404. |
| 5 | read incident / analysis document | browser session | upload and analysis rows joined on org | **404**. Analysis document key is never returned to the browser (contract §2.3). |
| 6 | re-analysis (7.34) | owner or member (policy to decide) | org match; engine key unique per upload (`UNIQUE(upload_id, engine_key)`) | **404**. A re-run of the same engine is a no-op, not an error. |
| 7 | set active analysis (7.34) | owner only (**enforced**, `requireOwner`, principal) | org match; role check; change recorded with who and when | **404** for other orgs. **403** for a member in the same org who is not owner. |
| 8 | download original (7.29) | browser session | org match; 60-second signed GET minted after the check | **404**. No signed URL is minted before the check. |
| 9 | delete (7.28) | owner only (**enforced**, `requireOwner`, principal) | org match; role check; document keys read first, then rows, then every object | **404** for other orgs. **403** for a member in the same org. |
| 10 | token create / revoke | session user | tokens belong to the user and are listed only within their own orgs | Token ids from other users: **404**. |
| 11 | worker job call (web → worker) | web only | shared secret or platform identity; worker reads only the key it was given | Not user-facing. Any other caller: **401**, no read performed. |
| 12 | storage object direct access | none | object ACL private; no public URL | Not reachable by URL. |

## Two-organization test cases

The implemented subset lives in `tests/phase7_server_test.go`
(`TestPhase7ServerPipeline`, `TestPhase7ServerRefusesHostileStorage`): two
organizations, two tokens, the same bundle, every read path checked from both
sides, deletion attempted by the wrong organization first. The list below is
the full set the contract asks for; cases 6 and 8 still need a role fixture and
the browser session.

1. Org A uploads bundle X. Org B, same bytes: upload succeeds as a new upload
   (no duplicate), and org B cannot list, read or download org A's upload.
2. Org B calls `complete` with org A's `upload_id`: **404**, no job enqueued.
3. Org B requests org A's analysis document id directly: **404**, body
   identical to an unknown id.
4. Org B requests a download of org A's original: **404**; no signed URL in
   the response.
5. A bundle whose `incident_id` equals org A's incident is uploaded by org B:
   no link is created; the incident lists only under org B.
6. A member (not owner) in org A calls delete: **403**; the owner gets 200.
7. Expired or revoked token: **401** on every API path.
8. Token from org A used while its active org is B: only B's rows are visible.

## Not covered

- Auth provider behaviour (contract §8.2 is undecided; the server only consumes
  personal tokens today).
- Rate limits (contract §5.3), which are implemented as per-organization
  counters in `usage.go` and tested only for their refusal path.
- The browser session cookie scope; that belongs to the auth design.
- Cases 6 (member vs owner role) and 8 (organization switching): the role check
  exists for 4xx responses but no test creates a member-level token yet.

## principal update (November 9, 2026)

Cases 7 and 9 are now enforced: a member token gets **403** on activate and delete,
and another organization still gets **404** because the org lookup runs first.
`TestPhase7MemberCannotDeleteOrActivate` covers both. Reads, upload and re-analysis
stay open to members. Case 8 (one user switching organizations) still has no fixture.
Detail: `docs/reviews/phase7-principal-security-gate.md`.
