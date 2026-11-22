# Browser sign-in (contract §8.2)

Status: **Done for the private beta (November 18, 2026).** The dashboard is
deployed on Railway with email and GitHub sign-in. The API accepts its session
tokens. Headers and session cookies pass the 7.60 gate, and the dashboard half
of 7.61 is verified. See "Deployed and verified" below.
Decision: **Neon's managed Better Auth.** It was chosen over self-run Better
Auth, Clerk and WorkOS because it is included in the Neon plan already in use,
supports GitHub sign-in, stores users in Runopsy's own Neon database (schema
`neon_auth`), and issues Ed25519 JWTs that Go verifies with the standard
library. Self-run Better Auth is the same library, so switching later changes
configuration, not code.

## How it fits together

```
browser ── session cookie ──▶ Next.js dashboard (Better Auth client, via Neon Auth)
                                   │  server-side fetch, Authorization: Bearer <session JWT>
                                   │                     X-Runopsy-Organization: org_…
                                   ▼
                              runopsy-cloud API ── verifies JWT against the auth URL's JWKS
                                   │                  sub → memberships (Runopsy's tables)
                                   ▼
                              Neon Postgres  ·  Railway bucket
```

- **The browser holds only Better Auth's session cookie.** The dashboard's
  server code gets the short-lived session JWT (15 minutes, EdDSA) and calls
  the API server-to-server. The API therefore needs no CORS, and a JWT is never
  exposed to page JavaScript.
- **The CLI is unchanged.** Personal API tokens keep working exactly as
  before. A bearer token takes the JWT path only when it has the three-part JWT
  shape *and* browser auth is configured.
- **Organizations and roles stay in Runopsy's tables.** The token's `sub` is
  the user id stored in `memberships.user_id`. Better Auth's own
  active-organization claim (`o`) is ignored, so there is one source of truth.
  Removing a member takes effect on the next request, without waiting for the
  token to expire.

## API side (built)

| Piece | Where |
|---|---|
| JWT verification: EdDSA only, JWKS cached with a 10-minute refresh, early refetch at most every 30 s for unknown key ids (rotation), last good keys kept through an outage; `iss`/`aud` must match, `exp` required, 60 s leeway, `sub` must match `^[A-Za-z0-9_-]{1,128}$` | `internal/cloudserver/browserauth.go` |
| `requireToken` accepts a session JWT beside personal tokens. The organization comes from `X-Runopsy-Organization`, which a user with one membership may omit. Responses: invalid token → 401, no membership → 403, ambiguous or malformed header → 400. Owner-only actions apply the same way. | `internal/cloudserver/server.go` |
| `GET /api/me` returns the caller and its organizations (`{"user_id","auth":"browser"\|"token","organizations":[{id,name,role}]}`), so the dashboard can pick the header | `internal/cloudserver/me.go` |
| Configuration: `RUNOPSY_AUTH_URL` (the Neon Auth URL); optional `RUNOPSY_AUTH_JWKS_URL`, `RUNOPSY_AUTH_ISSUER`, `RUNOPSY_AUTH_AUDIENCE`. With none set, the API is token-only. | `cmd/runopsy-cloud/main.go` |
| Granting access: `runopsy-cloud member -database DSN -user <user id> -org org_… [-role owner\|member] [-remove]` | `cmd/runopsy-cloud/main.go` |
| Tests: `browserauth_test.go` (valid token, 16 refusal cases, rotation without hammering, outage, config, refusal before the database), plus the gated `TestPhase7BrowserSessionsUseMembershipsAndOrganizationHeader` | `internal/cloudserver/`, `tests/` |

## Email sign-up: verified November 13, 2026

`neon.ts` sets `auth: true`. `neon deploy` turned Managed Auth on and wrote
`NEON_AUTH_BASE_URL` to `.env.local`. `web/scripts/auth-smoke.ts`
(`npm run auth:smoke` in `web/`) uses Neon's Auth SDK (`@neon/auth`, plain
client) against the real service. It signs up a new
`runopsy-smoke-<time>@example.com` user with a random in-memory password,
then:

1. reads the current user back from the session;
2. signs out and confirms no session is left;
3. checks that a wrong password is refused with `401 invalid_credentials`;
4. signs in again;
5. takes the session JWT;
6. with `RUNOPSY_API_URL` set, calls `GET /api/me` on a local
   `runopsy-cloud serve` started with `RUNOPSY_AUTH_URL=$NEON_AUTH_BASE_URL`.

Result: **ALL PASS.** The API verified the 868-character EdDSA JWT against
Neon's real JWKS and returned the same user id with `"auth":"browser"`.
Secrets are never printed. The SDK reports some failures by throwing, so the
script routes every call through one handler.

Each run leaves a test user. To remove them, run this in the Neon SQL editor,
after checking that the sessions and accounts of the deleted users are removed
with them:

```sql
SELECT id, email FROM neon_auth."user" WHERE email LIKE 'runopsy-smoke-%@example.com';
DELETE FROM neon_auth."user" WHERE email LIKE 'runopsy-smoke-%@example.com';
```

Before production: Managed Auth sends verification and reset emails from
Neon's shared SMTP. Production needs custom SMTP (Neon's production
checklist).

## Dashboard host: built, verified locally against production (November 14, 2026)

`web/` is now a Next.js 16 app (commit `7d3917d`). The pieces:

- `lib/auth/` uses Neon's SDK. `app/api/auth/[...path]` is the same-origin
  auth proxy, and `proxy.ts` protects every route except `/`, `/demo` and
  `/install`.
- `lib/runopsy-api.ts` calls the API server-side only, with Bearer JWT and
  `X-Runopsy-Organization`; an unreachable API shows a 503 page instead of
  a crash.
- The pages are the landing page, install guide, public demo (from the
  checked-in `frozen-worker` fixture), email sign-in and sign-up (GitHub
  button behind `NEXT_PUBLIC_AUTH_GITHUB`), the incident list and detail
  using the existing view components, and the organization picker.
- `next.config.ts` sets the security headers.
- `npm test` (34) passes, as do `npm run typecheck` and `next build`.

**Verified on November 14.** The dashboard ran locally (`npm start`) against
the deployed Railway API (`RUNOPSY_AUTH_URL` set, commit `7d3917d`), and:

1. `/` and `/demo` load signed out;
2. `/incidents` redirects to sign-in;
3. sign-up lands on "No organization yet" with the user id;
4. after `runopsy-cloud member … -role owner`, `/incidents` lists
   `frozen-worker` and `disk-full`;
5. `frozen-worker` opens its full analysis, read from the Railway bucket;
6. after sign-out, `/incidents` redirects to sign-in again.

One snag found on the way, now understood: a local API without
`RUNOPSY_S3_BUCKET` reads documents from local disk, so incidents uploaded
through Railway answer `404 analysis document is missing`. Point local
dashboards at the Railway API, or give the local API the Railway bucket
settings.

## Deployed and verified (November 14–18, 2026)

- **Host.** `web/` runs as a second Railway service (root directory `web`) at
  `https://web-production-d673c0ef.up.railway.app`. Its domain is a trusted
  domain in Neon Auth.
- **Headers and cookies (7.60).** On November 16, `curl -sI /` returned HSTS
  (`max-age=31536000; includeSubDomains`), the CSP from `next.config.ts`,
  `nosniff`, `Referrer-Policy: same-origin` and `X-Frame-Options: DENY`. On
  November 18, after sign-in, the session cookie showed `Secure`, `HttpOnly`
  and `SameSite=Lax`.
- **GitHub sign-in.** A GitHub OAuth app (homepage = the dashboard URL,
  callback = the `/callback/github` URL Neon shows) is registered as a provider
  on the production branch. The web service has `NEXT_PUBLIC_AUTH_GITHUB=1`,
  which is baked in at build time, so changing it needs a rebuild.
  `AuthForms.tsx` passes absolute `callbackURL` (`/incidents`) and
  `errorCallbackURL` (`/auth/sign-in`) values on the app's own origin.
- **7.61, dashboard half (November 18), on the deployed site.**
  1. GitHub sign-in completed. It created a new user, which was granted owner
     with `runopsy-cloud member`.
  2. `/incidents` listed `frozen-worker` and `disk-full`.
  3. An analysis opened.
  4. After sign-out, `/incidents` redirected to sign-in.

## Setup steps (reference; all done)

1. **Neon Auth is enabled** (email and password, November 13). Add **GitHub**
   as an OAuth provider next (a GitHub OAuth app; set its callback URL to the one
   Neon shows). Note the project's auth URL.
2. **Set the API variable.** In Railway, set `RUNOPSY_AUTH_URL=<auth URL>` and
   redeploy. The log should say `browser sign-in enabled`.
3. **Wire up Next.js** following Neon's Next.js quick start for Neon Auth:
   - Sign-in with GitHub, sign-out, and a session check on every route under
     the app.
   - A server-side route handler, `app/api/runopsy/[...path]`, that reads the
     session, gets its JWT, and forwards the request to the API with
     `Authorization: Bearer` and `X-Runopsy-Organization`. Forward only `GET`,
     plus the owner actions the UI offers. Forward no other headers. Pass the
     API's status and body back unchanged.
   - An organization picker fed by `GET /api/me`, remembered per user.
   - The existing `web/` view layer (incident list, detail, analysis), fed
     through that route.
4. **Cookie and header settings (7.60 gate rows):**
   - Session cookies must be `Secure`, `HttpOnly` and `SameSite=Lax`
     (Better Auth defaults over https; verify in the browser).
   - Serve the dashboard over https only, with
     `Strict-Transport-Security: max-age=31536000`.
   - Set a `Content-Security-Policy` that allows only the app's own origin and
     the auth URL.
   - Set `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.
5. **Onboarding.** After your first sign-in, find your user id and make
   yourself owner:
   ```sql
   SELECT id, email FROM neon_auth."user" WHERE email = 'you@example.com';
   ```
   ```sh
   bin/runopsy-cloud member -database "$DATABASE_URL_UNPOOLED" -user <id> -org org_bf4b855bef0d2125d27b797b550a9d78 -role owner
   ```
   Check the table name in your project's `neon_auth` schema; this is Better
   Auth's default.
6. **Verify (7.61 dashboard half).**
   - Sign in with GitHub.
   - See `frozen-worker` and `disk-full` from org `org_bf4b…`.
   - Open an analysis and confirm it matches `analyze --document`.
   - Sign out, then reload a page: it must redirect to sign-in.
   - As a member, confirm delete and activate are not offered, or return 403.

## Open

- **Hosting the dashboard:** a Railway service beside the API (simplest), or
  Vercel. Either way, the API stays reachable only server-to-server from the
  dashboard and the CLI.
- **Neon roadmap:** check which Better Auth plugins and frameworks Neon
  supports today before relying on more than GitHub OAuth and the JWT plugin.
