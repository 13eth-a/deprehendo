# Secrets audit: cloud upload path (checklist 7.39)

Scope: `cmd/deprehendo-agent/cloud.go` (login, upload, config file) and
`internal/cloudclient/client.go` (HTTP client, presigned storage upload).
Status: review by adversarial; **F1–F3 fixed and tested on the Go side**
(November 5, 2026), see each finding. F4/F5 remain informational.

## What holds

- **Token is never on the command line.** `login` reads it from stdin (or from
  `-token-file`), so it does not appear in `ps` or shell history.
- **Config file is written at 0600.** `writeCloudConfig` writes to a temporary
  file, restricts it to 0600, then renames it into place. A reader refuses a
  config whose permissions are not 0600.
- **Bearer token only on API calls.** `do()` sets `Authorization` for the
  Deprehendo API. The presigned storage upload sets no `Authorization` header
  (the URL is already signed).
- **Redirects cannot move the token to another host.** `sameHostRedirects`
  refuses any redirect to a different host.
- **Plain HTTP is refused except for loopback.** `NormalizeEndpoint` requires
  `https`, except for `localhost` and loopback addresses.
- **Bounded replies.** API and storage response bodies are read through
  `io.LimitReader(maxReplyBytes)`.
- **Bundle contents are not sent to the API.** Only the bundle's digest and
  size go to `POST /api/uploads`. The file itself goes to the presigned storage
  URL.

## Findings

### F1 (medium): endpoint errors echo the raw endpoint, including any userinfo

`NormalizeEndpoint` formats the caller's endpoint with `%q` in its errors
(`must use https`, `must be an https URL`, `has no host`). The login command
prints that error to stderr (`deprehendo-agent login: %v`). An endpoint written as
`http://user:password@host` therefore prints the password to the terminal and
to any captured log.

**Fixed.** `redactEndpointURL` renders the endpoint with `url.Redacted()`, so
every `NormalizeEndpoint` error names `xxxxx:xxxxx@host` rather than the
credentials. `internal/cloudclient` tests assert that an endpoint with userinfo
produces an error without the password and that the redacted form is used for
the no-host and wrong-scheme messages too.

### F2 (medium): the storage-upload error can contain the presigned URL

`PutObject` wraps the transport error with `%w` (`cloud: storage upload: %w`).
Go's `http.Client.Do` returns a `*url.Error` whose message includes the full
request URL. For a presigned POST, that URL carries the signature query
parameters. `runUpload` prints the wrapped error to stderr.

The signature is short-lived and is not the bearer token. It is still a
credential-like value, and it is printed to a terminal and any captured log.

**Fixed.** `PutObject` unwraps `*url.Error` with `errors.As` and wraps only the
underlying cause, so neither the presigned URL nor its signature can reach
stderr (`internal/cloudclient/client_test.go`, storage-upload transport
failure case). The queue stores that same error text, so a stored
`last_error` cannot contain the signature either.

### F3 (low): server messages are printed to the terminal unfiltered

`cloudclient.Error.Error()` prints the API's `message` field verbatim, and
`uploadHint` prints it again for 413 and 429. A message containing terminal
control sequences (ANSI escapes, carriage returns) is shown as-is. The endpoint
is user-configured, so the risk is limited to a compromised or misconfigured
server, but the terminal is a trust boundary.

**Fixed.** `cloudclient.sanitizeServerText` caps the message at 512 bytes and
strips control characters other than TAB (cap first, then strip); it is applied
by `Error.Error()` and by both `SanitizeServerText` call sites in
`uploadHint`. The server enforces the same rule on its own outbound messages
(`cloudserver.sanitizeText`), so the two sides agree instead of trusting each
other.

**Completed November 9, 2026 (principal).** One path was missed: `PutObject`
printed the storage reply body on a non-2xx answer without filtering it. It now
goes through `sanitizeServerText` too.

### F4 (info): the config file stores the token in clear text

This is by design (7.11/7.12 credential file at 0600). Note for the user:
anything running as the same user can read it. The token is stored only in
that file; no OS keychain is used.

### F5 (info): not checked in this review

- Server-side authorization is out of scope here; it is
  `docs/cloud/authz-matrix.md`, now implemented and exercised against Postgres.
- The scratch copy may be stale relative to the Mac tree. Re-stage the two
  files and confirm line references before acting on this document.

## Follow-up review of the server side (November 5, 2026)

The audit above covered the CLI and client. The server and queue added since
were checked against the same rules:

- **Tokens**: looked up by SHA-256 hash, never logged; the raw value is printed
  once by `deprehendo-cloud token` and stored hashed. Nothing in
  `internal/cloudserver` logs an `Authorization` header.
- **Request data**: handler logs carry only server-produced error values
  (`logf("incident list: %v", err)`), never a bundle, document, incident id or
  runner log. The 7.55 telemetry line is a fixed format string of counts and
  latencies.
- **Storage**: no signed URL is logged or returned outside the create response;
  object keys are never exposed on read paths. `LocalStore` writes under one
  root and refuses keys that escape it.
- **Queue**: the file holds local paths, states and error text only — no token,
  no endpoint credentials. It is 0600 in a 0700 directory, like the config.
- **Still outstanding**: no secret scanner has been run over the repository
  (none available offline); run one before the first public deployment.
