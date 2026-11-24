# GitHub provider privacy

Provider data is typed and bounded; the bundle schema has no field for raw log
lines, URLs, process command lines, environment variables, authorization
headers, or tokens. Runner logs are parsed locally and reduced to a closed event
enumeration, timestamp, source, and file-index/offset provenance. Unknown log
text is discarded. Runner configuration is parsed through an allowlist, and
`.runner` contents, labels, work paths, and authentication files are never
bundled.

By default, runner name, repository, workflow, job name, and numeric run/job IDs
are WITHHELD. `--provider-identifiers` opts into those known identifiers for
recording or the equivalent API-enrichment command. Versions and typed process
roles remain available. Opaque runner/job/worker references use an installation
salt that is not included in bundles. A known-but-withheld value differs from an
UNKNOWN value that was never observed.

## Credentials

The API credential source is `DEPREHENDO_GITHUB_TOKEN` or a
mode-0600 token file (`~/.deprehendo/github-token`, configurable with
`--token-file`). File credentials must be regular files owned by the current
user. The credential is requested only by the explicit `github api-enrich`
command; recording, doctor, watch and offline analysis do not read it. The
secret is not copied into provider evidence, logs, or `.deprehendo` fields. Authorization is
restricted to the API origin; cross-origin redirects are refused. API response
bodies and errors are not surfaced as bundle content. Configure least-privilege
read access sufficient for workflow and job metadata.

The API enrichment command preserves the original input and writes a distinct,
validated output bundle, even when credentials or network access are unavailable;
the degraded health reason is recorded without response bodies or credentials.
No collector reads process environments. Users should still treat diagnostic
logs and incident bundles as operationally sensitive: even structured process
IDs, timing, resource metrics, and opted-in identifiers can reveal information.
Store bundles with restrictive permissions and share only after review.
