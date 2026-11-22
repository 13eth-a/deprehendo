# Upload corpus (checklist 7.40)

Status: **executed by integration, updated November 6, 2026.** The earlier version of this
file mapped §5.5's sixteen cases to `internal/incident` unit tests by name and
explicitly could not confirm any of them, because the worker did not exist.
It does now, so the mappings below were re-derived by driving each bundle
through the real pipeline: minted storage policy → storage POST → complete →
real analyzer child → HTTP answer → what the dashboard can then read.

Driver: `tests/phase7_upload_corpus_test.go` (plus
`TestPhase7CompleteRecomputesTheDigestFromStoredBytes` for the integrity case).
Run with `make test-cloud`; the suite skips without
`RUNOPSY_CLOUD_TEST_DSN`.

## Executed through the worker

| # | §5.5 case | Bundle construction | Worker answer | Dashboard after |
|---|---|---|---|---|
| 1 | valid | checked-in `frozen-worker.runopsy` | 200, `READY` | one incident, signature present, bundle download byte-identical |
| 3 | truncated | first half of a valid archive | 422 `INVALID_BUNDLE` | one row, status `REJECTED`, no signature, `/analysis` 202 |
| 5 | duplicate member | second `snapshots.json` entry | 422 `INVALID_BUNDLE` | as above |
| 6 | sixth member | extra `notes.json` entry | 422 `INVALID_BUNDLE` | as above |
| 7 | symlink member | extra member with `os.ModeSymlink` | 422 `INVALID_BUNDLE` | as above |
| 8 | ZIP64 sizes | ZIP64 extra field on `manifest.json` | 422 `INVALID_BUNDLE` | as above |
| — | unsupported schema | `schema_version` 2, digests unchanged | 422 `INVALID_BUNDLE` | as above |
| 16 | forged manifest identity | metadata identity replaced, digests re-signed | 422 `INVALID_BUNDLE` | as above |
| 9 | declared-size bomb | 65 MiB expanded `snapshots.json`, digests re-signed | 422 `INVALID_BUNDLE` | as above |
| 4 | checksum mismatch | policy created for A, stored object replaced with valid bundle B | 422 `INVALID_BUNDLE` ("stored checksum …") | **no row**: refused before analysis |
| 12 | duplicate JSON key via case folding | still covered only by `TestBundleRejectsCaseAliasPrivacyBypass` in `internal/incident` | not driven through the worker | — |
| 10 | actual-size mismatch | covered by `TestDecompressionBombBound` (declared and actual branches) | not driven through the worker | — |
| 11 | duplicate key via Unicode folding | `TestBundleRejectsUnicodeCaseAliasPrivacyBypass` | not driven through the worker | — |
| 14 | privacy-violating payload | `TestForgedValidChecksumsStillRejectInvalidEvidence` (`secrets`, `wrong-policy`) | not driven through the worker | — |

Every driven bundle was built from a checked-in archive and, where the case is
semantic rather than structural, its manifest digests were recomputed. That
distinction matters: a rejection caused by a stale checksum proves nothing
about the rule the case is named for.

## Not driven, with the reason

| # | §5.5 case | Why not |
|---|---|---|
| 2 | old schema | No older decoder exists yet (contract §7.2). The unsupported-schema case proves a bumped version is refused; an *older* one cannot be accepted until the reader dispatches by version. |
| 13 | 250,001 records | The JSON preflight bounds this before typed allocation (`TestJSONPreflightBoundsBeforeTypedAllocation`). A worker-level copy would assert the same 422 through a slower path. |
| 15 | 30–60 MiB expanded valid bundle | Same code path as case 1; contract §5.2 measured ~7 s and ~420 MB for a 30 MB payload, which would dominate `make test-cloud` on every run. |

None of these are unverified claims about the server: they are cases whose
worker-level behavior is the same `incident.Read` refusal already covered at
the reader, and the corpus doc says so rather than implying the whole list ran.

## Review findings

1. **A refused bundle keeps a queryable incident status row.** `complete`
   inserts the `analyses` row and the `incidents` view row before mapping a
   non-READY status to its HTTP error. The result is one organization-scoped
   row per refused upload with `analysis_status` `REJECTED` /
   `FAILED_LIMIT` / `FAILED_CRASH`, no signature, and `/analysis` answering
   `202 PROCESSING` (7.31/7.32: the dashboard shows the state instead of a
   blank page). Contract §5.5 now specifies this minimal status row; there is
   no diagnosis document or bundle-derived metadata.
2. **The digest is genuinely recomputed.** Replacing the stored object with a
   different *valid* bundle is refused at `complete`, so the create-time
   `sha256` is a claim, not an authority (7.10). No incident row is created.
3. **Storage refusal and bundle rejection are different failure stages.**
   A policy/digest refusal happens at `/storage` before `complete` and leaves
   no analysis row; a reader refusal happens inside the analyzer and leaves the
   row described in finding 1. The corpus asserts both.
4. **Old-schema support is still the only §5.5 row that cannot pass**, and that
   is a known Phase 7 follow-up in contract §7.2, not a corpus gap.

The contract's §5.5 outcome is now aligned with the server: rejections keep a
minimal queryable status row, while omitting the analysis document and
bundle-derived metadata. This is needed for the dashboard's 7.31/7.32 failure
state.

## Reproduce

```sh
make test-cloud
# one case, verbose:
RUNOPSY_CLOUD_TEST_DSN=postgres://… go test -count=1 -run 'TestPhase7UploadCorpus' -v ./tests
```
