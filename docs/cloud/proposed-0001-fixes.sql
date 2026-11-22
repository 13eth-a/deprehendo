-- 0001_init review changes: what was applied, and what was not (7.56-7.58).
--
-- the review is docs/cloud/db-review.md. this file is the record of the
-- corrections rather than a patch to run: P2 and P3 are already in
-- db/migrations/0001_init.up.sql. P1 and P4 were rejected as schema changes;
-- their resolutions did not need SQL. do not run this file.

-- APPLIED in 0001_init.up.sql (P2): a READY analysis must have its document.
--
--   CONSTRAINT analyses_document_key_iff_ready
--       CHECK ((status = 'READY') = (document_key IS NOT NULL))

-- APPLIED in 0001_init.up.sql (P3): drop the redundant index. uploads_by_incident
-- (organization_id, incident_id, uploaded_at DESC) already serves the
-- (organization_id, incident_id) prefix.
--
--   DROP INDEX uploads_by_search;

-- REJECTED (P1): widening the object_key check to [A-Za-z0-9_-] does not fix
-- uppercase organization ids, it moves the failure. the go storage layer
-- enforces the same lowercase shape in three more places:
--
--   internal/cloudserver/storage.go  policyRE   ^orgs/[a-z0-9_-]+/bundles/...
--   internal/cloudserver/storage.go  safeKey    lowercase segments only
--   internal/cloudserver/storage.go  mintUploadPolicy builds the key from org
--
-- and clouddb.NewID generates lowercase hex by design. with only the CHECK
-- widened, create would succeed and the storage POST would then answer 403,
-- leaving a row that can never complete. organization ids are lowercase hex
-- today; the defect was the uppercase example in upload-api §1, now corrected.
-- if ULIDs are ever wanted, change NewID and all three regexes in one change,
-- not the schema alone.

-- REJECTED (P4): a `state` column has nothing to write it. readiness is
-- already carried by analyses.status, which complete reads for idempotence
-- (`existing.Status == READY`), and the contract now says so. adding
-- state TEXT DEFAULT 'PENDING' would create a column no code updates, which
-- reads as a promise the system does not keep. Stale-pending cleanup is an
-- operations task for when an expiry policy exists (7.58 time-based retention).
