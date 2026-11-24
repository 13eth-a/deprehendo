# Owner decisions — contract §8 (Phase 7)

Status: **decided, November 8, 2026** (engineering slot, standing in). These gate the
items contract §9 left open. Changing one needs a reason written here, not a
second implementation.

## 1. Worker hosting — container host, one request per container

- **Decision:** the analyzer worker runs on a container host with **one
  request per container** (for example Cloud Run with `concurrency=1`, 2 GiB,
  120 s request timeout). Web stays on Vercel/Next.js; Postgres and object
  storage stay managed.
- **What ships today:** `deprehendo-cloud serve` runs the same job through the
  `JobRunner` seam in-process (one child process per bundle, private temp dir,
  `GOMEMLIMIT=1GiB`, 60 s wall clock). That is the controlled server-side
  process contract §3.1 allows, and the seam a separate worker service calls —
  promoting it to its own service changes deployment, not handlers.
- **Why:** Vercel Functions share one process across concurrent invocations
  (Fluid compute) and cap request bodies at 4.5 MB; a hostile bundle must not
  take another organization's requests with it (contract §2.2/§5.4).

## 2. Authentication — provider for browsers, tokens for the CLI

- **Decision:** browsers authenticate through a maintained provider or library
  (for example Auth.js or a hosted auth service). The cloud server keeps
  consuming **personal API tokens only** (`Authorization: Bearer`, hashes in
  `personal_tokens`, 7.12). No hand-rolled sessions, no SSO in Phase 7.
- **What ships today:** `deprehendo-cloud token` mints the CLI token; every data
  query starts from the token's `organization_id` (§2.3); another org's object
  is 404, never 403. Sign-up/session UI belongs to the provider choice, not to
  this repo.

## 3. Rate defaults — contract §5.3 as code

- **Decision:** the MVP defaults in code are the policy:
  `MaxAnalysesPerHour = 60`, `MaxParseSecondsPerDay = 1800`,
  `MaxConcurrentPerOrg = 2`, create body 64 KiB, storage policy 22 B to
  `MaxArchiveSize` with a 15-minute lease, job wall clock 60 s.
- **Why:** §5.2 measured cost as parse time and memory, not bytes — a 456 KB
  upload cost 7.5 s and 421 MB — so the limits bind time and concurrency, and
  per-organization daily parse seconds is the billing-relevant meter (7.59).

## What this unblocks

- The worker's HTTP job endpoint is a hosting task, not a correctness task:
  package the `JobRunner` call as a service behind the provider's identity.
- The browser auth UI (7.4–7.5) builds against the provider; the server side
  does not move.
- Abuse counters (7.37) already enforce the numbers above; adjusting them is
  configuration, not a schema change.
