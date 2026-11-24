# Cloud cost measurement (checklist 7.59)

Status: **real bills measured on the deployed stack at 1, 100 and 1,000
incidents (November 20, 2026); see the next section.** The list-price model
from November 9 follows it; its storage bytes matched the deployed run
exactly. The model's prices are for Cloud Run and Neon object storage, which
are no longer the stack: the deployed stack is Railway (API, dashboard,
bucket) plus Neon Postgres on the Free plan.

## Real bills: deployed stack, November 20, 2026

`caffeinate -i bash scripts/cost-load.sh` loaded the deployed API
(the Railway deployment) through the real CLI. Every upload was a
real create, storage POST and complete, with the analysis run on Railway. It
used 53 throwaway orgs (`costload-11202208-NN`), each holding the 19 bundles
from `testdata/incidents/` once, which kept every org far under the 60
analyses/org/hour limit. Usage was read from the Railway and Neon consoles at
each stage, and the cleanup step then deleted everything the run created.

| Incidents | Uploads ok / failed | Stage time | Median upload (end to end) | Database | Bucket objects | Bucket bytes | Railway, project, current cycle | Neon |
|---:|---:|---:|---:|---:|---:|---:|---|---|
| 0 (baseline) | — | — | — | 11,493,376 B | 312 | 3,984,135 | $0.17 (API $0.12, web $0.05) | 0.23 CU-h, 32 MB |
| 1 | 1 / 0 | 4 s | 1.889 s | 11,501,568 B | 314 | 4,010,552 | $0.17 (API $0.12, web $0.05) | 0.23 CU-h, 32 MB |
| 100 | 99 / 0 | 112 s | 0.932 s | 11,616,256 B | 512 | 6,560,596 | $0.17 (API $0.12, web $0.05) | 0.23 CU-h, 32 MB |
| 1,000 | 900 / 0 | 1,006 s | 0.921 s | 13,033,472 B | 2,312 | 29,703,371 | $0.17 (API $0.12, web $0.05) | 0.23 CU-h, 32 MB |

Cleanup: 1,000 API deletes ok, the organizations were deleted, and no objects
were left under the run's org prefixes.

**What 1,000 incidents added:**
- **Bucket:** +2,000 objects and +25,719,236 B, which is 25,719 B per
  incident. That is exactly the model's 1,965 B bundle plus 23,754 B
  document, because the fixtures are the same.
- **Database:** +1,540,096 B, which is 1,540 B per incident, against 1,098 B of
  measured tuples. The difference is indexes and page overhead.
- **Bill:** no change visible. The Railway project total stayed at $0.17 and
  Neon at 0.23 CU-h and 32 MB.

**What this says:**

1. **The bill is the fixed baseline, not the incidents.** Railway charges for
   the always-on API and web services by the minute, whether or not they
   receive uploads. The project had used $0.17 of the current cycle before the
   run, with the API at $0.12 and the web service at $0.05. 1,000 incidents
   added nothing visible at the console's one-cent resolution.
   - At Railway's list rates ($20 per vCPU-month, $10 per GB-month of RAM,
     $0.015 per GB-month of bucket storage, no operation charges), the
     incidents' marginal cost is far below a cent. About 26 MB of bucket data
     falls within the first whole GB-month, which Railway rounds up to and the
     existing data already occupies. The extra compute is a fraction of a
     vCPU-minute.
   - On Hobby, the $5 monthly subscription includes $5 of usage, so the actual
     invoice is the flat $5 until usage exceeds it.
2. **Neon Free costs $0, and the load stayed far inside its limits:** 32 MB of
   storage and 0.23 CU-h. The 6-hour history window is the Free plan's real
   cost, in risk rather than money (see `pitr-drill.md`).
3. **Latency held.** The median end-to-end upload took 0.92 s from Chicago,
   covering three HTTPS requests plus the analysis, and it did not degrade
   from 100 to 1,000 incidents.
4. **The load found a production bug.** On the first attempt, about 1 in 20
   bucket writes failed with a server error from Railway's bucket, and each
   one failed the user's upload: 21 of the first about 420. The bucket client
   now retries 5xx, 429 and dropped connections (`s3store.go`, tests in
   `s3store_retry_test.go`). The rerun above had 0 failures in 1,000 uploads.

**Caveats:**
- Both consoles meter with a delay, and the readings were taken within minutes
  of each stage. A re-read some hours later should still show no visible
  change from the run; record it here if it does.
- The fixtures are small. The 10,000-event profile below (about 11 MB of
  document and seconds of analysis per incident) would show on the bill
  sooner, through compute rather than storage.
- A Railway projection for the whole month was not recorded. It depends on
  the cycle start date shown on the Usage page.

Reproduce the run: `caffeinate -i bash scripts/cost-load.sh`, then type
`CLEANUP` at the end, or later run `bash scripts/cost-load.sh cleanup <dir>`.
The script refuses to touch any org that does not carry its run's name.

```bash
make build
./bin/deprehendo-cost -runs 5 -database "$DSN"
```

Measurement owner: MiMo 2.6 Pro. secondary's review verified the current Neon object
storage rates and the request count in the pinned upload API, and corrected the
model below.

## What was measured

Real bundles: the 19 incidents in `testdata/incidents/`, measured on **this
Mac (Apple silicon) on November 9, 2026** by `cmd/deprehendo-cost`, which runs the
real analyzer child binary five times per bundle and takes each bundle's median
before taking the median across bundles. Document bytes now come from the
analyzer's own output rather than from the checked-in fixtures, so the two
columns cannot drift.

| Profile | Bundle (original) | Analysis document | `analysis.Run` |
|---|---:|---:|---:|
| 19 real incidents, mean | 1,965 B (min 1,850, max 2,127) | 23,754 B (min 19,487, max 27,907) | 21 ms median, 29.2 ms mean (8–163 ms) |
| 1,000 events (integration, Mac, `performance.md`) | 7.3 KB | 1.22 MB | 55 ms |
| 10,000 events (integration, Mac, `performance.md`) | 56 KB | 10.86 MB | 6.95–13.2 s |

The synthetic rows are carried from `performance.md` and are not re-measured
here; `deprehendo-cost` reads `testdata/incidents/` and would need those bundles
materialized to time them. The first `deprehendo-cost` run showed one 725 ms
outlier where a bundle's first analysis paid for cold page cache; the second
run's maximum was 85 ms. The per-bundle median absorbs it, which is why the
median — not the mean — is the model's input.

The sandbox first pass measured 6 ms, and the November 8 Mac run measured 13
ms. This latest run measures 21 ms; the child process spawn is included, and
the per-bundle medians vary between runs. These are local measurements, not
Cloud Run timings.

## Prices (list, November 2026)

| Item | Price | Source |
|---|---|---|
| Neon Object Storage | $0.023 per GB-month; no per-operation charge | [Neon pricing](https://neon.com/pricing). Free plan includes 5 GB per project; public transfer allowance is 5 GB on Free and 500 GB on Launch/Scale before overage. |
| Cloud Run CPU, request-based, us-central1 | $0.000024 per vCPU-second | Google: <https://cloud.google.com/run/pricing> |
| Cloud Run memory, request-based | $0.0000025 per GiB-second | Same page. |
| Cloud Run requests | $0.40 per million | Same page. |

The model assumes one vCPU and one GiB, and uses analyzer duration as the only
billable compute time. It counts **three Cloud Run requests per successful
upload** from `upload-api.md`: create, the server's `/storage` upload, and
complete. The analysis runs inside complete; it is not a fourth request.
Upload transfer/handler time, startup, and idle time are not measured, so the
Cloud Run figures are a floor. Neon object-storage operations have no charge;
`-put-per-1k` remains available for comparing a different provider.

## Model and results

Per incident: one original bundle and one analysis document, retained for one
month; three Cloud Run HTTP requests. Database rows are counted, not priced
(see below). These are gross list-rate figures before free allowances.

| Incidents | Profile | Stored | Storage per month | Requests + compute (one-time) | Total first month |
|---:|---|---:|---:|---:|---:|
| 1 | 19 real | 0.000026 GB | $0.0000006 | $0.0000018 | $0.0000023 |
| 100 | 19 real | 0.002572 GB | $0.0000592 | $0.0001757 | $0.0002348 |
| 1,000 | 19 real | 0.025720 GB | $0.0005915 | $0.0017565 | $0.0023480 |
| 1 | 1,000 events | 0.001227 GB | $0.0000282 | $0.0000027 | $0.0000309 |
| 100 | 1,000 events | 0.12273 GB | $0.0028228 | $0.0002658 | $0.0030885 |
| 1,000 | 1,000 events | 1.2273 GB | $0.0282279 | $0.0026575 | $0.0308854 |
| 1 | 10,000 events | 0.010916 GB | $0.0002511 | $0.0001854–$0.0003510 | $0.0004364–$0.0006021 |
| 100 | 10,000 events | 1.0916 GB | $0.0251068 | $0.0185375–$0.0351000 | $0.0436443–$0.0602068 |
| 1,000 | 10,000 events | 10.916 GB | $0.2510680 | $0.1853750–$0.3510000 | $0.4364430–$0.6020680 |

## What this says

1. **Per-incident storage and compute are negligible at these sizes.** The
   gross list-price model puts 1,000 fixture-sized incidents at about 0.21
   cents. Pricing decisions in Phases 8–9 will not turn on bundle or document
   bytes unless incidents are far larger than the fixtures.
2. **The 10,000-event profile is the one to watch.** A document of about 11 MB
   per incident is still cheap to store, but its analysis takes seconds of
   compute, which is most of its per-incident cost. Analysis time, not
   bytes, is the cost driver at that size.
3. **The model is not the invoice.** Neon database compute, PITR history,
   Cloud Run upload/handler time, free allowances, egress, and backups are not
   included. The Phase 7 stack has now run locally against Neon; its
   resource-level bills still need a deployed workload.

## Database rows per incident: now measured

`deprehendo-cost -database DSN` applies the migrations, inserts one incident's
rows inside a transaction, reads each tuple with `pg_column_size`, and rolls
back. Measured on PostgreSQL 16, one analysis row:

| Row | Bytes |
|---|---:|
| `organizations` | 56 (once per organization, not per incident) |
| `uploads` | 224 |
| `analyses` | 688 (the `engine` JSONB dominates) |
| `incidents` | 186 |
| **per incident** | **1,098** |

At 1,000 incidents that is about 1.1 MB of tuples — negligible against any
managed instance's smallest disk. At Neon Launch's $0.35/GB-month storage rate,
1.1 MB of measured tuples is about $0.0000004 per month, before indexes and
other database overhead. Each re-analysis adds one `analyses` row (about 688
B), which is the same order as the document it names.

Neon Launch Postgres compute is $0.106 per CU-hour, with storage at $0.35 per
GB-month; PITR history storage is separately priced at $0.20/GB-month. See
[Neon's current pricing](https://neon.com/pricing). These rates are not
included in the incident table: compute depends on active CU-hours and
workload shape, while PITR depends on retained history. Add measured usage from
the deployed workload before calling the table an all-in estimate.

## secondary review (November 9, 2026)

The previous table did not represent the selected stack: it used AWS PUT
charges even though Phase 7 now stores objects in Neon, and it counted one
Cloud Run request although the pinned upload contract performs three. It also
retained a 6 ms calculation beside the measured 13 ms result. Those inputs are
corrected above. Neon charges by stored GB-month and has no object-operation
fee; the tool defaults now match that pricing and `-requests-per-incident`
defaults to the three successful upload calls.

For 1,000 fixture-sized incidents, the recalculated gross list-price total is
about **$0.002348**: $0.000592 for one month of Neon object storage and $0.001757
for Cloud Run requests plus 21 ms of measured analysis per incident. Storage
and request free allowances can reduce those amounts, depending on the account
and other workloads. The Cloud Run estimate omits upload duration and handler
overhead, so it is a lower bound. Neon Postgres compute and PITR history remain
outside this per-incident model.

## Measurement run (MiMo slot, latest rerun November 9, 2026)

This pass replaced the hand-computed inputs with a tool, because a table copied
from a previous pass drifts the moment a bundle or a price changes.
`cmd/deprehendo-cost` does the whole model: it reads the bundles, runs the real
analyzer child (so process spawn is costed), optionally measures real row
bytes, and prints the 1/100/1,000 table. Every price is a flag.

The run recorded here:

```
Measured over 19 bundles, median of per-bundle medians:
  bundle bytes    mean 1965  min 1850  max 2127
  document bytes  mean 23754  min 19487  max 27907
  analysis        median 21 ms  mean 29.2 ms  min 8  max 163

Database rows per incident (pg_column_size, one analysis row):
  per incident   1098 B (+56 B once per organization)

incidents    stored GB   storage/mo        ops+compute total first month
        1     0.000026  0.000000592        0.000001757        0.000002348
      100     0.002572  0.000059155        0.000175650        0.000234805
     1000     0.025720  0.000591553        0.001756500        0.002348053
```

The earlier estimate does not agree after applying the actual Neon rates and
the implemented request count; the difference is about $0.0090 per 1,000
fixture-sized incidents. Two corrections came out of building the tool:

- **The analyzer path bug reached a third caller.** `analyzer.NewRunner`
  accepted a relative child path, but `Run` starts the child in a private
  working directory, so `bin/deprehendo-analyzer` could never resolve. `serve` had
  been patched locally in the 7.56 drill; the cost tool hit the same wall. The
  runner now resolves the path itself, so the next caller cannot repeat it.
- **The database column is no longer unpriced for lack of data.** Row bytes are
  measured (1,098 B per incident); what remains is the provider's instance and
  backup price, which is a contract §8.1 decision, not a measurement.

## Not measured

- Measured November 20: actual bills at 1, 100 and 1,000 incidents on the
  deployed Railway and Neon stack (see "Real bills" above). The items below
  refer to the November 9 model and its Cloud Run prices.
- Database instance, storage and backup prices (row bytes are measured; the
  managed plan's price is not).
- Egress and backup costs.
- Cloud Run idle and minimum-instance costs, upload transfer duration, and
  handler time.
- Memory and CPU on the target hosting platform. The timings come from this Mac
  and, in the carried rows, from `performance.md`'s Mac run.
- Whether the 21 ms median holds on the hosting platform; it is an analysis-time
  input, and the 10,000-event row already shows compute is the sensitive term.

## Next steps

1. Done November 20: the deployed stack was loaded to 1, 100 and 1,000
   incidents, and the bills were recorded (see "Real bills").
2. Before pricing (Phases 8–9), re-run `scripts/cost-load.sh` with large,
   10,000-event bundles. That profile, not the fixtures, is the one where
   analysis compute could show on the bill.
3. Re-read the Railway and Neon usage pages a day after a load, so lagged
   metering is captured. Record the month projection from the Railway Usage
   page.
4. Moving Neon to Launch (for a longer history window) adds about $0.106 per
   CU-hour and $0.35 per GB-month. Record the first Launch invoice here when
   that happens.
