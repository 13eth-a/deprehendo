import { test } from "node:test";
import assert from "node:assert/strict";

import { bandOptions, diagnosisOptions, isIncidentId, summaryFromApiRow } from "../lib/api-incidents.ts";

test("API rows map onto list summaries without inventing fields", () => {
  const ready = summaryFromApiRow({
    incident_id: "inc_00000000000000000000000000000002",
    created_at: "2026-11-12T01:03:47Z",
    triggered_at: "2026-11-12T01:03:40Z",
    primary_signature: "frozen_worker",
    confidence: 0.82,
    confidence_band: "HIGH",
    analysis_status: "READY",
  });
  assert.equal(ready.incidentId, "inc_00000000000000000000000000000002");
  assert.equal(ready.triggeredAt, "2026-11-12T01:03:40Z");
  assert.equal(ready.diagnosis, "frozen_worker");
  assert.equal(ready.confidenceBand, "HIGH", "the band is the stored one");
  assert.equal(ready.unknown, false);

  const unknown = summaryFromApiRow({ incident_id: "inc_x", created_at: "2026-11-09T22:02:10Z", analysis_status: "READY" });
  assert.equal(unknown.triggeredAt, "2026-11-09T22:02:10Z", "falls back to created_at");
  assert.equal(unknown.diagnosis, null);
  assert.equal(unknown.unknown, true);
  assert.equal(unknown.confidenceBand, null, "no stored band stays empty; never derived from the score");
  const scoreOnly = summaryFromApiRow({ incident_id: "inc_z", created_at: "2026-11-09T22:02:10Z", confidence: 0.95, analysis_status: "READY" });
  assert.equal(scoreOnly.confidenceBand, null, "a score without a stored band is not turned into one");

  const pending = summaryFromApiRow({ incident_id: "inc_y", created_at: "2026-11-09T22:02:10Z", analysis_status: "PROCESSING" });
  assert.equal(pending.unknown, false, "not analyzed yet is not 'unknown'");
});

test("diagnosis options are distinct and sorted", () => {
  const rows = ["b", "a", "b"].map((d, i) =>
    summaryFromApiRow({ incident_id: `inc_${i}00`, created_at: "2026-11-09T00:00:00Z", primary_signature: d, analysis_status: "READY" }),
  );
  assert.deepEqual(diagnosisOptions(rows), ["a", "b"]);
});

test("incident ids are checked before they reach a URL", () => {
  assert.equal(isIncidentId("inc_00000000000000000000000000000004"), true);
  for (const bad of ["", "ab", "../etc", "inc_x/analysis", "inc%2F", "a".repeat(65)]) {
    assert.equal(isIncidentId(bad), false, bad);
  }
});

test("band options are the bands present, strongest first", () => {
  const rows = ["MODERATE", "VERY_HIGH", undefined, "HIGH", "MODERATE"].map((band, i) =>
    summaryFromApiRow({ incident_id: `inc_${i}00`, created_at: "2026-11-09T00:00:00Z", confidence_band: band, analysis_status: "READY" }),
  );
  assert.deepEqual(bandOptions(rows), ["VERY_HIGH", "HIGH", "MODERATE"]);
});
