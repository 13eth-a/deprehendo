import { test } from "node:test";
import assert from "node:assert/strict";

import { checkAnalysisDocument } from "../lib/guards.ts";
import { epochNanos, formatBytes, formatClock, formatOffset, formatPercent } from "../lib/format.ts";
import { claimLabel, evidenceLabel, isDirect } from "../lib/evidence.ts";
import { pageOf } from "../lib/paging.ts";
import { filterTimeline, eventTypes } from "../lib/timeline.ts";
import { filterIncidents, sortNewestFirst, type IncidentSummary } from "../lib/incidents.ts";
import { buildProcessTree, processKey, processLifetimes } from "../lib/processes.ts";
import { systemPercentSeries, toSvgPaths } from "../lib/series.ts";
import { FAILURE_COPY, failureCopy, type FailureKind } from "../lib/failures.ts";
import type { ProcessSnapshot, Snapshot, TimelineEvent } from "../types/analysis.ts";

const ORIGIN = "2026-11-05T12:00:00.000000000Z";

test("epochNanos keeps nanosecond precision that Date would drop", () => {
  const a = epochNanos("2026-11-05T12:00:00.000000001Z");
  const b = epochNanos("2026-11-05T12:00:00Z");
  assert.equal(a! - b!, 1n);
  assert.equal(epochNanos("2026-11-05T12:00:00+01:00"), null, "offsets other than Z are refused");
  assert.equal(epochNanos("not a time"), null);
});

test("formatOffset chooses ms, s and minutes, with a signed prefix", () => {
  assert.equal(formatOffset("2026-11-05T12:00:00.001400000Z", ORIGIN), "+1.4 ms");
  assert.equal(formatOffset("2026-11-05T11:59:51.600000000Z", ORIGIN), "−8.4 s");
  assert.equal(formatOffset("2026-11-05T12:01:05Z", ORIGIN), "+1m 05s");
  assert.equal(formatOffset("bad", ORIGIN), "unknown time");
});

test("formatClock is UTC and keeps milliseconds", () => {
  assert.equal(formatClock("2026-11-05T12:04:19.250Z"), "12:04:19.250");
});

test("formatBytes and formatPercent never invent a value for missing data", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(1536), "1.5 KiB");
  assert.equal(formatBytes(null), "not captured");
  assert.equal(formatPercent(12.345), "12.3%");
  assert.equal(formatPercent(0, false), "not captured", "an unavailable sensor is not zero");
});

test("evidence labels: only the two direct classes are direct, and unknown never becomes direct", () => {
  assert.equal(isDirect("DIRECT_KERNEL"), true);
  assert.equal(isDirect("DIRECT_PROCESS"), true);
  assert.equal(isDirect("DERIVED_SNAPSHOT"), false);
  assert.equal(isDirect("SOMETHING_NEW"), false);
  assert.equal(evidenceLabel("DIRECT_KERNEL"), "DIRECT KERNEL TRACE");
  assert.equal(evidenceLabel("DERIVED_SNAPSHOT"), "INFERRED FROM SNAPSHOTS");
  assert.equal(evidenceLabel("SOMETHING_NEW"), "EVIDENCE UNKNOWN");
  assert.match(claimLabel("mixed"), /^Mixed/);
  assert.match(claimLabel("nonsense"), /^Unknown/);
});

test("pageOf clamps the page, reports bounds, and keeps stored order", () => {
  const items = Array.from({ length: 25 }, (_, i) => i);
  const page2 = pageOf(items, 2, 10);
  assert.deepEqual(page2.items, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
  assert.equal(page2.start, 10);
  assert.equal(pageOf(items, 99, 10).page, 3, "past the end clamps to the last page");
  assert.equal(pageOf(items, -4, 10).page, 1, "before the start clamps to the first page");
  assert.equal(pageOf([], 1, 10).pages, 1, "an empty list still has one page");
  assert.throws(() => pageOf(items, 1, 0), RangeError);
});

function event(id: string, type: string, pid: number | undefined, quality: string, at: string): TimelineEvent {
  return {
    id,
    type,
    timestamp: at,
    sequence: 0,
    subject: { Kind: "process", ID: `${pid ?? 0}` },
    provenance: { sources: [] },
    class: "CONDITION",
    pid,
    evidence_class: quality as TimelineEvent["evidence_class"],
  };
}

test("filterTimeline filters by type, pid, evidence and window without reordering", () => {
  const events = [
    event("e1", "PROCESS_EXITED", 10, "DIRECT_KERNEL", "2026-11-05T12:00:01Z"),
    event("e2", "CPU_SATURATION_ACTIVE", 11, "DERIVED_SNAPSHOT", "2026-11-05T12:00:02Z"),
    event("e3", "PROCESS_EXITED", 11, "DIRECT_PROCESS", "2026-11-05T12:00:03Z"),
  ];
  assert.deepEqual(filterTimeline(events, { types: ["PROCESS_EXITED"] }).map((e) => e.id), ["e1", "e3"]);
  assert.deepEqual(filterTimeline(events, { pid: 11 }).map((e) => e.id), ["e2", "e3"]);
  assert.deepEqual(filterTimeline(events, { evidence: ["DERIVED_SNAPSHOT"] }).map((e) => e.id), ["e2"]);
  assert.deepEqual(
    filterTimeline(events, { from: "2026-11-05T12:00:02Z", to: "2026-11-05T12:00:03Z" }).map((e) => e.id),
    ["e2", "e3"],
  );
  assert.deepEqual(filterTimeline(events, {}).map((e) => e.id), ["e1", "e2", "e3"]);
  assert.deepEqual(eventTypes(events), ["PROCESS_EXITED", "CPU_SATURATION_ACTIVE"]);
});

function row(id: string, at: string, diagnosis: string | null, band: string | null): IncidentSummary {
  return {
    incidentId: id,
    triggeredAt: at,
    trigger: "manual",
    diagnosis,
    confidenceBand: band,
    unknown: diagnosis === null,
    analyzerVersion: "0.3.3",
    causalRules: "abc",
  };
}

test("incident filters and newest-first sorting", () => {
  const rows = [
    row("a", "2026-11-01T10:00:00Z", "OOM_KILL", "HIGH"),
    row("b", "2026-11-05T10:00:00Z", "DISK_EXHAUSTION", "MODERATE"),
    row("c", "2026-11-03T10:00:00Z", null, null),
  ];
  assert.deepEqual(filterIncidents(rows, { diagnosis: "OOM_KILL" }).map((r) => r.incidentId), ["a"]);
  assert.deepEqual(filterIncidents(rows, { since: "2026-11-02", until: "2026-11-05" }).map((r) => r.incidentId), ["b", "c"], "filters keep the input order");
  assert.deepEqual(sortNewestFirst(rows).map((r) => r.incidentId), ["b", "c", "a"]);
});

test("checkAnalysisDocument rejects shapes and versions the dashboard cannot read", () => {
  assert.equal(checkAnalysisDocument(null).ok, false);
  assert.equal(checkAnalysisDocument([]).ok, false);
  const wrongVersion = checkAnalysisDocument({ document_version: 2 });
  assert.equal(wrongVersion.ok === false && wrongVersion.reason, "unsupported_version");
  const missing = checkAnalysisDocument({ document_version: 1, engine: {}, bundle: {}, privacy: {}, causal: {}, timeline: [] });
  assert.equal(missing.ok === false && missing.reason, "missing_section");
  const badEdges = checkAnalysisDocument({
    document_version: 1,
    engine: {},
    bundle: {},
    privacy: {},
    causal: { nodes: [], failures: [], edges: "none" },
    timeline: [],
    series: [],
  });
  assert.equal(badEdges.ok === false && badEdges.reason, "missing_section");
  const nullEdges = checkAnalysisDocument({
    document_version: 1,
    engine: {},
    bundle: {},
    privacy: {},
    causal: { nodes: [], failures: [], edges: null },
    timeline: [],
    series: [],
  });
  assert.equal(nullEdges.ok, true, "null edges are valid: Go nil slices serialize as null");
});

function proc(pid: number, ppid: number, start = 1): ProcessSnapshot {
  return { pid, ppid, pgid: pid, sid: pid, name: `p${pid}`, state: "S", cpu_percent: 0, open_fds: 0, start_ticks: start };
}

test("buildProcessTree nests by stored PPID and keeps orphans and cycles visible", () => {
  const tree = buildProcessTree([proc(1, 0), proc(2, 1), proc(3, 2), proc(9, 77), proc(20, 21), proc(21, 20)]);
  const rootPids = tree.map((n) => n.process.pid);
  assert.deepEqual(rootPids.slice(0, 2), [1, 9], "the orphan 9 becomes a root");
  assert.equal(tree[0]!.children[0]!.process.pid, 2);
  assert.equal(tree[0]!.children[0]!.children[0]!.process.pid, 3);
  const flatten = (nodes: ReturnType<typeof buildProcessTree>): number[] =>
    nodes.flatMap((n) => [n.process.pid, ...flatten(n.children)]);
  const shown = flatten(tree);
  assert.deepEqual([...shown].sort((a, b) => a - b), [1, 2, 3, 9, 20, 21], "every process is shown exactly once");
});

test("processLifetimes identifies processes by PID and start time", () => {
  const s = (t: string, processes: ProcessSnapshot[]): Snapshot => ({
    timestamp: t,
    CaptureIndex: 0,
    processes,
  });
  const series = [
    s("2026-11-05T12:00:00Z", [proc(5, 1, 100)]),
    s("2026-11-05T12:00:01Z", [proc(5, 1, 100), proc(5, 1, 200)]),
    s("2026-11-05T12:00:02Z", [proc(5, 1, 200)]),
  ];
  const lifetimes = processLifetimes(series);
  assert.deepEqual(lifetimes.get(processKey(proc(5, 1, 100))), {
    first: "2026-11-05T12:00:00Z",
    last: "2026-11-05T12:00:01Z",
    samples: 2,
  });
  assert.equal(lifetimes.get(processKey(proc(5, 1, 200)))!.samples, 2, "a reused PID is a separate identity");
});

test("systemPercentSeries marks the trigger and leaves gaps where the sensor was absent", () => {
  const sys = (available: boolean, value: number) => ({
    cpu_available: available,
    cpu_percent_available: available,
    cpu_percent: value,
    cpu_count: 2,
    load_available: false,
    load_average: 0,
    memory_stats_available: false,
    memory_total: 0,
    memory_used: 0,
    memory_free: 0,
    process_count_available: false,
    process_count: 0,
  });
  const series: Snapshot[] = [
    { timestamp: "2026-11-05T12:00:00Z", CaptureIndex: 0, system: sys(true, 10) },
    { timestamp: "2026-11-05T12:00:01Z", CaptureIndex: 1, system: sys(false, 0) },
    { timestamp: "2026-11-05T12:00:02Z", CaptureIndex: 2, system: sys(true, 90) },
  ];
  const metric = systemPercentSeries(series, "2026-11-05T12:00:01.500Z");
  assert.equal(metric.triggerIndex, 2, "first sample at or after the trigger");
  assert.deepEqual(metric.range, { min: 10, max: 90 });
  const { segments } = toSvgPaths(metric, 100, 50);
  assert.equal(segments.length, 2, "the missing sample splits the line into two segments");
});

test("every failure kind has copy that names a next step where one exists", () => {
  const kinds: FailureKind[] = [
    "unsupported_bundle",
    "corrupt_bundle",
    "invalid_document",
    "unsupported_version",
    "missing_trace",
    "partial_evidence",
    "old_analyzer",
    "unknown_diagnosis",
  ];
  assert.deepEqual(Object.keys(FAILURE_COPY).sort(), [...kinds].sort());
  for (const kind of kinds) {
    const copy = failureCopy(kind);
    assert.ok(copy.title.length > 0 && copy.body.length > 0, `${kind} needs a title and body`);
    assert.doesNotMatch(copy.body + (copy.action ?? ""), /\bundefined\b/);
  }
});
