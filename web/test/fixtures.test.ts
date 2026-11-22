import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { checkAnalysisDocument } from "../lib/guards.ts";
import { summarize } from "../lib/incidents.ts";
import type { AnalysisDocument } from "../types/analysis.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "fixtures", "analysis");
const goldenPath = join(here, "fixtures", "analysis-keys.golden.json");

function loadFixtures(): { name: string; raw: unknown }[] {
  return readdirSync(fixtureDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => ({ name: f, raw: JSON.parse(readFileSync(join(fixtureDir, f), "utf8")) as unknown }));
}

function typeName(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "boolean") return "bool";
  if (typeof value === "number") return Number.isInteger(value) ? "int" : "float";
  if (typeof value === "string") return "string";
  return "object";
}

/** same walk the golden file was made with: key:type per object path. */
function shapeOf(value: unknown): Record<string, string[]> {
  const shapes = new Map<string, Set<string>>();
  const walk = (x: unknown, path: string) => {
    if (typeof x === "object" && x !== null && !Array.isArray(x)) {
      const set = shapes.get(path) ?? new Set<string>();
      shapes.set(path, set);
      for (const [key, child] of Object.entries(x)) {
        set.add(`${key}:${typeName(child)}`);
        walk(child, `${path}.${key}`);
      }
    } else if (Array.isArray(x)) {
      for (const child of x) walk(child, `${path}[]`);
    }
  };
  walk(value, "$");
  return Object.fromEntries([...shapes].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => [k, [...v].sort()]));
}

const fixtures = loadFixtures();

test("every stored fixture is a supported v1 document", () => {
  assert.ok(fixtures.length >= 19, "expected the 19 bundled incidents");
  for (const { name, raw } of fixtures) {
    const check = checkAnalysisDocument(raw);
    assert.equal(check.ok, true, `${name}: ${check.ok ? "" : check.detail}`);
  }
});

test("the key shape of every fixture matches the golden file (drift alarm)", () => {
  const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as Record<string, string[]>;
  const merged: Record<string, Set<string>> = {};
  for (const { raw } of fixtures) {
    for (const [path, keys] of Object.entries(shapeOf(raw))) {
      merged[path] ??= new Set();
      for (const key of keys) merged[path].add(key);
    }
  }
  const current = Object.fromEntries(
    Object.entries(merged).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => [k, [...v].sort()]),
  );
  assert.deepEqual(
    current,
    golden,
    "Go changed the analysis document. Update the types in types/analysis.ts and the golden file in the same change.",
  );
});

test("timeline and series keep the stored order (index equals position)", () => {
  for (const { name, raw } of fixtures) {
    const doc = raw as AnalysisDocument;
    doc.timeline.forEach((event, i) => {
      assert.equal(event.sequence >= 0, true, `${name}: timeline[${i}] has a negative sequence`);
      if (i > 0) {
        assert.ok(
          doc.timeline[i - 1]!.sequence <= event.sequence,
          `${name}: timeline sequence goes backwards at ${i}`,
        );
      }
    });
    // CaptureIndex is zero in v1 bundles (internal/collector/snapshot.go), so the
    // UI must order samples by array position. A non-zero value must match it.
    doc.series.forEach((snapshot, i) => {
      assert.ok(
        snapshot.CaptureIndex === 0 || snapshot.CaptureIndex === i,
        `${name}: series[${i}].CaptureIndex is ${snapshot.CaptureIndex}`,
      );
    });
  }
});

test("every edge and failure refers to an event that is in the causal nodes", () => {
  for (const { name, raw } of fixtures) {
    const doc = raw as AnalysisDocument;
    const ids = new Set(doc.causal.nodes.map((n) => n.event.id));
    for (const edge of doc.causal.edges ?? []) {
      assert.ok(ids.has(edge.from), `${name}: edge ${edge.id} from unknown ${edge.from}`);
      assert.ok(ids.has(edge.to), `${name}: edge ${edge.id} to unknown ${edge.to}`);
    }
    for (const failure of doc.causal.failures) {
      assert.ok(ids.has(failure.anchor), `${name}: failure anchor ${failure.anchor} is not a node`);
      for (const id of failure.known_chain ?? []) {
        assert.ok(ids.has(id), `${name}: known_chain item ${id} is not a node`);
      }
    }
  }
});

test("diagnosis matches arrive primary-first (confidence, then signature name)", () => {
  for (const { name, raw } of fixtures) {
    const report = (raw as AnalysisDocument).diagnosis;
    if (!report) continue;
    for (let i = 1; i < report.matches.length; i++) {
      const prev = report.matches[i - 1]!;
      const cur = report.matches[i]!;
      const ordered =
        prev.confidence > cur.confidence ||
        (prev.confidence === cur.confidence && prev.signature <= cur.signature);
      assert.ok(ordered, `${name}: matches[${i}] is out of order`);
    }
  }
});

test("summaries agree with the stored primary diagnosis", () => {
  for (const { raw } of fixtures) {
    const doc = raw as AnalysisDocument;
    const row = summarize(doc);
    assert.equal(row.diagnosis, doc.diagnosis?.matches[0]?.signature ?? null);
    assert.equal(row.causalRules, doc.engine.causal_rules);
  }
});
