import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { renderToStaticMarkup } from "react-dom/server";

import type { AnalysisDocument, TimelineEvent } from "../types/analysis.ts";
import { TimelineTable } from "../components/TimelineTable.tsx";
import { pageOf } from "../lib/paging.ts";

/**
 * checklist 7.44: the dashboard must not render 10,000 DOM nodes at once.
 *
 * these measurements are server-side renders of the real component with real
 * document shapes, not a browser. they bound element count and render time for
 * a stored document; paint, layout and memory in a browser are still unmeasured
 * and are not claimed here (docs/cloud/performance.md records that gap).
 *
 * the payload sizes are 7.44's: 100, 1,000 and 10,000 events.
 */

const here = dirname(fileURLToPath(import.meta.url));
const PAGE = 200;

const base = JSON.parse(
  readFileSync(join(here, "fixtures", "analysis", "frozen-worker.json"), "utf8"),
) as AnalysisDocument;

/**
 * grow a real fixture's timeline to `events` entries. only the array length
 * changes: each row is a copy of a stored event with a unique id and a
 * strictly increasing timestamp, so the measurement is about how many rows are
 * rendered, not about different content.
 */
function documentOf(events: number): AnalysisDocument {
  const source = base.timeline;
  const start = Date.parse(base.bundle.created_at);
  const timeline: TimelineEvent[] = Array.from({ length: events }, (_, i) => {
    const template = source[i % source.length]!;
    return {
      ...template,
      id: `${template.id}#${i}`,
      timestamp: new Date(start + i * 10).toISOString(),
    };
  });
  return { ...base, timeline };
}

/** element count of rendered markup (opening tags; deterministic). */
function elementCount(html: string): number {
  return (html.match(/<[a-zA-Z][^>]*>/g) ?? []).length;
}

test("7.44: a timeline page stays bounded at 100, 1,000 and 10,000 events", () => {
  let fullPageNodes: number | null = null;
  const measurements: string[] = [];

  for (const total of [100, 1000, 10000]) {
    const doc = documentOf(total);

    // what 7.44 forbids: the whole array in one table.
    const fullStart = performance.now();
    const fullHtml = renderToStaticMarkup(
      <TimelineTable page={pageOf(doc.timeline, 1, total)} origin={doc.bundle.created_at} />,
    );
    const fullMs = performance.now() - fullStart;

    // what the app does: one page of 200, sliced by position.
    const page = pageOf(doc.timeline, 1, PAGE);
    const pageStart = performance.now();
    const pageHtml = renderToStaticMarkup(
      <TimelineTable page={page} origin={doc.bundle.created_at} />,
    );
    const pageMs = performance.now() - pageStart;

    const fullNodes = elementCount(fullHtml);
    const pageNodes = elementCount(pageHtml);

    assert.equal(page.items.length, Math.min(PAGE, total), "a page holds at most 200 rows");
    assert.equal(page.total, total);
    assert.equal(page.start, 0);
    assert.ok(pageHtml.includes(`showing ${page.items.length} of ${total}`), "the caption states the true total");
    // the markup is exactly the page, never the rest of the array.
    assert.ok(!pageHtml.includes("#201"), "no row from beyond the page is rendered");

    // 200 rows of 8 elements plus the table shell; independent of total.
    assert.ok(pageNodes < 4000, `${pageNodes} elements for a ${total}-event page exceeds the page bound`);
    if (total >= 1000) {
      if (fullPageNodes === null) {
        fullPageNodes = pageNodes;
      } else {
        assert.equal(pageNodes, fullPageNodes, "page size, not payload size, decides the DOM");
      }
    }
    if (total === 10000) {
      assert.ok(
        fullNodes > pageNodes * 10,
        `full render is ${fullNodes} elements (${fullNodes / pageNodes}x the page): 7.44 requires paging`,
      );
    }

    measurements.push(
      `7.44 events=${total} full_nodes=${fullNodes} page_nodes=${pageNodes} ` +
        `full_ms=${fullMs.toFixed(1)} page_ms=${pageMs.toFixed(1)}`,
    );
  }

  console.log(measurements.join("\n"));
});

test("7.44: page arithmetic keeps stored order at 10,000 events", () => {
  const doc = documentOf(10000);
  const second = pageOf(doc.timeline, 2, PAGE);
  assert.equal(second.start, 200);
  assert.equal(second.items[0]!.id, `${doc.timeline[200]!.id}`);
  assert.equal(second.items.at(-1)!.id, `${doc.timeline[399]!.id}`);
  // A request past the end clamps to the last page instead of rendering empty.
  const clamped = pageOf(doc.timeline, 999, PAGE);
  assert.equal(clamped.page, 50);
  assert.equal(clamped.items.length, 200);
});
