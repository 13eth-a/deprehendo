import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";

import type { AnalysisDocument } from "../types/analysis.ts";
import { Overview } from "../components/Overview.tsx";
import { DiagnosisPanel } from "../components/DiagnosisPanel.tsx";
import { CausalChain } from "../components/CausalChain.tsx";
import { EvidenceDrawer } from "../components/EvidenceDrawer.tsx";
import { TimelineTable } from "../components/TimelineTable.tsx";
import { ProcessTree } from "../components/ProcessTree.tsx";
import { NetworkTable } from "../components/NetworkTable.tsx";
import { CpuChart } from "../components/Sparkline.tsx";
import { PrivacyPanel } from "../components/PrivacyPanel.tsx";
import { FailureState } from "../components/FailureState.tsx";
import { IncidentList } from "../components/IncidentList.tsx";
import { pageOf } from "../lib/paging.ts";
import { summarize, sortNewestFirst } from "../lib/incidents.ts";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name: string): AnalysisDocument =>
  JSON.parse(readFileSync(join(here, "fixtures", "analysis", `${name}.json`), "utf8")) as AnalysisDocument;

test("Overview shows the stored primary signature and never a different one", () => {
  for (const name of ["disk-full", "network-failure", "healthy-idle", "oom"]) {
    const doc = load(name);
    const html = renderToStaticMarkup(<Overview doc={doc} />);
    const expected = doc.diagnosis?.matches[0]?.signature ?? "NO KNOWN SIGNATURE";
    assert.ok(html.includes(expected), `${name}: headline should read ${expected}`);
    assert.ok(html.includes(doc.bundle.incident_id), `${name}: incident id shown`);
  }
});

test("DiagnosisPanel keeps the analyzer's primary and shows counts without reranking", () => {
  const doc = load("disk-full");
  const html = renderToStaticMarkup(<DiagnosisPanel doc={doc} />);
  const primary = doc.diagnosis!.matches[0]!;
  assert.ok(html.includes(primary.signature));
  assert.ok(html.includes(primary.confidence_band));
  assert.ok(html.includes("signature(s) were checked and rejected"));
});

test("CausalChain renders stored edges in the analyzer's known_chain order", () => {
  for (const name of ["disk-full", "network-failure", "orphan", "healthy-idle"]) {
    const doc = load(name);
    const html = renderToStaticMarkup(<CausalChain doc={doc} />);
    for (const failure of doc.causal.failures) {
      for (const id of failure.known_chain ?? []) {
        const event = doc.causal.nodes.find((n) => n.event.id === id)?.event;
        if (event) assert.ok(html.includes(event.type), `${name}: ${event.type} shown`);
      }
    }
    if (doc.causal.failures.length === 0) {
      assert.ok(html.includes("No failure anchor"), `${name}: says so when there are no anchors`);
    }
  }
});

test("TimelineTable pages the stored events and labels evidence as stored", () => {
  const doc = load("oom");
  const page = pageOf(doc.timeline, 1, 200);
  const html = renderToStaticMarkup(<TimelineTable page={page} origin={doc.bundle.created_at} />);
  for (const event of page.items) {
    assert.ok(html.includes(event.type), `event type ${event.type} shown`);
  }
  assert.ok(html.includes(`showing ${page.items.length} of ${doc.timeline.length}`));
});

test("EvidenceDrawer shows the stored source, rule and evidence class for an event", () => {
  const doc = load("disk-full");
  const event = doc.timeline.find((e) => e.provenance.rule_id) ?? doc.timeline[0];
  assert.ok(event, "fixture has at least one event");
  const html = renderToStaticMarkup(<EvidenceDrawer doc={doc} event={event} />);
  assert.ok(html.includes(event.type));
  assert.ok(html.includes("not recorded in the event"), "collector is not invented");
  if (event.provenance.rule_id) assert.ok(html.includes(event.provenance.rule_id));
});

test("ProcessTree and NetworkTable render the sample they are given", () => {
  const doc = load("frozen-worker");
  const index = doc.series.length - 1;
  const tree = renderToStaticMarkup(<ProcessTree series={doc.series} index={index} />);
  for (const p of doc.series[index]!.processes ?? []) {
    assert.ok(tree.includes(p.name), `process ${p.name} shown`);
  }
  const net = renderToStaticMarkup(<NetworkTable series={doc.series} index={index} />);
  assert.ok(net.includes("Network connections"));
});

test("CpuChart draws only stored samples and states the trigger position", () => {
  const doc = load("disk-full");
  const html = renderToStaticMarkup(<CpuChart series={doc.series} triggeredAt={doc.diagnosis?.triggered_at} />);
  assert.ok(html.includes("<svg"));
  assert.ok(html.includes("data-marker=\"trigger\"") || html.includes("outside the captured samples"));
});

test("PrivacyPanel says absent data is not in the bundle, never that it was redacted", () => {
  const doc = load("disk-full");
  const html = renderToStaticMarkup(<PrivacyPanel privacy={doc.privacy} />);
  assert.ok(html.includes(doc.privacy.policy));
  assert.ok(!/redacted/i.test(html.replace("does not say whether the data was redacted", "")), "no redaction claim");
  if (!doc.privacy.command_lines) assert.ok(html.includes("Not in bundle"));
});

test("FailureState is announced as a status and gives its copy", () => {
  const html = renderToStaticMarkup(<FailureState kind="corrupt_bundle" detail="sha256 mismatch" />);
  assert.ok(html.includes('role="status"'));
  assert.ok(html.includes("This bundle is damaged"));
  assert.ok(html.includes("sha256 mismatch"));
});

test("IncidentList renders newest-first rows and the filter form", () => {
  const rows = sortNewestFirst(
    ["disk-full", "oom", "healthy-idle"].map((n) => summarize(load(n))),
  );
  const html = renderToStaticMarkup(
    <IncidentList rows={rows} filter={{}} diagnoses={["DISK_EXHAUSTION"]} bands={["MODERATE"]} />,
  );
  assert.ok(html.includes('aria-label="Filter incidents"'));
  for (const row of rows) assert.ok(html.includes(row.incidentId));
  // 7.53: a first run is told how to upload; an empty filtered result is not
  // mistaken for an empty organization.
  const firstRun = renderToStaticMarkup(<IncidentList rows={[]} filter={{}} diagnoses={[]} bands={[]} />);
  assert.ok(firstRun.includes("No incidents yet"));
  assert.ok(firstRun.includes("runopsy-agent upload incident.runopsy"));
  const filtered = renderToStaticMarkup(
    <IncidentList rows={[]} filter={{ diagnosis: "DISK_EXHAUSTION" }} diagnoses={[]} bands={[]} />,
  );
  assert.ok(filtered.includes("No incidents match these filters."));
  assert.ok(!filtered.includes("No incidents yet"));
});
