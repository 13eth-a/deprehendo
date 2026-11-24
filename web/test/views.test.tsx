import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";

import type { AnalysisDocument } from "../types/analysis.ts";
import { IncidentView } from "../components/IncidentView.tsx";
import { IncidentList } from "../components/IncidentList.tsx";
import { EvidenceBadge } from "../components/EvidenceBadge.tsx";
import { ClaimBadge, ConfidenceBadge, SeverityBadge } from "../components/Status.tsx";
import { pageOf } from "../lib/paging.ts";
import { summaryFromApiRow } from "../lib/api-incidents.ts";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name: string): AnalysisDocument =>
  JSON.parse(readFileSync(join(here, "fixtures", "analysis", `${name}.json`), "utf8")) as AnalysisDocument;

const hrefFor = ({ page, event }: { page?: number; event?: string }) =>
  `/incidents/x?${page ? `page=${page}` : ""}${event ? `&event=${event}` : ""}`;

test("IncidentView keeps the order: diagnosis, root cause, causal chain, timeline, raw data", () => {
  const doc = load("frozen-worker");
  const html = renderToStaticMarkup(<IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} hrefFor={hrefFor} />);
  const order = ["overview-title", "diagnosis-title", "chain-title", "timeline-title", "raw-title"].map((id) => html.indexOf(`id="${id}"`));
  for (const at of order) assert.ok(at >= 0, "every section is present");
  assert.deepEqual([...order].sort((a, b) => a - b), order, "sections appear in the forensic order");
  assert.ok(html.includes("Every conclusion is inspectable"), "the idle drawer explains how to open evidence");
  assert.ok(html.includes("event=EV_"), "chain steps and timeline rows link to the evidence drawer");
});

test("IncidentView opens the evidence drawer for the selected stored event only", () => {
  const doc = load("frozen-worker");
  const event = doc.timeline[0]!;
  const html = renderToStaticMarkup(
    <IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} selectedEvent={event.id} hrefFor={hrefFor} />,
  );
  assert.ok(html.includes('id="drawer-title"'));
  assert.ok(html.includes("not recorded in the event"), "collector is not invented");
  const unknown = renderToStaticMarkup(
    <IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} selectedEvent="EV_not_in_document" hrefFor={hrefFor} />,
  );
  assert.ok(!unknown.includes('id="drawer-title"'), "an id that is not in the document opens nothing");
});

test("IncidentView shows the no-signature state when nothing matched", () => {
  const doc = load("healthy-idle");
  const html = renderToStaticMarkup(<IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} hrefFor={hrefFor} />);
  assert.ok(html.includes("NO KNOWN SIGNATURE"));
  assert.ok(html.includes("No known signature matched"));
});

test("status marks carry shape and words, not color alone", () => {
  const direct = renderToStaticMarkup(<EvidenceBadge quality="DIRECT_KERNEL" />);
  const inferred = renderToStaticMarkup(<EvidenceBadge quality="DERIVED_SNAPSHOT" />);
  assert.ok(direct.includes('data-direct="true"') && direct.includes("DIRECT KERNEL TRACE"), "direct: filled mark and words");
  assert.ok(!inferred.includes("data-direct") && inferred.includes("INFERRED FROM SNAPSHOTS"), "inferred: hollow mark and words");
  assert.ok(renderToStaticMarkup(<SeverityBadge severity="CRITICAL" />).includes("Critical"));
  assert.equal(renderToStaticMarkup(<SeverityBadge severity={null} />), "");
  assert.ok(renderToStaticMarkup(<ConfidenceBadge band="VERY_HIGH" score={0.93} />).includes("Very high confidence"));
  assert.ok(renderToStaticMarkup(<ClaimBadge claim="inferred" />).includes("Inferred evidence"));
  assert.ok(renderToStaticMarkup(<ClaimBadge claim="nonsense" />).includes("Unknown evidence"), "unknown words stay unknown");
});

test("IncidentList tallies stored severities and shows GitHub context from the API row", () => {
  const rows = [
    { incident_id: "inc_a00", created_at: "2026-11-21T07:16:01Z", primary_signature: "OOM_KILL", confidence_band: "HIGH", severity: "CRITICAL", workflow: "ci", job: "build", analysis_status: "READY" },
    { incident_id: "inc_b00", created_at: "2026-11-21T07:20:01Z", analysis_status: "READY" },
  ].map(summaryFromApiRow);
  const html = renderToStaticMarkup(<IncidentList rows={rows} all={rows} filter={{}} diagnoses={[]} bands={[]} />);
  assert.ok(html.includes('aria-label="Incident counts"'));
  assert.ok(html.includes("ci · build"), "workflow and job come from the API row");
  assert.ok(html.includes("Critical"));
});

test("every evidence item under Root cause opens the evidence drawer with its stored values", () => {
  const doc = load("frozen-worker");
  const match = doc.diagnosis!.matches[0]!;
  const href = ({ page, event, evidence }: { page?: number; event?: string; evidence?: string }) =>
    `/x?${page ? `page=${page}` : ""}${event ? `&event=${event}` : ""}${evidence ? `&evidence=${evidence}` : ""}`;
  const closed = renderToStaticMarkup(<IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} hrefFor={href} />);
  for (let i = 0; i < (match.supporting ?? []).length; i++) {
    assert.ok(closed.includes(`evidence=${match.signature}.s.${i}`), `supporting item ${i} links to the drawer`);
  }
  const key = `${match.signature}.s.0`;
  const item = match.supporting![0]!;
  const open = renderToStaticMarkup(
    <IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} selectedEvidence={key} hrefFor={href} />,
  );
  assert.ok(open.includes('id="drawer-title"') && open.includes(item.code));
  assert.ok(open.includes("Supporting evidence"));
  if (item.observed !== undefined) {
    const raw = JSON.stringify(item.observed, null, 2).replaceAll('"', "&quot;");
    assert.ok(open.includes(raw), "the observed value is shown exactly as stored");
  }
  for (const id of match.related_events ?? []) assert.ok(open.includes(`event=${id}`), "related events link to their drawer");
  // a key that names nothing in the document leaves the drawer idle
  const bogus = renderToStaticMarkup(
    <IncidentView doc={doc} page={pageOf(doc.timeline, 1, 200)} selectedEvidence="OOM_KILL.s.99" hrefFor={href} />,
  );
  assert.ok(bogus.includes("Every conclusion is inspectable"));
  assert.ok(!bogus.includes('id="drawer-title"'));
});
