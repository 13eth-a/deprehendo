import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";

import { checkAnalysisDocument } from "../lib/guards.ts";
import { pageOf } from "../lib/paging.ts";
import { Overview } from "../components/Overview.tsx";
import { DiagnosisPanel } from "../components/DiagnosisPanel.tsx";
import { CausalChain } from "../components/CausalChain.tsx";
import { TimelineTable } from "../components/TimelineTable.tsx";
import { ProcessTree } from "../components/ProcessTree.tsx";
import { NetworkTable } from "../components/NetworkTable.tsx";
import { PrivacyPanel } from "../components/PrivacyPanel.tsx";

/**
 * renders one stored `runopsy.analysis` v1 document through the dashboard
 * components and prints what the incident page shows, as one JSON line.
 *
 * this is the dashboard leg of checklist 7.61: tests/phase7_dashboard_render_test.go
 * hands it the document the CLI wrote (and, via the byte equality in
 * tests/phase7_server_test.go, the document the cloud serves) and compares the
 * headline and paging with that document. it is a renderer only; it never
 * diagnoses or reinterprets (contract §3.1).
 *
 * usage: node --import tsx test/render-document.ts <document.json> [page-size]
 */

function fail(message: string, code = 2): never {
  console.error(message);
  process.exit(code);
}

const [path, pageSizeArg] = process.argv.slice(2);
if (!path) {
  fail("usage: render-document.ts <document.json> [page-size]");
}
const pageSize = pageSizeArg === undefined ? 200 : Number(pageSizeArg);
if (!Number.isInteger(pageSize) || pageSize < 1) {
  fail("page-size must be a positive integer");
}

let parsed: unknown;
try {
  parsed = JSON.parse(readFileSync(path, "utf8"));
} catch (error) {
  fail(`cannot read ${path}: ${String(error)}`);
}

const check = checkAnalysisDocument(parsed);
if (!check.ok) {
  // 7.32: an unsupported or damaged document is reported, never a blank page.
  fail(`unsupported document (${check.reason}): ${check.detail}`, 3);
}
const doc = check.document;

const sampleIndex = doc.series.length > 0 ? doc.series.length - 1 : 0;
const page = pageOf(doc.timeline, 1, pageSize);
const html = [
  renderToStaticMarkup(<Overview doc={doc} />),
  doc.diagnosis ? renderToStaticMarkup(<DiagnosisPanel doc={doc} />) : "",
  renderToStaticMarkup(<CausalChain doc={doc} />),
  renderToStaticMarkup(<TimelineTable page={page} origin={doc.bundle.created_at} />),
  renderToStaticMarkup(<ProcessTree series={doc.series} index={sampleIndex} />),
  renderToStaticMarkup(<NetworkTable series={doc.series} index={sampleIndex} />),
  renderToStaticMarkup(<PrivacyPanel privacy={doc.privacy} />),
].join("\n");

const top = doc.diagnosis?.matches[0];
console.log(
  JSON.stringify({
    document_version: doc.document_version,
    incident_id: doc.bundle.incident_id,
    headline: top ? top.signature : "NO KNOWN SIGNATURE",
    confidence_band: top ? top.confidence_band : null,
    unknown: doc.diagnosis ? doc.diagnosis.unknown : true,
    timeline_total: doc.timeline.length,
    page_rows: page.items.length,
    page_first_id: page.items[0]?.id ?? null,
    dom_nodes: (html.match(/<[a-zA-Z][^>]*>/g) ?? []).length,
    html_bytes: Buffer.byteLength(html, "utf8"),
  }),
);
