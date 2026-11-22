import type { AnalysisDocument } from "../types/analysis.ts";
import { formatClock } from "../lib/format.ts";

/**
 * incident overview header (checklist 7.14): the first thing a reader sees.
 * every value is copied from the document. the signature name is shown as
 * stored, never rewritten.
 */
export function Overview({ doc }: { doc: AnalysisDocument }) {
  const report = doc.diagnosis;
  const top = report?.matches[0];
  const headline = top ? top.signature : "NO KNOWN SIGNATURE";
  return (
    <section aria-labelledby="overview-title" className="overview">
      <p className="eyebrow">Incident</p>
      <h1 id="overview-title">{headline}</h1>
      <dl className="facts">
        <div>
          <dt>Confidence</dt>
          <dd>
            {top ? `${top.confidence_band} (${top.confidence.toFixed(2)})` : "No diagnosis above the threshold"}
          </dd>
        </div>
        <div>
          <dt>Trigger</dt>
          <dd>
            {report ? `${report.trigger} at ${formatClock(report.triggered_at)} UTC` : "Not recorded"}
          </dd>
        </div>
        <div>
          <dt>Incident ID</dt>
          <dd>
            <code>{doc.bundle.incident_id}</code>
          </dd>
        </div>
        <div>
          <dt>Analyzer</dt>
          <dd>
            <code>
              {doc.engine.analyzer_version} · rules {doc.engine.causal_rules.slice(0, 12)}
            </code>
          </dd>
        </div>
        <div>
          <dt>Bundle SHA-256</dt>
          <dd>
            <code title={doc.bundle.sha256}>{doc.bundle.sha256.slice(0, 16)}…</code>
          </dd>
        </div>
      </dl>
    </section>
  );
}
