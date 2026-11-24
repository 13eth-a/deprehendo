import type { AnalysisDocument } from "../types/analysis.ts";
import { ClaimBadge, ConfidenceBadge, SeverityBadge } from "./Status.tsx";
import { Clock } from "./Clock.tsx";

/**
 * Incident overview header (checklist 7.14): the first thing a reader sees,
 * answering "what failed?". The headline is the match's own stored summary;
 * the signature underneath is shown exactly as stored, never rewritten.
 * When nothing matched, it says so instead of inventing a cause.
 */
export function Overview({ doc }: { doc: AnalysisDocument }) {
  const report = doc.diagnosis;
  const top = report?.matches[0];
  const headline = top ? top.signature : "NO KNOWN SIGNATURE";
  const claim = doc.causal.failures[0]?.claim;
  return (
    <section aria-labelledby="overview-title" className="report-head" data-diagnosed={top ? "true" : undefined}>
      <p className="report-head__kind">{top ? "Primary diagnosis" : "No diagnosis"}</p>
      <h1 id="overview-title" className="report-head__title">
        {top ? sentence(top.summary) : "No known signature matched"}
      </h1>
      <p className="report-head__signature">
        <code>{headline}</code>
      </p>
      <div className="tags">
        {top && <SeverityBadge severity={top.severity} />}
        {top && <ConfidenceBadge band={top.confidence_band} score={top.confidence} />}
        {claim && <ClaimBadge claim={claim} />}
      </div>
      <dl className="meta-grid">
        <div>
          <dt>Trigger</dt>
          <dd>
            {report ? (
              <>
                <code>{report.trigger}</code> at <Clock iso={report.triggered_at} zone />
              </>
            ) : (
              "Not recorded"
            )}
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

/** Display only: the stored summary starts lowercase; the headline starts with a capital. */
function sentence(text: string): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}
