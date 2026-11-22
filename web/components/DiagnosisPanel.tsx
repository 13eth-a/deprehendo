import type { AnalysisDocument, SignatureMatch } from "../types/analysis.ts";

/**
 * diagnosis panel (checklist 7.15). it shows the primary and alternative
 * diagnoses in the analyzer's order, with counts of supporting, contradicting
 * and missing evidence. uncertainty stays visible: nothing is hidden or
 * reranked here.
 */
export function DiagnosisPanel({ doc }: { doc: AnalysisDocument }) {
  const report = doc.diagnosis;
  if (!report) {
    return (
      <section aria-labelledby="diagnosis-title">
        <h2 id="diagnosis-title">Diagnosis</h2>
        <p>The analyzer produced no diagnosis for this incident.</p>
      </section>
    );
  }
  const [primary, ...alternatives] = report.matches;
  return (
    <section aria-labelledby="diagnosis-title">
      <h2 id="diagnosis-title">Diagnosis</h2>
      {primary ? (
        <MatchCard label="Primary" match={primary} />
      ) : (
        <p>No signature cleared the confidence threshold of {report.min_confidence.toFixed(2)}.</p>
      )}
      {alternatives.length > 0 && (
        <>
          <h3>Alternative diagnoses</h3>
          <ul className="cards">
            {alternatives.map((match) => (
              <li key={match.signature}>
                <MatchCard label={match.signature} match={match} />
              </li>
            ))}
          </ul>
        </>
      )}
      {report.ambiguous && report.ambiguous.length > 0 && (
        <p>
          The analyzer could not rank these pairs: <code>{report.ambiguous.join(", ")}</code>
        </p>
      )}
      <p className="muted">
        {report.rejections.length} signature(s) were checked and rejected. Their reasons are in the raw analysis.
      </p>
    </section>
  );
}

function MatchCard({ label, match }: { label: string; match: SignatureMatch }) {
  const supporting = match.supporting?.length ?? 0;
  const contradicting = match.contradicting?.length ?? 0;
  const missing = match.missing_evidence ?? [];
  return (
    <article className="card" aria-label={`${label}: ${match.signature}`}>
      <p className="eyebrow">{label}</p>
      <h3>{match.signature}</h3>
      <p>{match.summary}</p>
      <dl className="facts">
        <div>
          <dt>Confidence</dt>
          <dd>
            {match.confidence_band} ({match.confidence.toFixed(2)})
          </dd>
        </div>
        <div>
          <dt>Severity</dt>
          <dd>{match.severity}</dd>
        </div>
        <div>
          <dt>Supporting evidence</dt>
          <dd>{supporting}</dd>
        </div>
        <div>
          <dt>Contradicting evidence</dt>
          <dd>{contradicting}</dd>
        </div>
        <div>
          <dt>Missing evidence</dt>
          <dd>{missing.length > 0 ? missing.join(", ") : "none reported"}</dd>
        </div>
      </dl>
    </article>
  );
}
