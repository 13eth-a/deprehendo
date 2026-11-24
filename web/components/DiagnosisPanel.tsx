import type { AnalysisDocument, Evidence, SignatureMatch } from "../types/analysis.ts";
import { SectionHeading } from "./SectionHeading.tsx";
import { ConfidenceBadge, SeverityBadge } from "./Status.tsx";
import { ProviderFindings } from "./ProviderFindings.tsx";
import { Clock } from "./Clock.tsx";
import { evidenceKey, type EvidenceRole } from "../lib/evidence-ref.ts";

type EvidenceLinks = { href: (key: string) => string; selected?: string };

/**
 * Diagnosis panel (checklist 7.15), answering "why?". It shows the primary
 * and alternative diagnoses in the analyzer's order, with the evidence each
 * one stored: supporting, contradicting and missing. Uncertainty stays
 * visible: nothing is hidden or reranked here.
 */
export function DiagnosisPanel({
  doc,
  evidenceHref,
  selectedEvidence,
}: {
  doc: AnalysisDocument;
  /** Links each evidence item to the evidence drawer. Without it the items are plain text. */
  evidenceHref?: (key: string) => string;
  selectedEvidence?: string;
}) {
  const links: EvidenceLinks | undefined = evidenceHref ? { href: evidenceHref, selected: selectedEvidence } : undefined;
  const report = doc.diagnosis;
  if (!report) {
    return (
      <section aria-labelledby="diagnosis-title" className="section">
        <SectionHeading id="diagnosis-title">Root cause</SectionHeading>
        <p className="muted">The analyzer produced no diagnosis for this incident.</p>
      </section>
    );
  }
  const [primary, ...alternatives] = report.matches;
  return (
    <section aria-labelledby="diagnosis-title" className="section">
      <SectionHeading
        id="diagnosis-title"
       
        aside={<span className="muted small">threshold {report.min_confidence.toFixed(2)}</span>}
      >
        Root cause
      </SectionHeading>
      {primary ? (
        <MatchCard label="Primary" match={primary} links={links} />
      ) : (
        <p className="panel">No signature cleared the confidence threshold of {report.min_confidence.toFixed(2)}.</p>
      )}
      {alternatives.length > 0 && (
        <>
          <h3 className="subhead">Alternative diagnoses</h3>
          <ul className="stack">
            {alternatives.map((match) => (
              <li key={match.signature}>
                <MatchCard label={match.signature} match={match} compact />
              </li>
            ))}
          </ul>
        </>
      )}
      {report.ambiguous && report.ambiguous.length > 0 && (
        <p className="note">
          The analyzer could not rank these pairs: <code>{report.ambiguous.join(", ")}</code>
        </p>
      )}
      <ProviderFindings doc={doc} />
      <p className="muted small">
        {report.rejections.length} signature(s) were checked and rejected. Their reasons are in the raw analysis.
      </p>
    </section>
  );
}

function MatchCard({
  label,
  match,
  compact = false,
  links,
}: {
  label: string;
  match: SignatureMatch;
  compact?: boolean;
  links?: EvidenceLinks;
}) {
  const supporting = match.supporting ?? [];
  const contradicting = match.contradicting ?? [];
  const missing = match.missing_evidence ?? [];
  return (
    <article className="panel match" aria-label={`${label}: ${match.signature}`}>
      <header className="match__head">
        <div>
          <p className="match__kind">{label === match.signature ? "Alternative" : label}</p>
          <h3 className="mono">{match.signature}</h3>
        </div>
        <div className="status-row">
          <SeverityBadge severity={match.severity} />
          <ConfidenceBadge band={match.confidence_band} score={match.confidence} />
        </div>
      </header>
      <p className="match__summary">{match.summary}</p>
      <dl className="tally">
        <div>
          <dt>Supporting</dt>
          <dd>{supporting.length}</dd>
        </div>
        <div>
          <dt>Contradicting</dt>
          <dd>{contradicting.length}</dd>
        </div>
        <div>
          <dt>Missing evidence</dt>
          <dd>{missing.length > 0 ? missing.length : "none reported"}</dd>
        </div>
      </dl>
      {!compact && supporting.length > 0 && <EvidenceList title="Key evidence" items={supporting} signature={match.signature} role="supporting" links={links} />}
      {!compact && contradicting.length > 0 && <EvidenceList title="Contradicting evidence" items={contradicting} signature={match.signature} role="contradicting" links={links} />}
      {missing.length > 0 && (
        <p className="missing">
          <span className="muted">Not available to the analyzer:</span>{" "}
          {missing.map((code) => (
            <code key={code} className="chip">{code}</code>
          ))}
        </p>
      )}
    </article>
  );
}

function EvidenceList({
  title,
  items,
  signature,
  role,
  links,
}: {
  title: string;
  items: Evidence[];
  signature: string;
  role: EvidenceRole;
  links?: EvidenceLinks;
}) {
  return (
    <div className="evidence-list" data-tone={role === "supporting" ? "support" : "contra"}>
      <h4>{title}</h4>
      <ul>
        {items.map((item, i) => {
          const key = evidenceKey(signature, role, i);
          return (
          <li key={`${item.code}-${i}`} data-selected={links?.selected === key ? "true" : undefined}>
            <span className="evidence-list__weight" aria-hidden="true">
              <span style={{ width: `${Math.min(100, Math.max(4, item.weight * 100))}%` }} />
            </span>
            {links ? (
              <a className="evidence-list__code" href={links.href(key)} aria-current={links.selected === key ? "true" : undefined}>
                <code>{item.code}</code>
              </a>
            ) : (
              <code className="evidence-list__code">{item.code}</code>
            )}
            <span className="evidence-list__meta">
              {item.observed !== undefined && <span className="mono">{short(item.observed)}</span>}
              {item.threshold !== undefined && <span className="muted"> threshold {short(item.threshold)}</span>}
            </span>
            <span className="evidence-list__source muted">
              {item.source} · <Clock iso={item.at} /> · weight {item.weight.toFixed(2)}
            </span>
          </li>
          );
        })}
      </ul>
    </div>
  );
}

/** Compact JSON for an observed value; display only. */
function short(value: unknown): string {
  // Long floats are rounded for reading; the stored value is unchanged.
  const text =
    typeof value === "string"
      ? value
      : typeof value === "number" && !Number.isInteger(value)
        ? String(Number(value.toFixed(2)))
        : JSON.stringify(value);
  return text.length > 80 ? `${text.slice(0, 77)}…` : text;
}
