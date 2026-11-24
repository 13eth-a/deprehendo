import type { AnalysisDocument, CausalEdge, CausalFailure, CausalNode } from "../types/analysis.ts";
import { evidenceLabel, isDirect } from "../lib/evidence.ts";
import { formatClock, formatOffset } from "../lib/format.ts";
import { SectionHeading } from "./SectionHeading.tsx";
import { ClaimBadge } from "./Status.tsx";
import { Clock } from "./Clock.tsx";

/**
 * Vertical causal chain per failure anchor (checklist 7.16), answering "how
 * did it happen?". The order is the analyzer's known_chain. Each connector is
 * the stored edge between the two events: its relation, band and rule are
 * copied, not inferred. Nothing here decides that an edge exists. The time
 * between two steps is display arithmetic on their stored timestamps.
 *
 * With `eventHref`, every step links to the evidence drawer for its event.
 */
export function CausalChain({
  doc,
  eventHref,
  selected,
}: {
  doc: AnalysisDocument;
  eventHref?: (eventId: string) => string;
  selected?: string;
}) {
  const origin = doc.diagnosis?.triggered_at ?? doc.bundle.created_at;
  const nodes = new Map<string, CausalNode>();
  for (const node of doc.causal.nodes) nodes.set(node.event.id, node);
  const edges = doc.causal.edges ?? [];
  const byPair = new Map<string, CausalEdge>();
  for (const edge of edges) byPair.set(`${edge.from}>${edge.to}`, edge);

  if (doc.causal.failures.length === 0) {
    return (
      <section aria-labelledby="chain-title" className="section">
        <SectionHeading id="chain-title">Causal chain</SectionHeading>
        <p className="panel muted">
          {doc.causal.healthy ? "No failure anchor. The capture looks healthy." : "No failure anchor was found."}
        </p>
      </section>
    );
  }

  return (
    <section aria-labelledby="chain-title" className="section">
      <SectionHeading id="chain-title">Causal chain</SectionHeading>
      {doc.causal.failures.map((failure) => (
        <FailureChain
          key={failure.anchor}
          failure={failure}
          nodes={nodes}
          byPair={byPair}
          origin={origin}
          eventHref={eventHref}
          selected={selected}
        />
      ))}
    </section>
  );
}

function FailureChain({
  failure,
  nodes,
  byPair,
  origin,
  eventHref,
  selected,
}: {
  failure: CausalFailure;
  nodes: Map<string, CausalNode>;
  byPair: Map<string, CausalEdge>;
  origin: string;
  eventHref?: (eventId: string) => string;
  selected?: string;
}) {
  const chain = failure.known_chain ?? [];
  const steps = chain.length > 0 ? chain : [failure.anchor];
  return (
    <article className="panel chain" aria-label={`Failure anchor ${failure.anchor_type}`}>
      <header className="chain__head">
        <p className="chain__anchor">
          <span className="mono">{failure.anchor_type}</span> · {failure.status}
        </p>
        <ClaimBadge claim={failure.claim} />
      </header>
      <ol className="chain-steps">
        {steps.map((id, index) => {
          const node = nodes.get(id);
          const event = node?.event;
          const next = steps[index + 1];
          const nextEvent = next ? nodes.get(next)?.event : undefined;
          const edge = next ? byPair.get(`${id}>${next}`) : undefined;
          const direct = node ? isDirect(node.evidence_class) : false;
          const body = (
            <>
              <span className="step__time mono" data-unknown={!event || formatClock(event.timestamp) === "unknown time" ? "true" : undefined}>
                {event ? <Clock iso={event.timestamp} /> : "—"}
              </span>
              <span className="step__main">
                <code className="step__type">{event?.type ?? "EVENT NOT IN NODES"}</code>
                <span className="step__meta muted">
                  {event ? `${formatOffset(event.timestamp, origin)} · ${event.id}` : id}
                  {event?.provenance.rule_id && <> · rule {event.provenance.rule_id}</>}
                </span>
              </span>
              {node && (
                <span className="step__quality" data-direct={direct ? "true" : undefined} title={evidenceLabel(node.evidence_class)}>
                  <span className="q-mark" aria-hidden="true" data-direct={direct ? "true" : undefined} />
                  <span className="sr-only">{evidenceLabel(node.evidence_class)}</span>
                </span>
              )}
            </>
          );
          return (
            <li key={`${id}-${index}`} className="step" data-selected={selected === id ? "true" : undefined}>
              {eventHref && event ? (
                <a className="step__card" href={eventHref(event.id)} aria-current={selected === id ? "true" : undefined}>
                  {body}
                </a>
              ) : (
                <div className="step__card">{body}</div>
              )}
              {next && (
                <div className="edge" aria-label={edge ? `${edge.relation} with ${edge.confidence} confidence` : "no stored edge"}>
                  {edge ? (
                    <>
                      <strong>{edge.relation}</strong> <span className="mono">{edge.confidence}</span> <code>{edge.rule}</code>
                      {event && nextEvent && <span className="edge__gap mono">{formatOffset(nextEvent.timestamp, event.timestamp)}</span>}
                      {edge.mechanism && <span className="edge__why muted">{edge.mechanism}</span>}
                    </>
                  ) : (
                    <span className="muted">no stored edge between these events</span>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ol>
      {failure.missing_evidence && failure.missing_evidence.length > 0 && (
        <p className="missing">
          <span className="muted">Missing evidence:</span>{" "}
          {failure.missing_evidence.map((code) => (
            <code key={code} className="chip">{code}</code>
          ))}
        </p>
      )}
      {(failure.alternatives ?? []).length > 0 && (
        <p className="muted small">Alternatives checked: {failure.alternatives.join("; ")}</p>
      )}
      {nodes.get(failure.anchor) && (
        <p className="muted small">
          Anchor evidence: {evidenceLabel(nodes.get(failure.anchor)?.evidence_class ?? "UNKNOWN")}
        </p>
      )}
    </article>
  );
}
