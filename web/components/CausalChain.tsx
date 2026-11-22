import type { AnalysisDocument, CausalEdge, CausalFailure, CausalNode } from "../types/analysis.ts";
import { claimLabel, evidenceLabel } from "../lib/evidence.ts";
import { formatOffset } from "../lib/format.ts";

/**
 * vertical causal chain per failure anchor (checklist 7.16). the order is the
 * analyzer's known_chain. each arrow is the stored edge between the two
 * events: its relation, band and rule are copied, not inferred. nothing here
 * decides that an edge exists.
 */
export function CausalChain({ doc }: { doc: AnalysisDocument }) {
  const origin = doc.diagnosis?.triggered_at ?? doc.bundle.created_at;
  const nodes = new Map<string, CausalNode>();
  for (const node of doc.causal.nodes) nodes.set(node.event.id, node);
  const edges = doc.causal.edges ?? [];
  const byPair = new Map<string, CausalEdge>();
  for (const edge of edges) byPair.set(`${edge.from}>${edge.to}`, edge);

  if (doc.causal.failures.length === 0) {
    return (
      <section aria-labelledby="chain-title">
        <h2 id="chain-title">Causal chain</h2>
        <p>{doc.causal.healthy ? "No failure anchor. The capture looks healthy." : "No failure anchor was found."}</p>
      </section>
    );
  }

  return (
    <section aria-labelledby="chain-title">
      <h2 id="chain-title">Causal chain</h2>
      {doc.causal.failures.map((failure) => (
        <FailureChain
          key={failure.anchor}
          failure={failure}
          nodes={nodes}
          byPair={byPair}
          origin={origin}
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
}: {
  failure: CausalFailure;
  nodes: Map<string, CausalNode>;
  byPair: Map<string, CausalEdge>;
  origin: string;
}) {
  const chain = failure.known_chain ?? [];
  const steps = chain.length > 0 ? chain : [failure.anchor];
  return (
    <article className="chain" aria-label={`Failure anchor ${failure.anchor_type}`}>
      <p className="eyebrow">
        {failure.anchor_type} · {failure.status} · {claimLabel(failure.claim)}
      </p>
      <ol className="chain-steps">
        {steps.map((id, index) => {
          const event = nodes.get(id)?.event;
          const next = steps[index + 1];
          const edge = next ? byPair.get(`${id}>${next}`) : undefined;
          return (
            <li key={`${id}-${index}`}>
              <div className="step">
                <code>{event?.type ?? "EVENT NOT IN NODES"}</code>
                <span className="muted">
                  {event ? `${formatOffset(event.timestamp, origin)} · ${event.id}` : id}
                </span>
                {event?.provenance.rule_id && <span className="muted">rule {event.provenance.rule_id}</span>}
              </div>
              {next && (
                <div className="edge" aria-label={edge ? `${edge.relation} with ${edge.confidence} confidence` : "no stored edge"}>
                  {edge ? (
                    <>
                      ↓ <strong>{edge.relation}</strong> · {edge.confidence} · <code>{edge.rule}</code>
                      {edge.mechanism && <span className="muted"> — {edge.mechanism}</span>}
                    </>
                  ) : (
                    <span className="muted">↓ no stored edge between these events</span>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ol>
      {failure.missing_evidence && failure.missing_evidence.length > 0 && (
        <p>
          Missing evidence: <code>{failure.missing_evidence.join(", ")}</code>
        </p>
      )}
      {(failure.alternatives ?? []).length > 0 && <p>Alternatives checked: {failure.alternatives.join("; ")}</p>}
      {nodes.get(failure.anchor) && (
        <p className="muted">
          Anchor evidence: {evidenceLabel(nodes.get(failure.anchor)?.evidence_class ?? "UNKNOWN")}
        </p>
      )}
    </article>
  );
}
