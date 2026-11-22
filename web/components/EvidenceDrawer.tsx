import type { AnalysisDocument, CausalEdge, TimelineEvent } from "../types/analysis.ts";
import { formatClock, formatOffset } from "../lib/format.ts";
import { EvidenceBadge } from "./EvidenceBadge.tsx";

/**
 * evidence drawer for one event (checklist 7.17): timestamp, source, rule,
 * evidence, raw value, collector and trace quality. every value comes from the
 * stored event and its stored edges. fields the event does not record are
 * labelled as not recorded, not filled in.
 */
export function EvidenceDrawer({ doc, event }: { doc: AnalysisDocument; event: TimelineEvent }) {
  const origin = doc.diagnosis?.triggered_at ?? doc.bundle.created_at;
  const touching = (doc.causal.edges ?? []).filter((edge) => edge.from === event.id || edge.to === event.id);
  const sources = event.provenance.sources;
  return (
    <aside className="drawer" aria-labelledby="drawer-title">
      <h2 id="drawer-title">{event.type}</h2>
      <dl className="facts">
        <div>
          <dt>Timestamp</dt>
          <dd>
            {formatClock(event.timestamp)} UTC, {formatOffset(event.timestamp, origin)} from trigger
          </dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>
            {sources.length > 0
              ? sources.map((source) => `${source.kind} ${source.ref}`).join(", ")
              : "no source recorded"}
          </dd>
        </div>
        <div>
          <dt>Rule</dt>
          <dd>{event.provenance.rule_id ?? "no rule recorded"}</dd>
        </div>
        <div>
          <dt>Subject</dt>
          <dd>
            {event.subject.Kind} {event.subject.ID}
            {event.pid !== undefined ? ` (PID ${event.pid})` : ""}
          </dd>
        </div>
        <div>
          <dt>Collector</dt>
          <dd>not recorded in the event</dd>
        </div>
        <div>
          <dt>Trace quality</dt>
          <dd>
            <EvidenceBadge quality={event.evidence_class} />
          </dd>
        </div>
      </dl>
      <h3>Raw value</h3>
      {event.data ? <pre>{JSON.stringify(event.data, null, 2)}</pre> : <p className="muted">No data recorded.</p>}
      <h3>Edges</h3>
      {touching.length === 0 ? (
        <p className="muted">No stored edge touches this event.</p>
      ) : (
        <ul>
          {touching.map((edge) => (
            <li key={edge.id}>{describeEdge(edge, event.id)}</li>
          ))}
        </ul>
      )}
    </aside>
  );
}

function describeEdge(edge: CausalEdge, self: string): string {
  const direction = edge.from === self ? `to ${edge.to}` : `from ${edge.from}`;
  const checks = edge.checks.map((check) => `${check.kind} ${check.code}: ${check.status}`).join("; ");
  return `${edge.relation} ${direction}, ${edge.confidence}, rule ${edge.rule}. Checks: ${checks || "none"}`;
}
