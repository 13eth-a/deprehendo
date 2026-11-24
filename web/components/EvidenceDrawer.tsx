import type { AnalysisDocument, CausalEdge, TimelineEvent } from "../types/analysis.ts";
import type { EvidenceRef } from "../lib/evidence-ref.ts";
import { formatOffset } from "../lib/format.ts";
import { EvidenceBadge } from "./EvidenceBadge.tsx";
import { Clock } from "./Clock.tsx";

/**
 * Evidence drawer for one event (checklist 7.17): timestamp, source, rule,
 * evidence, raw value, collector and trace quality. Every value comes from the
 * stored event and its stored edges. Fields the event does not record are
 * labelled as not recorded, not filled in.
 *
 * It is a server-rendered panel opened by a link (`?event=<id>`), so it works
 * without client JavaScript.
 */
export function EvidenceDrawer({ doc, event, closeHref }: { doc: AnalysisDocument; event: TimelineEvent; closeHref?: string }) {
  const origin = doc.diagnosis?.triggered_at ?? doc.bundle.created_at;
  const touching = (doc.causal.edges ?? []).filter((edge) => edge.from === event.id || edge.to === event.id);
  const sources = event.provenance.sources;
  return (
    <aside className="drawer" id="evidence" aria-labelledby="drawer-title">
      <header className="drawer__head">
        <p className="drawer__label">Evidence</p>
        {closeHref && (
          <a className="uv-button uv-button--ghost uv-button--sm" href={closeHref}>Close</a>
        )}
      </header>
      <h2 id="drawer-title" className="mono">{event.type}</h2>
      <EvidenceBadge quality={event.evidence_class} />
      <dl className="facts facts--stacked">
        <div>
          <dt>Timestamp</dt>
          <dd>
            <Clock iso={event.timestamp} zone />, {formatOffset(event.timestamp, origin)} from trigger
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
          <dd><code>{event.provenance.rule_id ?? "no rule recorded"}</code></dd>
        </div>
        <div>
          <dt>Subject</dt>
          <dd>
            {event.subject.Kind} <code>{event.subject.ID}</code>
            {event.pid !== undefined ? ` (PID ${event.pid})` : ""}
          </dd>
        </div>
        <div>
          <dt>Collector</dt>
          <dd className="muted">not recorded in the event</dd>
        </div>
        <div>
          <dt>Trace quality</dt>
          <dd>
            <EvidenceBadge quality={event.evidence_class} />
          </dd>
        </div>
      </dl>
      <h3 className="subhead">Raw value</h3>
      {event.data ? <pre className="code-block">{JSON.stringify(event.data, null, 2)}</pre> : <p className="muted">No data recorded.</p>}
      <h3 className="subhead">Edges</h3>
      {touching.length === 0 ? (
        <p className="muted">No stored edge touches this event.</p>
      ) : (
        <ul className="edge-list">
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

/**
 * Evidence drawer for one stored evidence item of a diagnosis
 * (`?evidence=OOM_KILL.s.0`): the item exactly as stored, including the raw
 * observed value and threshold without the rounding the diagnosis panel
 * applies for reading. An evidence item names its collector and time but not
 * a timeline event, so no event is matched to it here; the events listed are
 * the ones the analyzer itself related to the diagnosis.
 */
export function EvidenceItemDrawer({
  doc,
  evidence,
  eventHref,
  closeHref,
}: {
  doc: AnalysisDocument;
  evidence: EvidenceRef;
  eventHref?: (id: string) => string;
  closeHref?: string;
}) {
  const { match, role, item } = evidence;
  const origin = doc.diagnosis?.triggered_at ?? doc.bundle.created_at;
  const related = (match.related_events ?? []).map((id) => ({ id, event: doc.timeline.find((e) => e.id === id) }));
  return (
    <aside className="drawer" id="evidence" aria-labelledby="drawer-title">
      <header className="drawer__head">
        <p className="drawer__label">{role === "supporting" ? "Supporting evidence" : "Contradicting evidence"}</p>
        {closeHref && (
          <a className="uv-button uv-button--ghost uv-button--sm" href={closeHref}>Close</a>
        )}
      </header>
      <h2 id="drawer-title" className="mono">{item.code}</h2>
      <dl className="facts facts--stacked">
        <div>
          <dt>{role === "supporting" ? "Supports" : "Contradicts"}</dt>
          <dd>
            <code>{match.signature}</code> v{match.signature_version} · confidence{" "}
            <span className="num">{match.confidence.toFixed(2)}</span>
          </dd>
        </div>
        <div>
          <dt>Weight</dt>
          <dd><span className="num">{item.weight}</span></dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd><code>{item.source}</code></dd>
        </div>
        <div>
          <dt>Observed at</dt>
          <dd>
            <Clock iso={item.at} zone />, {formatOffset(item.at, origin)} from trigger
          </dd>
        </div>
      </dl>
      <h3 className="subhead">Observed value</h3>
      {item.observed !== undefined ? (
        <pre className="code-block">{JSON.stringify(item.observed, null, 2)}</pre>
      ) : (
        <p className="muted">No observed value stored.</p>
      )}
      <h3 className="subhead">Threshold</h3>
      {item.threshold !== undefined ? (
        <pre className="code-block">{JSON.stringify(item.threshold, null, 2)}</pre>
      ) : (
        <p className="muted">No threshold stored for this check.</p>
      )}
      <h3 className="subhead">Events related to {match.signature}</h3>
      {related.length === 0 ? (
        <p className="muted">The analyzer stored no related events for this diagnosis.</p>
      ) : (
        <ul className="edge-list">
          {related.map(({ id, event }) => (
            <li key={id}>
              {event && eventHref ? (
                <a href={eventHref(id)}><code>{event.type}</code></a>
              ) : (
                <code>{event?.type ?? id}</code>
              )}{" "}
              <span className="muted small">{id}{event ? ` · ${formatOffset(event.timestamp, origin)}` : " · not in the timeline"}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="muted small">
        Stored evidence names its collector and time, not a timeline event, so none is matched to it here.
      </p>
    </aside>
  );
}
