import type { ReactNode } from "react";

import type { AnalysisDocument, TimelineEvent } from "../types/analysis.ts";
import type { Page } from "../lib/paging.ts";
import { CausalChain } from "./CausalChain.tsx";
import { DiagnosisPanel } from "./DiagnosisPanel.tsx";
import { EvidenceDrawer, EvidenceItemDrawer } from "./EvidenceDrawer.tsx";
import { findEvidence } from "../lib/evidence-ref.ts";
import { FailureState } from "./FailureState.tsx";
import { NetworkTable } from "./NetworkTable.tsx";
import { Overview } from "./Overview.tsx";
import { PrivacyPanel } from "./PrivacyPanel.tsx";
import { ProcessTree } from "./ProcessTree.tsx";
import { SectionHeading } from "./SectionHeading.tsx";
import { CpuChart } from "./Sparkline.tsx";
import { TimelineTable } from "./TimelineTable.tsx";
import { Clock, ZoneName } from "./Clock.tsx";

/**
 * One incident, in the order a reader asks about it:
 * what failed (overview) → why (root cause) → how (causal chain) →
 * when (timeline) → raw system data. The evidence drawer sits beside the
 * page and opens for whichever event the reader picks.
 *
 * Links are built by the host (`hrefFor`) so the same view serves the signed-in
 * incident page and the public sample.
 */
export function IncidentView({
  doc,
  page,
  selectedEvent,
  selectedEvidence,
  hrefFor,
  banner,
}: {
  doc: AnalysisDocument;
  page: Page<TimelineEvent>;
  selectedEvent?: string;
  /** an evidence item of the diagnosis, as lib/evidence-ref.ts keys it */
  selectedEvidence?: string;
  hrefFor: (params: { page?: number; event?: string; evidence?: string }) => string;
  banner?: ReactNode;
}) {
  const sample = doc.series.length > 0 ? doc.series.length - 1 : 0;
  const selected = selectedEvent ? doc.timeline.find((event) => event.id === selectedEvent) : undefined;
  const evidence = selected ? undefined : findEvidence(doc, selectedEvidence);
  const eventHref = (id: string) => `${hrefFor({ page: page.page, event: id })}#evidence`;
  const evidenceHref = (key: string) => `${hrefFor({ page: page.page, evidence: key })}#evidence`;
  const origin = doc.diagnosis?.triggered_at ?? doc.bundle.created_at;

  return (
    <div className="incident-layout" data-drawer={selected || evidence ? "open" : undefined}>
      <div className="incident-main">
        {banner}
        <Overview doc={doc} />
        {!doc.diagnosis && <FailureState kind="unknown_diagnosis" />}
        <DiagnosisPanel doc={doc} evidenceHref={evidenceHref} selectedEvidence={evidence ? selectedEvidence : undefined} />
        <CausalChain doc={doc} eventHref={eventHref} selected={selected?.id} />

        <section aria-labelledby="timeline-title" className="section">
          <SectionHeading
            id="timeline-title"
            aside={<span className="muted small">{doc.timeline.length} events · <ZoneName /></span>}
          >
            Timeline
          </SectionHeading>
          <CpuChart series={doc.series} triggeredAt={doc.diagnosis?.triggered_at} />
          <TimelineTable page={page} origin={doc.bundle.created_at} eventHref={eventHref} selected={selected?.id} />
          {page.pages > 1 && (
            <nav aria-label="Timeline pages" className="pager">
              {page.page > 1 ? (
                <a className="uv-button uv-button--sm" href={hrefFor({ page: page.page - 1, event: selected?.id })}>Previous page</a>
              ) : (
                <span />
              )}
              <span className="muted small">Page {page.page} of {page.pages}</span>
              {page.page < page.pages ? (
                <a className="uv-button uv-button--sm" href={hrefFor({ page: page.page + 1, event: selected?.id })}>Next page</a>
              ) : (
                <span />
              )}
            </nav>
          )}
        </section>

        <section aria-labelledby="raw-title" className="section">
          <SectionHeading id="raw-title">Raw system data</SectionHeading>
          <div className="panel raw-panel">
            <ProcessTree series={doc.series} index={sample} />
            <NetworkTable series={doc.series} index={sample} />
            <PrivacyPanel privacy={doc.privacy} />
          </div>
        </section>
      </div>

      <div className="incident-aside">
        {selected ? (
          <EvidenceDrawer doc={doc} event={selected} closeHref={hrefFor({ page: page.page })} />
        ) : evidence ? (
          <EvidenceItemDrawer doc={doc} evidence={evidence} eventHref={eventHref} closeHref={hrefFor({ page: page.page })} />
        ) : (
          <aside className="drawer drawer--idle" id="evidence" aria-labelledby="drawer-idle-title">
            <h2 id="drawer-idle-title">Every conclusion is inspectable</h2>
            <p className="muted small">
              Select an evidence item under Root cause, a step in the causal chain, or an event name in the timeline.
              This panel then shows what was stored for it: source, rule, raw value, and whether it was observed
              directly or inferred.
            </p>
            <dl className="facts facts--stacked">
              <div>
                <dt>Captured</dt>
                <dd><Clock iso={doc.bundle.created_at} date zone /></dd>
              </div>
              <div>
                <dt>Trigger</dt>
                <dd><Clock iso={origin} zone /></dd>
              </div>
              <div>
                <dt>Platform</dt>
                <dd><code>{doc.bundle.platform}/{doc.bundle.architecture}</code></dd>
              </div>
              <div>
                <dt>Agent</dt>
                <dd><code>{doc.bundle.agent_version}</code></dd>
              </div>
            </dl>
          </aside>
        )}
      </div>
    </div>
  );
}
