import type { AnalysisDocument } from "../types/analysis.ts";

/**
 * one row of the incident list (checklist 7.13). every field is copied from
 * the stored document. runner, workflow, job and repository are not in the
 * core document; they come from the GitHub provider section, so they are
 * left out here instead of guessed.
 */
export interface IncidentSummary {
  incidentId: string;
  triggeredAt: string;
  trigger: string;
  /** top diagnosis, or null when the analyzer reported unknown. */
  diagnosis: string | null;
  confidenceBand: string | null;
  unknown: boolean;
  analyzerVersion: string;
  /** Re-analysis identity (7.34): the engine that produced this row. */
  causalRules: string;
}

export function summarize(doc: AnalysisDocument): IncidentSummary {
  const report = doc.diagnosis;
  const top = report?.matches[0] ?? null;
  return {
    incidentId: doc.bundle.incident_id,
    triggeredAt: report?.triggered_at ?? doc.bundle.created_at,
    trigger: report?.trigger ?? "",
    diagnosis: top ? top.signature : null,
    confidenceBand: top ? top.confidence_band : null,
    unknown: report ? report.unknown : true,
    analyzerVersion: doc.engine.analyzer_version,
    causalRules: doc.engine.causal_rules,
  };
}

export interface IncidentFilter {
  /** exact signature name; empty or undefined keeps all. */
  diagnosis?: string;
  /** exact band; empty or undefined keeps all. */
  band?: string;
  /** include only rows whose triggered_at date (YYYY-MM-DD, UTC) is on or after this. */
  since?: string;
  /** include only rows whose triggered_at date (YYYY-MM-DD, UTC) is on or before this. */
  until?: string;
}

export function filterIncidents(rows: readonly IncidentSummary[], filter: IncidentFilter): IncidentSummary[] {
  return rows.filter((row) => {
    if (filter.diagnosis && row.diagnosis !== filter.diagnosis) return false;
    if (filter.band && row.confidenceBand !== filter.band) return false;
    const day = row.triggeredAt.slice(0, 10);
    if (filter.since && day < filter.since) return false;
    if (filter.until && day > filter.until) return false;
    return true;
  });
}

/** newest first. ISO timestamps in the same zone sort as text. */
export function sortNewestFirst(rows: readonly IncidentSummary[]): IncidentSummary[] {
  return [...rows].sort((a, b) => (a.triggeredAt < b.triggeredAt ? 1 : a.triggeredAt > b.triggeredAt ? -1 : 0));
}
