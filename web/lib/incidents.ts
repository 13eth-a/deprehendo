import type { AnalysisDocument } from "../types/analysis.ts";

/**
 * One row of the incident list (checklist 7.13). Every field is copied from
 * the stored document or the API row. Runner, workflow and job are not in the
 * core document; only API rows carry them (the server copies them from the
 * GitHub provider section), so `summarize` leaves them out instead of guessing.
 */
export interface IncidentSummary {
  incidentId: string;
  triggeredAt: string;
  trigger: string;
  /** Top diagnosis, or null when the analyzer reported unknown. */
  diagnosis: string | null;
  confidenceBand: string | null;
  unknown: boolean;
  analyzerVersion: string;
  /** Re-analysis identity (7.34): the engine that produced this row. */
  causalRules: string;
  /** Stored severity of the top diagnosis, when there is one. */
  severity?: string | null;
  /** GitHub context the server stored from the provider section, when known. */
  runner?: string | null;
  workflow?: string | null;
  job?: string | null;
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
    severity: top ? top.severity : null,
  };
}

export interface IncidentFilter {
  /** Exact signature name; empty or undefined keeps all. */
  diagnosis?: string;
  /** Exact band; empty or undefined keeps all. */
  band?: string;
  /** Include only rows whose triggered_at date (YYYY-MM-DD, UTC) is on or after this. */
  since?: string;
  /** Include only rows whose triggered_at date (YYYY-MM-DD, UTC) is on or before this. */
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

/** Newest first. ISO timestamps in the same zone sort as text. */
export function sortNewestFirst(rows: readonly IncidentSummary[]): IncidentSummary[] {
  return [...rows].sort((a, b) => (a.triggeredAt < b.triggeredAt ? 1 : a.triggeredAt > b.triggeredAt ? -1 : 0));
}
