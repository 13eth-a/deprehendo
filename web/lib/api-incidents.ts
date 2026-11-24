import type { IncidentSummary } from "./incidents.ts";

/**
 * One row of GET /api/incidents (internal/cloudserver/incidents.go,
 * incidentSummary). Optional fields are omitted by the API when unknown.
 */
export interface ApiIncidentRow {
  incident_id: string;
  created_at: string;
  triggered_at?: string;
  primary_signature?: string;
  confidence?: number;
  /** The engine's band for the top match, copied from the document. */
  confidence_band?: string;
  severity?: string;
  runner_name?: string;
  repository?: string;
  workflow?: string;
  job?: string;
  platform?: string;
  analysis_status: string;
}

/**
 * Maps an API row onto the list's IncidentSummary, copying only what the API
 * stores. The band is the document's, stored by the server; it is never
 * recomputed from the score here. The list endpoint has no analyzer version,
 * so the analyzer column shows the analysis status.
 */
export function summaryFromApiRow(row: ApiIncidentRow): IncidentSummary {
  const ready = row.analysis_status === "READY";
  return {
    incidentId: row.incident_id,
    triggeredAt: row.triggered_at ?? row.created_at,
    trigger: "",
    diagnosis: row.primary_signature ?? null,
    confidenceBand: row.confidence_band ?? null,
    unknown: ready && !row.primary_signature,
    analyzerVersion: row.analysis_status,
    causalRules: row.incident_id,
    severity: row.severity ?? null,
    runner: row.runner_name ?? null,
    workflow: row.workflow ?? null,
    job: row.job ?? null,
  };
}

/** Engine bands (diagnosis.ConfidenceBand), strongest first. */
const BAND_ORDER = ["VERY_HIGH", "HIGH", "MODERATE", "NONE"];

/** Distinct bands present in the rows, strongest first, for the filter select. */
export function bandOptions(rows: readonly IncidentSummary[]): string[] {
  const present = new Set(rows.map((r) => r.confidenceBand).filter((b): b is string => !!b));
  const rank = (b: string) => (BAND_ORDER.includes(b) ? BAND_ORDER.indexOf(b) : BAND_ORDER.length);
  return [...present].sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : 1));
}

/** Distinct, sorted diagnosis names for the filter select. */
export function diagnosisOptions(rows: readonly IncidentSummary[]): string[] {
  return [...new Set(rows.map((r) => r.diagnosis).filter((d): d is string => !!d))].sort();
}

/** Incident ids the API accepts in a path (create.go incidentIDRE). */
export function isIncidentId(value: string): boolean {
  return /^[A-Za-z0-9_-]{3,64}$/.test(value);
}
