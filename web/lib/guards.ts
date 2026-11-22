import { SUPPORTED_DOCUMENT_VERSION, type AnalysisDocument } from "../types/analysis.ts";

/**
 * decides whether a parsed JSON value can be rendered as a v1 analysis
 * document. it checks shape and version only. it does not verify checksums or
 * re-run any analysis: that is the go side's job (contract §5.1).
 *
 * A failure returns a reason the UI shows instead of a blank page (7.32).
 */
export type DocumentCheck =
  | { ok: true; document: AnalysisDocument }
  | { ok: false; reason: "not_an_object" | "unsupported_version" | "missing_section"; detail: string };

const REQUIRED_SECTIONS = [
  "engine",
  "bundle",
  "privacy",
  "causal",
  "timeline",
  "series",
] as const;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function checkAnalysisDocument(value: unknown): DocumentCheck {
  if (!isObject(value)) {
    return { ok: false, reason: "not_an_object", detail: "the document is not a JSON object" };
  }
  if (value.document_version !== SUPPORTED_DOCUMENT_VERSION) {
    return {
      ok: false,
      reason: "unsupported_version",
      detail: `document_version ${String(value.document_version)} is not ${SUPPORTED_DOCUMENT_VERSION}`,
    };
  }
  for (const key of REQUIRED_SECTIONS) {
    if (!(key in value)) {
      return { ok: false, reason: "missing_section", detail: `section "${key}" is missing` };
    }
  }
  if (!Array.isArray(value.timeline) || !Array.isArray(value.series)) {
    return { ok: false, reason: "missing_section", detail: "timeline and series must be arrays" };
  }
  const causal = value.causal;
  if (!isObject(causal) || !Array.isArray(causal.nodes) || !Array.isArray(causal.failures)) {
    return { ok: false, reason: "missing_section", detail: "causal must hold nodes and failures arrays" };
  }
  if (causal.edges !== null && causal.edges !== undefined && !Array.isArray(causal.edges)) {
    return { ok: false, reason: "missing_section", detail: "causal.edges must be an array or null" };
  }
  return { ok: true, document: value as unknown as AnalysisDocument };
}
