import type { ClaimWord, Quality } from "../types/analysis.ts";

/**
 * labels for the evidence classes the analyzer assigned (checklist 7.22).
 * the class itself comes from the document. this table only names it.
 */
const LABELS: Record<Quality, { badge: string; plain: string }> = {
  DIRECT_KERNEL: { badge: "DIRECT KERNEL TRACE", plain: "Observed directly by the kernel tracer" },
  DIRECT_PROCESS: { badge: "DIRECT PROCESS READING", plain: "Read directly from /proc or a cgroup file" },
  DERIVED_SNAPSHOT: { badge: "INFERRED FROM SNAPSHOTS", plain: "Inferred from the difference between two samples" },
  PROVIDER_LOG: { badge: "PROVIDER LOG", plain: "Stated in a provider's log" },
  PROVIDER_API: { badge: "PROVIDER API", plain: "Stated by a provider's API" },
  AGENT: { badge: "RECORDER OBSERVATION", plain: "The recorder's own observation, such as the trigger" },
  UNKNOWN: { badge: "EVIDENCE UNKNOWN", plain: "The bundle does not say where this came from" },
};

/** badge text for one class. an unrecognized value shows as unknown, never as direct. */
export function evidenceLabel(quality: string): string {
  return (LABELS as Record<string, { badge: string }>)[quality]?.badge ?? LABELS.UNKNOWN.badge;
}

export function evidenceDescription(quality: string): string {
  return (LABELS as Record<string, { plain: string }>)[quality]?.plain ?? LABELS.UNKNOWN.plain;
}

/**
 * mirrors incident.Quality.Direct in go: only the two direct classes count as
 * observed. the list is repeated here only to pick a badge style; the
 * document still carries the class itself.
 */
export function isDirect(quality: string): boolean {
  return quality === "DIRECT_KERNEL" || quality === "DIRECT_PROCESS";
}

const CLAIM_LABELS: Record<ClaimWord, string> = {
  direct: "Direct: every premise was observed",
  mixed: "Mixed: some premises observed, some inferred",
  inferred: "Inferred: no premise was observed directly",
  unknown: "Unknown: the bundle does not support a claim",
};

export function claimLabel(claim: string): string {
  return (CLAIM_LABELS as Record<string, string>)[claim] ?? CLAIM_LABELS.unknown;
}
