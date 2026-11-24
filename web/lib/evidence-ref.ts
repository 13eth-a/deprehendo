/**
 * References to one stored evidence item of a diagnosis, for the evidence
 * drawer (`?evidence=OOM_KILL.s.0`): signature, s(upporting) or
 * c(ontradicting), and the item's index in the stored list. The reference
 * only points into the document; it never names anything the document lacks.
 */
import type { AnalysisDocument, Evidence, SignatureMatch } from "../types/analysis.ts";

export type EvidenceRole = "supporting" | "contradicting";

export interface EvidenceRef {
  match: SignatureMatch;
  role: EvidenceRole;
  index: number;
  item: Evidence;
}

const KEY = /^([A-Z][A-Z0-9_]{0,63})\.([sc])\.(\d{1,3})$/;

export function evidenceKey(signature: string, role: EvidenceRole, index: number): string {
  return `${signature}.${role === "supporting" ? "s" : "c"}.${index}`;
}

/** The evidence item a key names, among the diagnosis's matches; undefined for anything else. */
export function findEvidence(doc: AnalysisDocument, key: string | undefined): EvidenceRef | undefined {
  if (!key) return undefined;
  const m = KEY.exec(key);
  if (!m) return undefined;
  const match = doc.diagnosis?.matches.find((x) => x.signature === m[1]);
  if (!match) return undefined;
  const role: EvidenceRole = m[2] === "s" ? "supporting" : "contradicting";
  const index = Number(m[3]);
  const item = (role === "supporting" ? match.supporting : match.contradicting)?.[index];
  return item ? { match, role, index, item } : undefined;
}
