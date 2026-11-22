import { evidenceDescription, evidenceLabel, isDirect } from "../lib/evidence.ts";

/**
 * direct versus inferred badge (checklist 7.22). the class is the one the
 * document stored. direct and inferred look different, so the distinction is
 * not carried by colour alone (7.45).
 */
export function EvidenceBadge({ quality }: { quality: string }) {
  const direct = isDirect(quality);
  return (
    <span
      className={direct ? "badge badge-direct" : "badge badge-inferred"}
      title={evidenceDescription(quality)}
      data-evidence={quality}
    >
      <span aria-hidden="true">{direct ? "● " : "○ "}</span>
      {evidenceLabel(quality)}
    </span>
  );
}
