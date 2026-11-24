import { evidenceDescription, evidenceLabel, isDirect } from "../lib/evidence.ts";
import { Badge } from "./shadcn/Badge.tsx";

/**
 * Direct versus inferred tag (checklist 7.22). The class is the one the
 * document stored. Direct evidence is a filled square, inferred a hollow one,
 * so the two differ in shape and words as well as color (7.45).
 */
export function EvidenceBadge({ quality, compact = false }: { quality: string; compact?: boolean }) {
  const direct = isDirect(quality);
  return (
    <Badge
      variant={direct ? "direct" : "outline"}
      className={direct ? "badge-direct" : "badge-inferred"}
      title={evidenceDescription(quality)}
      data-evidence={quality}
      data-compact={compact ? "true" : undefined}
    >
      <span className="q-mark" aria-hidden="true" data-direct={direct ? "true" : undefined} />
      {evidenceLabel(quality)}
    </Badge>
  );
}
