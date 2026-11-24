import { Badge, type BadgeVariant } from "./shadcn/Badge.tsx";
import { claimLabel } from "../lib/evidence.ts";

/**
 * deprehendo's status tags. Each pairs a word with its color, so color is
 * never the only carrier of meaning (7.45). Every value shown is the stored
 * one; these components only choose how it looks.
 */

const SEVERITY_VARIANT: Record<string, BadgeVariant> = {
  CRITICAL: "critical",
  WARNING: "warning",
  INFORMATIONAL: "info",
};

/** The stored severity, e.g. "Critical". An unrecognized value keeps its own text. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return null;
  const variant = SEVERITY_VARIANT[severity.toUpperCase()] ?? "outline";
  return (
    <Badge variant={variant} data-severity={severity}>
      {titleCase(severity)}
    </Badge>
  );
}

/** "High confidence 0.80". The band is the stored one, never derived from the score. */
export function ConfidenceBadge({ band, score }: { band: string | null | undefined; score?: number | null }) {
  if (!band) return null;
  return (
    <Badge variant="outline" data-band={band}>
      {titleCase(band)} confidence
      {typeof score === "number" && <span className="num"> {score.toFixed(2)}</span>}
    </Badge>
  );
}

const CLAIM_WORD: Record<string, { word: string; variant: BadgeVariant }> = {
  direct: { word: "Direct", variant: "direct" },
  mixed: { word: "Mixed", variant: "outline" },
  inferred: { word: "Inferred", variant: "outline" },
  unknown: { word: "Unknown", variant: "outline" },
};

/** Direct / mixed / inferred evidence, with the full meaning as a tooltip. */
export function ClaimBadge({ claim }: { claim: string }) {
  const mark = CLAIM_WORD[claim] ?? CLAIM_WORD.unknown!;
  return (
    <Badge variant={mark.variant} title={claimLabel(claim)} data-claim={claim}>
      {mark.word} evidence
    </Badge>
  );
}

function titleCase(value: string): string {
  const lower = value.toLowerCase().replace(/_/g, " ");
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}
