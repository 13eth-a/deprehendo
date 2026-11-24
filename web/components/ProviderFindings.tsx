import type { AnalysisDocument } from "../types/analysis.ts";
import { Badge } from "./shadcn/Badge.tsx";
import { Clock } from "./Clock.tsx";

/**
 * What a provider section (today, GitHub Actions) found, next to the generic
 * diagnosis. The document types `providers` as unknown[], so each entry is
 * read defensively: only string fields that are present are shown, and an
 * entry in any other shape is skipped rather than guessed at.
 */
type Finding = { provider: string; label: string; confidence?: string; onset?: string; evidence: string[] };

const PROVIDER_NAME: Record<string, string> = { "github-actions": "GitHub Actions" };

export function providerFindings(doc: AnalysisDocument): Finding[] {
  const out: Finding[] = [];
  for (const entry of doc.providers ?? []) {
    if (!entry || typeof entry !== "object") continue;
    const { Provider, Signatures } = entry as { Provider?: unknown; Signatures?: unknown };
    if (typeof Provider !== "string" || !Array.isArray(Signatures)) continue;
    for (const sig of Signatures) {
      if (!sig || typeof sig !== "object") continue;
      const { Label, Confidence, Onset, Evidence } = sig as Record<string, unknown>;
      if (typeof Label !== "string" || Label === "") continue;
      out.push({
        provider: Provider,
        label: Label,
        confidence: typeof Confidence === "string" && Confidence ? Confidence : undefined,
        onset: typeof Onset === "string" && Onset ? Onset : undefined,
        evidence: Array.isArray(Evidence) ? Evidence.filter((e): e is string => typeof e === "string") : [],
      });
    }
  }
  return out;
}

export function ProviderFindings({ doc }: { doc: AnalysisDocument }) {
  const findings = providerFindings(doc);
  if (findings.length === 0) return null;
  return (
    <section aria-labelledby="provider-title" className="subsection provider-findings">
      <h3 id="provider-title" className="subhead">Provider findings</h3>
      <p className="muted small">
        Read from the runner&rsquo;s own logs. They sit beside the generic diagnosis and do not change it.
      </p>
      <ul>
        {findings.map((f, i) => (
          <li key={`${f.provider}-${f.label}-${i}`}>
            <span className="provider-findings__source">{PROVIDER_NAME[f.provider] ?? f.provider}</span>
            <code className="provider-findings__label">{f.label}</code>
            {f.confidence && (
              <Badge variant="outline">
                {f.confidence.charAt(0) + f.confidence.slice(1).toLowerCase()} confidence
              </Badge>
            )}
            {f.onset && (
              <span className="muted small">
                onset <Clock iso={f.onset} zone />
              </span>
            )}
            {f.evidence.length > 0 && <span className="muted small">from {f.evidence.join(", ")}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}
