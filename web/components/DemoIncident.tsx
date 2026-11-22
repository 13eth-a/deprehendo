import type { AnalysisDocument } from "../types/analysis.ts";
import { pageOf } from "../lib/paging.ts";
import { CausalChain } from "./CausalChain.tsx";
import { DiagnosisPanel } from "./DiagnosisPanel.tsx";
import { Overview } from "./Overview.tsx";
import { PrivacyPanel } from "./PrivacyPanel.tsx";
import { TimelineTable } from "./TimelineTable.tsx";

/** Read-only sample view. the host supplies a sanitized, checked-in fixture. */
export function DemoIncident({
  doc,
  uploadHref,
}: {
  doc: AnalysisDocument;
  uploadHref?: string;
}) {
  const timeline = pageOf(doc.timeline, 1, 50);
  return (
    <main className="demo-incident" aria-labelledby="demo-title">
      <p className="demo-banner" role="note">
        Sample incident · This is a sanitized demonstration bundle, not a live customer incident.
      </p>
      <h1 id="demo-title" className="sr-only">Sample incident</h1>
      <Overview doc={doc} />
      <DiagnosisPanel doc={doc} />
      <CausalChain doc={doc} />
      <TimelineTable page={timeline} origin={doc.bundle.created_at} />
      <PrivacyPanel privacy={doc.privacy} />
      {uploadHref && <p><a href={uploadHref}>Sign in to upload your own incident</a></p>}
    </main>
  );
}
