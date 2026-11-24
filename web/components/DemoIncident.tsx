import type { AnalysisDocument } from "../types/analysis.ts";
import { pageOf } from "../lib/paging.ts";
import { IncidentView } from "./IncidentView.tsx";

/** Read-only sample view. The host supplies a sanitized, checked-in fixture. */
export function DemoIncident({
  doc,
  uploadHref,
  page = 1,
  selectedEvent,
  selectedEvidence,
}: {
  doc: AnalysisDocument;
  uploadHref?: string;
  page?: number;
  selectedEvent?: string;
  selectedEvidence?: string;
}) {
  const timeline = pageOf(doc.timeline, page, 50);
  const hrefFor = ({ page: p, event, evidence }: { page?: number; event?: string; evidence?: string }) => {
    const params = new URLSearchParams();
    if (p && p > 1) params.set("page", String(p));
    if (event) params.set("event", event);
    if (evidence) params.set("evidence", evidence);
    const query = params.toString();
    return query ? `/demo?${query}` : "/demo";
  };
  return (
    <main className="demo-incident page" aria-labelledby="overview-title">
      <IncidentView
        doc={doc}
        page={timeline}
        selectedEvent={selectedEvent}
        selectedEvidence={selectedEvidence}
        hrefFor={hrefFor}
        banner={
          <p className="demo-banner" role="note">
            <strong>Sample incident.</strong> A sanitized bundle from the test corpus, not a live customer incident.
            {uploadHref && (
              <>
                {" "}
                <a href={uploadHref}>Sign in to upload your own</a>
              </>
            )}
          </p>
        }
      />
    </main>
  );
}
