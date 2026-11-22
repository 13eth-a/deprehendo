import { notFound, redirect } from "next/navigation";

import { AppHeader } from "../../../components/AppHeader.tsx";
import { CausalChain } from "../../../components/CausalChain.tsx";
import { DiagnosisPanel } from "../../../components/DiagnosisPanel.tsx";
import { FailureState } from "../../../components/FailureState.tsx";
import { NetworkTable } from "../../../components/NetworkTable.tsx";
import { Overview } from "../../../components/Overview.tsx";
import { PrivacyPanel } from "../../../components/PrivacyPanel.tsx";
import { ProcessTree } from "../../../components/ProcessTree.tsx";
import { CpuChart } from "../../../components/Sparkline.tsx";
import { TimelineTable } from "../../../components/TimelineTable.tsx";
import { isIncidentId } from "../../../lib/api-incidents.ts";
import { checkAnalysisDocument } from "../../../lib/guards.ts";
import { pageOf } from "../../../lib/paging.ts";
import { apiGet, chosenOrganization, requireUser } from "../../../lib/runopsy-api.ts";

export const dynamic = "force-dynamic";

const TIMELINE_PAGE = 200;

export default async function IncidentDetail({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const user = await requireUser();
  const { id } = await params;
  if (!isIncidentId(id)) notFound();
  const res = await apiGet<unknown>(`/api/incidents/${encodeURIComponent(id)}/analysis`);
  if (res.status === 400) redirect("/org");
  // another organization's incident is a 404 from the API, never a 403.
  if (res.status === 404) notFound();
  const header = <AppHeader email={user.email} organization={await chosenOrganization()} />;
  if (res.status === 202) {
    return (
      <>
        {header}
        <main role="status">
          <h1>Analysis in progress</h1>
          <p>This incident is still being analyzed. Reload in a few seconds.</p>
        </main>
      </>
    );
  }
  if (res.status !== 200) {
    return (
      <>
        {header}
        <main role="status">
          <h1>Analysis unavailable</h1>
          <p>The deprehendo API answered {res.status}{res.errorCode ? ` (${res.errorCode})` : ""}.</p>
        </main>
      </>
    );
  }

  const check = checkAnalysisDocument(res.body);
  if (!check.ok) {
    return (
      <>
        {header}
        <main>
          <FailureState kind={check.reason === "unsupported_version" ? "unsupported_version" : "invalid_document"} detail={check.detail} />
        </main>
      </>
    );
  }
  const doc = check.document;
  const requested = Number((await searchParams).page ?? "1");
  const page = pageOf(doc.timeline, Number.isInteger(requested) ? requested : 1, TIMELINE_PAGE);
  const sample = doc.series.length > 0 ? doc.series.length - 1 : 0;

  return (
    <>
      {header}
      <main className="incident" aria-label={`Incident ${doc.bundle.incident_id}`}>
        <p><a href="/incidents">← All incidents</a></p>
        <Overview doc={doc} />
        {doc.diagnosis ? <DiagnosisPanel doc={doc} /> : <FailureState kind="unknown_diagnosis" />}
        <CausalChain doc={doc} />
        <CpuChart series={doc.series} triggeredAt={doc.diagnosis?.triggered_at} />
        <TimelineTable page={page} origin={doc.bundle.created_at} />
        {page.pages > 1 && (
          <nav aria-label="Timeline pages" className="actions">
            {page.page > 1 && <a href={`?page=${page.page - 1}`}>Previous page</a>}
            <span>Page {page.page} of {page.pages}</span>
            {page.page < page.pages && <a href={`?page=${page.page + 1}`}>Next page</a>}
          </nav>
        )}
        <ProcessTree series={doc.series} index={sample} />
        <NetworkTable series={doc.series} index={sample} />
        <PrivacyPanel privacy={doc.privacy} />
      </main>
    </>
  );
}
