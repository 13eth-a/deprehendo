import { notFound, redirect } from "next/navigation";

import { AppShell } from "../../../components/AppShell.tsx";
import { FailureState } from "../../../components/FailureState.tsx";
import { IncidentView } from "../../../components/IncidentView.tsx";
import { ProgressBar } from "../../../components/uiverse/Loaders.tsx";
import { isIncidentId } from "../../../lib/api-incidents.ts";
import { checkAnalysisDocument } from "../../../lib/guards.ts";
import { pageOf } from "../../../lib/paging.ts";
import { apiGet, chosenOrganization, requireUser } from "../../../lib/deprehendo-api.ts";

export const dynamic = "force-dynamic";

const TIMELINE_PAGE = 200;

function one(value: string | string[] | undefined): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return v ? v.slice(0, 200) : undefined;
}

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
  // Another organization's incident is a 404 from the API, never a 403.
  if (res.status === 404) notFound();
  const organization = await chosenOrganization();
  const base = `/incidents/${encodeURIComponent(id)}`;
  const crumbs = (
    <nav className="crumbs" aria-label="Breadcrumb">
      <a href="/incidents">Incidents</a>
      <span aria-hidden="true">/</span>
      <code aria-current="page">{id}</code>
    </nav>
  );

  if (res.status === 202) {
    return (
      <AppShell email={user.email} organization={organization} active="incidents" label={`Incident ${id}`}>
        <div className="page">
          {crumbs}
          <section className="panel pending" role="status" aria-labelledby="pending-title">
            <h1 id="pending-title">Analysis in progress</h1>
            <p className="muted">This incident is still being analyzed. Reload in a few seconds.</p>
            <ProgressBar label="Analysis in progress" />
          </section>
        </div>
      </AppShell>
    );
  }
  if (res.status !== 200) {
    return (
      <AppShell email={user.email} organization={organization} active="incidents" label={`Incident ${id}`}>
        <div className="page" role="status">
          {crumbs}
          <section className="failure panel" aria-labelledby="unavailable-title">
            <span className="failure__mark" aria-hidden="true">!</span>
            <div>
              <h1 id="unavailable-title">Analysis unavailable</h1>
              <p>The deprehendo API answered {res.status}{res.errorCode ? ` (${res.errorCode})` : ""}.</p>
            </div>
          </section>
        </div>
      </AppShell>
    );
  }

  const check = checkAnalysisDocument(res.body);
  if (!check.ok) {
    return (
      <AppShell email={user.email} organization={organization} active="incidents" label={`Incident ${id}`}>
        <div className="page">
          {crumbs}
          <FailureState kind={check.reason === "unsupported_version" ? "unsupported_version" : "invalid_document"} detail={check.detail} />
        </div>
      </AppShell>
    );
  }
  const doc = check.document;
  const query = await searchParams;
  const requested = Number(one(query.page) ?? "1");
  const page = pageOf(doc.timeline, Number.isInteger(requested) ? requested : 1, TIMELINE_PAGE);
  const hrefFor = ({ page: p, event, evidence }: { page?: number; event?: string; evidence?: string }) => {
    const qs = new URLSearchParams();
    if (p && p > 1) qs.set("page", String(p));
    if (event) qs.set("event", event);
    if (evidence) qs.set("evidence", evidence);
    const s = qs.toString();
    return s ? `${base}?${s}` : base;
  };

  return (
    <AppShell email={user.email} organization={organization} active="incidents" label={`Incident ${doc.bundle.incident_id}`}>
      <div className="page">
        {crumbs}
        <IncidentView
          doc={doc}
          page={page}
          selectedEvent={one(query.event)}
          selectedEvidence={one(query.evidence)}
          hrefFor={hrefFor}
        />
      </div>
    </AppShell>
  );
}
