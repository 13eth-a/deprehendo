import { redirect } from "next/navigation";

import { AppShell } from "../../components/AppShell.tsx";
import { IncidentList } from "../../components/IncidentList.tsx";
import { Empty } from "../../components/shadcn/Empty.tsx";
import { bandOptions, diagnosisOptions, summaryFromApiRow, type ApiIncidentRow } from "../../lib/api-incidents.ts";
import { filterIncidents, sortNewestFirst, type IncidentFilter } from "../../lib/incidents.ts";
import { apiGet, chosenOrganization, requireUser } from "../../lib/deprehendo-api.ts";

export const dynamic = "force-dynamic";

const DATE = /^\d{4}-\d{2}-\d{2}$/;

function one(value: string | string[] | undefined): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return v ? v.slice(0, 200) : undefined;
}

export default async function Incidents({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const user = await requireUser();
  const res = await apiGet<ApiIncidentRow[]>("/api/incidents");
  // Several memberships and none chosen yet, or the chosen one was revoked.
  if (res.status === 400 || (res.status === 403 && (await chosenOrganization()))) redirect("/org");
  if (res.status === 403) {
    return (
      <AppShell email={user.email} organization={null} active="incidents">
        <div className="page">
          <Empty
            titleId="no-org-title"
            title="No organization yet"
            description="You are signed in, but you are not a member of any organization."
          >
            <p>
              Ask an owner to add you with your user id <code>{user.id}</code>.
            </p>
          </Empty>
        </div>
      </AppShell>
    );
  }
  if (res.status !== 200 || !res.body) {
    return (
      <AppShell email={user.email} organization={await chosenOrganization()} active="incidents">
        <div className="page" role="status">
          <section className="failure panel" aria-labelledby="unavailable-title">
            <span className="failure__mark" aria-hidden="true">!</span>
            <div>
              <h1 id="unavailable-title">Incidents are unavailable</h1>
              <p>The deprehendo API answered {res.status}{res.errorCode ? ` (${res.errorCode})` : ""}. Try again shortly.</p>
            </div>
          </section>
        </div>
      </AppShell>
    );
  }

  const params = await searchParams;
  const since = one(params.since);
  const until = one(params.until);
  const filter: IncidentFilter = {
    diagnosis: one(params.diagnosis),
    band: one(params.band),
    since: since && DATE.test(since) ? since : undefined,
    until: until && DATE.test(until) ? until : undefined,
  };
  const all = res.body.map(summaryFromApiRow);
  const rows = sortNewestFirst(filterIncidents(all, filter));

  return (
    <AppShell email={user.email} organization={await chosenOrganization()} active="incidents">
      <IncidentList
          rows={rows}
          all={all}
          filter={filter}
          diagnoses={diagnosisOptions(all)}
          bands={bandOptions(all)}
          uploadCommand="deprehendo-agent upload incident.deprehendo"
          installHref="/install"
          hrefFor={(id) => `/incidents/${encodeURIComponent(id)}`}
        />
    </AppShell>
  );
}
