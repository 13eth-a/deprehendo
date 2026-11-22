import { redirect } from "next/navigation";

import { AppHeader } from "../../components/AppHeader.tsx";
import { IncidentList } from "../../components/IncidentList.tsx";
import { bandOptions, diagnosisOptions, summaryFromApiRow, type ApiIncidentRow } from "../../lib/api-incidents.ts";
import { filterIncidents, sortNewestFirst, type IncidentFilter } from "../../lib/incidents.ts";
import { apiGet, chosenOrganization, requireUser } from "../../lib/runopsy-api.ts";

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
  // several memberships and none chosen yet, or the chosen one was revoked.
  if (res.status === 400 || (res.status === 403 && (await chosenOrganization()))) redirect("/org");
  if (res.status === 403) {
    return (
      <>
        <AppHeader email={user.email} organization={null} />
        <main>
          <h1>No organization yet</h1>
          <p>
            You are signed in, but you are not a member of any organization. Ask an owner to add you with your user id{" "}
            <code>{user.id}</code>.
          </p>
        </main>
      </>
    );
  }
  if (res.status !== 200 || !res.body) {
    return (
      <>
        <AppHeader email={user.email} organization={await chosenOrganization()} />
        <main role="status">
          <h1>Incidents are unavailable</h1>
          <p>The deprehendo API answered {res.status}{res.errorCode ? ` (${res.errorCode})` : ""}. Try again shortly.</p>
        </main>
      </>
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
    <>
      <AppHeader email={user.email} organization={await chosenOrganization()} />
      <main>
        <IncidentList
          rows={rows}
          filter={filter}
          diagnoses={diagnosisOptions(all)}
          bands={bandOptions(all)}
          uploadCommand="runopsy-agent upload incident.runopsy"
          demoHref="/demo"
          hrefFor={(id) => `/incidents/${encodeURIComponent(id)}`}
        />
      </main>
    </>
  );
}
