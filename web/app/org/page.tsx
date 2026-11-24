import { AppShell } from "../../components/AppShell.tsx";
import { Badge } from "../../components/shadcn/Badge.tsx";
import { Empty } from "../../components/shadcn/Empty.tsx";
import { apiGet, chosenOrganization, requireUser, type Me } from "../../lib/deprehendo-api.ts";
import { chooseOrganization } from "./actions.ts";

export const dynamic = "force-dynamic";

export default async function Organizations() {
  const user = await requireUser();
  const me = await apiGet<Me>("/api/me", { withOrganization: false });
  const current = await chosenOrganization();
  const orgs = me.body?.organizations ?? [];
  // With one membership the API uses it without a cookie, so it is current.
  const active = current ?? (orgs.length === 1 ? orgs[0]!.id : null);
  return (
    <AppShell email={user.email} organization={current} active="org">
      <section className="page" aria-labelledby="org-title">
        <header className="page-header">
          <div>
            <h1 id="org-title">Organizations</h1>
          </div>
        </header>
        {me.status !== 200 && <p role="status" className="panel muted">The deprehendo API answered {me.status}. Try again shortly.</p>}
        {me.status === 200 && orgs.length === 0 && (
          <Empty titleId="org-empty-title" title="No organization yet" description="You are not a member of any organization yet.">
            <p>
              Ask an owner to add you with your user id <code>{user.id}</code>.
            </p>
          </Empty>
        )}
        {orgs.length === 1 && (
          <p className="muted small org-note">
            You belong to one organization, so there is nothing to switch to. An owner of another organization can add
            you with your user ID <code>{user.id}</code>.
          </p>
        )}
        {orgs.length > 0 && (
          <ul className="org-list panel panel--flush">
            {orgs.map((o) => (
              <li key={o.id}>
                <form action={chooseOrganization} className="org-row">
                  <input type="hidden" name="organization" value={o.id} />
                  <span className="org-row__name">
                    <strong>{o.name || o.id}</strong>
                    <code className="muted">{o.id}</code>
                  </span>
                  <Badge variant="secondary">{o.role}</Badge>
                  {o.id === active ? (
                    <Badge variant="brand" aria-current="true">Current</Badge>
                  ) : (
                    <button className="uv-button uv-button--sm" type="submit">Switch</button>
                  )}
                </form>
              </li>
            ))}
          </ul>
        )}
      </section>
    </AppShell>
  );
}
