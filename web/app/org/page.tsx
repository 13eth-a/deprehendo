import { AppHeader } from "../../components/AppHeader.tsx";
import { apiGet, chosenOrganization, requireUser, type Me } from "../../lib/runopsy-api.ts";
import { chooseOrganization } from "./actions.ts";

export const dynamic = "force-dynamic";

export default async function Organizations() {
  const user = await requireUser();
  const me = await apiGet<Me>("/api/me", { withOrganization: false });
  const current = await chosenOrganization();
  const orgs = me.body?.organizations ?? [];
  return (
    <>
      <AppHeader email={user.email} organization={current} />
      <main aria-labelledby="org-title">
        <h1 id="org-title">Organizations</h1>
        {me.status !== 200 && <p role="status">The deprehendo API answered {me.status}. Try again shortly.</p>}
        {me.status === 200 && orgs.length === 0 && (
          <p>
            You are not a member of any organization yet. Ask an owner to add you with your user id{" "}
            <code>{user.id}</code>.
          </p>
        )}
        {orgs.length > 0 && (
          <ul className="org-list">
            {orgs.map((o) => (
              <li key={o.id}>
                <form action={chooseOrganization}>
                  <input type="hidden" name="organization" value={o.id} />
                  <button type="submit" aria-current={o.id === current ? "true" : undefined}>
                    {o.name || o.id}
                  </button>{" "}
                  <span className="muted">{o.role}{o.id === current ? " · current" : ""}</span>
                </form>
              </li>
            ))}
          </ul>
        )}
      </main>
    </>
  );
}
