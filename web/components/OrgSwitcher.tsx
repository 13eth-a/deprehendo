import { chooseOrganization } from "../app/org/actions.ts";
import { apiGet, type Me } from "../lib/deprehendo-api.ts";

/**
 * Organization switcher for the sidebar. The list is the API's own
 * (GET /api/me), so it shows only organizations the user belongs to right
 * now. Switching posts to the same server action as the Organizations page,
 * which checks membership again before it sets the cookie. It is a plain
 * form, so it works without client JavaScript.
 */
export async function OrgSwitcher({ current }: { current: string | null }) {
  const me = await apiGet<Me>("/api/me", { withOrganization: false });
  if (me.status !== 200 || !me.body) return null;
  const orgs = me.body.organizations;
  if (orgs.length === 0) {
    return (
      <a className="org-switch org-switch--empty" href="/org">
        No organization yet
      </a>
    );
  }
  // With a single membership the API uses it without a cookie, so it is the
  // current one even before the user picks it.
  const active = orgs.find((o) => o.id === current) ?? (orgs.length === 1 ? orgs[0] : undefined);
  if (orgs.length === 1) {
    return (
      <div className="org-switch" title={orgs[0]!.id}>
        <span className="org-switch__label">Organization</span>
        <span className="org-switch__name">{orgs[0]!.name || orgs[0]!.id}</span>
        <span className="org-switch__role">{orgs[0]!.role}</span>
      </div>
    );
  }
  return (
    <form action={chooseOrganization} className="org-switch org-switch--form">
      <label className="uv-field">
        <select className="uv-input" name="organization" defaultValue={active?.id ?? ""} required>
          {!active && (
            <option value="" disabled>
              Choose an organization
            </option>
          )}
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>
              {o.name || o.id} · {o.role}
            </option>
          ))}
        </select>
        <span>Organization</span>
      </label>
      <button className="uv-button uv-button--sm" type="submit">
        Switch
      </button>
    </form>
  );
}
