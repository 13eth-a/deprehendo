import { SignOutButton } from "./AuthForms.tsx";

/** header for signed-in pages: where you are, which organization, sign out. */
export function AppHeader({ email, organization }: { email: string; organization: string | null }) {
  return (
    <header className="app-header">
      <nav aria-label="Main">
        <a href="/incidents">Incidents</a>
        <a href="/org">{organization ? `Organization: ${organization}` : "Choose organization"}</a>
      </nav>
      <span className="muted">{email}</span>
      <SignOutButton />
    </header>
  );
}
