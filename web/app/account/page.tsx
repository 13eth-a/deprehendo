import { cookies } from "next/headers";

import { AppShell } from "../../components/AppShell.tsx";
import { DisplaySettings } from "../../components/DisplaySettings.tsx";
import { SignInMethodControls } from "../../components/AuthForms.tsx";
import { PasswordField } from "../../components/PasswordField.tsx";
import {
  accountMessage,
  githubLinkOutcome,
  LINK_COOKIE,
  NAME_MAX,
  oauthErrorCode,
  PASSWORD_MAX,
  PASSWORD_MIN,
} from "../../lib/account.ts";
import { auth } from "../../lib/auth/server.ts";
import { chosenOrganization, requireUser } from "../../lib/deprehendo-api.ts";
import { decodeDisplay, DISPLAY_COOKIE } from "../../lib/display.ts";
import { changePassword, saveDisplay, signOutOtherDevices, startGitHubLink, updateName } from "./actions.ts";


export const dynamic = "force-dynamic";

// list-accounts: one entry per sign-in method. "credential" is an email and
// password; anything else (here "github") is a social provider.
type ListAccounts = () => Promise<{ data?: { providerId: string }[] | null; error?: unknown }>;

async function signInMethods(): Promise<string[] | null> {
  try {
    const result = await (auth as unknown as { listAccounts: ListAccounts }).listAccounts();
    return result?.data ? result.data.map((a) => a.providerId) : null;
  } catch {
    return null;
  }
}

function one(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function Account({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const user = await requireUser();
  const organization = await chosenOrganization();
  const query = await searchParams;
  const jar = await cookies();
  const methods = await signInMethods();
  // When the method list cannot be read, offer the password form anyway; the
  // auth service still refuses a change for an account without a password.
  const hasPassword = methods === null || methods.includes("credential");
  const social = (methods ?? []).filter((m) => m !== "credential");
  // after a GitHub round trip, report what actually happened, not what was hoped for
  const status = one(query.status);
  const outcome =
    status === "github-check" ? githubLinkOutcome(jar.get(LINK_COOKIE)?.value, user.id, social.includes("github")) : null;
  const message = accountMessage(outcome ?? status);
  const oauthError = status === "github-link-failed" ? oauthErrorCode(one(query.error)) : null;
  const display = decodeDisplay(jar.get(DISPLAY_COOKIE)?.value);

  return (
    <AppShell email={user.email} organization={organization} active="account">
      <section className="page account" aria-labelledby="account-title">
        <header className="page-header">
          <div>
            <h1 id="account-title">Account</h1>
          </div>
        </header>

        {message && (
          <p role={message.tone === "error" ? "alert" : "status"} className={`notice notice--${message.tone}`}>
            {message.text}
            {oauthError && <> (<code>{oauthError}</code>)</>}
          </p>
        )}

        <div className="account-grid">
          <section className="panel account-card" aria-labelledby="profile-title">
            <h2 id="profile-title">Profile</h2>
            <dl className="facts facts--stacked">
              <div>
                <dt>Email</dt>
                <dd>{user.email}</dd>
              </div>
              <div>
                <dt>User ID</dt>
                <dd><code>{user.id}</code></dd>
              </div>
            </dl>
            <form action={updateName} className="account-form">
              <label className="uv-field">
                <input className="uv-input" name="name" type="text" autoComplete="name" defaultValue={user.name} maxLength={NAME_MAX} required />
                <span>Display name</span>
              </label>
              <button className="uv-button" type="submit">Save name</button>
            </form>
            <p className="muted small">An owner adds you to an organization with your user ID. Your email cannot be changed here yet.</p>
          </section>

          <section className="panel account-card" aria-labelledby="password-title">
            <h2 id="password-title">Password</h2>
            {hasPassword ? (
              <form action={changePassword} className="account-form">
                <PasswordField name="current" label="Current password" autoComplete="current-password" />
                <PasswordField
                  name="next"
                  label={`New password (${PASSWORD_MIN}+ characters)`}
                  autoComplete="new-password"
                  minLength={PASSWORD_MIN}
                  maxLength={PASSWORD_MAX}
                />
                <PasswordField
                  name="confirm"
                  label="Confirm new password"
                  autoComplete="new-password"
                  minLength={PASSWORD_MIN}
                  maxLength={PASSWORD_MAX}
                />
                <button className="uv-button uv-button--primary" type="submit">Change password</button>
                <p className="muted small">Changing it signs out your other devices.</p>
              </form>
            ) : (
              <p className="muted">
                This account signs in with GitHub and has no deprehendo password yet. Add one under Sign-in methods.
              </p>
            )}
          </section>

          <section className="panel account-card" aria-labelledby="methods-title">
            <h2 id="methods-title">Sign-in methods</h2>
            {methods === null ? (
              <p className="muted">The sign-in methods could not be read right now. Reload in a moment.</p>
            ) : (
              <SignInMethodControls
                email={user.email}
                hasPassword={hasPassword}
                hasGitHub={social.includes("github")}
                startGitHubLink={startGitHubLink}
              />
            )}
          </section>

          <section className="panel account-card" aria-labelledby="sessions-title">
            <h2 id="sessions-title">Sessions</h2>
            <p className="muted small">
              Signed in somewhere you no longer use, or think a password was exposed? Sign out everywhere except this
              browser.
            </p>
            <form action={signOutOtherDevices}>
              <button className="uv-button" type="submit">Sign out other devices</button>
            </form>
          </section>

          <DisplaySettings display={display} action={saveDisplay} />
        </div>
      </section>
    </AppShell>
  );
}
