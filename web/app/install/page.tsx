import { AppShell } from "../../components/AppShell.tsx";
import { PublicHeader, SiteFooter } from "../../components/PublicHeader.tsx";
import { chosenOrganization, currentUser } from "../../lib/deprehendo-api.ts";

export const dynamic = "force-dynamic";

// The steps are genuinely sequential, so they are an ordered list.
const STEPS: { title: string; body: string; command: string }[] = [
  {
    title: "Build the agent",
    body: "From a checkout of the repository, on the machine that runs your runner.",
    command: "go build -o bin/deprehendo-agent ./cmd/deprehendo-agent",
  },
  {
    title: "Log in with an API token",
    body: "Ask an organization owner for a token and save it to a file. Log in, then delete the file.",
    command: "deprehendo-agent login --endpoint https://deprehendo.example.com --token-file token.txt",
  },
  {
    title: "Upload an incident",
    body: "Bundles are written locally first. Upload the ones you want to see in the dashboard.",
    command: "deprehendo-agent upload incident.deprehendo",
  },
];

function Steps() {
  return (
    <ol className="install-steps">
      {STEPS.map((step) => (
        <li key={step.title}>
          <h2>{step.title}</h2>
          <p>{step.body}</p>
          <pre className="command"><code>{step.command}</code></pre>
        </li>
      ))}
    </ol>
  );
}

/**
 * Install and first-upload guide (docs/cloud/ux-copy.md). Signed out, it is a
 * public page; signed in, it sits inside the app frame and leads back to the
 * user's incidents.
 */
export default async function Install() {
  const user = await currentUser();
  if (user) {
    return (
      <AppShell email={user.email} organization={await chosenOrganization()} active="install">
        <section className="page page--narrow" aria-labelledby="install-title">
          <header className="page-header">
            <h1 id="install-title">Install the agent</h1>
          </header>
          <Steps />
          <p><a className="uv-button" href="/incidents">Back to incidents</a></p>
        </section>
      </AppShell>
    );
  }
  return (
    <>
      <PublicHeader current="install" />
      <main className="page page--narrow" aria-labelledby="install-title">
        <header className="page-header">
          <h1 id="install-title">Install deprehendo</h1>
          <p className="page-header__lede">Three commands, from a checkout to your first incident in the dashboard.</p>
        </header>
        <Steps />
        <p className="actions">
          <a className="uv-button uv-button--primary" href="/auth/sign-in">Sign in to see your incidents</a>
          <a className="text-link" href="/demo">Open the sample incident</a>
        </p>
      </main>
      <SiteFooter />
    </>
  );
}
