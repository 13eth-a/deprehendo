/** small product introduction for a host app's public landing route. */
export function LandingPage({
  installHref = "/install",
  demoHref = "/demo",
}: {
  installHref?: string;
  demoHref?: string;
}) {
  return (
    <main className="landing" aria-labelledby="landing-title">
      <p className="eyebrow">deprehendo · self-hosted CI diagnostics</p>
      <h1 id="landing-title">Know why your self-hosted CI runner died.</h1>
      <p className="landing-lede">
        deprehendo records a local incident bundle and explains the failure with a
        deterministic diagnosis, causal chain, timeline, and supporting evidence.
      </p>
      <ol className="steps" aria-label="How deprehendo works">
        <li><strong>Install deprehendo</strong><span>Run the agent beside your runner.</span></li>
        <li><strong>Capture an incident</strong><span>The bundle is saved locally first.</span></li>
        <li><strong>Inspect the evidence</strong><span>Analyze locally or upload the bundle to your dashboard.</span></li>
      </ol>
      <nav aria-label="Get started" className="actions">
        <a className="button" href={installHref}>Installation guide</a>
        <a href={demoHref}>View a sample incident</a>
      </nav>
      <p className="muted">Cloud upload is optional. Local capture and analysis work offline.</p>
    </main>
  );
}
