import { GridPattern } from "./magicui/GridPattern.tsx";

/**
 * Public landing page (7.51). It describes what this product actually does
 * and shows one real result instead of a mock-up: the excerpt below is copied
 * from the analysis of a real capture (testdata/github/real-runner-demo,
 * 7.62), so keep it in step with that document if the engine changes.
 */
export function LandingPage({
  installHref = "/install",
  demoHref = "/demo",
}: {
  installHref?: string;
  demoHref?: string;
}) {
  return (
    <main className="landing" aria-labelledby="landing-title">
      <section className="landing-intro">
        <div className="landing-intro__text">
          <h1 id="landing-title">Find out why a <span className="nowrap">self-hosted</span> GitHub Actions runner died.</h1>
          <p className="landing-lede">
            deprehendo keeps a rolling record of the runner&rsquo;s processes, sockets, memory and kernel events. When a
            job dies, it saves that record as an incident bundle and names the failure, or says plainly that it
            can&rsquo;t tell.
          </p>
          <p className="actions">
            <a className="uv-button uv-button--primary" href={installHref}>Install the agent</a>
            <a className="text-link" href={demoHref}>Open the sample incident</a>
          </p>
        </div>

        <figure className="excerpt">
          <GridPattern width={24} height={24} className="excerpt__paper" />
          <div className="excerpt__sheet">
            <p className="excerpt__kind">Primary diagnosis</p>
            <p className="excerpt__title">Process vanished while memory was at or near exhaustion</p>
            <p className="excerpt__sig"><code>OOM_KILL</code></p>
            <p className="excerpt__tags">
              <span className="badge" data-variant="critical">Critical</span>
              <span className="badge" data-variant="outline">High confidence <span className="num">0.80</span></span>
              <span className="badge" data-variant="direct">Direct evidence</span>
            </p>
            <table className="excerpt__evidence">
              <caption>Supporting evidence, by weight</caption>
              <tbody>
                <tr><td><code>KERNEL_OOM_COUNTER_ROSE</code></td><td className="num">0.40</td></tr>
                <tr><td><code>HOST_MEMORY_NEAR_LIMIT</code> <span className="muted">96.8%</span></td><td className="num">0.20</td></tr>
                <tr><td><code>PROCESS_DEPARTURE_NEAR_MEMORY_PEAK</code></td><td className="num">0.15</td></tr>
                <tr><td><code>CANDIDATE_RSS_LARGE</code> <span className="muted">83% of RSS</span></td><td className="num">0.05</td></tr>
              </tbody>
            </table>
          </div>
          <figcaption>
            From a real capture: a job allocated 4&nbsp;GiB on a 4&nbsp;GiB self-hosted runner and was killed with
            exit code 137.
          </figcaption>
        </figure>
      </section>

      <section className="landing-block" aria-labelledby="recorded-title">
        <h2 id="recorded-title">What the agent records</h2>
        <dl className="recorded">
          <div>
            <dt>Processes</dt>
            <dd>The runner&rsquo;s process tree: states, parents, memory and CPU, sampled on a fixed interval.</dd>
          </div>
          <div>
            <dt>Sockets</dt>
            <dd>TCP connections and which process owns each one.</dd>
          </div>
          <div>
            <dt>Memory and pressure</dt>
            <dd>Host memory, cgroup limits and out-of-memory counters, and Linux pressure-stall readings.</dd>
          </div>
          <div>
            <dt>Kernel events</dt>
            <dd>Process starts, exits and signals from the kernel tracer, when it is running.</dd>
          </div>
          <div>
            <dt>Runner logs</dt>
            <dd>GitHub Actions runner and worker events, read into a separate provider section.</dd>
          </div>
        </dl>
        <p className="landing-note">
          The bundle is written on the runner first. Uploading it to the dashboard is optional, and analysis gives the
          same result locally and in the cloud.
        </p>
      </section>

      <section className="landing-block landing-block--split" aria-labelledby="decide-title">
        <div>
          <h2 id="decide-title">How a diagnosis is made</h2>
          <p>
            Nine failure signatures each list the recorded conditions they require. A signature is named only when its
            evidence clears a confidence threshold; the evidence against it is shown next to the evidence for it.
          </p>
          <p>
            Versioned causal rules then link the events into a chain, and every event says whether the kernel observed
            it directly or it was inferred by comparing samples.
          </p>
        </div>
        <div>
          <h2 id="unknown-title">When it can&rsquo;t tell</h2>
          <p>
            In a second real capture, the runner lost its connection to GitHub for three minutes. The bundle holds no
            socket byte counters, so the engine answers <code>UNKNOWN</code> rather than guess. The GitHub section still
            reports what it saw: <code>GITHUB_RUNNER_COMMUNICATION_STALL</code>.
          </p>
        </div>
      </section>
    </main>
  );
}
