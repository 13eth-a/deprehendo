/** public install and first-upload guide (docs/cloud/ux-copy.md). */
export default function Install() {
  return (
    <main className="landing" aria-labelledby="install-title">
      <h1 id="install-title">Install deprehendo</h1>
      <ol className="steps">
        <li>
          <strong>Build the agent</strong>
          <span><code>go build -o bin/runopsy-agent ./cmd/runopsy-agent</code></span>
        </li>
        <li>
          <strong>Log in with an API token</strong>
          <span>
            Ask an organization owner for a token, save it to a file, then run{" "}
            <code>runopsy-agent login --endpoint https://runopsy.up.railway.app --token-file token.txt</code> and
            delete the file.
          </span>
        </li>
        <li>
          <strong>Upload an incident</strong>
          <span><code>runopsy-agent upload incident.runopsy</code></span>
        </li>
      </ol>
      <p><a href="/auth/sign-in">Sign in to see your incidents</a> · <a href="/demo">View a sample incident</a></p>
    </main>
  );
}
