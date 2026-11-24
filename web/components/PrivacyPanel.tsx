import type { PrivacyReport } from "../types/analysis.ts";

/**
 * What the bundle contains (checklist 7.27). A true flag means that kind of
 * data is in the bundle. A false flag means it is not, whether it was redacted
 * or never collected: the report does not separate the two, so the panel does
 * not claim either.
 */
const ROWS: { key: keyof PrivacyReport; label: string }[] = [
  { key: "command_lines", label: "Command lines" },
  { key: "environment", label: "Environment" },
  { key: "hostname", label: "Hostname" },
  { key: "repository_name", label: "Repository name" },
  { key: "network_addresses", label: "IP addresses" },
  { key: "filesystem_paths", label: "Filesystem paths" },
  { key: "process_names", label: "Process names" },
  { key: "user_note", label: "Trigger note" },
  { key: "provider_identifiers", label: "Provider identifiers" },
];

export function PrivacyPanel({ privacy }: { privacy: PrivacyReport }) {
  const rows = ROWS.filter((row) => privacy[row.key] !== undefined);
  return (
    <section aria-labelledby="privacy-title" className="subsection">
      <div className="subsection__head">
        <h3 id="privacy-title" className="subhead">
          Privacy
        </h3>
        <span className="muted small">
          Policy <code>{privacy.policy}</code>
        </span>
      </div>
      <p className="muted small">
        “Not in bundle” means the bundle does not contain that data. It does not say whether the data was redacted or
        never collected.
      </p>
      <table className="data-table privacy-table">
        <caption>What this bundle contains</caption>
        <thead>
          <tr>
            <th scope="col">Data</th>
            <th scope="col">In this bundle</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td>{row.label}</td>
              <td data-present={privacy[row.key] ? "true" : undefined}>{privacy[row.key] ? "Present" : "Not in bundle"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
