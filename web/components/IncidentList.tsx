import type { IncidentFilter, IncidentSummary } from "../lib/incidents.ts";
import { Empty } from "./shadcn/Empty.tsx";
import { Kbd } from "./shadcn/Kbd.tsx";
import { SeverityBadge } from "./Status.tsx";
import { Clock, ZoneName } from "./Clock.tsx";

/**
 * Incident list (checklist 7.13) with a plain GET filter form, so it works
 * without client JavaScript. Rows arrive already filtered and sorted by
 * lib/incidents.ts. The counts above the table are tallies of stored fields
 * (severity, diagnosis, analysis status) over every row, not a judgment.
 */
export function IncidentList({
  rows,
  all,
  filter,
  diagnoses,
  bands,
  uploadCommand = "deprehendo-agent upload incident.deprehendo",
  installHref = "/install",
  hrefFor,
}: {
  rows: readonly IncidentSummary[];
  /** Every row before filtering, for the tallies. Defaults to `rows`. */
  all?: readonly IncidentSummary[];
  filter: IncidentFilter;
  diagnoses: readonly string[];
  bands: readonly string[];
  uploadCommand?: string;
  /** Where the empty state points for agent setup. */
  installHref?: string;
  /** When given, each incident id links to its detail page. */
  hrefFor?: (incidentId: string) => string;
}) {
  const hasFilter = Boolean(filter.diagnosis || filter.band || filter.since || filter.until);
  const everything = all ?? rows;
  const critical = everything.filter((row) => row.severity?.toUpperCase() === "CRITICAL").length;
  const unknown = everything.filter((row) => row.unknown).length;
  const firstRun = rows.length === 0 && !hasFilter;
  return (
    <section aria-labelledby="list-title" className="page">
      <header className="page-header">
        <div>
          <h1 id="list-title">Incidents</h1>
        </div>
        {everything.length > 0 && (
          <dl className="stat-strip" aria-label="Incident counts">
            <div>
              <dt>Incidents</dt>
              <dd>{everything.length}</dd>
            </div>
            <div data-tone={critical > 0 ? "critical" : undefined}>
              <dt>Critical</dt>
              <dd>{critical}</dd>
            </div>
            <div>
              <dt>No known signature</dt>
              <dd>{unknown}</dd>
            </div>
          </dl>
        )}
      </header>

      {firstRun ? (
        <Empty
          titleId="empty-title"
          title="No incidents yet"
          description="Upload a deprehendo bundle to see its diagnosis, timeline, and evidence here."
        >
          <p className="command"><span aria-hidden="true" className="command__prompt">$</span><code>{uploadCommand}</code></p>
          <p><a className="uv-button" href={installHref}>Installation guide</a></p>
        </Empty>
      ) : (
        <form method="get" className="filters" aria-label="Filter incidents">
          <label className="uv-field">
            <select className="uv-input" name="diagnosis" defaultValue={filter.diagnosis ?? ""}>
              <option value="">All</option>
              {diagnoses.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <span>Diagnosis</span>
          </label>
          <label className="uv-field">
            <select className="uv-input" name="band" defaultValue={filter.band ?? ""}>
              <option value="">All</option>
              {bands.map((band) => (
                <option key={band} value={band}>
                  {band}
                </option>
              ))}
            </select>
            <span>Confidence</span>
          </label>
          <label className="uv-field">
            <input className="uv-input" type="date" name="since" defaultValue={filter.since ?? ""} />
            <span>From (UTC date)</span>
          </label>
          <label className="uv-field">
            <input className="uv-input" type="date" name="until" defaultValue={filter.until ?? ""} />
            <span>To (UTC date)</span>
          </label>
          <button className="uv-button uv-button--primary" type="submit">Apply</button>
          {hasFilter && <a className="uv-button uv-button--ghost" href="?">Clear</a>}
        </form>
      )}

      {rows.length === 0 && hasFilter && (
        <p role="status" className="panel muted">No incidents match these filters. Change or clear a filter to see more.</p>
      )}

      {rows.length > 0 && (
        <div className="table-wrap" role="region" aria-label="Incident results" tabIndex={0}>
          <table className="data-table incident-table">
            <caption>Incidents, newest first. Runner, workflow and job come from the GitHub section when the bundle has one.</caption>
            <thead>
              <tr>
                <th scope="col">Diagnosis</th>
                <th scope="col">Severity</th>
                <th scope="col">Confidence</th>
                <th scope="col">Time (<ZoneName />)</th>
                <th scope="col">Analyzer</th>
                <th scope="col">Incident</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const context = [row.workflow, row.job, row.runner].filter(Boolean).join(" · ");
                return (
                  <tr key={`${row.incidentId}-${row.causalRules}`}>
                    <td>
                      <span className={row.diagnosis ? "mono strong" : "muted"}>
                        {row.diagnosis ?? (row.unknown ? "Unknown" : "—")}
                      </span>
                      {context && <span className="row-context">{context}</span>}
                    </td>
                    <td>{row.severity ? <SeverityBadge severity={row.severity} /> : <span className="muted">—</span>}</td>
                    <td className="mono">{row.confidenceBand ?? "—"}</td>
                    <td className="mono nowrap">
                      <Clock iso={row.triggeredAt} date />
                    </td>
                    <td><span className="chip mono">{row.analyzerVersion}</span></td>
                    <td>
                      {hrefFor ? (
                        <a className="row-link" href={hrefFor(row.incidentId)}>
                          <code>{row.incidentId}</code>
                        </a>
                      ) : (
                        <code>{row.incidentId}</code>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > 0 && (
        <p className="muted small hint">
          Upload another bundle with <Kbd>deprehendo-agent upload</Kbd>
        </p>
      )}
    </section>
  );
}
