import type { IncidentFilter, IncidentSummary } from "../lib/incidents.ts";
import { formatClock } from "../lib/format.ts";

/**
 * incident list (checklist 7.13) with a plain GET filter form, so it works
 * without client JavaScript. rows arrive already filtered and sorted by
 * lib/incidents.ts. runner, workflow, job and repository columns are not in
 * the core document, so they are not shown until the GitHub section is read.
 */
export function IncidentList({
  rows,
  filter,
  diagnoses,
  bands,
  uploadCommand = "runopsy-agent upload incident.runopsy",
  demoHref = "/demo",
  hrefFor,
}: {
  rows: readonly IncidentSummary[];
  filter: IncidentFilter;
  diagnoses: readonly string[];
  bands: readonly string[];
  uploadCommand?: string;
  demoHref?: string;
  /** when given, each incident id links to its detail page. */
  hrefFor?: (incidentId: string) => string;
}) {
  const hasFilter = Boolean(filter.diagnosis || filter.band || filter.since || filter.until);
  return (
    <section aria-labelledby="list-title">
      <h1 id="list-title">Incidents</h1>
      {rows.length === 0 && (hasFilter ? (
        <p role="status">No incidents match these filters. Change or clear a filter to see more.</p>
      ) : (
        <section className="empty-state" aria-labelledby="empty-title">
          <h2 id="empty-title">No incidents yet</h2>
          <p>Upload a deprehendo bundle to see its diagnosis, timeline, and evidence here.</p>
          <p><code>{uploadCommand}</code></p>
          <p><a href={demoHref}>View a sample incident</a></p>
        </section>
      ))}
      <form method="get" className="filters" aria-label="Filter incidents">
        <label>
          Diagnosis
          <select name="diagnosis" defaultValue={filter.diagnosis ?? ""}>
            <option value="">All</option>
            {diagnoses.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Confidence
          <select name="band" defaultValue={filter.band ?? ""}>
            <option value="">All</option>
            {bands.map((band) => (
              <option key={band} value={band}>
                {band}
              </option>
            ))}
          </select>
        </label>
        <label>
          From (UTC date)
          <input type="date" name="since" defaultValue={filter.since ?? ""} />
        </label>
        <label>
          To (UTC date)
          <input type="date" name="until" defaultValue={filter.until ?? ""} />
        </label>
        <button type="submit">Apply</button>
      </form>
      {rows.length > 0 && (
        <div className="table-scroll" role="region" aria-label="Incident results" tabIndex={0}>
          <table>
            <caption>Incidents, newest first. Runner, workflow, job and repository come from the GitHub section.</caption>
            <thead>
              <tr>
                <th scope="col">Time (UTC)</th>
                <th scope="col">Diagnosis</th>
                <th scope="col">Confidence</th>
                <th scope="col">Analyzer</th>
                <th scope="col">Incident</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.incidentId}-${row.causalRules}`}>
                  <td>{row.triggeredAt.slice(0, 10)} {formatClock(row.triggeredAt)}</td>
                  <td>{row.diagnosis ?? (row.unknown ? "Unknown" : "—")}</td>
                  <td>{row.confidenceBand ?? "—"}</td>
                  <td>{row.analyzerVersion}</td>
                  <td>
                    {hrefFor ? (
                      <a href={hrefFor(row.incidentId)}>
                        <code>{row.incidentId}</code>
                      </a>
                    ) : (
                      <code>{row.incidentId}</code>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
