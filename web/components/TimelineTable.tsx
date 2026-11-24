import type { TimelineEvent } from "../types/analysis.ts";
import type { Page } from "../lib/paging.ts";
import { formatOffset } from "../lib/format.ts";
import { evidenceLabel, isDirect } from "../lib/evidence.ts";
import { Clock, ZoneName } from "./Clock.tsx";

/**
 * One page of the timeline (checklist 7.18 and 7.24). Rows keep the stored
 * order, and only the requested page is rendered (7.44). The table has a
 * caption and column headers so a screen reader can navigate it (7.45).
 * With `eventHref`, each event name opens the evidence drawer.
 */
export function TimelineTable({
  page,
  origin,
  caption = "Timeline events",
  eventHref,
  selected,
}: {
  page: Page<TimelineEvent>;
  origin: string;
  caption?: string;
  eventHref?: (eventId: string) => string;
  selected?: string;
}) {
  return (
    <div className="table-wrap" role="region" aria-label={caption} tabIndex={0}>
      <table className="data-table">
        <caption>
          {caption}: showing {page.items.length} of {page.total} (page {page.page} of {page.pages})
        </caption>
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">Time (<ZoneName />)</th>
            <th scope="col">From trigger</th>
            <th scope="col">Event</th>
            <th scope="col">PID</th>
            <th scope="col">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {page.items.map((event, index) => (
            <tr key={event.id} data-selected={selected === event.id ? "true" : undefined}>
              <td className="mono muted">{page.start + index}</td>
              <td className="mono"><Clock iso={event.timestamp} /></td>
              <td className="mono muted">{formatOffset(event.timestamp, origin)}</td>
              <td>
                {eventHref ? (
                  <a href={eventHref(event.id)}><code>{event.type}</code></a>
                ) : (
                  <code>{event.type}</code>
                )}
              </td>
              <td className="mono">{event.pid ?? "—"}</td>
              <td className={isDirect(event.evidence_class) ? "q-direct" : "q-inferred"}>
                <span className="q-mark" aria-hidden="true" data-direct={isDirect(event.evidence_class) ? "true" : undefined} />
                {evidenceLabel(event.evidence_class)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
