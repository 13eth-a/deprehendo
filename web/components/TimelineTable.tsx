import type { TimelineEvent } from "../types/analysis.ts";
import type { Page } from "../lib/paging.ts";
import { formatClock, formatOffset } from "../lib/format.ts";
import { evidenceLabel } from "../lib/evidence.ts";

/**
 * one page of the timeline (checklist 7.18 and 7.24). rows keep the stored
 * order, and only the requested page is rendered (7.44). the table has a
 * caption and column headers so a screen reader can navigate it (7.45).
 */
export function TimelineTable({
  page,
  origin,
  caption = "Timeline events",
}: {
  page: Page<TimelineEvent>;
  origin: string;
  caption?: string;
}) {
  return (
    <div className="table-wrap" role="region" aria-label={caption} tabIndex={0}>
      <table>
        <caption>
          {caption}: showing {page.items.length} of {page.total} (page {page.page} of {page.pages})
        </caption>
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">Time (UTC)</th>
            <th scope="col">From trigger</th>
            <th scope="col">Event</th>
            <th scope="col">PID</th>
            <th scope="col">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {page.items.map((event, index) => (
            <tr key={event.id}>
              <td>{page.start + index}</td>
              <td>{formatClock(event.timestamp)}</td>
              <td>{formatOffset(event.timestamp, origin)}</td>
              <td>
                <code>{event.type}</code>
              </td>
              <td>{event.pid ?? "—"}</td>
              <td>{evidenceLabel(event.evidence_class)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
