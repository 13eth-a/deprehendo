import type { TimelineEvent } from "../types/analysis.ts";
import { epochNanos } from "./format.ts";

/**
 * filters for the raw event explorer (checklist 7.24): event type, PID,
 * evidence source and a time window. filtering keeps the stored order and
 * never changes an event.
 */
export interface TimelineFilter {
  /** empty or undefined means every type. */
  types?: readonly string[];
  pid?: number;
  /** evidence classes to keep; empty or undefined means every class. */
  evidence?: readonly string[];
  /** inclusive window, as RFC 3339 timestamps. */
  from?: string;
  to?: string;
}

export function filterTimeline(events: readonly TimelineEvent[], filter: TimelineFilter): TimelineEvent[] {
  const from = filter.from ? epochNanos(filter.from) : null;
  const to = filter.to ? epochNanos(filter.to) : null;
  const types = filter.types && filter.types.length > 0 ? new Set(filter.types) : null;
  const evidence = filter.evidence && filter.evidence.length > 0 ? new Set(filter.evidence) : null;
  return events.filter((event) => {
    if (types && !types.has(event.type)) return false;
    if (filter.pid !== undefined && event.pid !== filter.pid) return false;
    if (evidence && !evidence.has(event.evidence_class)) return false;
    if (from !== null || to !== null) {
      const at = epochNanos(event.timestamp);
      if (at === null) return false;
      if (from !== null && at < from) return false;
      if (to !== null && at > to) return false;
    }
    return true;
  });
}

/** distinct event types in first-seen order, for the filter control. */
export function eventTypes(events: readonly TimelineEvent[]): string[] {
  const seen = new Set<string>();
  for (const event of events) seen.add(event.type);
  return [...seen];
}
