"use client";

import { createContext, useContext, type ReactNode } from "react";

import { zonedClock } from "../lib/format.ts";

/**
 * The time zone a reader picked in display settings. The root layout reads it
 * from the cookie and provides it here, so the server renders the chosen zone
 * in the first response. Outside a provider (tests, previews) it is UTC.
 */
const ZoneContext = createContext("UTC");

export function ZoneProvider({ zone, children }: { zone: string; children: ReactNode }) {
  return <ZoneContext.Provider value={zone}>{children}</ZoneContext.Provider>;
}

/**
 * One timestamp, in the reader's zone. `zone` adds the zone's name after the
 * time ("07:15:56.295 UTC"); `date` puts the date before it. The full stored
 * timestamp is always in the title and dateTime, so nothing is lost by the
 * change of zone. suppressHydrationWarning: the browser's Intl data can name a
 * zone slightly differently from the server's.
 */
export function Clock({ iso, zone: showZone = false, date = false }: { iso: string; zone?: boolean; date?: boolean }) {
  const reader = useContext(ZoneContext);
  const c = zonedClock(iso, reader);
  return (
    <time className="num" dateTime={iso} title={iso} suppressHydrationWarning data-unknown={c.date === "" ? "true" : undefined}>
      {date && c.date ? `${c.date} ` : ""}
      {c.time}
      {showZone && c.label ? ` ${c.label}` : ""}
    </time>
  );
}

/** The reader's zone as a column label: "UTC" or "America/Chicago". */
export function ZoneName() {
  return <>{useContext(ZoneContext)}</>;
}
