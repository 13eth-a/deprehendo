import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";

import { cleanDisplay, decodeDisplay, DEFAULT_DISPLAY, encodeDisplay, isZone } from "../lib/display.ts";
import { formatClock, zonedClock } from "../lib/format.ts";
import { Clock, ZoneName, ZoneProvider } from "../components/Clock.tsx";
import { MARK_DOT, MARK_PATH } from "../components/Logo.tsx";

test("display cookie round-trips, zone with slashes included", () => {
  const s = { theme: "dark", zone: "America/Argentina/Buenos_Aires", density: "compact" } as const;
  assert.deepEqual(decodeDisplay(encodeDisplay(s)), s);
});

test("display settings fall back field by field, never wholesale", () => {
  assert.deepEqual(decodeDisplay(undefined), DEFAULT_DISPLAY);
  assert.deepEqual(decodeDisplay("dark.compact.Not/AZone"), { theme: "dark", density: "compact", zone: "UTC" });
  assert.deepEqual(cleanDisplay({ theme: "neon", zone: "Europe/Berlin", density: 7 }), {
    theme: "system",
    zone: "Europe/Berlin",
    density: "comfortable",
  });
  assert.equal(isZone("UTC"), true);
  assert.equal(isZone("../../etc"), false);
  assert.equal(isZone("<script>"), false);
});

test("zonedClock in UTC is exactly formatClock; other zones name themselves", () => {
  const iso = "2026-11-21T01:15:56.295-06:00";
  assert.deepEqual(zonedClock(iso, "UTC"), { time: formatClock(iso), date: "2026-11-21", label: "UTC" });
  const chicago = zonedClock("2026-11-21T07:15:56.295Z", "America/Chicago");
  assert.equal(chicago.time, "01:15:56.295");
  assert.equal(chicago.date, "2026-11-21");
  assert.equal(chicago.label, "CST");
  // the date moves with the zone
  assert.equal(zonedClock("2026-11-21T03:00:00Z", "America/Chicago").date, "2026-11-20");
  assert.equal(zonedClock("not a time", "America/Chicago").time, "unknown time");
});

test("Clock renders the reader's zone and keeps the stored value in title and dateTime", () => {
  const iso = "2026-11-21T07:15:56.295Z";
  const utc = renderToStaticMarkup(<Clock iso={iso} zone />);
  assert.ok(utc.includes("07:15:56.295 UTC"), utc);
  const local = renderToStaticMarkup(
    <ZoneProvider zone="America/Chicago">
      <Clock iso={iso} zone date /> <ZoneName />
    </ZoneProvider>,
  );
  assert.ok(local.includes("2026-11-21 01:15:56.295 CST"), local);
  assert.ok(local.includes(`dateTime="${iso}"`) && local.includes(`title="${iso}"`));
  assert.ok(local.includes("America/Chicago"));
});

test("the mark is the specified construction (BRAND.md)", () => {
  assert.equal(MARK_PATH, "M0 6H11V0H14V20H0ZM3 9V17H11V9Z");
  // the square is centered in the 8 x 8 counter that spans x 3..11, y 9..17
  assert.equal(MARK_DOT.x + MARK_DOT.size / 2, (3 + 11) / 2);
  assert.equal(MARK_DOT.y + MARK_DOT.size / 2, (9 + 17) / 2);
});
