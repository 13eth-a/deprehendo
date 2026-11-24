/**
 * display formatting only. nothing here changes what a value means.
 * times are rendered in UTC by default so the same document shows the same
 * text on every machine, which keeps local and cloud output comparable (7.43).
 * a reader may pick another zone in display settings; zonedClock is that view,
 * and it always names the zone it used.
 */

const NANOS_PER_MS = 1_000_000n;

/**
 * parses an RFC 3339 timestamp, as go writes it (RFC3339Nano), into integer
 * nanoseconds since the epoch. date alone would lose the fraction. most events
 * are UTC ("Z"), but kernel-tracer events keep the host's offset ("-06:00"),
 * so a numeric offset is accepted too; formatClock still shows UTC.
 * returns null for anything not in that form.
 */
export function epochNanos(iso: string): bigint | null {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(iso);
  if (!match) return null;
  const millis = Date.parse(`${match[1]}${match[3]}`);
  if (Number.isNaN(millis)) return null;
  const fraction = (match[2] ?? "").padEnd(9, "0");
  return BigInt(millis) * NANOS_PER_MS + BigInt(fraction === "" ? 0 : Number(fraction));
}

/**
 * signed offset of `at` from `origin`, formatted as "+1.4 ms", "−8.4 s" and so
 * on. returns "unknown time" when either timestamp cannot be parsed.
 */
export function formatOffset(at: string, origin: string): string {
  const a = epochNanos(at);
  const o = epochNanos(origin);
  if (a === null || o === null) return "unknown time";
  const delta = a - o;
  const sign = delta < 0n ? "−" : "+";
  const abs = delta < 0n ? -delta : delta;
  if (abs < 1_000_000_000n) return `${sign}${(Number(abs) / 1e6).toFixed(1)} ms`;
  if (abs < 60_000_000_000n) return `${sign}${(Number(abs) / 1e9).toFixed(1)} s`;
  const totalSeconds = Number(abs / 1_000_000_000n);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${sign}${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

/** UTC clock time, "HH:MM:SS.mmm", from an RFC 3339 timestamp. */
export function formatClock(iso: string): string {
  const nanos = epochNanos(iso);
  if (nanos === null) return "unknown time";
  const millis = Number(nanos / NANOS_PER_MS);
  const d = new Date(millis);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  const ss = String(d.getUTCSeconds()).padStart(2, "0");
  const ms = String(d.getUTCMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

export interface ZonedClock {
  /** "HH:MM:SS.mmm" in the zone, or "unknown time". */
  time: string;
  /** "YYYY-MM-DD" in the zone, or "". */
  date: string;
  /** "UTC", or the zone's short name at that instant ("CST", "GMT+5:30"). */
  label: string;
}

/** the clock in a display zone. "UTC" gives exactly formatClock's text. */
export function zonedClock(iso: string, zone: string): ZonedClock {
  const nanos = epochNanos(iso);
  if (nanos === null) return { time: "unknown time", date: "", label: zone === "UTC" ? "UTC" : "" };
  const millis = Number(nanos / NANOS_PER_MS);
  if (zone === "UTC") return { time: formatClock(iso), date: new Date(millis).toISOString().slice(0, 10), label: "UTC" };
  const parts: Record<string, string> = {};
  try {
    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: zone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
      timeZoneName: "short",
    });
    for (const p of fmt.formatToParts(new Date(millis))) parts[p.type] = p.value;
  } catch {
    return zonedClock(iso, "UTC");
  }
  const ms = String(millis % 1000 < 0 ? millis % 1000 + 1000 : millis % 1000).padStart(3, "0");
  return {
    time: `${parts.hour}:${parts.minute}:${parts.second}.${ms}`,
    date: `${parts.year}-${parts.month}-${parts.day}`,
    label: parts.timeZoneName ?? zone,
  };
}

/** binary units (KiB, MiB, GiB), one decimal above 1 KiB. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "not captured";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** percent with one decimal, or "not captured" when the sensor was absent. */
export function formatPercent(value: number | null | undefined, available = true): string {
  if (!available || value === null || value === undefined || !Number.isFinite(value)) {
    return "not captured";
  }
  return `${value.toFixed(1)}%`;
}
