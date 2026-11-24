/**
 * Display settings: theme, the time zone timestamps are shown in, and table
 * density. They are per browser, kept in one cookie, so the server renders the
 * chosen theme and zone in the first response (no flash, no client script).
 * The cookie holds only these three values; anything else in it is ignored.
 */

export type Theme = "system" | "light" | "dark";
export type Density = "comfortable" | "compact";

export interface DisplaySettings {
  theme: Theme;
  /** "UTC" or an IANA zone name such as "America/Chicago". */
  zone: string;
  density: Density;
}

export const DISPLAY_COOKIE = "deprehendo_display";
export const DEFAULT_DISPLAY: DisplaySettings = { theme: "system", zone: "UTC", density: "comfortable" };

const THEMES: readonly Theme[] = ["system", "light", "dark"];
const DENSITIES: readonly Density[] = ["comfortable", "compact"];

/** True for "UTC" and for any zone this runtime's Intl knows. */
export function isZone(value: string): boolean {
  if (value === "UTC") return true;
  if (!/^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/.test(value)) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

/** Every zone the runtime knows, UTC first. */
export function zoneOptions(): string[] {
  const all = typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : [];
  return ["UTC", ...all.filter((z) => z !== "UTC")];
}

/** Checks each field on its own: one bad value falls back without losing the others. */
export function cleanDisplay(input: { theme?: unknown; zone?: unknown; density?: unknown }): DisplaySettings {
  const theme = THEMES.includes(input.theme as Theme) ? (input.theme as Theme) : DEFAULT_DISPLAY.theme;
  const density = DENSITIES.includes(input.density as Density) ? (input.density as Density) : DEFAULT_DISPLAY.density;
  const zone = typeof input.zone === "string" && isZone(input.zone) ? input.zone : DEFAULT_DISPLAY.zone;
  return { theme, zone, density };
}

/** Cookie value: "theme.density.zone". The zone goes last because it may contain "/". */
export function encodeDisplay(s: DisplaySettings): string {
  return `${s.theme}.${s.density}.${s.zone}`;
}

export function decodeDisplay(raw: string | undefined): DisplaySettings {
  if (!raw) return DEFAULT_DISPLAY;
  const [theme, density, ...rest] = raw.split(".");
  return cleanDisplay({ theme, density, zone: rest.join(".") });
}
