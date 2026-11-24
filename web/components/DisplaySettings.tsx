import { BrowserZone } from "./BrowserZone.tsx";
import { zoneOptions, type Density, type DisplaySettings as Settings, type Theme } from "../lib/display.ts";

const THEME_CHOICES: { value: Theme; label: string }[] = [
  { value: "system", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];
const DENSITY_CHOICES: { value: Density; label: string; hint: string }[] = [
  { value: "comfortable", label: "Comfortable", hint: "Room to read" },
  { value: "compact", label: "Compact", hint: "More rows per screen" },
];

/**
 * Account → Display. A plain form posting to a server action, so it works
 * without client JavaScript; only "use this browser's zone" needs the browser.
 */
export function DisplaySettings({
  display,
  action,
}: {
  display: Settings;
  action: (formData: FormData) => void | Promise<void>;
}) {
  return (
    <section className="panel account-card account-card--wide" aria-labelledby="display-title">
      <h2 id="display-title">Display</h2>
      <form action={action} className="display-form">
        <fieldset className="choice-group">
          <legend>Theme</legend>
          <div className="segmented">
            {THEME_CHOICES.map((c) => (
              <label key={c.value}>
                <input type="radio" name="theme" value={c.value} defaultChecked={display.theme === c.value} />
                <span>{c.label}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="choice-group">
          <legend>Timestamps</legend>
          <p className="muted small">
            Stored times are UTC. Pick another zone to read them in; the stored value stays on hover.
          </p>
          <div className="zone-row">
            <label className="sr-only" htmlFor="display-zone">Time zone</label>
            <select id="display-zone" className="uv-input" name="zone" defaultValue={display.zone}>
              {zoneOptions().map((z) => (
                <option key={z} value={z}>{z === "UTC" ? "UTC (default)" : z.replaceAll("_", " ")}</option>
              ))}
            </select>
            <BrowserZone selectId="display-zone" />
          </div>
        </fieldset>

        <fieldset className="choice-group">
          <legend>Density</legend>
          <div className="segmented">
            {DENSITY_CHOICES.map((c) => (
              <label key={c.value} title={c.hint}>
                <input type="radio" name="density" value={c.value} defaultChecked={display.density === c.value} />
                <span>{c.label}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="display-form__foot">
          <button className="uv-button uv-button--primary" type="submit">Save display settings</button>
          <span className="muted small">Saved in this browser only.</span>
        </div>
      </form>
    </section>
  );
}
