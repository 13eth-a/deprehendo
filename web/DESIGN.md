# deprehendo dashboard design

The dashboard looks like an incident report, not a SaaS template. Each choice
below was made on purpose; change one only on purpose. The checklist it was
measured against is [Signs of AI design](https://github.com/febbhav/signs-of-ai-design)
(`design-rules.md`).

## Decisions

- **Light sheets on a cool gray page by default.** An incident report is read
  closely, pasted into tickets and printed. There is a print stylesheet, and
  print is always light.
- **Display settings are the reader's.** Theme (match system, light, dark),
  the time zone timestamps are read in, and density (comfortable, compact),
  under Account → Display. They live in one cookie per browser
  (`lib/display.ts`), so the server renders them in the first response. Every
  color is a `light-dark()` token in `:root`; nothing else names a color.
  Stored times stay UTC: another zone is a view, named next to the time, with
  the stored value in the tooltip. Filters stay in UTC dates.
- **One accent: recorder orange (`--accent`).** Flight recorders are painted
  international orange, and deprehendo is a flight recorder for CI runners.
  Orange marks deprehendo itself: the logo, the current page, the selected
  chain step, the trigger line on charts. It never means "warning".
- **Ink carries action.** The primary button is near-black. Red, amber and
  blue are status colors only and always sit next to a word.
- **Type: IBM Plex.** Condensed for headings, regular for reading, mono only
  for machine values (signatures, IDs, timestamps, PIDs, commands). No body
  text is set in mono.
- **Hairline rules, no shadows.** Sections are separated by rules, not boxed.
  Radius varies by element: 0 for tables, 2px for tags, 3px for inputs and
  buttons, 4px for sheets.
- **Direct versus inferred** is a filled versus hollow square plus the words,
  so it never depends on color.
- **Copy is specific.** Headlines say what this product does. The landing
  page shows a real result (the 7.62 OOM capture), not a mock-up, and no
  invented numbers, logos or testimonials.

## Brand

The mark and wordmark are specified in [BRAND.md](BRAND.md).

## Deliberately not used

Eyebrow pills, numbered section markers, bento grids, three-card feature rows,
icon tiles, fake terminal windows, gradient or glowing borders, shimmer text,
spotlight hover effects, glassmorphism, and scroll-triggered fade-ins. The
previous redesign used several of these; they were removed.

## Where the components come from

All of them are ported to plain CSS with deprehendo's tokens (no Tailwind, no
animation library, nothing from a CDN). Licenses sit next to the code.

| Source | Used for |
| --- | --- |
| shadcn/ui, as listed on 21st.dev (MIT) | Sidebar, Badge, Kbd, Empty, Table (`components/shadcn/`) |
| Uiverse.io (MIT) | Buttons, inputs, labelled field, progress bar, spinner (`styles/vendor.css`, `components/uiverse/`) |
| Magic UI (MIT) | Grid Pattern, once, as chart paper behind the landing excerpt (`components/magicui/`) |

React Bits components are all motion effects (spotlight, shimmer, counters),
which this design does not use, so none are included. Mobbin, Inspora and
Designeer are reference galleries rather than component sources.
