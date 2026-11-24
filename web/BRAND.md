# deprehendo brand

*Deprehendo*, Latin: I catch, I detect, I catch in the act. The product catches
the moment a CI runner died and shows the evidence for why. The identity is a
specification, so anyone can redraw it exactly; nothing here is a bitmap.

## The mark

A lowercase **d** built on a 14 × 20 unit grid, holding one orange square.

```
 units  0    3         11 14
   0                   ┌──┐   stem rises to the ascender (20 units)
                       │  │
   6    ┌──────────────┘  │   bowl top: x-height (bowl is 14 units tall)
   9    │  ┌────────┐     │
  11    │  │  ┌──┐  │     │   4 × 4 square, recorder orange,
  15    │  │  └──┘  │     │   centered in the 8 × 8 counter
  17    │  └────────┘     │
  20    └─────────────────┘   baseline
```

- **Stroke:** 3 units, everywhere. Corners are square, like the dashboard's
  tables and rules.
- **Proportions come from the type.** In IBM Plex Sans Condensed SemiBold the
  ascender is 0.740 em and the x-height 0.522 em. The stem is 20 units and the
  bowl 14, so 1 unit is 0.037 em and the bowl lands on the x-height (0.518 em).
  Next to the wordmark the mark is the same height as the wordmark's own d.
- **The square is the sign the interface already uses** for direct evidence:
  a filled square. In the mark it is the reading caught inside the letter.
- SVG path: `M0 6H11V0H14V20H0ZM3 9V17H11V9Z`; square at (5, 11), 4 × 4.
  Source of truth: `components/Logo.tsx` (`MARK_PATH`, `MARK_DOT`).

## Wordmark and lockups

- **Wordmark:** `deprehendo`, always lowercase, IBM Plex Sans Condensed
  SemiBold, tracking −0.005 em. Never set in another face, never title-cased.
- **Horizontal lockup** (headers, sidebar): mark at 0.74 em tall, standing on
  the wordmark's baseline; gap = the counter's width (8 units = 0.296 em).
- **Mark alone:** favicon, avatars, small spaces (`Mark` component,
  `app/icon.svg`).
- **Wordmark alone:** running text, footers, places where the mark would be
  smaller than its minimum size.

## Clear space and minimum size

- Clear space around any lockup: one counter width (8 units of the mark's
  height) on every side. Nothing, including other text, enters it.
- Minimum mark height: 16 px on screen, 5 mm in print. Below that, use the
  wordmark alone. The app icon (`app/icon.svg`) is the mark on a 24-unit ink
  tile with a 5 / 2 unit inset, and it holds at a 16 px favicon.

## Color

| Use | Value |
| --- | --- |
| Mark and wordmark | Ink `#14171a` (light) · `#e7e9ec` (dark) |
| The square | Recorder orange `#e2470b` (light) · `#f0621f` (dark) |
| App icon tile | Ink `#14171a`, letter `#f1f2f4` |
| One color (print, embroidery, fax) | Everything in one ink; the square stays filled |

Orange appears in the square only. The letter is never orange, and the square
is never another color except in one-color use.

## Pitfalls avoided

Checked against what makes a logo "logo-shaped" without construction behind
it ([Inkloom](https://github.com/Inkloom-art/inkloom)), and against common
generated-logo clichés:

- **No heartbeat line, magnifying glass, shield, eye, radar or bug.** The
  previous mark was a heartbeat on an orange tile: the generic "monitoring"
  sign. The new mark is drawn from the name's own letter.
- **No gradient, glow, gloss, 3D or drop shadow.** Flat, two colors, and it
  still works as one.
- **No detail that disappears small.** The smallest feature is the 2-unit gap
  around the square: 1.3 px at a 16 px favicon (2 px strokes), and still visible.
- **No arbitrary numbers.** Every dimension above is derived from the type's
  metrics or from the stroke; spacing in the lockup is the mark's own counter.
- **No letter in a circle or a rounded app tile in the lockup.** The tile is
  for the app icon only, where a background is required, and its corner
  radius (2 of 24 units) matches the dashboard's tags.
