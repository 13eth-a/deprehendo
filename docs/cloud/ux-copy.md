# Phase 7 product UX copy (secondary)

Status: **copy and route-ready view components, November 5, 2026.** This defines the short public landing, installation journey, empty dashboard, and sample-incident language for the hosted viewer. `web/components/LandingPage.tsx`, `IncidentList.tsx`, and `DemoIncident.tsx` provide the corresponding UI pieces. The current `web/` directory is still a React view layer; a Next.js host must wire the routes, authentication, stylesheet, and sanitized fixture.

## Landing page

**Headline:** Know why your self-hosted CI runner died.

**Description:** Runopsy records a local incident bundle and explains the failure with a deterministic diagnosis, causal chain, timeline, and supporting evidence.

**How it works:**

1. Install Runopsy and run the agent beside your runner.
2. Runopsy saves an incident bundle locally when it captures a failure.
3. Analyze it locally, or upload the bundle to your dashboard.

**Primary action:** Installation guide  
**Secondary action:** View a sample incident  
**Privacy note:** Cloud upload is optional. Local capture and analysis work offline.

## Installation journey

Keep the flow to the commands that exist today:

1. Install or build the Runopsy agent using the project installation guide.
2. For GitHub Actions runners, start capture with `runopsy-agent github watch`. For another process, use `runopsy-agent start` with the appropriate watch selector.
3. Confirm the resulting bundle is present in `~/.runopsy/incidents/` (or the configured `--incident-dir`). Bundles are written locally first.
4. Configure the dashboard endpoint and token with `runopsy-agent login -endpoint https://cloud.example`.
5. Upload a bundle with `runopsy-agent upload ~/.runopsy/incidents/<file>.runopsy`.
6. Open the dashboard URL printed by the CLI.

Do not imply that the browser has GitHub live access, that upload is automatic without opt-in, or that Runopsy installs itself as a service. Those capabilities are outside this flow.

## First-run empty state

**Title:** No incidents yet  
**Body:** Upload a Runopsy bundle to see its diagnosis, timeline, and evidence here.  
**Command:** `runopsy-agent upload incident.runopsy`  
**Secondary action:** View a sample incident

When filters are active and yield no rows, use: **No incidents match these filters. Change or clear a filter to see more.** Do not show the upload prompt for an empty filtered result.

## Sample incident

Mark every fixture-backed page **Sample incident** and state that it is a sanitized demonstration bundle, not a live customer incident. Render the stored diagnosis and evidence as-is. Link to sign-in/upload only after a host provides that route. Do not imply that demo data belongs to the visitor.

## Accessibility and responsive behavior

- Preserve native links, buttons, form controls, headings, table captions, and header scope so keyboard and assistive-technology users get browser defaults.
- Every filter has a visible label; the incident table sits in a keyboard scroll region on narrow screens.
- Empty states and failures use a status announcement where content changes.
- Focus is visible, text contrast is high, and reduced-motion preferences are respected by `web/styles/dashboard.css`.
- Keep the sample and first-run actions usable at laptop width and stack the landing steps and filters on small screens.

The host app still owns live loading and request-error states. It should render the existing `FailureState` component for failed loads and announce a concise loading status while the request is pending.
