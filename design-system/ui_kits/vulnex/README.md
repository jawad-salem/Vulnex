# Vulnex — UI kit

An interactive, click-through recreation of the Vulnex web app, composed
entirely from this design system's component primitives and tokens. It is a
**visual recreation**, not the real product — interactions are faked in memory.

## Run

Open `index.html`. It loads React + Babel, the compiled `_ds_bundle.js`
(two levels up at the project root), and `../../styles.css`.

> The bundle is regenerated automatically by the design-system compiler. If the
> screens render blank, the bundle hasn't been built yet — it appears after the
> next compile pass.

## Flow

`login → dashboard → engagements → engagement detail → findings → finding detail`

- **Login** — branded auth card (`auth-page` / `auth-card`), prefilled demo creds.
- **Dashboard** — stats grid, severity donut + findings sparkline, urgent-findings table.
- **Engagements** — list table; row click opens an engagement.
- **Engagement detail** — hero, `PhaseStepper`, `KpiStrip`, tabs (Overview / Findings / …), scope + quick-actions overview grid.
- **Findings** — filter bar + findings table with severity / status / review / SLA badges.
- **Finding detail** — hero with severity/status/review badges, CVSS KPI strip, tabbed body (Overview prose, Review approval).

## Files

| File | Role |
|---|---|
| `index.html` | Entry — loads bundle, CSS, and the babel scripts below |
| `icons.jsx` | `window.VIcon` — inline stroke icons faithful to the product |
| `data.jsx` | `window.VULNEX_DATA` — demo engagements + findings (mirrors `seed_demo`) |
| `Shell.jsx` | Sidebar + main-content layout (`window.Shell`) |
| `screens.jsx` | All screen components |
| `app.jsx` | In-memory router |

## Notes / faithfulness

- Real product uses **Chart.js** for charts; here they're lightweight CSS/SVG
  stand-ins so the kit has no chart dependency.
- Recon, Credentials, Methodology, Reports, Clients, Users, Audit are present in
  the nav but rendered as stubs — the kit focuses on the engagement → findings
  loop, which is the product's core.
