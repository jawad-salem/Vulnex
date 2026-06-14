# Vulnex Design System

A design system distilled from **Vulnex** — an open-source penetration-testing
workbench that runs the whole engagement loop in one app: *engagement → recon →
methodology → findings → peer review → PDF report → retest*.

The aesthetic is a **dark "cybersecurity terminal"**: near-black GitHub-dark
surfaces, a single violet brand accent used sparingly, a five-step severity
color ramp doing most of the communicative work, and monospace as a load-bearing
signal for any machine text (hosts, ports, CVSS vectors, scores, scan counts).
Depth comes from 1px borders and subtle background steps — almost never from
drop shadows.

## Sources

This system was reverse-engineered from a real codebase. If you have access,
explore it to design with higher fidelity:

- **GitHub:** https://github.com/jawad-salem/Vulnex
  - `static/css/main.css` — the product stylesheet (source of truth for tokens & components)
  - `templates/` — server-rendered Django HTML (screens)
  - `docs/screenshots/` — reference renders of every view
  - `README.md` — product overview, feature tour, tech stack

Vulnex is a vanilla Django 5 app, server-rendered HTML with a little vanilla JS
(CVSS calculator, attack-path SVG renderer, Markdown preview) and Chart.js for
dashboard charts. No SPA framework. The components in this system are fresh React
recreations of that visual language — they are not the product's real code.

---

## CONTENT FUNDAMENTALS

How Vulnex writes copy. Match this voice when generating product UI text.

- **Voice:** precise, operator-to-operator, unfussy. Written by and for
  pentesters. Confident but never marketing-fluffy. "What I wanted on my own
  engagements."
- **Person:** UI labels are impersonal nouns/verbs ("Add finding", "Import",
  "Generate report"). Prose docs use first person for rationale ("Why I built
  this") and second person for instructions ("Rotate every secret before…").
- **Casing:** **Sentence case** for buttons, page titles, card titles and
  nav ("New engagement", "Report templates", "Findings over time"). **UPPERCASE
  with letter-spacing** only for tiny eyebrow labels — stat labels, table
  headers, form field labels, section kickers. Badges are uppercase.
- **Terminology:** domain-exact and consistent — *engagement, finding, severity,
  CVSS, SLA, review state, retest, recon, scope, rules of engagement,
  kill-chain, evidence*. Severity is always Critical / High / Medium / Low /
  Info. Statuses are Open / Confirmed / Remediated / Accepted / False positive.
- **Numbers & machine text:** rendered in monospace. CVSS to one decimal
  (`8.8`). Hosts as `dc01.internal.acme.example:88`. Dates as `Jun 10, 2026`
  / `Jun 10`. SLA as `Overdue 3d`, `14d left`, `Due Jun 24`.
- **Microcopy is terse and useful.** Empty states tell you the next action
  ("Add a finding manually or import from a scanner."), not platitudes.
  Helper text is a single clarifying line ("One target per line.").
- **Tone of warnings:** direct and security-serious, no alarmism — "Flip to
  False in any deployment a stranger can reach."
- **Emoji:** none. Not in product UI, not in copy. Status is carried by color +
  badges, never emoji.
- **Punctuation:** middot `·` as a meta separator, chevron `›` in breadcrumbs,
  en-dash in ranges, em-dash for asides. `$` prompt glyph in the terminal-style
  empty scope state.

---

## VISUAL FOUNDATIONS

### Color
- **Surfaces** step from near-black up: `#0d1117` (app canvas / inputs / code) →
  `#161b22` (sidebar, panels) → `#1f2638` (cards, buttons, chips) → `#252d42`
  (hover). The whole UI is dark; there is no light theme.
- **One brand accent:** violet `#7a60e0` (primary buttons, active nav, progress,
  focus). `#a28ff0` accent-light for links and hover fills. Tint
  `rgba(122,96,224,.12)` for active-nav backgrounds and focus rings. Accent is
  spent sparingly — most of the UI is neutral grey on dark.
- **Severity ramp is the loudest color:** Critical `#f05853`, High `#f09236`,
  Medium `#e3b341`, Low `#58a6ff`, Info `#8b949e`. Always shown as a tinted pill
  (15% alpha background + saturated text), never a solid fill.
- **Semantic:** success `#3fb950`, warning `#e3b341`, danger `#f05853`.
- **Text hierarchy:** primary `#e6edf3`, secondary `#8b949e`, muted `#484f58`.

### Type
- **Sans:** system UI stack (`'Segoe UI', -apple-system, …`) — fast, native,
  unbranded chrome. **Mono:** developer monospace
  (`'JetBrains Mono', 'Cascadia Code', 'Fira Code', …`).
- **Base is 13px** — this is a dense, information-rich product UI, not a
  marketing site. Scale: 28 (hero/stat) / 22 (page title) / 15 (card title) /
  14 (nav, emphasis) / 13 (body) / 12 (sub) / 11 (table header, badge) / 10
  (eyebrow). Weights 400/500/600/700.
- **Mono is semantic**, not just for code: any host, port, IP, CVSS vector,
  score, count or ID renders in mono. It's a core brand tell.

### Spacing, radii, borders
- Radii: 4px (chips/tags), **8px** (controls/nav), **12px** (cards/panels),
  20px (pill badges), 50% (avatars).
- Spacing is a 4px scale (4/8/12/16/20/24/32). Card padding 20px; layout gutter
  24×32px; sidebar 240px fixed.
- **Borders do the structural work:** 1px `#353c4a` default, 1px `#262c3a` for
  subtle row dividers. Active nav has a 3px accent left-rail.

### Elevation & depth
- **Shadows are rare.** Depth = border + background step. Shadow appears only on:
  focus ring (`0 0 0 3px` accent tint), the active phase-stepper dot glow
  (`0 0 0 4px` accent /20), and floating popovers (`0 14px 30px rgba(0,0,0,.55)`).

### Cards
- Bordered surface (`#1f2638`, 1px `#353c4a`, radius 12px, 20px padding). Stat
  cards lift `translateY(-2px)` and accent their border on hover. No gradients
  on standard cards (one subtle accent-tinted gradient exists on the *primary*
  quick-action only).

### Motion
- Fast and restrained: `0.15s` for most hovers/transitions, `0.2s–0.3s` for
  bars and toasts. Toasts slide in from the top and auto-dismiss after 5s.
  A couple of purposeful loops only: blinking terminal cursor in the empty-scope
  state, pulsing "live" dot in the scanner manifest, button spinner. No
  decorative bounce.

### Interaction states
- **Hover:** background lifts to `#252d42`; bordered elements gain an accent
  border; badges scale `1.05`; quick-actions nudge `translateX(2px)`.
- **Focus:** violet border + 3px accent-tint ring.
- **Active nav:** accent-tint background, accent-light text, 3px accent left-rail.
- **Loading:** primary buttons append a spinner and disable.
- **Disabled:** reduced opacity, no pointer events.

### Imagery & backgrounds
- No photography, no illustration, no hero imagery. The product is pure UI on
  flat dark surfaces. Texture is used sparingly and technically: a 45° dashed
  hatch behind the empty-scope state; dashed/dotted rules in the scanner
  "manifest" receipt; a corner-cut on that card. The kill-chain feature renders
  a hand-laid SVG DAG (nodes + technique edges), not a generated graphic.

---

## ICONOGRAPHY

- **Style:** Feather / **Lucide**-style line icons — 24×24 grid, 2px stroke,
  `fill:none`, round caps/joins, drawn in `currentColor`. They inherit text
  color, so they read as muted grey in nav and accent-light when active.
- **In the product** these are hand-inlined `<svg>` in the Django templates
  (sidebar nav: shield, layout-grid, briefcase, building, users, award/star,
  message-square; plus search, log-out, chevrons, hamburger). There is **no
  icon font and no sprite sheet** — just inline SVG.
- **The brand mark** is a shield outline (`M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10
  8 10z`) in accent-light, paired with the "Vulnex" wordmark in the sidebar and
  auth card. See `assets/vulnex-mark.svg` and `assets/vulnex-logo.svg`.
- **Substitution for this system:** because the originals are inline (not a
  shippable set), specimen cards and UI kits use **Lucide** — from CDN in the
  static cards, and as faithful inline React copies in `ui_kits/vulnex/icons.jsx`
  (`window.VIcon`). Lucide is the same family the product traced, so stroke
  weight and silhouette match. ⚠️ *Flagged substitution:* if you need byte-exact
  product icons, lift the `<svg>` paths straight from `templates/base.html`.
- **No emoji, ever.** No unicode dingbats as icons (only `›`, `·`, `×`, `$` as
  typographic glyphs).

---

## Fonts — substitution notice

⚠️ Vulnex ships **no bundled webfonts**; it relies on the OS UI sans (Segoe UI on
Windows) and whatever developer monospace is installed. For faithful, portable
rendering, `tokens/fonts.css` pulls **JetBrains Mono** (the last family in the
product's mono stack, and the closest freely-hostable match) from Google Fonts.
The sans stays as the native system stack. **If you have licensed Cascadia Code
or Fira Code files, drop them in and add `@font-face` rules to override.**

---

## Index / manifest

**Foundations & entry**
- `styles.css` — global entry point (import this one file). `@import`s fonts → tokens → base.
- `tokens/colors.css`, `tokens/typography.css`, `tokens/spacing.css`, `tokens/fonts.css` — design tokens.
- `base.css` — curated base + component classes (from the product stylesheet), consuming the tokens.
- `assets/vulnex-mark.svg`, `assets/vulnex-logo.svg` — shield mark + wordmark lockup.

**Specimen cards** (`guidelines/`, shown in the Design System tab)
- Colors: surfaces, accent, severity, semantic & text
- Type: families, scale, mono-in-use
- Spacing: radii, scale, elevation & borders
- Brand: logo, badges-in-use, iconography

**Components** (`components/<group>/` — React primitives, one card per group)
- `core/` — Button, Badge, Avatar, Card, StatCard
- `forms/` — Input, Select
- `navigation/` — Tabs, Breadcrumbs
- `feedback/` — Alert, ProgressBar, EmptyState
- `data/` — KpiStrip, PhaseStepper

**UI kit** (`ui_kits/vulnex/`)
- `index.html` — interactive click-through of the web app (login → dashboard → engagement → findings → finding detail). See its `README.md`.

**Reference** (imported from the repo, not part of the shipped system)
- `static/css/main.css`, `static/js/*.js`, `templates/*`, `docs/screenshots/*`.

**Skill**
- `SKILL.md` — makes this folder usable as an Agent Skill.
