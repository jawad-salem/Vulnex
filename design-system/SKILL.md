---
name: vulnex-design
description: Use this skill to generate well-branded interfaces and assets for Vulnex, either for production or throwaway prototypes/mocks/etc. Contains essential design guidelines, colors, type, fonts, assets, and UI kit components for prototyping. Vulnex is a dark-themed, open-source penetration-testing workbench (engagement → recon → findings → review → PDF report → retest).
user-invocable: true
---

Read the `readme.md` file within this skill, and explore the other available files.

If creating visual artifacts (slides, mocks, throwaway prototypes, etc), copy assets out and create static HTML files for the user to view. If working on production code, you can copy assets and read the rules here to become an expert in designing with this brand.

If the user invokes this skill without any other guidance, ask them what they want to build or design, ask some questions, and act as an expert designer who outputs HTML artifacts _or_ production code, depending on the need.

## Where things are
- `readme.md` — full design guide: content voice, visual foundations, iconography, fonts, and a file index. **Start here.**
- `styles.css` — single global entry point. Link this one file and you get all tokens, fonts, and base/component classes.
- `tokens/` — color, typography, spacing, font tokens (CSS custom properties).
- `base.css` — base + component CSS classes (`.btn`, `.badge`, `.card`, `.stat-card`, tables, tabs, forms, etc.) consuming the tokens.
- `guidelines/` — foundation specimen cards (small HTML).
- `components/` — React component primitives (`Button`, `Badge`, `Card`, `StatCard`, `Input`, `Select`, `Tabs`, `Breadcrumbs`, `Alert`, `ProgressBar`, `EmptyState`, `KpiStrip`, `PhaseStepper`). Each has a `.d.ts` and `.prompt.md`.
- `ui_kits/vulnex/` — interactive click-through recreation of the web app; the best reference for composing screens.
- `assets/` — shield mark + wordmark SVGs.

## Quick rules (see readme.md for the full set)
- **Dark only.** Surfaces `#0d1117`/`#161b22`/`#1f2638`; never a light theme.
- **One accent:** violet `#7a60e0`, used sparingly. Severity ramp (Critical/High/Medium/Low/Info) does most of the color work, always as tinted pill badges.
- **Mono for machine text:** hosts, ports, CVSS, scores, counts, IDs.
- **Depth from 1px borders**, not shadows. Cards: radius 12px, 1px border, 20px padding.
- **Sentence case** for UI; UPPERCASE+tracking only for tiny eyebrow labels; badges uppercase.
- **Lucide line icons**, 2px stroke, `currentColor`. **No emoji.**

## Building static HTML artifacts
Two ways to consume the system:
1. **Plain CSS** — link `styles.css` (adjust the relative path) and use the
   documented classes directly (`<span class="badge badge-critical">Critical</span>`).
2. **React components** — load React + Babel + `_ds_bundle.js`, then
   `const { Button, Badge } = window.<Namespace>` (run the design-system check to
   get the exact namespace). See any `components/*/*.card.html` for the pattern.

When copying this skill out for use elsewhere, also copy `_ds_bundle.js` (the
compiled component runtime) if you intend to use the React components.
