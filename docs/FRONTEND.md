# Frontend structure

Vulnex uses Django templates and small vanilla JavaScript modules. There is no
frontend build step. Shared styles are loaded in a defined order, then each page
loads its own layout styles through `extra_css`.

## Page composition

- `templates/base.html` is the application shell (51 lines). Sidebar, topbar,
  stylesheet loading, and engagement navigation live under `templates/includes/`.
- `templates/engagements/detail.html` composes the header, overview, scope,
  activity and team partials. The overview gives the work queue the main column
  and puts finding totals, the engagement brief and activity in a side column.
- `templates/dashboard/home.html` composes a compact summary, triage and
  engagement tables, with workload and activity in a side column.
- `templates/vulns/detail.html` composes overview, evidence, comments and activity
  panels. Finding prose is a continuous document; review/retest controls remain
  in the side column.
- `templates/vulns/form.html` composes basics, location, content, CVSS and metadata
  sections. Layout grids use classes rather than inline column definitions.

Partials own a meaningful section of a page. They are not separate applications:
the parent view supplies their context. Custom template tag libraries must be
loaded in the partial that uses them.

## Stylesheet ownership

`templates/includes/styles.html` defines the shared cascade. The initial split
preserves the previous source order to avoid changing unrelated pages. It reduces
file size for maintenance, not total CSS bytes. Some inherited theme overrides
remain and should be consolidated only with visual checks of affected pages.

| File | Responsibility |
| --- | --- |
| `main.css` | Design tokens, reset and small utilities (118 lines) |
| `shell.css` | Sidebar, topbar and application frame |
| `controls.css` | Typography, buttons, forms, badges and basic tables |
| `workflow.css` | Shared workflow, tabs, scope and legacy detail components |
| `data.css` | Grids, filters, scan feeds and empty/detail states |
| `content.css` | Prose, Markdown, pagination, breadcrumbs and error pages |
| `responsive.css` | Existing shared responsive rules |
| `imports.css` | Scanner import layouts and manifests |
| `theme.css` | Existing theme refinements, kept in cascade order |
| `console.css` | Shared console tables, signals, feeds and domain components |
| `workspace.css` | Workspace navigation, section/rail primitives and focus |
| `engagement-detail.css` | Engagement overview composition |
| `dashboard.css` | Portfolio dashboard composition |
| `finding-form.css` | Responsive long-form finding editor |
| `findings.css` | Finding narrative, side controls, evidence and discussion |

Keep page-specific layout rules in that page's stylesheet. Reuse a shared
component only when its behavior and meaning are actually shared. Use spacing,
headings and separators before adding another card. Keep CSS variables for theme
colors and use named classes for responsive grids.

## Interaction modules

- `shell.js`: mobile sidebar, focus handling, confirmation prompts, form loading,
  autosubmit controls, shortcuts, and the current workspace section.
- `tabs.js`: opt-in `[data-tabs]` containers with hash navigation, arrow/Home/End
  keyboard controls, roving focus and ARIA tab/panel relationships.
- `finding-detail.js`: evidence preview and upload interactions, inline PoC editor.
- `finding-form.js`: template/host autofill and CVSS calculation/parsing.
- `markdown_preview.js`: Markdown preview requests.

Pass server-generated URLs through data attributes rather than embedding Django
tags in JavaScript. Load scripts through the static template tag. Existing CSP
nonces remain where needed; do not add inline event handlers.

## Verification

Application tests:

```powershell
.\myvenv\Scripts\python.exe manage.py test --settings=vulnex.test_settings
```

Browser checks (optional development dependency):

```powershell
.\myvenv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\myvenv\Scripts\python.exe scripts/ui_checks.py
```

On Windows the script uses installed Microsoft Edge in headless mode. On other
platforms install Playwright Chromium with `python -m playwright install chromium`.
The script uses a temporary test database and file directories; it does not seed
or modify the application's database. Screenshots go to ignored `artifacts/ui/`.

The checks cover dashboard, engagement, finding detail/editor/list, reports,
recon and methodology at widths 1440, 390 and 320 pixels. They exercise tab
keyboard navigation, hash links, mobile menu focus, invite-panel expansion,
CVSS calculation, Markdown preview, client navigation and empty states. They
also fail on page overflow or browser console errors. This is focused interaction
coverage, not a complete accessibility audit or a pixel-diff baseline.


## Operator workflow refinement

- Engagement navigation: Overview, Scope, Assets & recon, Testing, Findings and
  Reports; Vault and red-team attack paths remain under More. Review and Retest
  are finding queues. Scope links retain keyboard-accessible hash navigation.
- My work defaults to assigned findings and provides paginated open, review and
  retest queues. Review/retest queues respect engagement roles. Dashboard reads
  live in `dashboard/selectors.py`; client counts exclude unpublished findings
  and client memberships do not expose internal activity.
- Neutral progress badges reserve strong colors for severity and overdue work.
  Finding titles wrap; compact metadata gives prose and evidence more room.
- The editor has section links, a persistent save bar and a native unsaved-change
  warning based on actual form values (including autofill). No draft persistence
  is introduced. Detailed CVSS metrics are expandable on the finding detail.
- Finding filters live in a partial and external JS. Pagination encodes search
  parameters correctly and filtered empty results offer a reset.
- Browser fixtures include 27 findings and long titles, second-page navigation,
  and dismissing the unsaved-change warning. Screenshots remain disposable.


## Reading density

Shared pages are bounded to 1360px, with tighter navigation and dashboard spacing.
Finding title, actions, metadata and provenance share one header surface. Narrative
sections use a consistent 20px rhythm; a 280px asset/workflow rail groups secondary
controls. Rail form fields stack so retest options remain readable. Browser checks
include 1920px desktop and the client finding view as well as smaller viewports.


## RoE and red-team workflow

RoE signing stays in the external document process. `authorization_reference`
records the document/version reference. The lead explicitly confirms scope and
locks edits; this is not a client signature. Confirmation requires targets, rules,
a reference and acknowledgement. Reopening requires a reason. Repeated requests
are idempotent; an audit event retains the scope, rules, reference and reason.
Existing locked engagements stay locked after migration; their reference remains
blank until a lead reopens and updates the record.

Attack paths are a primary red-team tab and overview task. Editors can rename
paths, refine narratives and link nodes to discovered assets in the engagement.
The detail page reports missing entry points, objectives and disconnected nodes;
connectivity does not assert testing success. New cycle-forming connections are
rejected, and legacy cycles no longer hang the renderer. The textual connection
list follows dependency order and includes accessible finding links. Clients do
not receive unpublished linked finding titles/IDs in the page or graph JSON.
Path publication/versioning and per-objective execution outcomes remain future work.

Apply the new migrations before running the updated application:
`python manage.py migrate`. Production static files also require `collectstatic`.
Validation uses the disposable test database; project data is not migrated by tests.
