# Refactoring status

## Implemented in the first pass

- Shared atomic engagement creation, including lead membership and activity.
- Shared scope-lock validation and atomic finding review transitions for UI/API.
- Client finding visibility on API lists, details, evidence and summary counts.
- Cross-engagement reassignment blocked for findings and credentials.
- Internal-only host/vault lists and lead-only engagement deletion.
- Recon result persistence extracted from views for use by workers.
- Protected report storage with an existing-file migration and conflict checks.
- Persistent engagement workspace navigation, an actionable overview, retest
  outcome filters, responsive cards and visible keyboard focus.
- Demo environment example with documented clean-install settings, localhost binding, explicit account
  bootstrap, build exclusions for evidence and virtual environments.
- Dependency constraints snapshot, isolated test settings, CI and a release test gate.

## Implemented in the UI pass

- Replaced overview card rows with a work list and a contextual summary rail.
- Reorganized the dashboard around primary queues and secondary activity.
- Flattened finding prose into a readable document and reorganized the editor.
- Removed duplicated engagement navigation from the sidebar; preserved one
  role-aware workspace bar, including on finding details.
- Split large page templates into meaningful partials. The engagement page is
  now 29 lines, finding detail 68, finding form 54, and dashboard 25.
- Split the 2700-line shared stylesheet by responsibility, preserving cascade
  order; `main.css` now contains 118 lines of tokens/reset/utilities.
- Extracted shared shell/tabs and finding detail/editor JavaScript modules.
- Added keyboard tab navigation, menu focus handling, hash navigation, focus
  indicators and a skip link. Fixed narrow-screen finding form overflow.
- Added opt-in headless browser checks at desktop and mobile widths, including
  editor interactions, client navigation and empty states.
- Validated all 80 templates and production static-file processing.
- Fixed API key parsing for generated prefixes containing underscores, found
  during final regression verification; added deterministic coverage.

See [frontend structure](FRONTEND.md) for file ownership and verification commands.

## Remaining work

1. Report revision provenance, source snapshots and content hashes. Client access
   now requires explicit lead publication of each PDF; see LOGIC_REVIEW.md.
2. Methodology-to-finding/evidence links and test-case coverage history.
3. Append-only retest attempts with evidence, plus a shared UI/API retest operation.
4. Explicit scanner policy for internal networks, in-flight cancellation and
   structured time-window/RoE restrictions. Target scope enforcement is implemented;
   see [scanner scope](SCAN_SCOPE.md).
5. Bulk actions, saved filters, notifications and integration delivery/retries.
6. Extract remaining mutation logic and query duplication incrementally.
7. Production deployment profile, explicit one-shot initialization, shared cache,
   background report generation, worker health checks and restore verification.
8. Broader accessibility checks and browser coverage for other pages, long content,
   dialogs, and edge cases. Consolidate inherited theme overrides incrementally.

## Validation

Run `python manage.py test --settings=vulnex.test_settings` and
`python manage.py makemigrations --check --dry-run --settings=vulnex.test_settings`.
The test configuration supplies disposable storage and a test-only vault key;
it must never be used to run a deployed instance.


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


## Logic review

See [LOGIC_REVIEW.md](LOGIC_REVIEW.md) for confirmed fixes, rollout notes and the
remaining feature gaps. Existing reports now require explicit publication before
clients can access them. Narrative edits invalidate finding review approval.


## Scanner enforcement and panel fix

- Shared execution-time scope validation covers manual, queued, scheduled and
  pipeline scans, including discovered targets and resolved-IP exclusions.
- Pipeline errors produce failed status; skipped targets expose their reasons.
- The shared shell owns the New scan panel toggle; recon JavaScript only manages
  preset descriptions. Scope guidance uses theme text and background colors.
- Browser checks cover panel toggling, text/link contrast and horizontal overflow
  at desktop/mobile widths. See [scanner scope](SCAN_SCOPE.md) for operating limits.
