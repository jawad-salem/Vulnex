# Logic review - 2026-10-27

This is a focused source review of engagement confirmation, finding review,
report access, evidence uploads, methodology updates, and scanner dispatch.
It is not an exhaustive security audit or a production deployment certification.

## Confirmed issues fixed

| Priority | Finding | Result |
| --- | --- | --- |
| High | Client report preview and saved-report downloads could expose draft findings and internal report context. | Reports default to internal. A lead/admin must review and explicitly publish each stored PDF. HTML and API share membership-scoped visibility. Client live preview is blocked. Withdrawal removes subsequent client access. |
| High | Material edits to approved/in-review findings retained review status. | Normal model saves, including UI/API edits and merges, return changed narrative/location/CVSS content to draft and clear the current approval. Status and assignment alone do not revoke review. |
| High | API evidence upload bypassed the UI filename/extension/size rules. | API serializer reuses EvidenceForm validation. |
| Medium | Scope confirmation could race a stale edit. | Browser and API scope edits re-read the engagement under a transaction/row lock, as confirmation already does. |
| Medium | Methodology apply/update accepted GET and could create checklist records. | Mutation endpoints require POST. Report generation and engagement status updates also explicitly require POST. |
| Medium | Reopened checklist items retained completed_by/completed_at. | Leaving completed clears both fields. |
| Low | Invalid assignee IDs silently broadened the list. | IDs use the user FK's actual type; invalid IDs return no matches. Valid numeric IDs were already supported; the initial UUID diagnosis was incorrect. |
| Low | A missing stored PDF could raise a server error. | HTML and API downloads return 404; publication refuses a missing file. |
| Test reliability | Random Fernet keys starting with a hyphen could be parsed as CLI flags. | Rotation tests and command examples use --option=value syntax. |

Publication is approval of a specific PDF artifact, not a guarantee that its
source findings were individually approved. The UI tells the lead to inspect
that file, which can contain drafts and internal context. Existing reports become
internal after migration; no old report is silently published. Withdrawal cannot
recall an already downloaded copy.

## Scanner follow-up - 2026-10-28

Manual, queued, scheduled and pipeline scans now share execution-time scope
validation. Scope must be confirmed; exclusions take precedence. Pipeline
discoveries are filtered before dispatch, resolved addresses are checked against
exclusions, and failed steps mark the pipeline failed. The New scan panel now
uses the shared shell toggle only, fixing duplicate handlers that immediately
closed it again. Its scope guidance uses readable theme colors.

See [scanner scope](SCAN_SCOPE.md) for matching rules and limits. This is not an
egress firewall: changes do not cancel an already-running probe, and prose RoE
restrictions and engagement time windows are not automatically interpreted.
Existing private/reserved-IP restrictions on active probes remain in place.

## Outstanding gaps, ordered by impact

1. **Evidence-aware review revisions (high):** narrative edits now invalidate
   approval, but evidence additions/edits and direct QuerySet.update operations
   are not covered by the Finding.save guard. Immutable review revisions should
   bind approval to the complete narrative and evidence set, with historical
   reviewer decisions rather than only the latest decision.
2. **Retest history (medium):** finding retest fields represent only the latest
   attempt. Add append-only attempts with actor, date, outcome, notes and evidence,
   and share one validated operation across API and UI.
3. **Report revision provenance (medium):** publication is now gated, but reports
   need source revision IDs, version lineage and content hashes to explain what
   changed between published artifacts. Generation remains synchronous.
4. **Testing coverage semantics (medium):** methodology dashboard counts the
   library while engagement overview counts applied checklist records, and N/A
   is treated differently. Separate catalog browsing from applied coverage and
   link completed tests to findings/evidence.
5. **Red-team objective outcomes (medium):** connectivity proves a diagram has
   a route, not an objective was achieved. Add per-objective observed outcome,
   evidence, timestamps and detection/response observations; path publication
   remains separate future work.
6. **Concurrent editing and operations (medium):** add revision-conflict handling
   for stale editor submissions, cross-process rate limiting, scan retry/cancel
   semantics and deployment/restore verification. SQLite tests cannot prove
   PostgreSQL row-lock behavior under concurrent transactions.

## Validation and rollout

Regression coverage is in api/test_review_regressions.py and
reports/test_publication.py. Browser checks exercise publication/withdrawal and
all existing workspace screens at desktop/mobile widths.

Apply `python manage.py migrate` before starting this version. New migrations
add report publication metadata and its audit event type. Run `collectstatic`
for deployments with DEBUG disabled. Tests use temporary data/storage and do not
apply migrations to the user's database.
