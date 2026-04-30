# Vulnex — Next Steps

Goal: ship Vulnex as a serious solo OSS project on GitHub. Real tool, real users, recruiter-ready.

---

## TL;DR

**Do Weekend 1 first.** It is packaging only — no new features. By Sunday evening you have:
- A public live demo URL anyone can click.
- `docker compose up` works on a fresh laptop in 60 seconds.
- A README a recruiter reads on their phone.
- A green CI badge.

That single weekend is worth more than three feature weekends.

---

## Schedule at a glance

| Weekend | Tasks | What it ships |
|---|---|---|
| 0 | HF.1 → HF.6 | Hotfixes from live walkthrough: API schema, audit events, +New client, draft block, toasts, promote-to-finding |
| 1 | 0.1 → 0.7 | Packaging: Docker, demo data, README, CI, live demo, docs, license |
| 2 | 1.1 + 1.3 | OWASP/ATT&CK tagging · Bulk actions + kanban + shortcuts |
| 3 | 1.2 + 1.5 | DOCX export + report versions · Scope-warning system |
| 4 | 1.6 + 1.7 + 1.10 | Notifications · GitHub Issues sync · Reversible merge |
| 5 | 1.8 + 1.9 | Methodology↔Findings two-way · CVSS v4 |
| Stretch | one of 2.1 / 2.2 / 2.3 | Client portal · Google OIDC · Outbound webhooks |

**Note:** The recon execution backend (previously slotted as Weekend 4) is already shipped — `nmap` runs against real targets, returns ports, and promotes hosts. The remaining recon polish (promote-to-finding) is folded into hotfix HF.6.

Each task below follows the same shape: **Why** (1 line) · **Prompt** (paste into Claude Code) · **Files** · **Done when**.

---

# Weekend 0 — Hotfixes (live walkthrough findings)

Six small fixes for issues I hit while clicking through every module on 2026-04-28. All quick. Do these first if you can — they remove honest-bug embarrassment from the public repo.

## HF.1 Fix `/api/schema/` 500 (and unblock Swagger UI)
**Why:** `/api/schema/` returns HTTP 500 reproducibly, which makes `/api/docs/` render an empty white page. The README advertises the API; right now the docs surface is broken.
**Prompt:**
> `/api/schema/` is returning 500 Internal Server Error. Reproduce by visiting `http://127.0.0.1:8000/api/schema/` while logged in as admin. Check `python manage.py spectacular --validate --fail-on-warn` for the underlying error — it's almost certainly a `drf-spectacular` issue: a serializer with a circular reference, an undeclared `OpenApiTypes.UUID`, a `SerializerMethodField` without `@extend_schema_field`, or a view-set `@action` missing a return type. Fix every warning the validator surfaces. Confirm `/api/schema/` returns a 200 OpenAPI 3.0 document and `/api/docs/` renders the Swagger UI with all endpoints. Add a regression test that GETs `/api/schema/` and asserts 200.
**Files:** `vulnex/settings.py` (SPECTACULAR_SETTINGS), all DRF serializers + view-sets that the validator complains about, `api/tests.py`
**Done when:** `python manage.py spectacular --validate --fail-on-warn` exits 0; `/api/schema/` returns 200; `/api/docs/` shows the operation list.

## HF.2 Add finding-level audit events  ~~(skipped — covered by ActivityLog)~~
**Status:** Skipped on 2026-04-30. Every finding mutation already writes an `ActivityLog` row that surfaces in the engagement Activity tab: create (`vulns/views.py:429`), reassign on edit (`:462`), retest (`:153`), submit-for-review (`:520`), approve (`:548`), request changes (`:580`), delete (`:492`), merge (`:296`). Adding parallel `AuditLog` rows would duplicate the user-visible record without meaningfully improving forensics on a solo OSS project. Revisit if a multi-tenant/compliance use case appears.

## HF.3 Add "+ New client" affordance + Client create form
**Why:** Clients list page has no Add button. A client can only be created today as a side effect of typing a new name into the New-engagement form. There is no way to seed a client with a logo and primary contact email before opening the engagement.
**Prompt:**
> Add a `+ New client` button on `/engagements/clients/` (admin / lead only). It opens `/engagements/clients/new/` with a form: name (required), primary_contact_email, primary_contact_name, logo (FileField, PNG/JPG ≤ 1 MB, validated with PIL), notes (markdown). On save, redirect to the new client's detail page. Also add an `Edit` button on the client detail page that opens `/engagements/clients/<id>/edit/` with the same form. Audit-log creation and edits as `CLIENT_CREATED` / `CLIENT_UPDATED` (add to `AuditLog.Action`). Tests: create / edit round-trips, non-admin gets 403.
**Files:** `engagements/models.py` (add the new fields if missing), `engagements/views.py`, `engagements/forms.py`, `engagements/urls.py`, `templates/engagements/client_form.html` (new), `accounts/models.py`, `engagements/tests.py`
**Done when:** Clicking "+ New client" → fill form → save → land on the populated detail page; logo renders.

## HF.4 Block report generation when DRAFT findings exist
**Why:** Today the Generate PDF button is enabled even when every finding is still DRAFT. That produces a deliverable containing material the client should not see.
**Prompt:**
> On the report-generate form (`reports/views.py`, generate endpoint), check `engagement.findings.filter(status='draft').exists()` before rendering. If any drafts exist, return the form with a red banner: "N findings are still in Draft and would appear in this report." Disable the Generate button by default; show an opt-in checkbox: "Include drafts (internal use only — will appear watermarked DRAFT)." Only when the checkbox is ticked is the form submittable. When the override is used, audit-log a `REPORT_GENERATED_WITH_DRAFTS` event recording the count of drafts. Tests: an engagement with 1 draft refuses generation by default; with the checkbox ticked, generation succeeds and the audit event fires.
**Files:** `reports/views.py`, `reports/forms.py`, `templates/reports/generate.html`, `accounts/models.py`, `reports/tests.py`
**Done when:** Hitting Generate PDF on the Acme demo (5/5 drafts) shows the warning banner; ticking the override produces a watermarked PDF and an audit row.

## HF.5 Toast confirmations after POSTs
**Why:** Posting a comment, sending an invite, or saving a profile change all silently refresh the page. Users have no positive feedback that the action succeeded.
**Prompt:**
> Add a toast notification system using Django messages framework + a small vanilla-JS toast component in `templates/base.html`. Slide-in from the bottom-right, auto-dismiss after 4 seconds, ARIA `role="status"`. Wire `messages.success(request, ...)` calls to: post note, post comment, send team invite, save profile, save password, save engagement edit, save finding edit, generate report, issue API key, save report template, retest status update. Use `messages.error()` for failed POSTs (validation errors). Tests: a successful POST stores exactly one success message; a 400 stores exactly one error message.
**Files:** `templates/base.html`, `static/js/toasts.js` (new), `static/css/toasts.css` (new), every view that POSTs successfully (mostly add one `messages.success` line each), `core/tests.py` if a generic test makes sense
**Done when:** Posting a comment shows "Comment posted." in a green toast that fades after 4 s.

## HF.7 API access hardening
**Why:** During the 2026-04-30 walkthrough, a session-authenticated pentester could hit `/api/v1/...` *before* completing MFA setup, and any authenticated user (including clients/reviewers) could browse `/api/docs/` and the OpenAPI schema. Vulnex is an internal pentest tool, not a public developer API; the surface should be locked to the roles that actually use it programmatically.
**Prompt:**
> Four-part hotfix. (a) In `accounts/middleware.py`, replace the blanket `'/api/'` entry in `ALLOWED_PATH_PREFIXES` with only the bootstrap endpoints: `/api/v1/auth/token/`, `/api/v1/auth/token/refresh/`, `/api/schema/`. Session-authed users without confirmed TOTP must redirect to MFA setup; JWT/API-key clients (which hit the middleware as `AnonymousUser` because DRF auth runs after Django middleware) still pass through. (b) Add `api/permissions.py: IsStaffOrPentester`. Apply it to `SpectacularAPIView`, `SpectacularSwaggerView`, and the DRF router root so reviewers/clients get 403 on `/api/docs/`, `/api/schema/`, and `/api/v1/`. Block `role='client'` from every viewset. (c) Subclass `TokenObtainPairSerializer` to refuse tokens for users in `settings.MFA_REQUIRED_ROLES` who don't have a confirmed TOTP device — they must complete UI MFA setup before they can mint a programmatic token. (d) Set `REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES']` to `JSONRenderer` only when `DEBUG=False`; keep the browsable renderer only in dev. Tests for each: pre-MFA pentester redirected on `/api/v1/engagements/`, client gets 403 on `/api/docs/` and `/api/v1/findings/`, pentester without TOTP gets 401 from token endpoint with a clear message, browsable HTML disabled when DEBUG=False.
**Files:** `accounts/middleware.py`, `accounts/tests.py`, `api/permissions.py`, `api/views.py`, `api/urls.py`, `api/serializers.py` (new `MFAAwareTokenObtainPairSerializer`), `api/tests.py`, `vulnex/settings.py`
**Done when:** `python manage.py test` exits 0 and a logged-in non-MFA pentester redirects to `/accounts/mfa/setup/` when hitting `/api/v1/engagements/`; a logged-in client gets 403 on `/api/docs/`.

## HF.6 Promote scan result to finding
**Why:** Recon already runs nmap and persists results — but turning a discovered service into a draft Finding still requires manual entry. Closing this loop is the single biggest recon UX win.
**Prompt:**
> On each row of the Scans tab's result detail (e.g. `mariamhotel.com 3306/TCP`), add a "Promote to finding" button next to the existing "Promote to host" button. Clicking it opens the New Finding form with these fields pre-filled from the scan result: `host`, `port`, `service`, `version` (in the description), `discovered_host` (FK to the matching `DiscoveredHost`), `tool_source` (`nmap` / `httpx` / `nuclei`), and a default title (`<service> exposed on <host>:<port>` for nmap, `<template-id> on <url>` for nuclei). For nuclei results that carry a CVSS vector, paste it into the CVSS-vector-string field automatically. The user reviews and saves; the resulting Finding's `details` shows it was created from `ScanRun #<id>`. Tests: promote a sample nmap row, finding form opens with host + port pre-filled and the user can save without typing.
**Files:** `recon/views.py`, `recon/templates/recon/scan_detail.html` or wherever the result rows render, `vulns/views.py` (the new-finding view should accept GET-string pre-fill params), `vulns/forms.py`, `recon/tests.py`
**Done when:** On the existing Acme port-scan result, "Promote to finding" opens a New Finding form with `mariamhotel.com` and the relevant port pre-filled.

---

# Weekend 1 — Packaging

## 0.1 Docker Compose one-command setup
**Why:** "Clone and run" decides whether anyone bothers with your repo.
**Prompt:**
> Create `docker-compose.yml` at repo root with services: `web` (Django + Gunicorn on 8000), `db` (Postgres 16), `redis`, `worker` (Celery worker). Add `Dockerfile` (Python 3.12-slim, multi-stage, non-root user). Entrypoint runs migrations, collectstatic, creates `admin/admin1` if no superuser, then starts gunicorn. Add `.env.example` with every required env var. README must show `cp .env.example .env && docker compose up` produces a logged-in dashboard at http://localhost:8000 in under 60 seconds.
**Files:** `Dockerfile`, `docker-compose.yml`, `.env.example`, `entrypoint.sh`, `README.md`
**Done when:** Fresh clone → 3 commands → dashboard loads.

## 0.2 Seed demo command
**Why:** Empty UI on first run = bounce. Populated UI = engagement.
**Prompt:**
> Add `python manage.py seed_demo` (idempotent). Creates: 1 client (Acme Corporation), 2 engagements, 4 users (admin, pentester, reviewer, client) with simple passwords, 8 findings spanning all severities, evidence files (placeholder PNGs), 1 generated PDF report, populated audit + activity logs, recon hosts. Wire into Docker entrypoint so compose comes up populated.
**Files:** `core/management/commands/seed_demo.py`, `entrypoint.sh`
**Done when:** Re-running the command does nothing new; first run populates everything.

## 0.3 README rewrite
**Why:** README is the product page. Treat it like one.
**Prompt:**
> Rewrite `README.md` for a public OSS audience. Order: project name + tagline → hero GIF/screenshot → badges (CI, license, Python, Django, coverage) → 5-bullet feature summary → "Why I built this" (1 paragraph) → Quick start (3 commands) → demo credentials → live demo link. Then deeper sections: feature tour with 6–8 inline screenshots, architecture (1 paragraph + diagram link), API docs pointer, tech stack, roadmap link, contributing link, license. Cut every aspirational claim that isn't true today.
**Files:** `README.md`, `docs/screenshots/`, `docs/architecture.md`
**Done when:** A recruiter on a phone gets the gist in 30 seconds.

## 0.4 GitHub Actions CI
**Why:** Green badges signal "alive and tested."
**Prompt:**
> `.github/workflows/ci.yml` — on push and PR, Python 3.12, install requirements, run `python manage.py test`, `bandit -r . -x tests,migrations,staticfiles,.venv`, `pip-audit -r requirements.txt`, `ruff check .`, upload coverage to Codecov. `.github/workflows/release.yml` — on tag push, build and publish Docker image to GHCR. Add `requirements-dev.txt` with ruff. Add badges to README.
**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `requirements-dev.txt`, `README.md`
**Done when:** Push to main shows green check on the repo home.

## 0.5 Live demo + showcase mode
**Why:** Recruiters click links before they read.
**Prompt:**
> Deploy to Fly.io free tier (or Render). `fly.toml` checked in, free Postgres add-on, single web instance. Add `SHOWCASE_MODE=True` env flag that: resets the database every hour via cron, shows a banner "Public demo · resets hourly · do not enter real data", blocks outbound email, blocks new admin accounts, blocks API key creation. Document the live URL in README.
**Files:** `fly.toml`, `core/middleware/showcase.py`, `core/tasks/reset_demo.py`, `vulnex/settings.py`, `README.md`
**Done when:** Public URL works, banner is visible, demo logins work, hourly reset confirmed.

## 0.6 LICENSE + CONTRIBUTING + issue templates
**Why:** Without these the repo looks abandoned.
**Prompt:**
> Add `LICENSE` (MIT or Apache-2.0 — pick one, justify in README). `CONTRIBUTING.md` (dev setup, run tests, ruff style, branch and PR conventions, commit format). `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1). Sweep `SECURITY.md` for accuracy after MFA + API keys landed. `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md`.
**Files:** `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `.github/ISSUE_TEMPLATE/*`
**Done when:** Repo home shows the License badge and the "Contributing guidelines" tile.

## 0.7 Architecture doc
**Why:** Proves you can think about systems, not just ship features.
**Prompt:**
> `docs/ARCHITECTURE.md` — one page. App layout (each Django app in 1 line), data model (each core model + relationships in 3 bullets), request lifecycle (auth → RBAC → view → template), report-generation pipeline, API auth flow (JWT vs ApiKey). Include one Mermaid diagram inline.
**Files:** `docs/ARCHITECTURE.md`
**Done when:** Someone unfamiliar can locate any feature's code in under 60 seconds.

---

# Weekend 2 — Visible features

## 1.1 OWASP Top 10 + MITRE ATT&CK tagging
**Why:** Senior pentesters look for this on first browse. CWE alone is junior.
**Prompt:**
> Add two taxonomies to `Finding` and `FindingTemplate`. `owasp_top10` (JSONField) — choices for OWASP Web Top 10 2021 and API Top 10 2023. `attack_techniques` — M2M to a new `MitreTechnique` model (id like `T1190`, name, tactic, url). Management command `import_mitre_attack` pulls the MITRE STIX bundle and upserts. Multi-select on the finding form (vendored Tom Select, no CDN). Tag chips on list/detail and PDF report. Filter list by `?owasp=A03_INJECTION` and `?attack=T1190`. Templates pre-fill both taxonomies. Tests: tag round-trip, filter narrows, PDF renders chips.
**Files:** `vulns/models.py`, `vulns/forms.py`, `vulns/views.py`, `mitre/` (new app), `templates/vulns/`, `reports/generator.py`, `static/js/tom-select.js`
**Done when:** A finding can be tagged `A03_INJECTION` + `T1190`, both show as chips, both filter the list.

## 1.3 Bulk actions + kanban + keyboard shortcuts
**Why:** Visible in 10 seconds in a screenshot. Signals "real product."
**Prompt:**
> Three additions on the findings list. (a) Bulk action bar appears when rows are checked: Set severity / status / assignee / retest result, Add tag, Export selected (CSV/JSON). Server-side validates per-row permissions and audit-logs each change. (b) Kanban view at `/engagements/<id>/findings/board/` with columns Open · Confirmed · Submitted · Approved · Remediated · Risk Accepted. Drag-to-change-status via HTMX. Cards show severity chip, title, assignee, SLA pill. (c) Keyboard shortcuts: `g e/f/r/d` for nav, `n f` new finding, `?` help modal, `j`/`k` next/prev row.
**Files:** `vulns/views.py`, `vulns/forms.py`, `templates/vulns/{list,board}.html`, `static/js/{shortcuts,board}.js`
**Done when:** Selecting 3 findings + "Set severity to High" works; dragging a card on the board updates status; `?` shows the help modal.

---

# Weekend 3 — Reporting + scope

## 1.2 DOCX export + report versions
**Why:** Pentesters want a Word draft they can edit before sending.
**Prompt:**
> Add `python-docx` to requirements. Create `reports/generators/docx.py` mirroring the ReportLab generator. Use a base `.docx` template at `reports/templates/base_report.docx`. Format selector on the generate form: PDF (default) or DOCX. `Report.version` increments per regeneration; previous files persist under `reports/<engagement_id>/v<n>.<ext>`; report detail lists every version with download + generated-by + generated-at. Block report generation when any `Finding.status=DRAFT` exists unless user checks "Include drafts (internal use only)" — audit-log the override.
**Files:** `reports/{models,views,forms}.py`, `reports/generators/`, `reports/templates/base_report.docx`, `templates/reports/`, `requirements.txt`
**Done when:** Generating produces both PDF and DOCX; second generation creates v2; drafts block generation by default.

## 1.5 Scope-enforcement warnings
**Why:** Out-of-scope findings are a real-world legal liability. Surface them.
**Prompt:**
> When a host/URL/IP is added to a finding, evidence, credential, or scan run, check it against the engagement's in-scope and out-of-scope lists. Warn (don't block) when out-of-scope; require an explicit checkbox: "I confirm this target is outside the documented scope (will be flagged on the report)." Persist `Finding.out_of_scope_acknowledged_at`/`_by`. Show "Out of scope" badge on the row. Top-of-engagement banner when un-acknowledged out-of-scope findings exist. Block report generation only when un-acknowledged exist; offer "Acknowledge all" (lead/admin). Same check on importers — preview lists out-of-scope rows needing override.
**Files:** `engagements/models.py`, `vulns/{models,forms,views}.py`, `recon/tasks.py`, `templates/vulns/`
**Done when:** Adding `8.8.8.8` to a finding when it's not in scope shows a warning, requires explicit acknowledgement, badges the finding, and blocks the report until acknowledged.

---

# Weekend 4 — Workflow polish

## 1.6 In-app notifications
**Why:** People don't refresh dashboards; they want a bell.
**Prompt:**
> `Notification` model (recipient, kind, title, body, link_url, created_at, read_at). Triggers: assigned to a finding, finding submitted-for-review you must approve, SLA flips to Overdue on a finding you own, retest requested on a finding you authored, comment mentions you (`@username`), report ready. Bell icon top-right with unread count, dropdown shows last 10, full list at `/notifications/`. Per-trigger preferences at `/accounts/notifications/`. Email digests deferred. Tests: assignment creates exactly one Notification for the assignee.
**Files:** `notifications/` (new app), `notifications/{models,signals,views}.py`, `templates/notifications/`, `templates/base.html`
**Done when:** Assigning a finding to another user pops a notification on their bell within seconds.

## 1.7 GitHub Issues sync
**Why:** One tracker integration that everyone has. PRs welcome for others.
**Prompt:**
> Per-engagement GitHub config: `IntegrationConfig` (engagement FK, github_repo `owner/repo`, github_token_encrypted via `VAULT_MASTER_KEY`). "Push to GitHub" button on finding detail (Lead) creates an issue with title `[<severity>] <title>`, body containing description + PoC + remediation as markdown, labels `vulnex`, `severity:<level>`, optional `cwe:<id>`. Save `Finding.external_ticket_url`. Optional inbound webhook at `/integrations/github/webhook/<config_id>/` flips `Finding.status=REMEDIATED` when the issue closes. README: "GitHub Issues today; PRs welcome for other trackers."
**Files:** `integrations/` (new app), `integrations/{models,github,views}.py`, `templates/integrations/`
**Done when:** Pushing a finding to a real GitHub repo creates an issue with severity label and remediation body.

## 1.10 Reversible merge
**Why:** Merge today is destructive. Real teams undo merges.
**Prompt:**
> Make `Finding` merge reversible for 30 days. Instead of deleting the source, set `merged_into=<target>`, `merged_at=<now>`, `is_active=False`. List view excludes inactive by default. Target finding shows "Merged from N findings (split back out)". Split flow restores `is_active=True`, clears `merged_into`. Celery beat task hard-purges sources after 30 days (audit-logged). Add `AuditLog.Action.FINDING_SPLIT`. Surviving finding shows breadcrumb: "← merged in <id> on <date> by <user>".
**Files:** `vulns/{models,views,tasks}.py`, `vulns/migrations/`, `templates/vulns/detail.html`
**Done when:** Merging A into B, then "Split back out" within 30 days, restores A intact.

---

# Weekend 5 — Domain depth

## 1.8 Methodology ↔ Finding bidirectional
**Why:** Coverage % is the metric senior pentesters report on.
**Prompt:**
> `MethodologyItem` gains a M2M `findings` to `Finding`. On the methodology page, each WSTG item shows: status pill, "covering findings" list (links), and "Mark covered by finding…" picker. On finding detail, "Methodology coverage" section shows which checklist items the finding satisfies, with add/remove. Coverage % shown on the engagement summary. Stay WSTG-only.
**Files:** `methodology/{models,views}.py`, `vulns/views.py`, `templates/methodology/`, `templates/vulns/detail.html`
**Done when:** Marking a WSTG item as covered by Finding X shows the link both ways and bumps the coverage %.

## 1.9 CVSS v4.0
**Why:** v4 is in active rollout. Easy win that reads as "current."
**Prompt:**
> Add `Finding.cvss_v4_vector` and `Finding.cvss_v4_score`. Engagement-level `cvss_default_version` setting (`3.1` default, switchable to `4.0`). Finding form shows both calculators (vendor FIRST's CVSS v4.0 calculator JS locally). Severity ladder uses v4 score when present, falls back to v3. PDF/DOCX renders both vectors when both populated. CSV export gains v4 columns.
**Files:** `vulns/{models,forms}.py`, `vulns/migrations/`, `static/js/cvss4.js`, `templates/vulns/`, `reports/generators/`
**Done when:** A finding can carry both v3 and v4 vectors; severity uses v4 when set.

---

# Stretch — pick at most one

## 2.1 Client Portal
**Why:** Currently the Client role sees a stripped admin shell. A real portal closes that gap.
**Prompt:**
> Separate UI at `/portal/`. Own base template, trimmed nav, lighter chrome, client logo. `RetestRequest` and `RiskAcceptance` models. Read-only finding list (only submitted findings, internal comments hidden). "Request retest" and "Request risk acceptance" buttons. Report download with "CLIENT COPY — <client>" watermark. Middleware redirects `role=CLIENT` from non-`/portal/` URLs to `/portal/`.
**Files:** `portal/` (new app), `vulns/models.py`, `accounts/middleware.py`, `templates/portal/`, `vulnex/urls.py`
**Done when:** A client user only ever sees `/portal/`; admin URLs return 403.

## 2.2 Google OIDC
**Why:** SSO at all is a nice-to-have for people who use Google for everything.
**Prompt:**
> Add `mozilla-django-oidc`. Wire OIDC for **Google Workspace only** (env vars `OIDC_RP_CLIENT_ID`, `OIDC_RP_CLIENT_SECRET`). Disable when env vars unset. JIT provisioning: first login creates user; role defaults to `pentester` (admin must promote). Local password login stays available. Document Google Cloud setup in `docs/SSO.md`. No Entra, no Okta, no SAML.
**Files:** `vulnex/settings.py`, `accounts/auth.py`, `accounts/urls.py`, `requirements.txt`, `docs/SSO.md`
**Done when:** Setting the two env vars enables a "Sign in with Google" button.

## 2.3 Outbound webhooks
**Why:** Lets a forker pipe events into Discord/Slack themselves.
**Prompt:**
> One webhook per engagement. `Webhook` model (engagement FK, url, secret, events multi-select). Events: `finding.submitted`, `finding.approved`, `finding.remediated`, `report.generated`. Sign payload HMAC-SHA256 in `X-Vulnex-Signature` header. Single delivery attempt — no retry queue, no delivery log UI. Document the payload schema in `docs/WEBHOOKS.md`.
**Files:** `webhooks/` (new app), `webhooks/{models,signals}.py`, `docs/WEBHOOKS.md`
**Done when:** Approving a finding fires a signed POST to the configured URL.

---

# After every task

```bash
python manage.py test
python manage.py check --deploy
bandit -r . -x tests,migrations,staticfiles,.venv
pip-audit -r requirements.txt
ruff check .
```

Then a CHANGELOG entry under the next version header, and a screenshot in `docs/screenshots/` if it's user-visible.

---

# CV line (when Phase 0 + Weekend 2 are done)

> **Vulnex** — Open-source pentest workflow platform (Django + REST API). Engagement lifecycle, finding management with CVSS + CWE + ATT&CK tagging, brand-kit reports, credential vault, MFA + API keys, recon orchestration. Live demo · GitHub: <link>.

Update this line as you ship more. Don't list features that aren't in the repo yet.