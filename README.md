# Vulnex

[![Tests](https://github.com/jawad-salem/Vulnex/actions/workflows/tests.yml/badge.svg)](https://github.com/jawad-salem/Vulnex/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Django 5.x](https://img.shields.io/badge/django-5.x-092e20.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A full-featured penetration testing workflow platform built with Django. Manage engagements, track vulnerabilities, run reconnaissance scans, follow testing methodologies, and generate professional PDF reports — all from a single dark-themed interface.

## Why Vulnex?

Most open-source tools in this space are one slice: reporting (Dradis, PwnDoc) or vulnerability databases (DefectDojo). Vulnex is a **pentest workbench** — the full loop, from engagement kickoff to retest closure, in one app:

- **End-to-end workflow** — engagement → recon → methodology → findings → peer review → PDF → retest
- **Integrated recon with scheduling** — Celery-backed scan pipelines, not just ingestion of scanner output
- **First-class peer review** — findings move `DRAFT → IN_REVIEW → APPROVED` before clients see them
- **Encrypted credentials vault** — Fernet at rest with a dedicated `VAULT_MASTER_KEY`, audit-logged reveals, role-gated access
- **REST API + OpenAPI docs** — JWT or long-lived API keys; every UI capability is scriptable
- **Modern UI** — dark terminal aesthetic, designed rather than Bootstrap-defaulted

## Known limitations

Things this project intentionally does **not** do — call these out so you can decide if Vulnex fits your workflow:

- **No multi-org SaaS tenancy.** Vulnex is single-tenant. Roles and per-engagement membership scope visibility within one deployment, but there is no "organization" boundary above that.
- **No mobile or native app.** Web only.
- **No compliance-framework auto-mapping** (no PCI / ISO / NIST / SOC 2 control linkage on findings).
- **No agent-based recon.** Recon scanners are network-based and run from the Vulnex host; there is no installable endpoint agent.
- **Red Team tooling is intentionally lightweight.** Attack-path mapping and credential capture are supported (see Features); BloodHound-style AD enumeration, C2 integration, and live session management are out of scope.
- **No production-grade Jira / GitHub Issues sync** yet — see Roadmap.

## Features

### Engagement Management
- Create and track pentest engagements with scope, phases, and timelines
- **Client model** — engagements roll up under a `Client` record (logo, contacts, notes); per-client dashboard aggregates findings-by-severity and SLA status across every engagement for that client
- Per-engagement team roles (Lead, Pentester, Reviewer, Client)
- Email-based invitation system with token acceptance
- Activity logging and audit trail
- Engagement types: Web App, Network, Mobile, API, Cloud, Social Engineering, Red Team, Physical, IoT, Wireless
- **Red Team attack-path mapper** — for `Red Team` engagements, build a DAG of nodes (entrypoints, hosts, identities, assets, objectives) connected by techniques with optional MITRE ATT&CK IDs; rendered in-browser as SVG and embedded in the Technical PDF report.

### Vulnerability Tracking
- Full CRUD for findings with CVSS v3.1 auto-calculation
- Structured location fields (host, port, URL, endpoint, HTTP method, parameter)
- **Markdown rendering** on `description`, `proof_of_concept`, and `remediation` fields, sanitised with `bleach` and rendered both in the UI and the PDF report. Live preview on the finding form.
- **Threaded comments** per finding with internal-only and "review feedback" visibility flags; clients never see internal threads
- **Scanner imports** with automatic dedup against existing findings (hash of `title + host + port + endpoint + parameter`):
  - **Nuclei** (JSON / JSONL)
  - **Nikto** (JSON)
  - **Burp Suite** (XML issue export)
  - **Nessus** (`.nessus` XML, plugin-level)
  - **OWASP ZAP** (JSON)
  - **Semgrep** (JSON, SAST)
- **CSV bulk import** — upload a CSV, preview row-level errors and duplicates, then commit (strict header validation; partial imports allowed)
- Evidence upload (images and files) per finding; downloads are gated through an authenticated view (no direct `/media/` URLs)
- Export findings to **CSV** or **JSON**
- Severity auto-assigned from CVSS vectors
- **Finding merge** — Lead and Reviewer can merge a duplicate finding into another; evidence, comments, and external references move with it; merge is audit-logged
- **SLA tracking** — severity-based remediation deadlines (Critical 7d / High 14d / Medium 30d / Low 60d / Info 90d) with overdue detection and dashboard widget
- **Finding assignment** — assign individual findings to team members; filter by assignee; personal "assigned to me" dashboard widget
- **Review workflow** — findings move DRAFT → IN_REVIEW → APPROVED before clients see them; reviewers and leads can approve or send back with feedback (CHANGES_REQUESTED)

### Credentials vault
- Store passwords, hashes, API tokens, SSH keys, and session cookies captured during an engagement
- Encrypted at rest with Fernet (AES-128-CBC + HMAC); only ciphertext hits the database
- Masked by default in the UI; one-click reveal is recorded to the engagement activity log
- Hidden from clients — only lead / pentester / reviewer roles can see the vault
- Link credentials to discovered hosts and track validation status (untested / valid / invalid / expired)

### Reconnaissance
- Built-in Python scanners (no external tools required):
  - **Port scanning** — threaded TCP connect scan with banner grabbing
  - **Subdomain enumeration** — DNS-based discovery
  - **Technology detection** — HTTP header/body analysis
  - **DNS enumeration** — A, AAAA, PTR records
  - **WHOIS lookup** — registrar, dates, nameservers
  - **Directory bruteforce** — common path discovery
- **Nmap XML import** for host/port discovery

### Methodology Checklists
- Apply testing methodologies (OWASP)
- Track checklist progress per engagement
- Status tracking: Not Started, In Progress, Completed, N/A

### Reporting
- PDF report generation via ReportLab:
  - **Full Report** — executive summary + scope + detailed findings + remediation
  - **Executive Summary** — high-level risk overview for management
  - **Technical Detail** — deep technical findings with PoC, CVSS vectors, and (for Red Team engagements) embedded attack-path diagrams
- **Customisable report templates** — `ReportTemplate` model with cover logo, primary/accent colours, preamble, disclaimer, and footer; assign a default template per Client; preview the cover before generating
- Filenames use RFC 5987 encoding so engagement names with quotes / Unicode round-trip safely

### Dashboard & Analytics
- Real-time stats: active engagements, findings by severity, urgent items
- Interactive charts (Chart.js): severity distribution, status breakdown, findings over time, top engagements
- Activity feed and recent engagement overview
- **Global search** — top-bar search across engagements, findings, hosts, and credentials. Postgres FTS-ranked when running on Postgres; SQLite falls back to `icontains`. Results are scoped by engagement membership — credentials are never surfaced to clients.

### REST API
- `/api/v1/` resources: engagements, findings, evidence, hosts, credentials (vault reveal gated identically to the UI), reports
- **Auth**: long-lived API keys (issue/revoke per user; only the prefix is stored, raw key shown once on issue) **or** JWT for SPA clients
- Reuses the same role decorators as the UI via DRF permission classes (`IsEngagementMember`, `IsEngagementEditor`, `IsEngagementReviewer`)
- Throttling: 1000 requests / hour / user (authenticated)
- **OpenAPI schema** at `/api/schema/`, **Swagger UI** at `/api/docs/`

### Access Control
- **Global roles**: Admin, Pentester, Reviewer, Client
- **Per-engagement roles**: Lead, Pentester, Reviewer, Client
- Client role restrictions: no access to Recon, Methodology, or Notes
- Reviewer role: read-only access to all sections including Recon
- Admin user management (create, edit, deactivate, delete users)
- Self-registration via invitation links — no public signup
- **TOTP multi-factor auth** — required for Admin, Pentester, and Reviewer roles; optional for Clients. Backup tokens issued on enrolment.
- **Login rate-limit & lockout** via `django-axes` (5 failed attempts per username+IP within 15 minutes → 30-minute lockout; lockouts written to the audit log)
- **Password policy** — Django's full validator stack (`MinimumLength`, `CommonPassword`, `NumericPassword`, `UserAttributeSimilarity`) enforced on every password-setting form
- **CSP, COOP, Referrer-Policy, Permissions-Policy** headers; `SameSite=Strict` session and CSRF cookies; HSTS toggled by `DJANGO_USE_HTTPS`
- **Audit log** covers logins, logouts, MFA events, password changes, credential reveals/creates/deletes, evidence downloads, report generation/download, invitation lifecycle, finding merges, and comment posts

## Screenshots

<details>
<summary>Dashboard</summary>

![Dashboard](docs/screenshots/dashboard.png)
</details>

<details>
<summary>Engagement Detail</summary>

![Engagement Detail](docs/screenshots/engagement-detail.png)
</details>

<details>
<summary>Finding Form with CVSS Preview</summary>

![Finding Form](docs/screenshots/finding-form.png)
</details>

<details>
<summary>Reconnaissance</summary>

![Recon Dashboard](docs/screenshots/recon.png)
</details>

<details>
<summary>Methodology Checklist</summary>

![Methodology](docs/screenshots/methodology.png)
</details>

> **To add screenshots**: Save your screenshots to `docs/screenshots/` and they'll render above.

## Tech Stack

- **Backend**: Django 5.x, Python 3.11+
- **Database**: SQLite (dev), PostgreSQL (prod) — Postgres unlocks FTS-ranked global search
- **API**: Django REST Framework + SimpleJWT, OpenAPI via drf-spectacular
- **Async tasks**: Celery + Redis (recon scans, scheduled jobs)
- **PDF Generation**: ReportLab
- **Charts**: Chart.js 4.x (CDN, allow-listed via CSP)
- **Auth & security**: `django-otp` (TOTP MFA), `django-axes` (lockout), `django-csp`, `cryptography` (Fernet vault)
- **Markdown**: `markdown` + `bleach` (sanitised allowlist)
- **Styling**: Custom CSS, dark cybersecurity theme
- **Containerization**: Docker + Docker Compose

## Quick Start

### Docker (recommended — three commands, ~60 seconds)

```bash
git clone https://github.com/jawad-salem/Vulnex.git
cd Vulnex
cp .env.example .env && docker compose up --build
```

When the logs settle, open <http://localhost:8000> and sign in with the bootstrap superuser:

| Username | Password |
|---|---|
| `admin` | `admin1` |

The entrypoint runs migrations, collects static files, seeds finding templates and OWASP methodology checklists, and creates that superuser only if no superuser already exists. Override the bootstrap creds via `DJANGO_BOOTSTRAP_USERNAME` / `DJANGO_BOOTSTRAP_PASSWORD` / `DJANGO_BOOTSTRAP_EMAIL` in `.env`.

> The shipped `.env.example` is dev-only — it pre-fills a known-bad `DJANGO_SECRET_KEY` and runs with `DJANGO_DEBUG=True` so a fresh clone boots without configuration. Rotate every value before exposing the instance to the public internet.

### Local Development

```bash
git clone https://github.com/jawad-salem/Vulnex.git
cd Vulnex

python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

pip install -r requirements.txt
cp .env.example .env

python manage.py migrate
python manage.py seed_templates
python manage.py seed_methodologies
python manage.py createsuperuser
python manage.py runserver
```

## Project Structure

```
Vulnex/
├── accounts/          # User model, auth, admin user management
├── dashboard/         # Dashboard views and analytics
├── engagements/       # Engagement CRUD, team management, invitations
├── vulns/             # Findings, evidence, import/export
├── recon/             # Scanners, Nmap import, host discovery
├── methodology/       # Testing checklists and progress tracking
├── reports/           # PDF report generation
├── vulnex/            # Project settings, URLs, admin config
├── templates/         # All HTML templates
├── static/css/        # Dark theme CSS
├── Dockerfile
└── docker-compose.yml
```

## Usage

### Initial Setup
1. Create a superuser with `python manage.py createsuperuser`
2. Log in and set your role to **Admin** via `/admin`
3. Seed finding templates: `python manage.py seed_templates`
4. Create other users via **Users** in the sidebar (or invite them to engagements)
5. Create your first engagement

### Typical Workflow
1. **Create engagement** — define scope, targets, dates
2. **Invite team** — add pentesters and reviewers via email
3. **Run recon** — use built-in scanners or import Nmap XML
4. **Track findings** — add manually or import from Nuclei/Nikto
5. **Follow methodology** — apply and track testing checklists
6. **Generate reports** — export PDF reports for clients
7. **Export data** — download findings as CSV/JSON

### Inviting Team Members
- Navigate to an engagement's detail page
- Use the invite form (visible to Leads only)
- If the email matches an existing user, they're added immediately
- Otherwise, an invitation email is sent with a secure token link
- New users can create their account directly from the invitation link — no admin intervention needed
- Accepting an invitation only grants access to **that engagement**; platform-wide role (Admin / Pentester / Reviewer / Client) is never changed by an invitation. Newly-created accounts default to the Client platform role and must be promoted by an admin via the Users page if they need wider access.

### Recon ↔ Findings
- Link findings to discovered hosts from recon
- Use finding templates (seed with `python manage.py seed_templates`) to auto-fill common vulnerabilities
- Live CVSS severity preview when creating/editing findings

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | `dev-insecure-key...` | Django secret key |
| `DJANGO_DEBUG` | `True` | Debug mode |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated host allowlist |
| `DJANGO_USE_HTTPS` | `False` | When `True`, enables HSTS and `Secure` cookies |
| `DATABASE_URL` | SQLite | Database connection string |
| `VAULT_MASTER_KEY` | — | **Required in production.** Fernet key (44-char base64) for the credentials vault. See [SECURITY.md](SECURITY.md) for generation and rotation. |
| `SITE_URL` | `http://localhost:8000` | Base URL for invitation links |
| `EMAIL_BACKEND` | Console | Email backend class |
| `EMAIL_HOST` | `smtp.gmail.com` | SMTP server |
| `EMAIL_HOST_USER` | — | SMTP username |
| `EMAIL_HOST_PASSWORD` | — | SMTP password |

## Roadmap

Tracked in detail in [`NEXT_STEPS.md`](NEXT_STEPS.md). Items still open:

- **SSO / OIDC** (NEXT_STEPS 2.7) — Azure AD / Okta / Google Workspace login via `mozilla-django-oidc`
- **Jira / GitHub Issues sync** (NEXT_STEPS 3.2) — push approved findings to an external tracker, poll for closure to flip status to `REMEDIATED`
- **Evidence annotation** (NEXT_STEPS 3.4) — draw rectangles and numbered callouts on image evidence, persist as a sibling JSON blob, rasterise into the PDF report
- **Retest scheduling automation** (NEXT_STEPS 3.5) — Celery beat reminders 7 days after a finding is marked `REMEDIATED`; auto-flip to `NOT_RETESTED` after 30 days

If you're considering Vulnex for a real engagement, also read **Known limitations** above.

## License

This project is open source and available under the [MIT License](LICENSE).
