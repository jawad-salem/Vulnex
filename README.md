# Vulnex

A full-featured penetration testing workflow platform built with Django. Manage engagements, track vulnerabilities, run reconnaissance scans, follow testing methodologies, and generate professional PDF reports — all from a single dark-themed interface.

## Features

### Engagement Management
- Create and track pentest engagements with scope, phases, and timelines
- Per-engagement team roles (Lead, Pentester, Reviewer, Client)
- Email-based invitation system with token acceptance
- Activity logging and audit trail
- Engagement types: Web App, Network, Mobile, API, Cloud, Social Engineering, Red Team, Physical, IoT, Wireless
  > **Note:** Some engagement types (e.g., Red Team, IoT, Wireless) are included as labels for categorization. The platform's core workflow — findings, recon, methodology checklists, and reporting — applies to all types, but specialized tooling for certain engagement types (like Active Directory attack paths for Red Team) is not yet built in.

### Vulnerability Tracking
- Full CRUD for findings with CVSS v3.1 auto-calculation
- Structured location fields (host, port, URL, endpoint, HTTP method, parameter)
- Import from **Nuclei** (JSON/JSONL) and **Nikto** (JSON) with automatic deduplication
- Evidence upload (images and files) per finding
- Export findings to **CSV** or **JSON**
- Severity auto-assigned from CVSS vectors
- **SLA tracking** — severity-based remediation deadlines (Critical 7d / High 14d / Medium 30d / Low 60d / Info 90d) with overdue detection and dashboard widget
- **Finding assignment** — assign individual findings to team members; filter by assignee; personal "assigned to me" dashboard widget

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
  - **Technical Detail** — deep technical findings with PoC and CVSS vectors

### Dashboard & Analytics
- Real-time stats: active engagements, findings by severity, urgent items
- Interactive charts (Chart.js): severity distribution, status breakdown, findings over time, top engagements
- Activity feed and recent engagement overview

### Access Control
- **Global roles**: Admin, Pentester, Reviewer, Client
- **Per-engagement roles**: Lead, Pentester, Reviewer, Client
- Client role restrictions: no access to Recon, Methodology, or Notes
- Reviewer role: read-only access to all sections including Recon
- Admin user management (create, edit, deactivate, delete users)
- Self-registration via invitation links — no public signup

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
- **Database**: SQLite (dev), PostgreSQL (prod)
- **PDF Generation**: ReportLab
- **Charts**: Chart.js 4.x (CDN)
- **Styling**: Custom CSS, dark cybersecurity theme
- **Containerization**: Docker + Docker Compose

## Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/jawad-salem/Vulnex.git
cd Vulnex

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -e .

# Run migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Seed finding templates (optional)
python manage.py seed_templates

# Start the server
python manage.py runserver
```

### One-line setup

```bash
pip install -r requirements.txt && python manage.py migrate && python manage.py seed_templates && python manage.py seed_methodologies && python manage.py createsuperuser && python manage.py runserver
```

Then open http://localhost:8000 and log in with your superuser credentials.

### Docker

```bash
docker compose up --build
```

Then create an admin user:

```bash
docker compose exec web python manage.py createsuperuser
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
- Account role is automatically set based on the engagement role (e.g., invited as Client → Client platform role)

### Recon ↔ Findings
- Link findings to discovered hosts from recon
- Use finding templates (seed with `python manage.py seed_templates`) to auto-fill common vulnerabilities
- Live CVSS severity preview when creating/editing findings

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | `dev-insecure-key...` | Django secret key |
| `DJANGO_DEBUG` | `True` | Debug mode |
| `DATABASE_URL` | SQLite | Database connection string |
| `SITE_URL` | `http://localhost:8000` | Base URL for invitation links |
| `EMAIL_BACKEND` | Console | Email backend class |
| `EMAIL_HOST` | `smtp.gmail.com` | SMTP server |
| `EMAIL_HOST_USER` | — | SMTP username |
| `EMAIL_HOST_PASSWORD` | — | SMTP password |

## License

This project is open source and available under the [MIT License](LICENSE).
