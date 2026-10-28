# Architecture

Vulnex is a modular Django application with server-rendered templates and a DRF
API. PostgreSQL is used in Compose; SQLite is supported for local development.
Redis carries Celery tasks. The same application image runs the web server,
worker and scheduler.

## Domain boundaries

| App | Responsibility |
| --- | --- |
| accounts | Users, MFA, API keys and audit events |
| engagements | Clients, engagement scope, membership, invitations and attack paths |
| vulns | Findings, evidence, review, comments, imports and merging |
| recon | Discovered hosts, scans, schedules and pipelines |
| methodology | Methodology templates and engagement checklist progress |
| credentials | Encrypted credential storage and audited reveal |
| reports | Report branding, PDF generation and stored reports |
| dashboard | Cross-engagement summaries and search |
| api | HTTP serialization, authentication and permissions |

## Request and task boundaries

Browser and API requests authenticate independently and apply engagement
membership permissions. Views handle HTTP input/output. Shared operations live in
services; read models for the workspace live in selectors.

- `engagements/services.py`: atomic engagement creation with lead membership and
  activity; signed-off engagement edit validation.
- `engagements/selectors.py`: scope, testing, review and retest work queues.
- `vulns/services/workflow.py`: finding visibility and atomic review transitions.
- `vulns/services/imports.py` and `merge.py`: import and merge operations.
- `recon/services.py`: host-result merging used by views and Celery workers.

This separation is incremental. Other mutations still live in views. See
[refactoring status](REFACTORING.md) for remaining boundaries to extract.

## Roles and review

Global admins can access all engagements. Other users receive lead, pentester,
reviewer or client roles per engagement. Clients see approved findings; recon
and the credential vault are internal sections.

Review follows draft/changes requested ? in review ? approved/changes requested.
Editors submit; leads and reviewers review. The shared transition service checks
permissions and state under a database row lock and records an activity event.
The API cannot write review state through ordinary finding updates.

The browser uses session authentication, CSRF and the OTP login flow. MFA
middleware enforces enrollment for configured roles. JWT issuance currently
checks enrollment, not a fresh OTP challenge. API keys and JWTs are authenticated
by DRF after Django middleware. These mechanisms should not be described as
identical MFA guarantees.

## Files and reports

Public media stores assets such as client and report-kit logos. Evidence and
report PDFs live under `PROTECTED_MEDIA_ROOT` and are downloaded through
membership-checked views. Migration `reports.0003` relocates existing report
files; follow the upgrade instructions in the README.

PDF generation uses ReportLab and runs synchronously. Each generation creates a
Report row and a file. There is no explicit revision or publication model yet:
existing reports are available to engagement members, and generated content may
include draft findings. Protected storage is separate from publication policy.

## Frontend

Django templates share `templates/base.html`, workspace navigation, and CSS.
The engagement overview presents scope sign-off, methodology progress, findings
awaiting review and remediated findings awaiting a first retest. Vanilla JS
supports tabs, previews and the attack-path editor. There is no SPA framework.

See [frontend structure](FRONTEND.md) for template, CSS and JavaScript ownership,
and for the optional real-browser checks.

## Deployment and tests

Compose starts PostgreSQL, Redis, Gunicorn, a Celery worker and Celery beat.
The entrypoint runs migrations, collects static files and seeds reference data.
Demo data is opt-in; automatic superuser creation requires an explicit password.
Compose binds port 8000 to localhost by default.

`requirements.lock` records development dependency versions and is applied as
constraints. CI tests Python 3.12 and 3.14 on Linux, checks migration consistency,
and gates tagged image releases. `vulnex.test_settings` provides a temporary
SQLite database, disposable file directories, and a test-only vault key.

The current Compose configuration is intended for local use. A production profile,
shared cache, dedicated initialization job, background report generation and
backup/restore verification remain follow-up work.
