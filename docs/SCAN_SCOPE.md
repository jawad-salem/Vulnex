# Scanner scope

Confirm and lock an engagement's scope before running scans. Confirmation records
internal approval of scope; the external authorization document remains the source
of client authorization. Completed and cancelled engagements cannot run scans.

## Targets and matching

Each scan accepts one hostname or IPv4 address. URL, host:port, wildcard, IPv6 and
CIDR scan targets are rejected because the current engines scan whole hosts.

Scope entries are one per line. Blank lines and lines beginning with `#` are ignored.
Malformed rules block scanning rather than being silently ignored.

| Scope rule | Meaning |
| --- | --- |
| `example.com` | Exact hostname only; does not include subdomains. |
| `*.example.com` | Descendant hostnames; does not include the apex `example.com`. |
| Individual IP or canonical CIDR | Authorizes matching individual IP targets, not batch CIDR scans. |
| HTTP(S) URL | Does not authorize host-wide scans; URL exclusions conservatively exclude the entire hostname. |

Hostnames are normalized for case, trailing dots and internationalized names.
An IP allowlist does not implicitly authorize hostnames resolving into that range.
Add both the apex and wildcard if both are authorized. Out-of-scope rules always
win, including IP/network exclusions checked against resolved addresses. A port-
limited rule cannot grant permission for an engine that scans other ports.

## Execution and limitations

Manual submissions, schedules and pipeline submissions validate scope before
acceptance. Workers re-read scope at execution; paused/reopened or changed scope
can therefore block an already-queued job. Pipeline steps recheck scope and filter
discovered targets before dispatch. Skipped candidates show their reason, and a
failed scan step marks the pipeline failed.

- A running scanner uses its current policy snapshot. Changing scope does not
  cancel an already-running probe; subsequent dispatches recheck the current scope.
- Existing private/reserved-IP restrictions on active probes remain. Listing an
  internal address in scope does not override those restrictions.
- DNS/WHOIS infrastructure requests are not a general network egress firewall.
- Prose RoE restrictions and engagement time windows are not automatically enforced.
- URL/path/port-limited scans, IPv6 targets and batch CIDR scans are unsupported.

## Verification and rollout

Run with the project's virtual environment:

```powershell
.\myvenv\Scripts\python.exe -B manage.py test --noinput --settings=vulnex.test_settings
.\myvenv\Scripts\python.exe -B scripts/ui_checks.py
.\myvenv\Scripts\python.exe -B manage.py makemigrations --check --dry-run --settings=vulnex.test_settings
```

Tests use disposable data and mocked scan execution; no real targets are scanned.
The browser suite checks panel opening/closing, text/link contrast and overflow at
1920, 1440, 390 and 320 pixels. The scanner follow-up adds no database migrations;
apply any pending migrations from the earlier application changes before deployment.

Restart Django and all Celery workers to load the new execution policy. Restart
Celery Beat if running it as part of the deployment restart. For Docker Compose,
rebuild the application image and recreate the web/worker/beat services. For a
local setup, stop and relaunch the existing server and worker processes using the
same environment and broker configuration. The worker command is
`celery -A vulnex worker -l info`.

For production static files, run `python manage.py collectstatic --noinput` using
the production environment, then hard-refresh the browser. Development `runserver`
with DEBUG enabled normally serves static source files without collectstatic.
