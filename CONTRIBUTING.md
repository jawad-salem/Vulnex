# Contributing to Vulnex

Thanks for your interest in Vulnex. This is a solo portfolio / educational project, but well-scoped pull requests, bug reports, and reviews are welcome.

Before opening anything substantial, please skim the [Roadmap](README.md#roadmap) and the open issues — there is probably already a thread for what you have in mind, and there are some directions I have decided not to take.

## Ground rules

- Be respectful. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- **Do not** open a public issue or PR for a security vulnerability. Follow the private process in [`SECURITY.md`](SECURITY.md) instead.
- Keep PRs focused. One logical change per PR — don't bundle a refactor with a feature with a dependency bump.
- A change without tests is usually a change I will ask you to add tests to. Match the style of the existing tests in the relevant app.

## Dev setup

```bash
git clone https://github.com/jawad-salem/Vulnex.git
cd Vulnex
cp .env.example .env

# Option A — Docker (closest to CI):
docker compose up --build

# Option B — Native (faster iteration):
python -m venv .venv
. .venv/Scripts/activate           # Windows
# . .venv/bin/activate             # macOS / Linux
pip install -r requirements.txt -r requirements-dev.txt
# Postgres + Redis still need to be running — easiest:
#   docker compose up db redis
python manage.py migrate
python manage.py seed_templates
python manage.py seed_methodologies
python manage.py seed_demo            # optional but recommended
python manage.py createsuperuser
python manage.py runserver
```

The first `docker compose up` takes a few minutes (multi-stage image build + initial migrate + seed). Subsequent starts are seconds.

## Running the checks

CI runs three jobs — lint, test, and security. Run them locally before pushing:

```bash
# Lint
ruff check .

# Tests + coverage (the same command CI runs)
coverage run manage.py test
coverage report

# Security (advisory — not blocking)
bandit -r . -x .venv,staticfiles,tests.py
pip-audit -r requirements.txt
```

`coverage` config lives in `pyproject.toml`. Ruff config lives there too — if a rule fires somewhere it shouldn't, prefer narrowing the rule with a `per-file-ignores` entry over `# noqa` comments scattered through the source.

## Code style

- **Python:** ruff is the source of truth. Line length is 120. We select `E`, `F`, `W` and ignore `E501` (long lines) and `E741` (single-letter names) — see `pyproject.toml`. We do not run black.
- **Imports:** standard library, then third-party, then local — one blank line between groups. Matches Django's own style.
- **Templates:** 4-space indent, no trailing whitespace, prefer template tags over inline JS. CSP is on, so any new `<script>` needs `nonce="{{ request.csp_nonce }}"`.
- **CSS:** single `static/css/main.css` file, organized by section comments. No frameworks — keep it hand-rolled.
- **Migrations:** every model change needs a migration committed in the same PR. Squash if you generated several while iterating.

## Branches and commits

- Branch off `main`. Name it after what you're doing: `fix/credential-export-csv`, `feat/jira-issue-sync`, `chore/bump-django-5.3`.
- Commit messages are lowercase, imperative, no scope prefix, no `Co-Authored-By` trailer:
  ```
  add jira issue sync for new findings
  fix off-by-one in attack-path edge ordering
  bump django to 5.2.13 for CVE-2026-XXXX
  ```
- Smaller commits are better than one giant "implement feature X" commit. Reviewers (and `git log`) are happier.

## Pull requests

- Open against `main`. Fill in the PR description: what changed, why, how you tested, and any screenshots if the UI moved.
- Make sure `ruff check .` and `coverage run manage.py test` pass locally before pushing.
- CI must be green before merge. If a check is flaky, please say so in the PR rather than hitting "re-run" in silence.
- Squash-merge is the default. Keep your branch's final commits clean — anything you don't want in `main` history should be squashed before review.

## Things I will probably push back on

These aren't hard "no"s but they need a strong case in the PR description:

- New top-level dependencies (every package is one more thing to patch and pip-audit).
- Frontend frameworks (React, Vue, htmx) — Vulnex is intentionally server-rendered Django + a single hand-rolled CSS file.
- Replacing the existing report engine, finding model, or auth stack.
- Features that only make sense for a paid SaaS deployment (multi-tenant billing, SSO with paid IdPs, per-seat licensing).

## Things I am happy to merge

- Bug fixes with tests.
- New scanner importers that follow the existing importer interface (`vulns/importers/`).
- Report template improvements and new export formats.
- Accessibility, keyboard, and dark-mode fixes.
- Documentation that an actual newcomer would benefit from.

Thanks for reading this far.
