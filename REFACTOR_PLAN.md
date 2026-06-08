# Vulnex — Architecture & UI Refactor Plan

Working plan from the codebase review. We walk these top-to-bottom. Each item has
a **goal**, the **files involved**, **steps**, and a **done-when** check. Tick the
box when complete. No behavior changes unless an item explicitly says so.

> Principle: every step should keep tests green and the app running. Refactor in
> small, verifiable commits — one plan item per commit where practical.

---

## Priority 1 — Extract a service layer for vulns imports/merge

**Goal:** Move domain logic out of the fat view module so views only orchestrate
HTTP. `vulns/views.py` is ~971 lines and currently *is* the import/merge engine.

**Files:** `vulns/views.py`, new `vulns/services/__init__.py`,
`vulns/services/imports.py`, `vulns/services/merge.py`, `vulns/tests.py`.

**Logic to move (currently in `vulns/views.py`):**
- `_merge_into(source, target, actor)` — [views.py:221](vulns/views.py#L221)
- `_classify_import(engagement, findings_data)` — [views.py:600](vulns/views.py#L600)
- `_commit_import(engagement, user, tool, new_items)` — [views.py:708](vulns/views.py#L708)
- `_parse_csv_findings(content)` — [views.py:745](vulns/views.py#L745)

**Steps:**
1. Create `vulns/services/` package.
2. Move merge logic → `services/merge.py`; import/CSV logic → `services/imports.py`.
3. Leave thin wrappers/imports in `views.py` so URLs/signatures are unchanged.
4. Update imports in `views.py` and `tests.py`.
5. Run the test suite.

**Done when:** view functions in `vulns/views.py` contain request/response
handling only; the four helpers live under `vulns/services/`; tests pass.

---

## Priority 2 — Move `markdown_to_platypus` out of the template layer + fix its bugs

**Goal:** PDF/ReportLab logic should not live in a templatetag. Also fix the
crash and dead code found in review.

**Files:** `vulns/templatetags/vulns_extras.py`, new `reports/markdown.py`
(or `reports/flowables.py`), `reports/generator.py`, `vulns/tests.py`,
`reports/tests.py`.

**Steps:**
1. Create `reports/markdown.py`; move `_PlatypusBuilder` and
   `markdown_to_platypus` there. Keep `render_markdown` + the `markdown` filter
   in the templatetag (that one genuinely is template rendering).
2. Update the import in [generator.py:28](reports/generator.py#L28).
3. **Fix the href-escaping crash:** anchor `href` is only `"`-escaped, so a URL
   containing `&`/`<`/`>` (e.g. `?a=1&b=2`) produces malformed ReportLab `<link>`
   markup and crashes PDF generation. XML-escape `&`, `<`, `>`, `"`.
4. **Remove dead code:** `_BLOCK_TAGS` (defined, never used) and `_in_thead`
   (written, never read).
5. **Collapse the dead `in_pre` branch** in `handle_data` (both arms are identical).
6. (Optional) Fix blockquote styling — inner `<p>` consumes the text so
   `quote_style` never applies.
7. Add a regression test: a finding description with a markdown link containing
   `&` must render to PDF without raising.

**Done when:** converter lives in `reports/`, the `&`-in-href case has a passing
test, dead code is gone, suite passes.

---

## Priority 3 — Stop tracking root artifact files

**Goal:** Remove working-dir noise from the repo root.

**Files:** `.gitignore`, root artifacts: `error.txt`, `server.err`, `server.out`,
`vulnex_mindmap.txt`, `Vulnex_Pentest_Report.pdf`, `EVALUATION.md`,
`CLAUDE.md` (decide: keep or ignore).

**Steps:**
1. Add patterns to `.gitignore` (`*.err`, `*.out`, `error.txt`, generated PDFs).
2. Decide per-file: ignore vs. move to a `scratch/` dir vs. keep intentionally.
3. Confirm none are currently tracked (they're untracked today — just ignore).

**Done when:** `git status` is clean of stray logs/artifacts.

---

## Priority 4 — Split monolithic test and CSS files

**Goal:** Make the two biggest files navigable.

### 4a. Tests → packages
**Files:** `vulns/tests.py` (1348 lines) → `vulns/tests/` package;
`accounts/tests.py` (641) → `accounts/tests/`.
- Split by concern: `test_imports.py`, `test_merge.py`, `test_views.py`,
  `test_models.py`, etc. Keep `__init__.py`.
- **Done when:** `manage.py test` discovers and runs the same set, all green.

### 4b. CSS → sectioned partials
**Files:** `static/css/main.css` (2543 lines).
- Either split into a few logical files (tokens, layout, components, pages) or
  enforce strict `/* ── SECTION ── */` banners and a table-of-contents header.
- No build step (keeps the no-build philosophy). If splitting into files, link
  each in `base.html` or use `@import`.
- **Done when:** stylesheet is sectioned/navigable; no visual regressions.

---

## Priority 5 — Tighten templates & fix doc drift

### 5a. Doc drift
**Files:** `docs/ARCHITECTURE.md` (lines ~19, ~57 reference `vulns/importers/`),
actual module `vulns/parsers.py`.
- Fix the doc to say `vulns/parsers.py` (reality wins), or rename the module.

### 5b. Fragile sidebar active-state logic
**Files:** `templates/base.html` (e.g. [base.html:46](templates/base.html#L46)).
- The `and`/`or` chains for nav highlighting rely on operator-precedence luck.
- Extract an `is_active` template tag or context helper; replace the inline
  multi-clause conditionals.
- **Done when:** nav active-state is computed in one place.

### 5c. Inline styles → utility classes (enables CSP hardening)
**Files:** templates with `style="..."`, `static/css/main.css`,
`vulnex/settings.py` CSP ([settings.py:192](vulnex/settings.py#L192)).
- Replace inline `style="grid-template-columns:..."` etc. with utility classes.
- Once inline styles are gone, drop `'unsafe-inline'` from `style-src`.
- **Done when:** no `style="..."` in templates; CSP `style-src` is `'self'` only;
  pages render unchanged.

---

## Priority 6 — Lower-urgency cleanups (do last / opt-in)

- [ ] Squash `accounts/` migrations (13, several repeated `alter_auditlog_action`).
- [ ] Split `vulns/parsers.py` so tool-parsers and CSV parsing are separate
      (folds into Priority 1's import service).
- [ ] Decide on light theme vs. dark-only (`:root` in main.css) — conscious choice.
- [ ] Add `ssl._create_unverified_context()` rationale comment in
      `recon/scanners.py` if not already obvious to readers.

---

## Progress tracker

- [x] P1 — vulns service layer (imports/merge) ✅ 114 vulns tests green
- [x] P2 — move `markdown_to_platypus` to `reports/` + fix href crash & dead code ✅ 23 tests green (+ href regression test)
- [x] P3 — gitignore root artifacts ✅ *.err/*.out/error.txt/EVALUATION.md/vulnex_mindmap.txt//*.pdf
- [~] P4 — SKIPPED (low value: pure file reorg, churns git blame, no behavior/arch change)
- [x] P5a — fix ARCHITECTURE.md `importers/` drift ✅
- [x] P5b — extract nav `is_active` helper ✅ {% nav_active %} tag, 6 unit tests, fixes precedence bug
- [~] P5c — SKIPPED. script-src already nonce-hardened (the part that matters);
      style-src 'unsafe-inline' can't be dropped without disproportionate rework
      because of data-driven inline styles (avatar colors, severity/risk meters,
      attack-path coords). Already documented at settings.py:183.
- P6 — lower-urgency cleanups:
  - [~] P6.1 squash accounts migrations — SKIPPED (deployed app; risk > value)
  - [x] P6.2 split vulns/parsers.py — N/A, already cohesive (CSV moved to services/imports.py in P1)
  - [~] P6.3 light vs dark theme — product decision; keep dark-only (no code change)
  - [x] P6.4 ssl._create_unverified_context() rationale comment ✅ added to scanners.py
