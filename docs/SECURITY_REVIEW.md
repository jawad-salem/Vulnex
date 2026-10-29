# Security review - 2026-10-29

Source review covered web/API authentication, role and engagement boundaries,
client linkage, evidence/report access, Markdown/PDF rendering, scanner dispatch,
imports, exports, and deployment settings. This is a targeted review with regression
tests, not a certification that the application has no vulnerabilities. No live
scans or tests against external targets were performed.

## Patched findings

| Priority | Finding | Fix |
| --- | --- | --- |
| High | Default Django admin login bypassed the shared MFA flow; middleware checked enrollment alone. | Route admin login through the shared flow and reject enrolled browser sessions without actual OTP verification. |
| High | JWT login checked MFA enrollment without requiring proof. | Verify TOTP/backup code before issuing tokens, including users with optional MFA. Reject legacy tokens; bind new tokens to the verified device and current password. Apply the same checks on refresh. |
| High | Global pentesters could GET/POST unrelated client edit pages; linking a new engagement to a known client could grant lead visibility. | Scope edit lookup to visible clients; restrict existing client selection in UI/API to led clients or currently unassigned client records. Hide unrelated suggestions. |
| Medium | OTP verification loaded devices without row locks; pending password challenges had no expiry or password-change binding. | Transactional device locking, committed failure counters, five-minute signed challenge and password-state validation. Setup confirmation also locks its device. |
| Medium | Finding/audit CSV exports emitted attacker-controlled formulas. | Neutralize formula-leading text (including whitespace/full-width prefixes), retain standard CSV quoting; JSON preserves original content. Use safe export filename headers. |
| Medium | Scanner imports read entire uploads without a size bound. | Validate a 10 MB limit before XML/JSON parsing. |
| Medium | Credential API could reference another engagement's host. | Validate host ownership on create/update. |
| Hardening | Responses containing vault secrets, API keys, JWTs or MFA enrollment data lacked explicit cache prevention. | Add private/no-store response headers. |
| Dependency | Bleach 6.3.0 matched three OSV advisories, including the enabled email-linkification path. | Upgrade to 6.4.0 and disable automatic email linking; explicit Markdown mailto links remain supported. |

All 57 pinned runtime dependencies were queried against OSV after the upgrade;
no matching advisories were returned at review time. This is a known-advisory
check, not proof that dependencies are vulnerability-free.

## Validation and compatibility

Regression tests cover missing/invalid/replayed OTP, successful TOTP and single-use
backup codes, failed-attempt persistence, stale/password-changed challenges, legacy
JWT rejection, access/refresh invalidation, client isolation/linkage, credential
host ownership, CSV safety, upload bounds and cache headers. Existing tests also
exercise report/evidence permissions, sanitized Markdown and scanner scope.

Install `pip install -r requirements.txt -c requirements.lock` in the application
environment and restart web/Celery processes. No new database migration is required
by these security patches. Existing JWT callers must sign in again and supply
`otp_code` when enrolled. Separately issued API keys retain their existing lifecycle;
revoke them explicitly if compromised. Previous UI refinements are included in this
release; refresh production static files with `collectstatic --noinput`.

## Remaining operational limits

- SQLite tests do not prove concurrent PostgreSQL row-lock behavior. Verify that
  deployment uses transactional row-lock support for concurrent OTP requests.
- Refresh tokens rotate but are not individually blacklisted. Password changes
  invalidate access and refresh tokens; API keys must be revoked separately.
- Configure reverse-proxy upload limits/timeouts and a shared throttle cache for
  multiple workers. Form size limits do not prevent large bodies reaching the server.
- Existing scanner restrictions on private IPs and scope snapshot behavior remain.
- Evidence-aware immutable approvals, retest history and report provenance remain
  tracked in LOGIC_REVIEW.md.
- Spreadsheet sanitization changes dangerous CSV cells into text; spreadsheet
  re-saving may reinterpret them. Use JSON for lossless programmatic exports.
- HTTPS/proxy trust, backups, secret rotation and production infrastructure were
  reviewed as configuration, not tested against a deployed service.

## References

- [django-otp verification and transaction guidance](https://django-otp-official.readthedocs.io/en/stable/auth.html)
- [OWASP CSV injection guidance and limitations](https://owasp.org/www-community/attacks/CSV_Injection)
- [Bleach URI advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-8rfp-98v4-mmr6)
- [Bleach email-linkification advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-g75f-g53v-794x)
- [Bleach formaction advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-gj48-438w-jh9v)
