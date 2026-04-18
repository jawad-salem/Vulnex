# Security Policy

Vulnex is a portfolio / educational project for managing penetration-testing workflows. It is not a hardened production system — see the caveats at the bottom of this document.

## Reporting a Vulnerability

If you find a security issue in Vulnex itself, please **do not open a public GitHub issue**. Report it privately so it can be fixed before anyone else learns of it.

- **Email:** jawadsalem12345@gmail.com
- **Subject line:** `SECURITY: <short description>`
- Please include: affected version / commit, reproduction steps, and (if known) a proposed fix.

I will acknowledge receipt within a reasonable time (this is a solo project, not a commercial product) and work with you on a fix and coordinated disclosure.

## Scope

In scope:
- Authentication, authorization, and session handling bugs
- Injection issues (SQL, template, command, XSS)
- Access-control bypasses between engagement roles
- Credentials-vault weaknesses (key derivation, encryption, audit gaps)
- Insecure direct object references in engagement / finding / report endpoints

Out of scope:
- Issues in third-party dependencies (report those upstream)
- Rate-limiting gaps in the dev server
- Missing headers in `DEBUG=True` configuration
- Social-engineering attacks against a running instance

## Production Caveats

This project is designed to showcase a pentest-workflow data model and UI, not to be deployed to the public internet as-is. Before any real-world deployment, at minimum:

- Set a strong `DJANGO_SECRET_KEY` and `DJANGO_DEBUG=False`
- Restrict `ALLOWED_HOSTS`
- Put Django behind a reverse proxy with TLS and an `X-Forwarded-For` policy
- Rotate the default PostgreSQL credentials in `docker-compose.yml`
- Review the `SITE_URL` used for invitation links
- Audit the credentials-vault Fernet key rotation strategy

These are not vulnerabilities — they are deployment responsibilities.
