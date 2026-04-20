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

## Credentials Vault Key Management

The credentials vault encrypts every stored secret (password, hash, API token, SSH key, session cookie) with a Fernet key. That key is supplied via the `VAULT_MASTER_KEY` environment variable — **it is NOT derived from `DJANGO_SECRET_KEY`** in production.

### Generating the key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the output (a base64url string, 44 characters) into your environment or secret manager as `VAULT_MASTER_KEY`.

### Behaviour

- `DJANGO_DEBUG=True` — `VAULT_MASTER_KEY` is optional. If unset, a key derived from `DJANGO_SECRET_KEY` is used and a warning is logged. Pre-1.2 development databases keep decrypting in this mode.
- `DJANGO_DEBUG=False` — `VAULT_MASTER_KEY` **must** be set. `python manage.py check --deploy` fails with `credentials.E001` if it is missing, and any encrypt/decrypt call raises `ImproperlyConfigured`.

### Rotation

To rotate the vault key (e.g. suspected compromise, compliance cadence, migrating off the pre-1.2 SECRET_KEY-derived key):

```bash
python manage.py rotate_vault_key --old-key <current-key> --new-key <new-key>
```

The command decrypts every `Credential.secret_encrypted` with the old key and re-encrypts it with the new one, all inside a single transaction. Any decryption failure aborts the rotation with no commits made.

After the command succeeds, update `VAULT_MASTER_KEY` in your environment to `<new-key>` and restart the app.

### Migrating from pre-1.2 installations

If you are upgrading a deployment that stored credentials under the SECRET_KEY-derived key, reproduce the old key first and pass it as `--old-key`:

```bash
OLD_KEY=$(python -c 'import base64, hashlib; from django.conf import settings; import django; django.setup(); print(base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest()).decode())')
python manage.py rotate_vault_key --old-key "$OLD_KEY" --new-key "$VAULT_MASTER_KEY"
```

Then deploy the new version with `VAULT_MASTER_KEY` set.
