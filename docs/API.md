# Vulnex REST API

All endpoints live under `/api/v1/`. Every request must be authenticated and
will be scoped to the caller's engagement memberships.

Interactive docs: **`/api/docs/`** (Swagger UI) — OpenAPI schema at `/api/schema/`.

---

## Authentication

Three options — pick whichever fits your client.

### API key (recommended for scripts / CI)

1. Create a key at **Profile → API keys → Manage API keys**.
2. Copy the raw key *immediately* — it is shown once and never stored in
   plaintext. Format: `vlnx_<prefix>_<secret>`.
3. Send it on every request:

```http
GET /api/v1/engagements/ HTTP/1.1
Authorization: ApiKey vlnx_a1B2c3D4_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```bash
curl -H "Authorization: ApiKey vlnx_a1B2c3D4_..." https://HOST/api/v1/engagements/
```

Revoke a key at any time from the same page. The server keeps only a SHA-256
hash and a short non-secret prefix; successful requests update `last_used_at`.

### JWT (for interactive apps / SPAs)

Exchange username + password and, when MFA is enrolled, a current TOTP or backup
code (`otp_code`) for a short-lived access token and a refresh token. Required-role
users must finish MFA setup first:

```bash
curl -X POST https://HOST/api/v1/auth/token/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"...","otp_code":"123456"}'
```

Response:

```json
{"access": "eyJhbGciOi...", "refresh": "eyJhbGciOi..."}
```

Use `Authorization: Bearer <access>` on subsequent requests. Refresh before
expiry (30 min) by POSTing the refresh token to
`/api/v1/auth/token/refresh/`; refresh tokens rotate; the old token is not blacklisted by the current configuration.

Tokens issued before the 2026-10-29 security update are rejected; sign in again.
Access and refresh tokens become invalid after password changes, removal of their
verified MFA device, or new MFA enrollment for a password-only token. API keys
remain separately revocable credentials and do not require a code per request.

### Session (for the browser)

Logging into the Vulnex UI also authenticates you against the API — useful
during development when probing from the browser dev tools or Swagger UI.

---

## Permissions

The API mirrors the HTML views' engagement-role model:

| Caller                         | Read  | Write findings/hosts | Credentials   | Admin users |
| ------------------------------ | ----- | -------------------- | ------------- | ----------- |
| Admin (platform role)          | all   | all                  | all           | yes         |
| Lead / Pentester on engagement | own   | own                  | own           | no          |
| Reviewer on engagement         | own   | —                    | read-only own | no          |
| Client on engagement           | own   | —                    | **blocked**   | no          |
| Not a member                   | —     | —                    | —             | no          |

Listing endpoints are always scoped to what the caller can access — there is
no "see everything" flag for non-admins.

Throttle: 1000 requests per hour per user.

---

## Endpoints

All list endpoints are paginated (`?page=N`, default page size 50). Detail
endpoints use the resource's UUID.

### Engagements

| Method | Path                                       | Purpose                            |
| ------ | ------------------------------------------ | ---------------------------------- |
| GET    | `/api/v1/engagements/`                     | List engagements you can access    |
| POST   | `/api/v1/engagements/`                     | Create (admin / pentester only)    |
| GET    | `/api/v1/engagements/{id}/`                | Retrieve                           |
| PUT / PATCH | `/api/v1/engagements/{id}/`           | Update (lead / pentester / admin)  |
| DELETE | `/api/v1/engagements/{id}/`                | Delete (lead / admin)              |
| GET    | `/api/v1/engagements/{id}/findings/`       | List findings on this engagement   |
| POST   | `/api/v1/engagements/{id}/findings/`       | Create a finding under it          |

### Findings

| Method | Path                                     | Purpose                       |
| ------ | ---------------------------------------- | ----------------------------- |
| GET    | `/api/v1/findings/`                      | List accessible findings      |
| POST   | `/api/v1/findings/`                      | Create                        |
| GET    | `/api/v1/findings/{id}/`                 | Retrieve                      |
| PUT / PATCH | `/api/v1/findings/{id}/`            | Update                        |
| DELETE | `/api/v1/findings/{id}/`                 | Delete                        |
| GET    | `/api/v1/findings/{id}/evidence/`        | List evidence                 |
| POST   | `/api/v1/findings/{id}/evidence/`        | Upload evidence (multipart)   |

### Hosts (read-only)

| Method | Path                    | Purpose                        |
| ------ | ----------------------- | ------------------------------ |
| GET    | `/api/v1/hosts/`        | List discovered hosts          |
| GET    | `/api/v1/hosts/{id}/`   | Retrieve one                   |

### Credentials

Clients (platform role) are **blocked** from every credentials endpoint.

| Method | Path                                  | Purpose                                     |
| ------ | ------------------------------------- | ------------------------------------------- |
| GET    | `/api/v1/credentials/`                | List — secret plaintext is never returned   |
| POST   | `/api/v1/credentials/`                | Create — send `secret` in the body          |
| GET    | `/api/v1/credentials/{id}/`           | Retrieve metadata only                      |
| GET    | `/api/v1/credentials/{id}/?reveal=true` | Retrieve with plaintext secret; audited  |
| PATCH  | `/api/v1/credentials/{id}/`           | Update (including rotating the secret)      |
| DELETE | `/api/v1/credentials/{id}/`           | Delete                                      |

Reveal requests are logged to the platform audit log
(`AuditLog.CREDENTIAL_REVEAL`).

### Reports (read-only)

| Method | Path                          | Purpose                      |
| ------ | ----------------------------- | ---------------------------- |
| GET    | `/api/v1/reports/`            | List accessible reports      |
| GET    | `/api/v1/reports/{id}/`       | Report metadata              |
| GET    | `/api/v1/reports/{id}/pdf/`   | Stream the PDF; audited      |

---

## Examples

### Create an engagement

```bash
curl -X POST https://HOST/api/v1/engagements/ \
  -H "Authorization: ApiKey vlnx_..." \
  -H 'Content-Type: application/json' \
  -d '{"name":"ACME Q2","client_name":"ACME","engagement_type":"webapp"}'
```

### File a finding

```bash
curl -X POST https://HOST/api/v1/findings/ \
  -H "Authorization: ApiKey vlnx_..." \
  -H 'Content-Type: application/json' \
  -d '{
    "engagement":"<engagement-uuid>",
    "title":"Stored XSS in comment form",
    "severity":"high",
    "description":"..."
  }'
```

### Attach evidence (multipart)

```bash
curl -X POST https://HOST/api/v1/findings/<id>/evidence/ \
  -H "Authorization: ApiKey vlnx_..." \
  -F "file=@screenshot.png" \
  -F "caption=XSS popup"
```

### Reveal a credential

```bash
curl "https://HOST/api/v1/credentials/<id>/?reveal=true" \
  -H "Authorization: ApiKey vlnx_..."
```

---

## Errors

Standard DRF shape:

```json
{"detail": "Authentication credentials were not provided."}
```

| Code | Meaning                                                             |
| ---- | ------------------------------------------------------------------- |
| 401  | Missing / invalid / revoked / expired authentication                |
| 403  | Authenticated but not permitted (e.g. client hitting credentials)   |
| 404  | Resource not found *or* caller has no access (scoped queryset miss) |
| 429  | Throttled — back off until the `Retry-After` header elapses         |

## Shared workflow rules

Creating an engagement adds the creator as its lead. Only leads and global admins
can delete engagements. Signed-off engagements cannot be edited until sign-off
is revoked in the UI. Finding and credential updates cannot change their parent
engagement.

Clients can only retrieve approved findings, including through nested lists and
evidence routes. Their engagement summary counts follow the same rule. Recon
hosts and credentials are restricted to internal engagement members.

`review_state` is read-only in finding create/update payloads. Use:

```http
POST /api/v1/findings/{id}/review/
Content-Type: application/json

{"state": "in_review"}
```

Lead/pentester/admin may submit drafts or findings with changes requested.
Lead/reviewer/admin may change an in-review finding to `approved` or
`changes_requested`. For `changes_requested`, provide a nonempty `notes` string.
Invalid transitions return 400; insufficient permissions return 403.


### Report visibility and finding review

Reports expose `published_at` and `published_by` as read-only metadata. Client
members can list/download only explicitly published PDFs. Lead/admin publication
and withdrawal are performed from the report dashboard after reviewing the file.
Live report preview is internal-only. Material changes to a finding's narrative,
location or CVSS fields reset its review state to draft; status-only changes do
not. Evidence uploads use the same file restrictions as browser uploads.
