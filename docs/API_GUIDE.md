# How the Vulnex API works

A plain-language explanation of what the REST API is, how a request flows through
it, and what it handles. For the exact endpoint list, request/response shapes,
and copy-paste `curl` examples, see [API.md](API.md) — this document explains the
*why* and *how* behind those endpoints.

---

## 1. What the API is (and isn't)

The Vulnex API is a **second front door to the same application**. Everything you
can do in the web UI — create engagements, file findings, pull reports — is also
exposed as JSON over HTTP so scripts, CI pipelines, and other tools can do it
without a browser.

It is **not** a separate service. It reads and writes the *same database models*
and enforces the *same permission rules* as the HTML pages. There is no "API
account" or "API role" — your normal user and your engagement memberships decide
what the API lets you do, exactly like the UI.

It's built with **Django REST Framework (DRF)**. If you've seen Django views, a
DRF "ViewSet" is the same idea: a class that handles list/create/retrieve/update/
delete for one kind of object.

---

## 2. The URL map

Everything lives under `/api/`. The root URLconf ([vulnex/urls.py](../vulnex/urls.py))
sends `/api/` into [api/urls.py](../api/urls.py), which defines four things:

| URL | What it is |
| --- | --- |
| `/api/v1/` | The API itself — an index listing the available resources. |
| `/api/v1/auth/token/` (+ `/refresh/`) | Log in with username/password to get a JWT token. |
| `/api/schema/` | The machine-readable OpenAPI spec (a `.yaml` describing every endpoint). |
| `/api/docs/` | Swagger UI — an interactive, human-friendly web page built from that schema. |

**`/api/v1/` is the real API.** `/api/schema/` and `/api/docs/` are *documentation*
generated automatically (by `drf-spectacular`) from the code — you don't write
them by hand, they always match reality.

> All three require you to be logged in **as an admin or pentester**. Reviewers,
> clients, and anonymous visitors get `403 Forbidden` — the API is an internal
> tool, so its surface isn't even enumerable to roles that have no use for it
> (see `IsStaffOrPentester` in [api/permissions.py](../api/permissions.py) and the
> custom `_StaffOnlyRouter` in [api/urls.py](../api/urls.py)). If a page looks
> "broken," first check you're signed in with the right role — and that the server
> is actually running.

---

## 3. What it handles (the resources)

The API exposes five resources. Each is one ViewSet in [api/views.py](../api/views.py),
registered on the router in [api/urls.py](../api/urls.py):

| Resource | Endpoint | Operations | Notes |
| --- | --- | --- | --- |
| **Engagements** | `/api/v1/engagements/` | full CRUD | Create is admin/pentester only. Has a nested `…/{id}/findings/` action to list/add findings under one engagement. |
| **Findings** | `/api/v1/findings/` | full CRUD | Has a nested `…/{id}/evidence/` action to list/upload evidence files. |
| **Hosts** | `/api/v1/hosts/` | read-only | Recon-discovered hosts. You can list/view but not create via the API. |
| **Credentials** | `/api/v1/credentials/` | full CRUD | The encrypted vault. The plaintext secret is only returned when you explicitly ask with `?reveal=true`, and that reveal is written to the audit log. **Clients are blocked entirely.** |
| **Reports** | `/api/v1/reports/` | read-only | List report metadata; `…/{id}/pdf/` streams the actual PDF (also audited). |

"Full CRUD" = Create (`POST`), Read (`GET`), Update (`PUT`/`PATCH`), Delete
(`DELETE`). "Read-only" = `GET` only.

---

## 4. How a request flows through the system

When a request hits `/api/v1/findings/`, four checks happen in order. Picture it
as four gates:

```
Request → [1 Authenticate] → [2 Permit] → [3 Scope the queryset] → [4 Serialize] → JSON
```

### Gate 1 — Authentication: *who are you?*

DRF tries three methods in order (configured in `REST_FRAMEWORK` in
[settings.py](../vulnex/settings.py)), and the first one that matches wins:

1. **API key** — header `Authorization: ApiKey vlnx_<prefix>_<secret>`.
   See [api/authentication.py](../api/authentication.py). The key looks up a row by
   its non-secret `prefix`, then verifies the rest against a stored **SHA-256
   hash** — the raw key is never stored, so even a database leak can't reveal it.
2. **JWT** — header `Authorization: Bearer <token>`. You get the token by POSTing
   your username/password to `/api/v1/auth/token/`. Access tokens last 30 minutes;
   you refresh them with the refresh token (valid 1 day).
3. **Session** — if you're already logged into the website in the same browser,
   that cookie authenticates you too. Handy for poking at Swagger UI.

If none match → **401 Unauthorized**.

### Gate 2 — Permission: *are you allowed to do this action?*

Each ViewSet has a permission class (in [api/permissions.py](../api/permissions.py))
that mirrors the UI's role rules. The important idea: **permission depends on your
role *within the engagement* the object belongs to**, not a global flag.

- `IsEngagementEditor` — any member can read; only lead/pentester (or admin) can write. (Engagements, Findings)
- `IsEngagementMember` — any member, including client, can read. (Hosts, Reports)
- `CredentialVaultPermission` — clients blocked; reviewers read-only; lead/pentester read+write. (Credentials)

These classes don't re-implement the rules — they call the *same*
`Engagement.user_can_access` / `user_can_edit` methods the HTML views use, so the
two surfaces can never drift apart.

If you're authenticated but not allowed → **403 Forbidden**.

### Gate 3 — Queryset scoping: *which rows can you even see?*

This is the most important security idea in the API. Every ViewSet's
`get_queryset()` **filters the database query to only the engagements you belong
to** before anything is returned:

```python
# api/views.py — simplified
if user.role == 'admin':
    return Finding.objects.all()           # admins see everything
return Finding.objects.filter(
    engagement_id__in=_accessible_engagement_ids(user),   # everyone else: only theirs
)
```

The practical consequence: if you request a finding that belongs to an engagement
you're not on, it isn't "forbidden" — it simply **doesn't exist for you**, so you
get **404 Not Found**. There is no "see everything" switch for non-admins.

### Gate 4 — Serialization: *turn objects into JSON (and back)*

Serializers (in `api/serializers.py`) convert database objects to JSON for
responses and validate incoming JSON for writes. List endpoints are **paginated**
— 50 per page, navigate with `?page=2`.

---

## 5. Cross-cutting behaviour

- **Throttling** — 1000 requests per hour per user. Exceed it and you get
  **429 Too Many Requests**; back off until the `Retry-After` header says.
- **Audit logging** — sensitive API actions (creating/deleting an engagement or
  credential, revealing a secret, downloading a report) are written to the same
  append-only `AuditLog` as the UI, tagged `"via": "api"` so you can tell where an
  action came from.
- **JSON only in production** — in `DEBUG` mode you also get DRF's clickable
  "Browsable API" HTML pages; deployed instances serve pure JSON.
- **UUID ids** — engagements, findings, etc. are addressed by UUID, e.g.
  `/api/v1/findings/3f72127a-…/`.

---

## 6. The error codes you'll actually see

| Code | Meaning |
| --- | --- |
| 401 | Not authenticated — missing/invalid/revoked key or token. |
| 403 | Authenticated, but your role isn't allowed (e.g. a client hitting credentials, or a reviewer hitting `/api/docs/`). |
| 404 | Either it genuinely doesn't exist, **or** it's outside your engagement scope (gate 3). |
| 429 | Throttled. |

---

## 7. Mental model in one paragraph

The Vulnex API is DRF ViewSets over the same models as the UI. A request is
authenticated (API key / JWT / session), checked against an engagement-role
permission class, and then served from a queryset that's already filtered to the
engagements you belong to — so you can only ever read or write data for your own
engagements, with admins as the only exception. `/api/v1/` is the API,
`/api/docs/` is the auto-generated interactive documentation, and both are
restricted to admins and pentesters. For exact endpoints and examples, read
[API.md](API.md).
