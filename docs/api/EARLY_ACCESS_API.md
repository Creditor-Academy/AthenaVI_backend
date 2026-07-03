# Early Access API

Public endpoint for the Early Access interest form. **No authentication required.**

> **Response envelope:** This route uses a **frontend-specific** JSON shape (`requestId` at top level; `error` + `fields` on failure). It does **not** follow the standard `{ data }` / `{ errors[] }` envelope in [OVERVIEW.md](OVERVIEW.md).

Signup (`/api/auth/register`, OTP, OAuth) is **unchanged** — gating signup is a frontend-only concern.

---

## Submit early access request

```
POST /api/early-access/request
```

| Property | Value |
|----------|--------|
| Auth | None |
| Rate limit | 3 requests / IP / hour (configurable) |
| Content-Type | `application/json` |

### Request body

```json
{
  "name": "Jane Doe",
  "email": "jane@company.com",
  "company": "Acme Corp",
  "role": "L&D Manager",
  "useCase": "Corporate Training",
  "message": "We want to use Athena VI for employee onboarding at scale."
}
```

| Field | Type | Required | Max length |
|-------|------|----------|------------|
| `name` | string | Yes | 100 |
| `email` | string | Yes | 254 (valid email) |
| `company` | string | No | 150 |
| `role` | string | No | 100 |
| `useCase` | string | No | 100 (enum values or any string) |
| `message` | string | No | 1000 |

Suggested `useCase` values: `Corporate Training`, `Educational Content`, `Marketing Videos`, `Product Demos`, `HR Onboarding`, `Sales Enablement`, `Other`.

### Success — `201 Created`

```json
{
  "success": true,
  "message": "Your early access request has been received. We'll be in touch within 1-3 business days.",
  "requestId": "ea_8f3kd92js"
}
```

### Errors

| Status | `error` | When |
|--------|---------|------|
| `400` | `VALIDATION_ERROR` | Invalid or missing fields (`fields` object included) |
| `409` | `DUPLICATE_REQUEST` | Email already submitted |
| `429` | `RATE_LIMIT_EXCEEDED` | IP rate limit exceeded (`Retry-After` header set) |
| `500` | `INTERNAL_ERROR` | SMTP failure, superadmin notification email not configured, or unexpected error |

**Validation example (`400`):**

```json
{
  "success": false,
  "error": "VALIDATION_ERROR",
  "message": "Name and email are required.",
  "fields": {
    "name": "Required",
    "email": "Must be a valid email address"
  }
}
```

**Duplicate example (`409`):**

```json
{
  "success": false,
  "error": "DUPLICATE_REQUEST",
  "message": "An early access request with this email already exists."
}
```

---

## Side effects on success

1. Row inserted into `early_access_requests` with status `pending`.
2. **Email** to platform superadmin inbox (`PLATFORM_SUPERADMIN_NOTIFICATION_EMAIL`, fallback `PLATFORM_SUPERADMIN_EMAILS`).
3. **Status email** to the applicant (`pending`).
4. **In-app inbox** notification (`PLATFORM_EARLY_ACCESS_REQUEST`) for platform superadmin user accounts.

On each later status change (`under_review`, `in_discussion`, `approved`, `rejected`), the applicant receives another status email. Superadmin updates via `PATCH /api/superadmin/early-access/requests/:requestId/status` (see [`SUPERADMIN_API.md`](SUPERADMIN_API.md)).

Requires SMTP (`SMTP_*`) and superadmin notification email configuration (same as storage upgrade requests).

---

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `PLATFORM_SUPERADMIN_NOTIFICATION_EMAIL` | — | Primary superadmin notification inbox |
| `PLATFORM_SUPERADMIN_EMAILS` | — | Fallback inbox + superadmin allowlist |
| `EARLY_ACCESS_RATE_LIMIT_MAX` | `3` | Max submissions per IP per window |
| `EARLY_ACCESS_RATE_LIMIT_WINDOW_SEC` | `3600` | Rate limit window (seconds) |

See [ENVIRONMENT.md](ENVIRONMENT.md).

---

**[← API index](README.md)** · [Project root README](../../README.md)
