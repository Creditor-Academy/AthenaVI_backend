# API overview

Shared conventions for all Athena VI backend routes.

## Base URL

All API routes are prefixed with:

```
/api
```

Example: `https://your-api-domain.com/api` or `http://localhost:9000/api`

---

## Response format

### Success response

```json
{
  "success": true,
  "message": "Optional success message",
  "data": { ... }
}
```

- `message` can be `null` for some endpoints.
- `data` may be an object, or `null` when there is no payload.

### Error response

```json
{
  "success": false,
  "message": "Human-readable error message",
  "errors": []
}
```

- HTTP status code is set on the response (400, 401, 403, 404, 409, 500, etc.).
- `errors` is optional and may be empty.

---

## Authentication

### Access token (protected routes)

- After **login** or **register**, the response body includes `accessToken`.
- Send it on every protected request:

```
Authorization: Bearer <access_token>
```

- Token is short-lived; use the refresh flow when it expires (typically 401).

### Refresh token

- Stored in an **HTTP-only cookie** named `refreshToken` (set by login, register, refresh rotation, and Google OAuth success).
- To get a new access token, call `POST /api/auth/refresh` so the cookie is sent (same site / credentials as your setup allow). No body required.
- A **new** refresh token is issued on refresh (rotation); the response body includes the new `accessToken`.

### Unprotected vs protected

- **Unprotected**: OTP generate/resend, register, login, superadmin login, refresh, logout (cookie only), forget-password, reset-password, `GET /api/auth/google` and `GET /api/auth/superadmin/google` (redirect).
- **Optional auth**: `/api/p/*` (view-only presentation share links — see [PRESENTATION_API.md](PRESENTATION_API.md)). The capability token in the path is the permission; a Bearer token is accepted but never required, and an invalid one is treated as a guest rather than a 401.
- **Protected**: All `/api/user/*`, `/api/workspaces/*`, `/api/credits/*`, `/api/assets/*`, and `/api/heygen/*` require `Authorization: Bearer <access_token>`. Workspace, project, render, asset, credit, and most HeyGen flows additionally require workspace membership or specific roles where noted. **Project**, **render**, and **HeyGen avatar video** routes under `/api/workspaces/:workspaceId/projects/*` require a workspace **member** role (OWNER, ADMIN, or MEMBER), and the `projectId` must belong to that workspace.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

