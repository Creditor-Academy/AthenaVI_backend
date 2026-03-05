# Athena VI Backend – API Documentation

Backend API for **Athena VI** (Virtual Instructor). Use this document for frontend integration.

---

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
- `data` contains the payload (object, array, or null).

### Error response

```json
{
  "success": false,
  "message": "Human-readable error message"
}
```

- HTTP status code is set on the response (400, 401, 403, 404, 409, 500, etc.).

---

## Authentication

### Access token (protected routes)

- After **login** or **register**, the response body includes `accessToken`.
- Send it on every protected request:

```
Authorization: Bearer <access_token>
```

- Token is short-lived; use the refresh flow when it expires (typically 401 with a message like "Token expired").

### Refresh token

- Stored in an **HTTP-only cookie** named `refreshToken` (set by login/register).
- To get a new access token, call `POST /api/auth/refresh` with the same origin so the cookie is sent. No body required.
- New access token is returned in the response body.

### Unprotected vs protected

- **Unprotected**: OTP, register, login, refresh, logout, forget-password, reset-password, Google OAuth.
- **Protected**: All `/api/user/*` and `/api/workspaces/*` routes require `Authorization: Bearer <access_token>`.

---

# Auth API

Base path: **`/api/auth`**

---

## OTP

### Generate OTP

Send OTP to the given email.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/otp/generate` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com"
}
```

---

### Resend OTP

Resend OTP to the same email.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/otp/resend` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com"
}
```

---

## Registration

### Verify OTP and register

Verify OTP and create a new user. Returns access token and sets refresh token cookie. New user gets a **private workspace** automatically.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/register` |
| **Auth** | None |

**Request body**

```json
{
  "name": "John Doe",
  "email": "user@example.com",
  "password": "yourSecurePassword",
  "otp": "308856"
}
```

**Response (201)** – `data`:

```json
{
  "accessToken": "eyJhbG...",
  "user": { "name": "John Doe", "email": "user@example.com" }
}
```

---

## Login

### Login

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/login` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com",
  "password": "yourPassword"
}
```

**Response (200)** – `data`:

```json
{
  "accessToken": "eyJhbG...",
  "user": { "name": "John Doe", "email": "user@example.com" }
}
```

Refresh token is set in HTTP-only cookie.

---

## Token management

### Refresh access token

Get a new access token. Cookie `refreshToken` must be sent (same origin).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/refresh` |
| **Auth** | Cookie: `refreshToken` |

**Response (201)** – `data`: `{ "accessToken": "eyJhbG..." }`

---

## Logout

### Logout (current device)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/logout` |
| **Auth** | Cookie: `refreshToken` |

Clears the refresh token cookie and invalidates current session.

---

### Logout from all devices

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/logout-all` |
| **Auth** | `Authorization: Bearer <access_token>` |

Invalidates all refresh tokens for the user.

---

## Password reset

### Forget password

Sends a password reset link to the email (if the user exists).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/forget-password` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com"
}
```

---

### Reset password

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/reset-password` |
| **Auth** | None |

**Request body**

```json
{
  "token": "reset-token-from-email-link",
  "newPassword": "newSecurePassword"
}
```

---

## Google OAuth

### Start Google sign-in

Redirect the user to this URL (GET). They will be sent to Google and then back to your callback.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/auth/google` |
| **Auth** | None |

---

### Google callback

Handled by the backend. After successful auth, user is redirected to:

`{FRONTEND_URL}{OAUTH_SUCCESS_PATH}#access_token=<access_token>`

The frontend should read `access_token` from the hash and store it. Refresh token is set in a cookie when the backend sets it (if applicable).

---

# User API

Base path: **`/api/user`**

---

## Get all users

Returns all users (protected; for admin or internal use).

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/getall` |
| **Auth** | `Authorization: Bearer <access_token>` |

**Response (200)** – `data`:

```json
{
  "users": [ { "id": "...", "email": "...", ... } ],
  "count": 10
}
```

---

# Workspace API

Base path: **`/api/workspaces`**

All workspace routes require **`Authorization: Bearer <access_token>`**. Some routes also require a specific **workspace role** (OWNER, ADMIN, or MEMBER).

- **OWNER**: Full control; can delete workspace, change roles, invite, remove members.
- **ADMIN**: Can invite, remove members (except owner), list members. Cannot delete workspace or change roles.
- **MEMBER**: Can view workspace and (where allowed) list members.

Each user has exactly one **private** workspace (created on registration). Users can create additional **team** workspaces.

---

## Create team workspace

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces` |
| **Auth** | Bearer |
| **Role** | N/A |

**Request body**

```json
{
  "name": "My Team"
}
```

**Response (201)** – `data`:

```json
{
  "workspace": {
    "id": "uuid",
    "name": "My Team",
    "type": "TEAM",
    "ownerId": "uuid",
    "createdAt": "ISO8601",
    "updatedAt": "ISO8601"
  }
}
```

---

## List my workspaces

Returns all workspaces the current user is a member of.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "workspaces": [
    {
      "id": "uuid",
      "name": "Personal",
      "type": "PRIVATE",
      "ownerId": "uuid",
      "owner": { "id": "...", "email": "...", "name": "..." },
      "members": [{ "role": "OWNER", "joinedAt": "ISO8601" }],
      "createdAt": "ISO8601",
      "updatedAt": "ISO8601"
    }
  ],
  "count": 1
}
```

---

## Get workspace by ID

User must be a member (any role).

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id` |
| **Auth** | Bearer |
| **Role** | Member |

**Response (200)** – `data`: `{ "workspace": { ... } }`

- **404** if workspace not found. **403** if user is not a member.

---

## Delete workspace

Only **OWNER**. Only **TEAM** workspaces can be deleted; private workspace cannot be deleted.

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id` |
| **Auth** | Bearer |
| **Role** | OWNER |

**Response (200)** – `message`: workspace deleted.

- **400** if workspace is PRIVATE. **403** if not owner.

---

## List workspace members

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/members` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Response (200)** – `data`:

```json
{
  "members": [
    {
      "id": "member-uuid",
      "workspaceId": "uuid",
      "userId": "uuid",
      "role": "OWNER",
      "joinedAt": "ISO8601",
      "user": { "id": "...", "email": "...", "name": "..." }
    }
  ]
}
```

---

## Invite member

Send an invitation to an email. Role must be **ADMIN** or **MEMBER** (not OWNER).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:id/invite` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Request body**

```json
{
  "email": "newmember@example.com",
  "role": "MEMBER"
}
```

**Response (201)** – `data`:

```json
{
  "token": "invitation-token-uuid",
  "expiresAt": "ISO8601"
}
```

Frontend can build an invite link, e.g. `{FRONTEND_URL}/invite/accept?token={token}`. User accepts via the accept-invitation endpoint.

- **409** if user is already a member.

---

## Accept invitation

Accept an invite with the token (e.g. from email link or query param). Authenticated user’s email must match the invitation email.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/invitations/accept` |
| **Auth** | Bearer |

**Request body**

```json
{
  "token": "invitation-token-from-invite"
}
```

**Response (200)** – `data`: `{ "workspace": { ... } }`

- **400** if token expired/invalid or email mismatch.

---

## Change member role

Only **OWNER** can change roles. Setting role to OWNER transfers ownership (current owner becomes ADMIN).

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:id/members/:memberId/role` |
| **Auth** | Bearer |
| **Role** | OWNER |

**Request body**

```json
{
  "role": "ADMIN"
}
```

Allowed `role`: `OWNER`, `ADMIN`, `MEMBER`.

**Response (200)** – `data`: `{ "member": { ... } }`

- **400** if removing the last OWNER. **404** if member not found.

---

## Remove member

Remove a member from the workspace. OWNER or ADMIN can remove others; members can remove themselves (except OWNER must transfer ownership first).

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id/members/:memberId` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN (or self-remove as MEMBER) |

**Response (200)** – member removed.

- **400** if removing the last OWNER or if OWNER tries to remove self without transferring ownership. **404** if member not found.

---

# Quick reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/otp/generate` | No | Send OTP |
| POST | `/api/auth/otp/resend` | No | Resend OTP |
| POST | `/api/auth/register` | No | Register (OTP + password) |
| POST | `/api/auth/login` | No | Login |
| POST | `/api/auth/refresh` | Cookie | New access token |
| POST | `/api/auth/logout` | Cookie | Logout current device |
| POST | `/api/auth/logout-all` | Bearer | Logout all devices |
| POST | `/api/auth/forget-password` | No | Request reset link |
| POST | `/api/auth/reset-password` | No | Reset password with token |
| GET | `/api/auth/google` | No | Start Google OAuth |
| GET | `/api/user/getall` | Bearer | List all users |
| POST | `/api/workspaces` | Bearer | Create team workspace |
| GET | `/api/workspaces` | Bearer | List my workspaces |
| POST | `/api/workspaces/invitations/accept` | Bearer | Accept invite |
| GET | `/api/workspaces/:id` | Bearer + member | Get workspace |
| DELETE | `/api/workspaces/:id` | Bearer + OWNER | Delete workspace |
| GET | `/api/workspaces/:id/members` | Bearer + OWNER/ADMIN | List members |
| POST | `/api/workspaces/:id/invite` | Bearer + OWNER/ADMIN | Invite by email |
| PATCH | `/api/workspaces/:id/members/:memberId/role` | Bearer + OWNER | Change role |
| DELETE | `/api/workspaces/:id/members/:memberId` | Bearer + OWNER/ADMIN | Remove member |

---

# Environment (for reference)

Frontend may need to know:

- **API base URL** – e.g. `process.env.REACT_APP_API_URL` or `NEXT_PUBLIC_API_URL` pointing to `https://your-backend.com/api`.
- **Google OAuth** – Backend redirects to `FRONTEND_URL` + `OAUTH_SUCCESS_PATH` with `#access_token=...`. Frontend should read token from hash and optionally store it.
- **Cookie** – Refresh token is HTTP-only; ensure requests to the API (e.g. `/api/auth/refresh`) are same-origin or CORS is configured so cookies are sent when needed.

---

**End of API documentation**
