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

- **Unprotected**: OTP generate/resend, register, login, refresh, logout (cookie only), forget-password, reset-password, `GET /api/auth/google` (redirect).
- **Protected**: All `/api/user/*`, `/api/workspaces/*`, and `/api/credits/*` require `Authorization: Bearer <access_token>`. Workspace and credit routes additionally require workspace membership and specific roles where noted.

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

**Response (200)** – `data`: `null`, `message`: success text.

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

**Response (200)** – `data`: `null`, `message`: success text.

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

- `name`: string, 2–50 characters.
- `email`: valid email.
- `password`: string, minimum **6** characters.
- `otp`: **number** between `100000` and `999999` (JSON number, not a quoted string).

```json
{
  "name": "John Doe",
  "email": "user@example.com",
  "password": "yourSecurePassword",
  "otp": 308856
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

Refresh token is set in an HTTP-only cookie (`path: /`).

---

## Token management

### Refresh access token

Cookie `refreshToken` must be sent.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/refresh` |
| **Auth** | Cookie: `refreshToken` |

**Response (201)** – `data`: `{ "accessToken": "eyJhbG..." }`. A new refresh token cookie is set.

---

## Logout

### Logout (current device)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/logout` |
| **Auth** | Cookie: `refreshToken` |

Clears the refresh token cookie and invalidates the current session.

**Response (200)** – `data`: `{}`.

---

### Logout from all devices

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/logout-all` |
| **Auth** | `Authorization: Bearer <access_token>` |

Invalidates all refresh tokens for the user.

**Response (200)** – `data`: `{}`.

---

## Password reset

### Forget password

Sends a password reset link to the email. Response is the same whether or not the user exists (no email enumeration).

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

**Response (200)** – `data`: `{}`.

---

### Reset password

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/reset-password` |
| **Auth** | None |

**Request body**

- `newPassword`: minimum **6** characters.

```json
{
  "token": "reset-token-from-email-link",
  "newPassword": "newSecurePassword"
}
```

**Response (200)** – `data`: `{}`.

---

## Google OAuth

### Start Google sign-in

Redirect the browser to this URL. The user is sent to Google, then to the backend callback.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/auth/google` |
| **Auth** | None |

---

### Google OAuth callback

Google redirects here after consent. **Not called by your frontend directly**—configure this URL in the Google Cloud console as the authorized redirect URI.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/auth/google/callback` |
| **Auth** | None |

**Query**

- `code` (required)
- `state` (required)

On success, the backend redirects to:

`{FRONTEND_URL}{OAUTH_SUCCESS_PATH}#access_token=<access_token>`

(URL-encoded token in the hash.)

The frontend should read `access_token` from the hash and store it. A refresh token cookie is set on success (same pattern as email login when redirect URL is configured). If `FRONTEND_URL` is not set, the API may respond with `200` and JSON `data`: `{ "accessToken", "user" }` instead of redirecting.

On error, the user is redirected to `{FRONTEND_URL}?error=...` with an error code in the query string.

---

# User API

Base path: **`/api/user`**

All routes below require **`Authorization: Bearer <access_token>`**.

---

## Get all users

Returns all user records from the database (intended for admin or internal use). **Responses currently include full user rows as stored** (e.g. may include `password` when the account has a password). Prefer a dedicated admin API with field selection for production exposure.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/getall` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "users": [ { "id": "...", "email": "...", "name": "...", "password": "...", ... } ],
  "count": 10
}
```

---

## Get profile

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/profile` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "profile": {
    "email": "user@example.com",
    "name": "John Doe",
    "profileImage": "https://...",
    "phoneNumber": "+1...",
    "createdAt": "ISO8601"
  }
}
```

---

## Update profile

At least one of `name` or `phoneNumber` must be present. `phoneNumber` must match server validation (digits, `+`, `-`, `()`, optional single space; length 8–20).

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/profile` |
| **Auth** | Bearer |

**Request body** (partial)

```json
{
  "name": "Jane Doe",
  "phoneNumber": "+1(310) 1234567"
}
```

**Response (200)** – `data`: `{ "profile": { "email", "name", "phoneNumber", "createdAt" } }`.

---

## Upload profile image

`multipart/form-data` with a single file field **`profileImage`**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/user/upload/profile-image` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "profile": { "id", "profileImage" } }`.

---

## Delete profile image

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/user/profile-image` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "profile": { "id", "profileImage" } }` (`profileImage` cleared).

---

# Workspace API

Base path: **`/api/workspaces`**

All workspace routes require **`Authorization: Bearer <access_token>`**. Some routes require a specific **workspace role** (OWNER, ADMIN, or MEMBER).

- **OWNER**: Full control; delete TEAM workspace, change roles, invite, cancel invitations, list members and invitations, remove members (per rules below).
- **ADMIN**: Invite, cancel invitations, list members and invitations, remove members (not owner). Cannot delete workspace or change roles.
- **MEMBER**: Can view workspace (`GET /:id`), list own credit history, accept invites, remove self (not as owner). Cannot list workspace members or pending invitations.

`:id` in paths below is the **workspace UUID**.

Each user has exactly one **private** workspace (created on registration). Users can create additional **team** workspaces.

---

## Create team workspace

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces` |
| **Auth** | Bearer |

**Request body**

- `name`: string, **3–100** characters.

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
    "credits": 0,
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

**Response (200)** – `message` may be `null`. `data`:

```json
{
  "workspaces": [
    {
      "id": "uuid",
      "name": "Personal",
      "type": "PRIVATE",
      "ownerId": "uuid",
      "credits": 0,
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

**Response (200)** – `message` may be `null`. `data`: `{ "workspace": { ... } }` (includes `owner`).

- **404** if workspace not found. **403** if user is not a member.

---

## Delete workspace

Only **OWNER**. Only **TEAM** workspaces can be deleted; **PRIVATE** cannot be deleted.

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id` |
| **Auth** | Bearer |
| **Role** | OWNER |

**Response (200)** – `data`: `null`, `message`: success.

- **400** if workspace is PRIVATE. **403** if not owner.

---

## List workspace members

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/members` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Response (200)** – `message` may be `null`. `data`:

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

## List pending invitations

Returns **PENDING** invitations only.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/invitations` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Response (200)** – `data`:

```json
{
  "invitations": [
    {
      "id": "uuid",
      "email": "invitee@example.com",
      "role": "MEMBER",
      "createdAt": "ISO8601",
      "expiresAt": "ISO8601"
    }
  ]
}
```

---

## Invite member

Sends an email with an accept link. Effective role for the invite must be **ADMIN** or **MEMBER** (OWNER is rejected by the server with **400** even if it passes generic validation).

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

**Response (201)** – `data`: `{}` (empty object). The invitation token is **not** returned in the API; the email contains a link:

`{FRONTEND_URL}/invitations/accept/<token>`

The user completes signup/login and calls **Accept invitation** with that `token` in the body.

- **409** if the user is already a member or a pending invite already exists for that email.

---

## Cancel invitation

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id/invitations/:invitationId` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Response (200)** – `data` includes `updatedInvitation` (invitee email string) and `message`; top-level `message` is also set.

---

## Accept invitation

Authenticated user’s email must match the invitation email.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/invitations/accept` |
| **Auth** | Bearer |

**Request body**

```json
{
  "token": "invitation-token-from-email-link"
}
```

**Response (200)** – `data`: `{ "workspace": { ... } }`

- **400** if token invalid, not pending, expired, or email mismatch.

---

## Change member role

Only **OWNER**. Setting role to **OWNER** transfers ownership (previous owner becomes **ADMIN**).

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

OWNER or ADMIN can remove others; a **MEMBER** can remove only themselves. **OWNER** cannot remove themselves without transferring ownership first.

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id/members/:memberId` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN, or self as non-owner member |

**Response (200)** – `data`: `null`, `message`: success.

- **400** if removing the last OWNER or owner tries to leave without transfer. **404** if member not found.

---

# Credits API

Base path: **`/api/credits`**

All routes require **`Authorization: Bearer <access_token>`**. The path parameter **`:id` is the workspace UUID**. Middleware requires you to be a member of that workspace with the role listed per route.

---

## Get workspace credit balance

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Response (200)** – `data`:

```json
{
  "workspaceId": "uuid",
  "credits": 0
}
```

---

## Workspace credit history

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/history` |
| **Auth** | Bearer |
| **Role** | OWNER or ADMIN |

**Query (optional)**

- `page` – default `1`
- `limit` – default `20`

**Response (200)** – `data`:

```json
{
  "history": {
    "transactions": [
      {
        "id": "uuid",
        "userId": "uuid",
        "workspaceId": "uuid",
        "amount": 10,
        "type": "usage",
        "reference": null,
        "createdAt": "ISO8601"
      }
    ],
    "pagination": {
      "total": 100,
      "page": 1,
      "limit": 20,
      "totalPages": 5
    }
  }
}
```

`type` is stored as a string (e.g. purchase, usage, refund, admin_adjustment).

---

## My credit history (within workspace)

Credit transactions for the **current user** only in the given workspace.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/my-history` |
| **Auth** | Bearer |
| **Role** | OWNER, ADMIN, or MEMBER |

**Query (optional)**

- `page` – default `1`
- `limit` – default `20`

**Response (200)** – same `history` shape as workspace history (filtered by `userId`).

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
| GET | `/api/auth/google/callback` | No | Google redirect (OAuth) |
| GET | `/api/user/getall` | Bearer | List all users |
| GET | `/api/user/profile` | Bearer | Get profile |
| PATCH | `/api/user/profile` | Bearer | Update profile |
| POST | `/api/user/upload/profile-image` | Bearer | Upload profile image (multipart) |
| DELETE | `/api/user/profile-image` | Bearer | Remove profile image |
| POST | `/api/workspaces` | Bearer | Create team workspace |
| GET | `/api/workspaces` | Bearer | List my workspaces |
| POST | `/api/workspaces/invitations/accept` | Bearer | Accept invite |
| GET | `/api/workspaces/:id` | Bearer + member | Get workspace |
| DELETE | `/api/workspaces/:id` | Bearer + OWNER | Delete workspace |
| GET | `/api/workspaces/:id/members` | Bearer + OWNER/ADMIN | List members |
| GET | `/api/workspaces/:id/invitations` | Bearer + OWNER/ADMIN | List pending invitations |
| POST | `/api/workspaces/:id/invite` | Bearer + OWNER/ADMIN | Invite by email |
| DELETE | `/api/workspaces/:id/invitations/:invitationId` | Bearer + OWNER/ADMIN | Cancel invitation |
| PATCH | `/api/workspaces/:id/members/:memberId/role` | Bearer + OWNER | Change role |
| DELETE | `/api/workspaces/:id/members/:memberId` | Bearer + OWNER/ADMIN or self | Remove member |
| GET | `/api/credits/:id` | Bearer + OWNER/ADMIN | Workspace credit balance |
| GET | `/api/credits/:id/history` | Bearer + OWNER/ADMIN | Workspace credit history |
| GET | `/api/credits/:id/my-history` | Bearer + any member | My credits in workspace |

---

# Environment (for reference)

Frontend may need to know:

- **API base URL** – e.g. `process.env.REACT_APP_API_URL` or `NEXT_PUBLIC_API_URL` pointing to `https://your-backend.com/api`.
- **Google OAuth** – Register redirect URI `.../api/auth/google/callback`. After success, backend redirects to `FRONTEND_URL` + `OAUTH_SUCCESS_PATH` with `#access_token=...`.
- **Invitations** – Email links use `{FRONTEND_URL}/invitations/accept/<token>`; your app should route the user to login if needed, then `POST /api/workspaces/invitations/accept` with `{ "token" }`.
- **Cookie** – Refresh token is HTTP-only; ensure credentials/cookies are sent when calling `/api/auth/refresh` (same-origin or CORS `credentials` as configured).

---

**End of API documentation**
