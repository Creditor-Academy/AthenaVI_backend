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
- **Protected**: All `/api/user/*`, `/api/workspaces/*`, and `/api/workspaces/:id/videos/*` routes require `Authorization: Bearer <access_token>`.

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

# Video editor (Video & Scene) API

Base path: **`/api/workspaces/:id/videos`**

All video editor routes require **`Authorization: Bearer <access_token>`** and **workspace membership** (any role: OWNER, ADMIN, MEMBER). Replace `:id` with the workspace ID.

Videos represent one timeline in the video editor; scenes are ordered segments (script, avatar, background, etc.) within a video.

---

## Create video

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:id/videos` |
| **Auth** | Bearer + member |

**Request body**

```json
{
  "name": "My training video",
  "aspectRatio": "16:9",
  "title": "Optional display title",
  "description": "Optional description"
}
```

- `name` (optional): video name; defaults to "Untitled video".
- `aspectRatio`, `title`, `description` (optional): stored in `metadata`.

**Response (201)** – `data`: `{ "video": { "id": "uuid", "workspaceId": "...", "name": "...", "metadata": { ... }, "createdAt": "...", "updatedAt": "..." } }`

---

## List videos

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/videos` |
| **Auth** | Bearer + member |
| **Query** | `include=scenes` (optional) – include scenes in each video |

**Response (200)** – `data`: `{ "videos": [ ... ], "count": N }`

---

## Get video by ID

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/videos/:videoId` |
| **Auth** | Bearer + member |
| **Query** | `include=scenes` (optional) – include scenes |

**Response (200)** – `data`: `{ "video": { "id", "workspaceId", "name", "metadata", "createdAt", "updatedAt", "scenes"?: [ ... ] } }`

- **404** if video not found. **403** if video does not belong to the workspace.

---

## Update video

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:id/videos/:videoId` |
| **Auth** | Bearer + member |

**Request body** (all optional): `name`, `aspectRatio`, `title`, `description`

**Response (200)** – `data`: `{ "video": { ... } }`

---

## Delete video

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id/videos/:videoId` |
| **Auth** | Bearer + member |

Deletes the video and all its scenes (cascade).

**Response (200)** – no body.

---

## Create scene

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:id/videos/:videoId/scenes` |
| **Auth** | Bearer + member |

**Request body**

```json
{
  "order": 0,
  "startTime": 0,
  "duration": 12.5,
  "payload": {
    "scriptText": "Welcome to this video.",
    "avatar": "avatar_id",
    "avatarSettings": { "style": "rectangular", "voice": null, "scale": 1, "horizontalAlign": "center" },
    "background": "background_id_or_url",
    "backgroundSettings": { "scale": 1 },
    "transition": "fade"
  }
}
```

- `order` (optional): 0-based sequence. `startTime`, `duration` (optional): seconds. `payload` (optional): JSON object (script, avatar, background, etc.).

**Response (201)** – `data`: `{ "scene": { "id", "videoId", "order", "startTime", "duration", "payload", "createdAt", "updatedAt" } }`

---

## List scenes

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/videos/:videoId/scenes` |
| **Auth** | Bearer + member |

**Response (200)** – `data`: `{ "scenes": [ ... ], "count": N }` (ordered by `order`, then `startTime`).

---

## Get scene by ID

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/videos/:videoId/scenes/:sceneId` |
| **Auth** | Bearer + member |

**Response (200)** – `data`: `{ "scene": { ... } }`

---

## Update scene

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:id/videos/:videoId/scenes/:sceneId` |
| **Auth** | Bearer + member |

**Request body** (all optional): `order`, `startTime`, `duration`, `payload`

**Response (200)** – `data`: `{ "scene": { ... } }`

---

## Delete scene

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:id/videos/:videoId/scenes/:sceneId` |
| **Auth** | Bearer + member |

**Response (200)** – no body.

---

## Align timeline (TTS-driven)

Set each scene’s `duration` and cumulative `startTime` from TTS-based duration (word-count estimate ~0.4 s/word). Call after editing scene scripts to keep the timeline in sync with speech.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:id/videos/:videoId/align-timeline` |
| **Auth** | Bearer + member |

**Response (200)** – `data`: `{ "video": { ...video with updated scenes (duration, startTime set) } }`

- No request body. Loads all scenes (by `order`), computes duration per scene from `payload.scriptText`, sets `startTime` (cumulative) and `duration`, then persists and returns the video with scenes.

---

## Generate video (render)

Start a render job for a video. Poll the job until `status` is `COMPLETED` or `FAILED`; when `COMPLETED`, `outputUrl` contains the video URL (or is null if no render backend is configured).

### Start render

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:id/videos/:videoId/render` |
| **Auth** | Bearer + member |

**Response (201)** – `data`: `{ "job": { "id", "videoId", "workspaceId", "userId", "status": "PENDING", "outputUrl", "error", "createdAt", "updatedAt" } }`

### Get render job status

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:id/render/:jobId` |
| **Auth** | Bearer + member |

**Response (200)** – `data`: `{ "job": { "id", "videoId", "workspaceId", "status", "outputUrl", "error", "createdAt", "updatedAt" } }`

- `status`: `PENDING` | `RENDERING` | `COMPLETED` | `FAILED`. When `COMPLETED`, use `outputUrl` for download/play (may be null if no render backend is configured).
- Run the render worker with `npm run worker:render` so jobs are processed.
- **Render backends (worker env):**
  - **HeyGen:** Set `HEYGEN_API_KEY`. The worker makes one HeyGen API call per video: combined script from all scenes, single avatar and voice from the first scene’s `payload.avatar` and `payload.avatarSettings.voice`, aspect ratio and background from video/first scene. If `HEYGEN_API_KEY` is not set, see below.
  - **Custom service:** Set `RENDER_SERVICE_URL` to a URL that accepts POST `{ inputProps }` and returns `{ outputUrl }` (e.g. Remotion Lambda).
  - If neither is set, the worker marks jobs `COMPLETED` with `outputUrl` null (for frontend polling until a backend is configured).

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
| POST | `/api/workspaces/:id/videos` | Bearer + member | Create video |
| GET | `/api/workspaces/:id/videos` | Bearer + member | List videos |
| GET | `/api/workspaces/:id/videos/:videoId` | Bearer + member | Get video |
| PATCH | `/api/workspaces/:id/videos/:videoId` | Bearer + member | Update video |
| DELETE | `/api/workspaces/:id/videos/:videoId` | Bearer + member | Delete video |
| POST | `/api/workspaces/:id/videos/:videoId/scenes` | Bearer + member | Create scene |
| GET | `/api/workspaces/:id/videos/:videoId/scenes` | Bearer + member | List scenes |
| GET | `/api/workspaces/:id/videos/:videoId/scenes/:sceneId` | Bearer + member | Get scene |
| PATCH | `/api/workspaces/:id/videos/:videoId/scenes/:sceneId` | Bearer + member | Update scene |
| DELETE | `/api/workspaces/:id/videos/:videoId/scenes/:sceneId` | Bearer + member | Delete scene |
| POST | `/api/workspaces/:id/videos/:videoId/align-timeline` | Bearer + member | Align timeline from TTS (scene duration/startTime) |
| POST | `/api/workspaces/:id/videos/:videoId/render` | Bearer + member | Start video render |
| GET | `/api/workspaces/:id/render/:jobId` | Bearer + member | Get render job status |

---

# Environment (for reference)

**Frontend:**

- **API base URL** – e.g. `process.env.REACT_APP_API_URL` or `NEXT_PUBLIC_API_URL` pointing to `https://your-backend.com/api`.
- **Google OAuth** – Backend redirects to `FRONTEND_URL` + `OAUTH_SUCCESS_PATH` with `#access_token=...`. Frontend should read token from hash and optionally store it.
- **Cookie** – Refresh token is HTTP-only; ensure requests to the API (e.g. `/api/auth/refresh`) are same-origin or CORS is configured so cookies are sent when needed.

**Backend (render worker):**

- **`HEYGEN_API_KEY`** – When set, the render worker uses HeyGen to generate videos (one API call per video; combined script, single avatar/voice from first scene).
- **`RENDER_SERVICE_URL`** – Optional. When HeyGen is not used, POST `{ inputProps }` here; response should include `{ outputUrl }`. If neither `HEYGEN_API_KEY` nor `RENDER_SERVICE_URL` is set, jobs complete with `outputUrl` null.

---

**End of API documentation**
