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
- **Protected**: All `/api/user/*`, `/api/workspaces/*`, `/api/credits/*`, `/api/assets/*`, and `/api/heygen/*` require `Authorization: Bearer <access_token>`. Workspace, project, render, asset, credit, and most HeyGen flows additionally require workspace membership or specific roles where noted. **Project**, **render**, and **HeyGen avatar video** routes under `/api/workspaces/:workspaceId/projects/*` require a workspace **member** role (OWNER, ADMIN, or MEMBER), and the `projectId` must belong to that workspace.

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

**Folders** for a workspace are documented under **`/api/workspaces/:workspaceId/folders`** (see **Folders** below in this section).

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

## Folders

Nested routes under **`/api/workspaces/:workspaceId/folders`**. All routes below require **`Authorization: Bearer <access_token>`**.

`rename` and `delete` run **`folderPermission`**: the user must be a **workspace member** with role **OWNER** or **ADMIN**, or be the **creator** of the folder.

---

### List folders

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/folders` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "folders": [
    {
      "id": "uuid",
      "name": "My folder",
      "workspaceId": "uuid",
      "createdBy": "uuid",
      "createdAt": "ISO8601",
      "updatedAt": "ISO8601"
    }
  ]
}
```

---

### Create folder

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/folders` |
| **Auth** | Bearer |

**Request body**

- `name`: string, **1–255** characters (trimmed).

```json
{
  "name": "New folder"
}
```

**Response (201)** – `data`:

```json
{
  "folder": {
    "id": "uuid",
    "name": "New folder",
    "createdAt": "ISO8601"
  }
}
```

---

### Rename folder

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/folders/:folderId` |
| **Auth** | Bearer |
| **Permission** | Folder creator, or workspace OWNER/ADMIN |

**Request body**

```json
{
  "name": "Renamed folder"
}
```

**Response (200)** – `data`: `{ "folder": { ... } }`.

---

### Delete folder

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:workspaceId/folders/:folderId` |
| **Auth** | Bearer |
| **Permission** | Folder creator, or workspace OWNER/ADMIN |

**Response (200)** – `data`: `{ "folder": { ... } }`.

---

## Projects

Nested routes under **`/api/workspaces/:workspaceId/projects`**. All routes below require **`Authorization: Bearer <access_token>`** and workspace **member** access.

`Project.data` stores the full video editor state. The backend validates:

- `videoSettings.width`
- `videoSettings.height`
- `videoSettings.fps`
- `scenes[]`
- each scene's `sceneId`, `durationInFrames`, `background`, `elements[]`
- each element's `id`, `type`, `layer`, `startFrame`, `durationInFrames`, `placement`, `content`, and `animations[]`

Supported V1 element types:

- `avatar`
- `text`
- `image`
- `video`
- `audio`
- `shape`
- `subtitle`

Supported V1 transition types:

- `cut`
- `fade`
- `slide-left`
- `slide-right`
- `slide-up`
- `slide-down`
- `wipe-left`
- `wipe-right`
- `zoom-in`
- `zoom-out`

Supported V1 animation types:

- `fade-in`
- `fade-out`
- `slide-up`
- `slide-down`
- `slide-left`
- `slide-right`
- `zoom-in`
- `zoom-out`
- `scale-in`
- `scale-out`
- `rotate-in`
- `rotate-out`
- `typewriter`
- `bounce`
- `pulse`

---

### Create project

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/projects` |
| **Auth** | Bearer + member |

**Request body**

Use either `data` or `projectState` for the editor payload. Both are validated the same way.

```json
{
  "name": "My Video Project",
  "folderId": "folder-uuid",
  "data": {
    "videoSettings": {
      "width": 1920,
      "height": 1080,
      "fps": 30,
      "backgroundColor": "#000000"
    },
    "scenes": []
  },
  "thumbnail": "https://example.com/project-preview.png",
  "status": "draft"
}
```

**Response (201)** – `data.project`: created project row with `folder`, `data`, `duration`, and timestamps.

---

### List projects

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects` |
| **Auth** | Bearer + member |

**Query (optional)**

- `folderId` – filter projects inside one folder

**Response (200)** – `data.projects`: array ordered by `updatedAt desc`.

---

### Get project

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId` |
| **Auth** | Bearer + member |

**Response (200)** – `data.project`: project row including `folder` and saved `data`.

---

### Update project metadata

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId` |
| **Auth** | Bearer + member |

**Request body** (any one or more fields)

```json
{
  "name": "Renamed video",
  "thumbnail": "https://example.com/new-preview.png",
  "duration": 450,
  "status": "draft"
}
```

**Response (200)** – `data.project`: updated project row.

---

### Save editor state

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/data` |
| **Auth** | Bearer + member |

**Request body**

```json
{
  "data": {
    "videoSettings": {
      "width": 1920,
      "height": 1080,
      "fps": 30,
      "backgroundColor": "#000000"
    },
    "scenes": [
      {
        "sceneId": "scene_001",
        "name": "Intro Scene",
        "durationInFrames": 150,
        "background": {
          "type": "color",
          "value": "#101828"
        },
        "transition": {
          "in": {
            "type": "fade",
            "durationInFrames": 12,
            "easing": "easeOut"
          },
          "out": {
            "type": "slide-left",
            "durationInFrames": 12,
            "easing": "easeInOut"
          }
        },
        "elements": [
          {
            "id": "avatar_001",
            "type": "avatar",
            "layer": 10,
            "startFrame": 0,
            "durationInFrames": 150,
            "placement": {
              "x": 1180,
              "y": 180,
              "width": 520,
              "height": 820,
              "rotation": 0,
              "scale": 1,
              "opacity": 1
            },
            "content": {
              "provider": "heygen",
              "sceneId": "scene_001",
              "avatarId": "heygen-avatar-id",
              "voiceId": "heygen-voice-id",
              "script": "Welcome to our platform.",
              "heygenVideoId": "heygen-response-id"
            },
            "animations": [
              {
                "type": "fade-in",
                "startFrame": 0,
                "durationInFrames": 10,
                "easing": "easeOut"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

Important rules:

- `sceneId` must stay stable across edits
- scene order is the order of `scenes[]`
- avatar elements must send `heygenVideoId` once the scene clip has been generated
- frontend should send `assetId`, not raw S3 keys

**Response (200)** – `data.project`: updated project row with normalized `data` and computed `duration`.

---

### Move project to another folder

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/move-folder` |
| **Auth** | Bearer + member |

**Request body**

```json
{
  "folderId": "new-folder-uuid"
}
```

When a project moves folders, the backend also migrates folder-aware S3 paths for:

- generated HeyGen scene clips
- cached rendered scene clips
- final rendered exports

**Response (200)** – `data.project`: updated project row now pointing at the new folder.

---

### Delete project

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId` |
| **Auth** | Bearer + member |

Deletes the project and attempts to delete related HeyGen scene clips, scene render caches, and final render files from S3.

**Response (200)** – `data`: `{}`.

---

## Project renders

Nested routes under **`/api/workspaces/:workspaceId/projects/:projectId/renders`**. These routes render the full project in the same backend using Remotion.

Render behavior in V1:

- resolves `assetId` references to real assets
- resolves avatar scene clips from saved `heygenVideoId`
- hashes scenes for cache reuse
- reuses unchanged cached scene renders
- stitches cached and newly rendered scene clips into one final MP4

Final output is stored under a folder-aware S3 key:

- `workspaces/{workspaceId}/folders/{folderId}/projects/{projectId}/renders/{renderId}/final.mp4`

Scene caches use:

- `workspaces/{workspaceId}/folders/{folderId}/projects/{projectId}/scene-cache/{sceneId}/{sceneHash}.mp4`

---

### Start render

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/renders` |
| **Auth** | Bearer + member |

**Request body**

```json
{
  "forceRebuild": false
}
```

- `forceRebuild: true` ignores cached scene renders and rebuilds every scene.

**Response (202)** – `data.render`: queued render row with `status`, `progress`, and ids.

---

### List renders

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/renders` |
| **Auth** | Bearer + member |

**Response (200)** – `data.renders`: render history ordered by `createdAt desc`.

---

### Get render

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId` |
| **Auth** | Bearer + member |

**Response (200)** – `data.render`: render row including `status`, `progress`, `sceneHashes`, `s3Key`, `outputUrl`, timestamps, and `error`.

---

### Download final render

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId/download` |
| **Auth** | Bearer + member |

Returns a fresh presigned URL for the completed final MP4.

**Response (200)** – `data`:

```json
{
  "presignedUrl": "https://...",
  "expiresInSeconds": 3600,
  "render": {
    "id": "render-uuid",
    "status": "completed",
    "s3Key": "workspaces/.../final.mp4"
  }
}
```

**409** if the render is not completed yet.

---

# Assets API

Base path: **`/api/assets`**

Workspace uploads are stored in **S3**; metadata is tied to the workspace and counts against the **workspace owner’s** storage quota.

All routes require **`Authorization: Bearer <access_token>`** and **`checkWorkspaceAccess`**:

- **PRIVATE** workspace: only the **owner** may access routes for that `workspaceId`.
- **TEAM** workspace: any **member** may access.

---

## Upload asset

`multipart/form-data` with a single file field **`file`**.

Allowed MIME types: **`image/jpeg`**, **`image/png`**, **`image/webp`**, **`video/mp4`**, **`audio/mp3`**. Maximum size **50 MB**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/assets/:workspaceId/upload` |
| **Auth** | Bearer (see workspace rules above) |

**Response (201)** – `data`: `{ "asset": { ... } }` (includes URL, name, size, type, etc.).

- **400** if file type invalid or storage limit exceeded.

---

## List assets

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/assets/:workspaceId` |
| **Auth** | Bearer (see workspace rules above) |

**Query (optional)**

- `take` – page size, **1–100** (default **20** when omitted).
- `skip` – offset, default **0**.

For **PRIVATE** workspaces, only assets **uploaded by the current user** are returned. For **TEAM** workspaces, assets for the whole workspace are listed.

**Response (200)** – `data`: `{ "assets": [ ... ] }`.

---

## Rename asset

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/assets/:workspaceId/:assetId/rename` |
| **Auth** | Bearer (see workspace rules above) |

**Request body**

```json
{
  "name": "new-name.webp"
}
```

- `name`: string, **1–255** characters (trimmed).

**Response (200)** – `data`: `{ "asset": { ... } }`.

---

## Delete asset

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/assets/:workspaceId/:assetId` |
| **Auth** | Bearer (see workspace rules above) |

Removes the object from storage (when applicable) and decrements the owner’s **storageUsed**.

**Response (200)** – `data`: `{ "asset": { ... } }`.

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

# HeyGen API

Base path: **`/api/heygen`**

Proxies **[HeyGen](https://www.heygen.com/)** v3 capabilities (avatars, voices — list, design, clone, detail, speech preview). The server must set **`HEYGEN_API_KEY`**; without it, HeyGen calls return **500**. Optional **`HEYGEN_BASE_URL`** overrides the API host (default `https://api.heygen.com`).

**Avatar / lip-sync video generation** (create job, list, status, S3 storage, **stream** & **presigned** playback) is **not** on this path — see **HeyGen avatar videos (workspace project)** later in this document (`/api/workspaces/.../heygen/...`).

All routes in this section require **`Authorization: Bearer <access_token>`**.

### User-scoped private avatars and voices

The backend uses a single **`HEYGEN_API_KEY`**, so HeyGen’s own “private” listings would normally include assets from every user of your app. This API **records ownership per authenticated user** and applies extra rules:

| Case | Behavior |
|------|----------|
| **`GET /api/heygen/avatars/groups?ownership=private`** | Response lists only avatar groups **created with `POST /api/heygen/avatars` while logged in as that user** (persisted after a successful create). |
| **`GET /api/heygen/avatars/looks?ownership=private`** | Response lists only looks whose avatar group id is **owned by that user**. If **`group_id`** is set together with **`ownership=private`**, the user must own that group or the API returns **403** (`message`: **`HEYGEN_FORBIDDEN`**). |
| **`GET /api/heygen/voices?type=private`** | Only voices **recorded for the current user** in `heygen_voices`: from **`POST /api/heygen/voices/select`** (after picking a design suggestion) or **`POST /api/heygen/voices/clone`**. Design suggestions alone are **not** stored. |
| **`POST /api/heygen/avatars/:groupId/consent`** | **403** if `groupId` is not owned by the current user. |
| **`GET /api/heygen/voices/:voiceId`** | **403** only for **another user’s cloned** voice (`source: clone` in `heygen_voices`). Public / selected catalog voices are readable by anyone; **select** can add the same `voiceId` to each user’s My voices separately. |
| **`ownership=public`**, **`type=public`**, or omitted filters | Unchanged passthrough to HeyGen (no user filtering). |

**Legacy:** Avatars/voices created before this ownership tracking was deployed were never recorded and **will not appear** in the filtered private lists until recreated or backfilled.

**Implementation note:** For **`ownership=private`** and **`type=private`**, the server still calls HeyGen with those params, then **filters the JSON locally** so other tenants’ rows disappear from the response. HeyGen’s list payloads vary (e.g. nested **`data`** arrays, **`avatar_group_list`**, **`looks`**, **`voices`**, **`suggestions`**); this backend discovers those containers and keeps only rows whose **group id** or **voice id** is stored for **your** JWT user (`heygen_avatars`, `heygen_voices`). **`POST /api/heygen/avatars`** resolves the avatar **group id** from nested **`data`** / **`avatar_group`** fields in HeyGen’s create response (not only a single top-level object) before writing **`heygen_avatars`**; if the response truly omits a group id until a future poll, nothing is recorded yet and private lists stay empty until creation returns one. It prefers **non-empty** array fields when several keys exist, rewrites pagination totals (**`total`**, **`count`**, **`total_count`**) when present to match the filtered length, and records voice ids from **clone** or **`POST .../voices/select`** so **private voice lists** stay consistent (design suggestions are not auto-recorded). For **`GET .../voices?type=private`**, after filtering HeyGen’s list, the server **merges in** voice ids stored in **`heygen_voices`** for your user that HeyGen did not return (common for some design-selected voices), using each row’s saved **`raw`** from **`/voices/select`** or clone where possible.

---

## List avatar groups

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/avatars/groups` |
| **Auth** | Bearer |

**Query (optional)** – forwarded to HeyGen; common keys include:

- `ownership` – `public` or `private` (**private**: filtered to the current user’s recorded avatar groups — see **User-scoped private avatars and voices** above)
- `limit` – integer **1–50**
- `token` – pagination cursor (string)

**Response (200)** – `data`: HeyGen payload (avatar groups).

**403** – **`HEYGEN_FORBIDDEN`** is not used here; filtering narrows the list instead.

---

## List avatar looks

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/avatars/looks` |
| **Auth** | Bearer |

**Query (optional)**

- `group_id`
- `avatar_type` – `studio_avatar`, `digital_twin`, or `photo_avatar`
- `ownership` – `public` or `private` (**private**: filtered to groups owned by the current user; **`group_id` + private** requires ownership or **403**)
- `limit` – **1–50**
- `token` – pagination cursor

**Response (200)** – `data`: HeyGen payload.

**403** – **`HEYGEN_FORBIDDEN`** — private listing with a **`group_id`** that belongs to another user.

---

## Create avatar

Starts HeyGen avatar creation (`digital_twin`, `photo`, or `prompt`).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/avatars` |
| **Auth** | Bearer |

**Option A — JSON** (`Content-Type: application/json`)

- `type`: **`digital_twin`** | **`photo`** | **`prompt`** (required).
- `name`: string, max **200** chars (required).
- For **`prompt`**: `prompt` text is required (non-empty).
- For **`digital_twin`** or **`photo`**: `file` is required — object shaped per HeyGen v3 (`type`: `url` \| `asset_id` \| `base64`, plus applicable fields).
- Optional: `reference_images` (array, max **20** items), `avatar_group_id`, etc.

**Option B — Multipart file** (`Content-Type: multipart/form-data`)

Use this to upload an image or video directly from Postman or the app without hosting a public URL.

- Form fields: **`type`** (`photo` or **`digital_twin` only**), **`name`** (required).
- Binary field **`file`** (required): **photo** → `image/jpeg`, `image/png`, or `image/webp`; **digital_twin** → same images or **`video/mp4`** / **`video/webm`**.
- Optional text fields: **`avatar_group_id`**, **`reference_images`** as a **JSON string** array (same shape as JSON API).
- Max **32 MB** per file. **`prompt`** avatars — use **JSON** only (no `file`).

The server converts the upload into HeyGen’s **`file`: `{ type: base64, media_type, data }`** payload.

**Response (200)** – `data`: HeyGen creation response. On success, the server persists the new avatar **group id** for the current user (when HeyGen returns it) so it appears under **`ownership=private`** lists (groups and looks).

---

## Avatar consent URL

Returns a consent / onboarding URL for a pending avatar group.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/avatars/:groupId/consent` |
| **Auth** | Bearer |

**Request body** (optional)

```json
{
  "reroute_url": "https://your-app.com/after-consent"
}
```

**Response (200)** – `data`: HeyGen payload.

**403** – **`HEYGEN_FORBIDDEN`** — `:groupId` is not owned by the current user.

---

## List voices

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/voices` |
| **Auth** | Bearer |

**Query (optional)**

- `type` – `public` or `private` (**private**: filtered to voices recorded for the current user from **select** or **clone** — see **User-scoped private avatars and voices** above)
- `engine`, `language`, `gender` (`male` \| `female`)
- `limit` – **1–100**
- `token` – pagination cursor

**Response (200)** – `data`: HeyGen voices payload.

---

## Design a voice (semantic search)

Maps to HeyGen **`POST /v3/voices`** — returns up to **3** suggested voices for a natural-language prompt. **Do not send `voice_id` on this route** (that field is for **`POST /api/heygen/voices/select`** after the user picks a suggestion).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices` |
| **Auth** | Bearer |

**Request body**

- `prompt`: string, **1–1000** chars (required) — e.g. “warm, confident female narrator”.
- Optional: `gender` (`male` \| `female`), `locale` (BCP-47), `seed` (integer ≥ 0 for alternate batches).

**Response (200)** – `data`: HeyGen payload (`voices`, `seed`). Suggestion **`voice_id`** values are **not** written to **`heygen_voices`** — same idea as avatar create vs. listing: only an explicit user action persists ownership.

**Frontend:** Show the suggestions, then on **Select** call **`POST /api/heygen/voices/select`** with the chosen id, then refresh **`GET .../voices?type=private`**.

---

## Select voice (persist to My voices)

Call this when the user clicks **Select** on a designed/suggested voice. It records the chosen **`voiceId`** for the current user in **`heygen_voices`** so it appears under **`GET /api/heygen/voices?type=private`**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/select` |
| **Auth** | Bearer |

**Request body**

Either field is accepted (use the id from the design suggestion object — often `voice_id`):

```json
{
  "voice_id": "heygen-voice-id-from-design-response"
}
```

or `{ "voiceId": "..." }`.

**Response (200)** – `data`:

```json
{
  "selected": true,
  "voiceId": "heygen-voice-id-from-design-response",
  "voice": { }
}
```

- `voice` is the proxied HeyGen **`GET /v3/voices/{voice_id}`** payload for that id.
- The server upserts a row in **`heygen_voices`** with `source: "select"`.

**Typical frontend flow**

1. `POST /api/heygen/voices` with `prompt` → show suggestion list.
2. User clicks **Select** on one suggestion → `POST /api/heygen/voices/select` with that `voiceId`.
3. Refresh **My voices** with `GET /api/heygen/voices?type=private`.

---

## Clone a voice

Maps to HeyGen **`POST /v3/voices/clone`**. Poll **`GET /api/heygen/voices/:voiceId`** with the returned **`voice_clone_id`** until status is **`complete`**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/clone` |
| **Auth** | Bearer |

**Request body** (proxied to HeyGen; use snake_case or camelCase for the name field)

- `voice_name` or `voiceName`: string, **1–100** chars (required).
- `audio`: object (required) — HeyGen asset union:
  - `{ "type": "url", "url": "https://..." }`
  - `{ "type": "asset_id", "asset_id": "..." }`
  - `{ "type": "base64", "media_type": "audio/mpeg", "data": "..." }`
- Optional: `language`, `remove_background_noise` / `removeBackgroundNoise` (boolean; HeyGen default **true**).

Example:

```json
{
  "voice_name": "My cloned voice",
  "audio": {
    "type": "url",
    "url": "https://example.com/sample.mp3"
  },
  "remove_background_noise": true
}
```

**Response (200)** – `data` includes HeyGen’s payload plus normalized ids when present:

- `voice_clone_id` from HeyGen (poll with this id).
- `voiceCloneId` / `voiceId` — same id, duplicated for convenience.

The clone id is **stored for the current user** (`source: clone`) so it appears under **`GET .../voices?type=private`** once HeyGen returns it.

**Do not send `voice_id` on clone** — that field is only for **`POST /api/heygen/voices/select`** after design suggestions.

**Troubleshooting (browser / CreateVoice)**

- **Body size** — Base64 audio grows ~4/3 vs raw bytes. The server uses **`express.json`** with limit **`JSON_BODY_LIMIT`** (default **15mb** in code). If the request never reaches HeyGen, you may see **413** with a hint to raise the limit or use **`url`** / **`asset_id`** instead of base64.
- **Format** — HeyGen may reject some containers/codecs. **Chrome `MediaRecorder` often outputs WebM**; if clone fails with a HeyGen **400**, try **WAV/MP3** (`audio/wav`, `audio/mpeg`) or upload to HeyGen assets and send **`asset_id`**.
- **Errors** — When HeyGen rejects the payload, the API usually returns **400** with HeyGen’s message in **`errors`** (not a silent **500**).

---

## Get voice by id

Maps to HeyGen **`GET /v3/voices/{voice_id}`** — voice details and clone **status** (`processing` \| `complete` \| `failed`) when applicable.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/voices/:voiceId` |
| **Auth** | Bearer |

**Response (200)** – `data`: HeyGen voice detail payload.

**403** – **`HEYGEN_FORBIDDEN`** — voice id is another user’s **clone** (not shared public/catalog voices).

---

## Preview speech (voice synthesis)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/preview-speech` |
| **Auth** | Bearer |

**Request body**

- `text`: string, **1–5000** chars (required).
- `voice_id`: string (required).
- `input_type`: **`text`** (default) or **`ssml`**.
- Optional: `speed` (**0.5–2**), `language`, `locale`.

**Response (200)** – `data`: HeyGen speech preview payload.

---

# HeyGen avatar videos (workspace project)

Creates HeyGen **`POST /v3/videos`** avatar jobs per **workspace → folder → project → scene**, polls **`GET /v3/videos/:video_id`**, downloads the finished MP4 to **S3** (`workspaces/{workspaceId}/folders/{folderId}/projects/{projectId}/scenes/{sceneId}/heygen/{heygenVideoId}.mp4`). Playback uses **`/download`** (presigned URL), **`/stream`** (authenticated pipe-through API), or optional **`/s3-location`** metadata—see below.

| | |
|---|---|
| **Base path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen` |
| **Auth** | **Bearer** + workspace **member** (OWNER, ADMIN, or MEMBER via `requireWorkspaceRole`) |
| **Server** | **`HEYGEN_API_KEY`**, **`AWS_S3_BUCKET`**, **`AWS_REGION`**, AWS credentials used by this backend, and optional **`HEYGEN_BASE_URL`** |

**Note:** The legacy unauthenticated `POST /api/video/avatar/generate` route and `POST /api/heygen/generate` have been **removed**; use the routes below only.

---

## App developer checklist (editor & preview)

Use this for the **scene-based editor** and **in-browser preview**. **Batch / offline rendering** workflows are **not** covered here.

**1. Server environment**

| Variable | Purpose |
|----------|---------|
| **`HEYGEN_API_KEY`** | Required. HeyGen API returns **500** if missing. |
| **`HEYGEN_BASE_URL`** | Optional. Override HeyGen API base (default `https://api.heygen.com`). |
| **`AWS_S3_BUCKET`**, **`AWS_REGION`**, **`AWS_ACCESS_KEY_ID`**, **`AWS_SECRET_ACCESS_KEY`** | Required for uploading rendered MP4s from HeyGen and for **`/download`**, **`/stream`**, **`/s3-location`**. |

**2. Auth** — Send **`Authorization: Bearer <access_token>`** on every request under this base path. The user must be a **member** of the workspace in the URL.

**3. Project / scene state** — After **Create**, persist **`heygenVideoId`** (from `data.heygenVideo.id`) in your project or scene model. **Do not** store presigned URLs in saved JSON; they expire. When the user reopens a project **days later**, call **`/download`** or **`/stream`** again to obtain a **fresh** playback source (your app can do this **automatically** on load—no user action required).

**4. Preview: choose one pattern**

- **`GET .../stream`** — The **path** stays the same for the life of the project; the server enforces access on every request. A raw **`<video src="https://.../stream">`** **cannot** send a **Bearer** token, so use **`fetch(url, { headers: { Authorization: … } })`**, then **`URL.createObjectURL(blob)`** for `src` (or use **same-origin cookie** session if you implement it). Supports **`Range`** for seeking.
- **`GET .../download`** — Returns a **`presignedUrl`** you can place directly in **`video.src`**. It **expires**; call **`/download`** again when loading a scene or on playback error (again, automate in the app).

**5. CORS** — Allow your **frontend origin** to call this **API** with the headers you use (e.g. `Authorization`). Traffic for **`/stream`** goes through your **backend**, not straight to S3 in the browser, so align CORS with your API host.

**6. Polling** — After **Create**, HeyGen may still be rendering. Use **`GET .../heygen/videos/:heygenVideoId`** (or **`/download`** / **`/stream`**, which run sync first) until **`status`** is **`completed`** or handle **409** / retry in the UI.

---

## Create avatar video

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` |
| **Auth** | Bearer + member |

**Request body (JSON, camelCase)**

| Field | Required | Description |
|--------|----------|-------------|
| `sceneId` | yes | Client scene key from the editor (1–256 chars); one stored video per idempotent hash per scene |
| `avatarId` | yes | HeyGen avatar id |
| `title` | yes | Video title for HeyGen |
| `resolution` | yes | `1080p` or `720p` |
| `aspectRatio` | yes | `16:9` or `9:16` |
| `backgroundColor` | yes | Solid background, e.g. `#008000` (hex) |
| `voiceId` | yes | HeyGen voice id |
| `script` | yes | Spoken script (TTS + lip sync) |
| `expressiveness` | yes | `low`, `medium`, or `high` |
| `voiceSettings` | no | Optional: `speed`, `pitch`, `volume`, `locale`, `engine_settings` |
| `removeBackground` | no | Boolean |
| `outputFormat` | no | `mp4` (default) |

**Response (201)** – `data.heygenVideo`: saved **`HeygenResponse`** row (`id`, `videoId`, `sceneId`, `status`, …). Same script + scene + avatar + voice returns the **existing** row (idempotent).

---

## List HeyGen videos for project

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` |
| **Auth** | Bearer + member |

**Response (200)** – `data.heygenVideos`: array of stored records for that project.

---

## Get HeyGen video (poll + sync to S3)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId` |
| **Auth** | Bearer + member |

Polls HeyGen (bounded) and, when **completed**, downloads to S3 if not already stored. **Response (200)** – `data.heygenVideo` with updated `status`, `s3Key`, `videoUrl`, etc.

---

## Download HeyGen video (presigned URL)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/download` |
| **Auth** | Bearer + member |

**Query (optional)**

- `expiresIn` – presigned URL lifetime in seconds (**60–3600**; default **300**).

Runs sync first. **Response (200)** – includes `data.presignedUrl`, `data.expiresInSeconds`, and `data.heygenVideo`. **409** if the video is not ready or not yet in S3.

---

## Stream HeyGen video (stable preview URL)

Same **path shape forever**: no presigned query string that expires. The API validates **Bearer** access then pipes bytes from S3. Supports **`Range`** requests (**206 Partial Content**) so browsers can seek in `<video>`.

| | |
|---|---|
| **Method** | `GET` or `HEAD` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` |
| **Auth** | Bearer + member |

**Headers**

- **`Authorization: Bearer <token>`** (required for GET/HEAD).
- **`Range`** (optional, GET only) – forwarded to S3 for seeking; e.g. `bytes=0-1048575`.

Runs sync first. **GET** returns **`video/mp4`** bytes. **HEAD** returns metadata only (`Content-Length`, `ETag`, etc.).

**Preview integration:** See **App developer checklist** above (Bearer + `<video>`, **`fetch` + blob**, **`/download`** alternative).

---

## S3 object metadata (optional, advanced)

This endpoint exists for **automation** that needs the canonical **bucket**, **key**, and **region** after sync (e.g. future batch jobs reading objects with **IAM**). **You do not need it** for the web editor or in-browser preview—use **`/stream`** or **`/download`** above.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/s3-location` |
| **Auth** | Bearer + member |

Runs sync first. **Response (200)** includes `data.bucket`, `data.key`, `data.region`, `data.objectArn`, and `data.heygenVideo`. **409** if not completed / not in S3 yet.

**Offline / batch rendering pipelines** are still under development and are **not** documented here.

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
| GET | `/api/workspaces/:workspaceId/folders` | Bearer | List folders |
| POST | `/api/workspaces/:workspaceId/folders` | Bearer | Create folder |
| PATCH | `/api/workspaces/:workspaceId/folders/:folderId` | Bearer + creator or OWNER/ADMIN | Rename folder |
| DELETE | `/api/workspaces/:workspaceId/folders/:folderId` | Bearer + creator or OWNER/ADMIN | Delete folder |
| POST | `/api/workspaces/:workspaceId/projects` | Bearer + member | Create project |
| GET | `/api/workspaces/:workspaceId/projects` | Bearer + member | List projects (`folderId` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Get project |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Update project metadata |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId/data` | Bearer + member | Save validated editor state |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId/move-folder` | Bearer + member | Move project and migrate folder-aware S3 assets |
| DELETE | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Delete project and related assets |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/renders` | Bearer + member | Start Remotion render |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders` | Bearer + member | List project renders |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId` | Bearer + member | Get render status/details |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId/download` | Bearer + member | Get final render presigned URL |
| POST | `/api/assets/:workspaceId/upload` | Bearer + workspace access | Upload workspace asset (multipart `file`) |
| GET | `/api/assets/:workspaceId` | Bearer + workspace access | List workspace assets (`take` / `skip`) |
| PATCH | `/api/assets/:workspaceId/:assetId/rename` | Bearer + workspace access | Rename asset |
| DELETE | `/api/assets/:workspaceId/:assetId` | Bearer + workspace access | Delete asset |
| GET | `/api/credits/:id` | Bearer + OWNER/ADMIN | Workspace credit balance |
| GET | `/api/credits/:id/history` | Bearer + OWNER/ADMIN | Workspace credit history |
| GET | `/api/credits/:id/my-history` | Bearer + any member | My credits in workspace |
| GET | `/api/heygen/avatars/groups` | Bearer | HeyGen avatar groups (`ownership=private` filtered per user) |
| GET | `/api/heygen/avatars/looks` | Bearer | HeyGen avatar looks (`ownership=private` filtered per user) |
| POST | `/api/heygen/avatars` | Bearer | Create HeyGen avatar (records group for private lists) |
| POST | `/api/heygen/avatars/:groupId/consent` | Bearer | HeyGen avatar consent (own group only; else **403**) |
| GET | `/api/heygen/voices` | Bearer | List HeyGen voices (`type=private` filtered per user) |
| POST | `/api/heygen/voices` | Bearer | Design voice (suggestions only; does not add to My voices) |
| POST | `/api/heygen/voices/select` | Bearer | Persist user’s chosen voiceId to My voices |
| POST | `/api/heygen/voices/clone` | Bearer | Clone voice (records id for private list) |
| GET | `/api/heygen/voices/:voiceId` | Bearer | Voice detail / clone status (another user’s **clone** → **403**) |
| POST | `/api/heygen/voices/preview-speech` | Bearer | Speech preview |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` | Bearer + member | Create HeyGen avatar video (scene, script, lip sync) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` | Bearer + member | List HeyGen video records for project |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId` | Bearer + member | Get / poll / sync to S3 |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/download` | Bearer + member | Presigned MP4 URL (`expiresIn` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` | Bearer + member | Stream MP4 through API (stable path; use fetch+blob or cookies for `<video>`) |
| HEAD | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` | Bearer + member | Video metadata before streaming |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/s3-location` | Bearer + member | S3 bucket/key metadata (optional; not needed for editor preview) |

---

# Environment (for reference)

Frontend may need to know:

- **API base URL** – e.g. `process.env.REACT_APP_API_URL` or `NEXT_PUBLIC_API_URL` pointing to `https://your-backend.com/api`.
- **Google OAuth** – Register redirect URI `.../api/auth/google/callback`. After success, backend redirects to `FRONTEND_URL` + `OAUTH_SUCCESS_PATH` with `#access_token=...`.
- **Invitations** – Email links use `{FRONTEND_URL}/invitations/accept/<token>`; your app should route the user to login if needed, then `POST /api/workspaces/invitations/accept` with `{ "token" }`.
- **Cookie** – Refresh token is HTTP-only; ensure credentials/cookies are sent when calling `/api/auth/refresh` (same-origin or CORS `credentials` as configured).
- **HeyGen avatar videos** – Server **`HEYGEN_API_KEY`** (optional **`HEYGEN_BASE_URL`**), plus **AWS** (`AWS_S3_BUCKET`, `AWS_REGION`, credentials). Editor preview: see **HeyGen avatar videos → App developer checklist** (`/stream` vs `/download`, persisting **`heygenVideoId`**, CORS).
- **Large JSON** (e.g. voice clone **base64**) – Optional **`JSON_BODY_LIMIT`** (e.g. `32mb`). If unset, the server defaults to **15mb** for `express.json`.

---

**End of API documentation**
