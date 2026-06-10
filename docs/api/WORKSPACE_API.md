# Workspace API

Base path: **`/api/workspaces`**

All workspace routes require **`Authorization: Bearer <access_token>`**. Some routes require a specific **workspace role** (OWNER, ADMIN, or MEMBER).

- **OWNER**: Full control; rename workspace, delete TEAM workspace, change roles, invite, cancel invitations, list members and invitations, remove members (per rules below).
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

## Rename workspace

Only **OWNER**. Applies to both **PRIVATE** and **TEAM** workspaces.

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:id` |
| **Auth** | Bearer |
| **Role** | OWNER |

**Request body**

- `name`: string, **3–100** characters.

```json
{
  "name": "Renamed Team"
}
```

**Response (200)** – `data`:

```json
{
  "workspace": {
    "id": "uuid",
    "name": "Renamed Team",
    "type": "TEAM",
    "ownerId": "uuid",
    "credits": 0,
    "owner": { "id": "...", "email": "...", "name": "..." },
    "createdAt": "ISO8601",
    "updatedAt": "ISO8601"
  }
}
```

- **403** if not owner. **404** if workspace not found.

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

Sends an email with an accept link. If the invitee already has an AthenaVI account, a **`WORKSPACE_INVITATION`** item is also added to their platform inbox (`GET /api/user/inbox`). Users who register later with the same email receive matching inbox items on signup. Effective role for the invite must be **ADMIN** or **MEMBER** (OWNER is rejected by the server with **400** even if it passes generic validation).

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
      "createdBy": "user-uuid",
      "updatedBy": "user-uuid",
      "createdAt": "2026-05-16T12:00:00.000Z",
      "lastModifiedAt": "2026-05-18T09:00:00.000Z",
      "owner": {
        "id": "user-uuid",
        "name": "Jane Doe",
        "email": "jane@example.com"
      },
      "lastModifiedBy": {
        "id": "user-uuid",
        "name": "Jane Doe",
        "email": "jane@example.com"
      },
      "creator": {
        "id": "user-uuid",
        "name": "Jane Doe",
        "email": "jane@example.com"
      },
      "projectCount": 3,
      "sizeBytes": 52428800,
      "lastActivityAt": "2026-05-20T14:30:00.000Z"
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `owner` | User who created the folder (`createdBy`). |
| `creator` | **Deprecated** — same object as `owner`; kept for backward compatibility. |
| `lastModifiedAt` | When the folder record was last updated (e.g. rename). |
| `lastModifiedBy` | User who last updated folder metadata. |
| `projectCount` | Number of projects in the folder. |
| `sizeBytes` | Sum of each project’s `storageBytes` in this folder (see projects). Shared assets referenced by multiple projects may be counted more than once. |
| `lastActivityAt` | Latest `updatedAt` among projects in the folder (editor saves), or `null` if empty. |

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
    "workspaceId": "uuid",
    "createdBy": "user-uuid",
    "updatedBy": "user-uuid",
    "createdAt": "2026-05-16T12:00:00.000Z",
    "lastModifiedAt": "2026-05-16T12:00:00.000Z",
    "owner": { "id": "user-uuid", "name": "Jane Doe", "email": "jane@example.com" },
    "lastModifiedBy": { "id": "user-uuid", "name": "Jane Doe", "email": "jane@example.com" },
    "creator": { "id": "user-uuid", "name": "Jane Doe", "email": "jane@example.com" },
    "projectCount": 0,
    "sizeBytes": 0,
    "lastActivityAt": null
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

Supported scene transition types (API values — kebab-case):

| Editor label | API `type` |
|--------------|------------|
| None | `cut` |
| Dissolve | `dissolve` |
| Slide left / right / up / down | `slide-left`, `slide-right`, `slide-up`, `slide-down` |
| Circle Wipe In / Out | `circle-wipe-in`, `circle-wipe-out` |
| Colour wipe left / right / up / down | `colour-wipe-left`, `colour-wipe-right`, `colour-wipe-up`, `colour-wipe-down` |
| Line wipe left / right / up / down | `line-wipe-left`, `line-wipe-right`, `line-wipe-up`, `line-wipe-down` |
| Match & Move | `match-move` |
| Flow left / right / up / down | `flow-left`, `flow-right`, `flow-up`, `flow-down` |
| Stack left / right / up / down | `stack-left`, `stack-right`, `stack-up`, `stack-down` |
| Chop | `chop` |

Legacy types still accepted: `fade`, `wipe-left`, `wipe-right`, `zoom-in`, `zoom-out`. Display names and `color-wipe-*` spellings are normalized via aliases. Optional on colour wipes: `color` or `wipeColor` (hex, default `#ffffff`).

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

Supports the **Create Video** wizard (**canvas size** → **details**) in one call when the user clicks **Create Video**.

| UI (Details step) | API | Required |
|-------------------|-----|----------|
| Video title | `title` or `name` | Yes |
| Tags | `tags` — string array, e.g. `["Professional", "Presentation"]` | No |
| Workspace | **URL** `:workspaceId` (from workspace dropdown). Optional body `workspaceId` must match the URL if sent. Load options: `GET /api/workspaces` |
| Choose folder | `folderId` — must belong to that workspace. Load options: `GET /api/workspaces/:workspaceId/folders` | Yes |

| Field | Required | Notes |
|-------|----------|--------|
| `aspectRatio` or `canvasSize` | No | From canvas step: `16:9` \| `9:16` \| `1:1` \| `4:5` \| `custom` |
| `customWidth`, `customHeight` | If `custom` | Pixel size when canvas is **Custom** |
| `data` or `projectState` | No | Full editor JSON; omit for empty `scenes` + canvas preset only |
| `thumbnail`, `duration`, `status` | No | Unchanged |

Use **either** `data` **or** `projectState` for the editor payload (not both). Canvas presets set `videoSettings.width` / `height` when not overridden in `data.videoSettings`:

| Preset | Default size |
|--------|----------------|
| `16:9` | 1920 × 1080 |
| `9:16` | 1080 × 1920 |
| `1:1` | 1080 × 1080 |
| `4:5` | 1080 × 1350 |
| `custom` | `customWidth` × `customHeight` |

**Wizard example (canvas + details)**

```http
POST /api/workspaces/{workspaceId-from-dropdown}/projects
```

```json
{
  "title": "Untitled Video",
  "folderId": "folder-uuid-from-dropdown",
  "aspectRatio": "16:9",
  "tags": ["Professional", "Presentation"]
}
```

**Full editor example (unchanged)**

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

Saved `data.meta` includes `aspectRatio` and `tags` when provided.

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

**Response (200)** – `data.projects`: array ordered by `lastModifiedAt` desc. List responses **omit** `data` (editor JSON); use get-by-id for full editor state.

Each project includes:

| Field | Meaning |
|-------|---------|
| `owner` | Creator (`createdBy`). |
| `lastModifiedAt` | `updatedAt` of the project row. |
| `lastModifiedBy` | User who last saved metadata or editor state (`updatedBy`). System-only rehydration on load does not change `lastModifiedBy`. |
| `storageBytes` | Denormalized footprint: editor JSON size + referenced workspace `Asset.size` values + HeyGen/render/cache S3 sizes for this project. |

---

### Get project

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId` |
| **Auth** | Bearer + member |

**Response (200)** – `data.project`: project row including `folder`, saved `data`, and the same metadata fields as list (`owner`, `lastModifiedAt`, `lastModifiedBy`, `storageBytes`).

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

> **Frontend integration guide:** [`docs/PROJECT_EDITOR_INTEGRATION.md`](docs/PROJECT_EDITOR_INTEGRATION.md) — full V2 payload, HeyGen flow, save/load, playback, and troubleshooting.

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

**V2 editor shape (full round-trip)** — The API accepts rich editor payloads; extra fields are **not stripped**. You may send either `elements` or `clips` (normalized to `elements`).

| Level | Optional fields (persisted) |
|-------|-----------------------------|
| **Scene** | `order`, `locked`, `layout`, `presenter` (`avatarId`, `voiceId`, `script`, `voiceSettings`, …), `generation` (`status`, `heygenVideoId`, …), flat or `in`/`out` **transition** |
| **Element** | `role`, `visible`, `editable`, `isBackground`, **`timing`** `{ startFrame, durationInFrames }` (or top-level `startFrame` / `durationInFrames`), **`style`**, **`filters`**, **`audio`** |

HeyGen: store **`presenter`** + **`generation.heygenVideoId`** at scene level and/or on avatar **`content`**. Do **not** rely on **`generation.generatedVideoUrl`** or **`blob:`** URLs after reload — refetch playback via **`GET .../heygen/videos/:heygenVideoId/download`** or **`/stream`**.

Text/image styles: top-level **`style`** / **`filters`** are saved; the server also mirrors key fields into **`content`** for Remotion (e.g. `style.fontSize` → `content.fontSize`, `style.objectFit` → `content.fit`).

Important rules:

- `sceneId` must stay stable across edits
- scene order is the order of `scenes[]`
- avatar elements should include `heygenVideoId` once the scene clip has been generated (from `POST .../heygen/videos` → `data.heygenVideo.id`), or on **`scene.generation.heygenVideoId`**
- frontend should send `assetId` for workspace uploads, not raw S3 keys
- **Server rehydration:** On **`GET .../projects/:projectId`** and **`PATCH .../projects/:projectId/data`**, the backend merges missing `heygenVideoId` from **`heygen_responses`** using **`scene.presenter`**, **`scene.generation`**, and avatar **`content`**. **`GET`** persists repairs when changes are detected.

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

---

**[← API index](README.md)** · [Project root README](../../README.md)

