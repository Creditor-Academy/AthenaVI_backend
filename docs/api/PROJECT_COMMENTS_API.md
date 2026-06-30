# Project comments API

Base path: **`/api/workspaces/:workspaceId/projects/:projectId/comments`**

All routes require **`Authorization: Bearer <access_token>`** and workspace membership (`OWNER`, `ADMIN`, or `MEMBER`).

Comments are plain text with explicit `@mention` user IDs supplied by the client. In-app notifications respect [`commentsAndMentions`](USER_SETTINGS_API.md) and the master `pushNotifications` toggle.

---

## List comments

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/comments` |
| **Auth** | Bearer |

**Query (optional)**

| Param | Type | Description |
|---|---|---|
| `limit` | number | 1–100, default 50 |
| `cursor` | UUID | Pagination: return comments older than this comment id |

**Response (200)** – `data`:

```json
{
  "comments": [
    {
      "id": "uuid",
      "body": "Looks great!",
      "mentionedUserIds": ["uuid"],
      "author": {
        "id": "uuid",
        "name": "Jane Doe",
        "profileImage": "https://..."
      },
      "createdAt": "ISO8601",
      "updatedAt": "ISO8601"
    }
  ],
  "nextCursor": "uuid-or-null"
}
```

---

## Create comment

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/comments` |
| **Auth** | Bearer |

**Request body**

```json
{
  "body": "Can we shorten the intro?",
  "mentionedUserIds": ["uuid"]
}
```

| Field | Type | Rules |
|-------|------|-------|
| `body` | string | Required, 1–4000 chars |
| `mentionedUserIds` | string[] | Optional, max 20 UUIDs; must be workspace members |

**Notifications (in-app)**

- Mentioned users → `PROJECT_COMMENT_MENTION`
- Project creator (`createdBy`) → `PROJECT_COMMENT_ADDED` (unless author or already mentioned)

**Response (201)** – `data`: `{ "comment": { ... } }`

---

## Update comment

Author only.

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/comments/:commentId` |
| **Auth** | Bearer |

**Request body** — same shape as create. Only **newly added** mention IDs trigger additional mention notifications.

**Response (200)** – `data`: `{ "comment": { ... } }`

**403** — not the author. **404** — comment or project not found.

---

## Delete comment

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/comments/:commentId` |
| **Auth** | Bearer |

Soft-deletes the comment. Author may delete own comment; workspace **OWNER** or **ADMIN** may delete any comment.

**Response (200)** – `data`: `{ "deleted": true }`

---

## Mentionable users (autocomplete)

Available to all workspace members (unlike `GET /api/workspaces/:id/members`, which is OWNER/ADMIN only).

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/comments/mentionable-users` |
| **Auth** | Bearer |

**Query (optional)**

| Param | Description |
|---|---|
| `q` | Search by name or email (case-insensitive), max 20 results |

**Response (200)** – `data`:

```json
{
  "users": [
    { "id": "uuid", "name": "Jane Doe", "email": "jane@example.com" }
  ]
}
```

---

**[← API index](README.md)** · [Notifications frontend guide](../NOTIFICATIONS_FRONTEND_INTEGRATION.md)
