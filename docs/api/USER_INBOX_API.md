# User inbox API

Base path: **`/api/user/inbox`**

All routes require **`Authorization: Bearer <access_token>`**. Notifications respect [`/api/user/settings/notifications`](USER_SETTINGS_API.md) (master `pushNotifications` plus per-domain toggles).

Workspace invitations are delivered by **email** and, when the invitee already has an account (or registers later with the same email), also appear here.

---

## Notification categories

| `category` | Types (examples) |
|------------|------------------|
| `videos` | `VIDEO_EXPORT_COMPLETED`, `VIDEO_EXPORT_FAILED` (final Remotion export only) |
| `credits` | `CREDITS_PLATFORM_GRANT`, `CREDITS_WORKSPACE_REVOKE`, `CREDITS_LOW_PERSONAL`, `CREDITS_ALLOCATED`, … |
| `storage` | `STORAGE_THRESHOLD_WARNING`, `STORAGE_UPGRADE_REJECTED`, `STORAGE_UPLOAD_BLOCKED`, … |
| `workspace` | `WORKSPACE_INVITATION`, `WORKSPACE_MEMBER_JOINED`, … |
| `platform` | `PLATFORM_HEYGEN_WALLET_LOW`, `PLATFORM_STORAGE_UPGRADE_REQUEST` (superadmin only) |

**TEAM workspace video exports:** when a member exports a final video, the **exporter**, all **OWNER**s, and all **ADMIN**s receive a notification (deduplicated per user).

---

## List inbox notifications

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/inbox` |
| **Auth** | Bearer |

**Query (optional)**

| Param | Type | Description |
|---|---|---|
| `unreadOnly` | `true` \| `false` | When `true`, only unread items |
| `limit` | number | Max items (1–100, default 50) |
| `type` | string | Filter by `InboxNotificationType` enum value |
| `category` | `videos` \| `credits` \| `storage` \| `workspace` \| `platform` | Filter by category |
| `workspaceId` | UUID | Filter by workspace |

**Response (200)** – `data`:

```json
{
  "notifications": [
    {
      "id": "uuid",
      "type": "VIDEO_EXPORT_COMPLETED",
      "category": "videos",
      "title": "\"Q1 Training\" export is ready",
      "message": "Your final video finished rendering and is ready to download.",
      "readAt": null,
      "metadata": {
        "workspaceId": "uuid",
        "workspaceName": "Acme Team",
        "workspaceType": "TEAM",
        "projectId": "uuid",
        "projectName": "Q1 Training",
        "renderId": "uuid",
        "triggeredByUserId": "uuid",
        "triggeredByName": "Jane Doe",
        "audience": "self",
        "actionUrl": "{FRONTEND_URL}/workspaces/.../projects/.../renders/..."
      },
      "workspaceId": "uuid",
      "invitationId": null,
      "referenceId": "render-uuid",
      "createdAt": "ISO8601"
    }
  ],
  "unreadCount": 1
}
```

---

## Get unread count

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/inbox/unread-count` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "unreadCount": 5,
  "byCategory": {
    "videos": 1,
    "credits": 2,
    "storage": 1,
    "workspace": 1,
    "platform": 0
  }
}
```

---

## Get one notification

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/inbox/:notificationId` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "notification": { ... } }` — **404** if not found.

---

## Mark one notification read

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/inbox/:notificationId/read` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "notification": { ... } }`

---

## Bulk mark read

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/inbox/read` |
| **Auth** | Bearer |

**Body:** `{ "notificationIds": ["uuid", "..."] }` (1–100 ids)

**Response (200)** – `data`: `{ "unreadCount": 2 }`

---

## Mark all notifications read

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/inbox/read-all` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "unreadCount": 0 }`

---

## Dismiss notification

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/user/inbox/:notificationId` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "deleted": true }`

---

**[← API index](README.md)** · [Project root README](../../README.md)
