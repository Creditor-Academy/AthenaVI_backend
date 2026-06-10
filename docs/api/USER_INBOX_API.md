# User inbox API

Base path: **`/api/user/inbox`**

All routes require **`Authorization: Bearer <access_token>`**. Workspace invitations are delivered by **email** and, when the invitee already has an account (or registers later with the same email), also appear here.

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

**Response (200)** – `data`:

```json
{
  "notifications": [
    {
      "id": "uuid",
      "type": "WORKSPACE_INVITATION",
      "title": "Invitation to Acme Team",
      "message": "You have been invited to join Acme Team as MEMBER.",
      "readAt": null,
      "metadata": {
        "invitationId": "uuid",
        "workspaceId": "uuid",
        "workspaceName": "Acme Team",
        "role": "MEMBER",
        "token": "invitation-token",
        "actionUrl": "{FRONTEND_URL}/invitations/accept/<token>",
        "inviterName": "Jane Doe",
        "expiresAt": "ISO8601"
      },
      "invitationId": "uuid",
      "createdAt": "ISO8601"
    }
  ],
  "unreadCount": 1
}
```

Use `metadata.token` with **`POST /api/workspaces/invitations/accept`** after login, or open `metadata.actionUrl` in the app.

---

## Get unread count

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/inbox/unread-count` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "unreadCount": 3 }`

---

## Mark one notification read

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/inbox/:notificationId/read` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "notification": { ... } }`

- **404** if the notification does not belong to the user.

---

## Mark all notifications read

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/inbox/read-all` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "unreadCount": 0 }`

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

