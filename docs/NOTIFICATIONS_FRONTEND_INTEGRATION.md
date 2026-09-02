# Notifications — Frontend Integration Guide

This guide is for frontend developers integrating the **Notifications** settings tab, in-app inbox, and project comments into the main Athena VI app.

**Canonical HTTP contracts:** [`docs/api/USER_SETTINGS_API.md`](api/USER_SETTINGS_API.md) · [`docs/api/USER_INBOX_API.md`](api/USER_INBOX_API.md) · [`docs/api/PROJECT_COMMENTS_API.md`](api/PROJECT_COMMENTS_API.md)

---

## Table of contents

1. [Concepts](#1-concepts)
2. [Settings screen](#2-settings-screen)
3. [TypeScript shapes](#3-typescript-shapes)
4. [Preference behavior](#4-preference-behavior)
5. [Inbox bell UI](#5-inbox-bell-ui)
6. [Comments panel](#6-comments-panel)
7. [Error handling](#7-error-handling)
8. [Checklist](#8-checklist)

---

## 1. Concepts

| Term | Meaning |
|------|---------|
| **Push Notifications (UI)** | In-app inbox notifications — **not** browser/Web Push |
| **Email toggles** | Separate channel: weekly digest job and superadmin product broadcasts |
| **Master switch** | `pushNotifications` gates **all** inbox items, including comments |
| **Granular toggles** | API also returns `videoExportAlerts`, `creditsAlerts`, etc. — optional advanced UI |

---

## 2. Settings screen

**Load on mount**

```http
GET /api/user/settings/notifications
Authorization: Bearer <access_token>
```

**Save (optimistic PATCH per toggle)**

```http
PATCH /api/user/settings/notifications
Content-Type: application/json

{ "weeklyDigestEmail": true }
```

Send only changed fields. Response returns the full `notifications` object after merge.

**Defaults** (user never saved settings):

| Field | Default |
|-------|---------|
| `pushNotifications` | `true` |
| `commentsAndMentions` | `true` |
| `weeklyDigestEmail` | `false` |
| `productEmails` | `false` |

---

## 3. TypeScript shapes

```ts
type NotificationSettingsUI = {
  pushNotifications: boolean;
  commentsAndMentions: boolean;
  weeklyDigestEmail: boolean;
  productEmails: boolean;
};

type NotificationSettingsFull = NotificationSettingsUI & {
  videoExportAlerts: boolean;
  workspaceVideoExportAlerts: boolean;
  creditsAlerts: boolean;
  storageAlerts: boolean;
  workspaceTeamAlerts: boolean;
  platformAdminAlerts: boolean;
};
```

Example client helper:

```ts
async function loadNotificationSettings(api: ApiClient): Promise<NotificationSettingsUI> {
  const { data } = await api.get<{ notifications: NotificationSettingsFull }>(
    '/api/user/settings/notifications'
  );
  const n = data.notifications;
  return {
    pushNotifications: n.pushNotifications,
    commentsAndMentions: n.commentsAndMentions,
    weeklyDigestEmail: n.weeklyDigestEmail,
    productEmails: n.productEmails,
  };
}

async function saveNotificationToggle(
  api: ApiClient,
  patch: Partial<NotificationSettingsUI>
) {
  const { data } = await api.patch<{ notifications: NotificationSettingsFull }>(
    '/api/user/settings/notifications',
    patch
  );
  return data.notifications;
}
```

---

## 4. Preference behavior

| UI toggle | API field | Runtime effect |
|-----------|-----------|----------------|
| Push Notifications | `pushNotifications` | Master switch for all in-app inbox notifications |
| Comments and Mentions | `commentsAndMentions` | `PROJECT_COMMENT_ADDED`, `PROJECT_COMMENT_MENTION`, `PRESENTATION_COMMENT_ADDED`, `PRESENTATION_COMMENT_MENTION` (requires push on) |
| Weekly Digest Email | `weeklyDigestEmail` | Weekly summary email (server job; opt-in only) |
| Product Emails | `productEmails` | Superadmin product broadcast emails (opt-in only) |

Render, credits, storage, and workspace team alerts use the extra granular fields documented in [`USER_SETTINGS_API.md`](api/USER_SETTINGS_API.md).

---

## 5. Inbox bell UI

**Unread badge**

```http
GET /api/user/inbox/unread-count
```

Response includes `byCategory` with keys: `videos`, `credits`, `storage`, `workspace`, `platform`, `collaboration`.

**List notifications**

```http
GET /api/user/inbox?limit=50
GET /api/user/inbox?category=collaboration
GET /api/user/inbox?unreadOnly=true
```

**Mark read / dismiss**

- `PATCH /api/user/inbox/:notificationId/read`
- `PATCH /api/user/inbox/read` — body `{ "notificationIds": ["uuid"] }`
- `PATCH /api/user/inbox/read-all`
- `DELETE /api/user/inbox/:notificationId`

Open deep links from `metadata.actionUrl` (project comments link to the editor project URL; presentation comments link to the presentation editor and carry `slideId` + `commentId` in `metadata` so you can scroll to the thread).

---

## 6. Comments panel

Base: `/api/workspaces/:workspaceId/projects/:projectId/comments`

| Action | Method | Notes |
|--------|--------|-------|
| List | `GET /` | `?limit`, `?cursor` for pagination |
| Create | `POST /` | `{ body, mentionedUserIds? }` |
| Update | `PATCH /:commentId` | Author only |
| Delete | `DELETE /:commentId` | Author; OWNER/ADMIN can delete any |
| Mention autocomplete | `GET /mentionable-users?q=` | All members; use for @ picker |

**Mention flow**

1. User types `@` → call `mentionable-users?q=<partial name>`
2. On submit, send selected user IDs in `mentionedUserIds` (server validates workspace membership)
3. Display `author` from list/create response

**Inbox after comment**

- Project creator gets `PROJECT_COMMENT_ADDED` (category `collaboration`)
- Mentioned users get `PROJECT_COMMENT_MENTION`

### Presentations (separate surface)

AI PPT decks have their own slide-threaded comments at `/api/workspaces/:workspaceId/presentations/:presentationId/comments`, plus a guest-facing surface on the share link. They emit `PRESENTATION_COMMENT_ADDED` / `PRESENTATION_COMMENT_MENTION` under the same `commentsAndMentions` toggle. A reply also notifies the thread's original author, and a comment left by a share-link guest notifies the deck owner with the guest's display name. Contracts: [`PRESENTATION_COMMENTS_API.md`](api/PRESENTATION_COMMENTS_API.md).

---

## 7. Error handling

All responses use the standard envelope (`success`, `message`, `data` / `errors`).

| Status | When |
|--------|------|
| `400` | Empty PATCH body, invalid mentions, validation errors |
| `401` | Missing or expired token |
| `403` | Not workspace member; not comment author |
| `404` | Project or comment not found |

---

## 8. Checklist

- [ ] Settings tab loads four toggles from `GET /notifications`
- [ ] Each toggle PATCHes optimistically and rolls back on error
- [ ] Inbox bell shows `unreadCount` and optional category breakdown
- [ ] Comment list/create/update/delete wired to project editor
- [ ] Mention autocomplete uses `mentionable-users`
- [ ] Inbox `collaboration` filter shows comment notifications
- [ ] `actionUrl` navigates to the correct project
- [ ] Weekly digest / product email toggles persist (delivery is server-side)

---

**[← API index](api/README.md)** · [Project editor integration](./PROJECT_EDITOR_INTEGRATION.md)
