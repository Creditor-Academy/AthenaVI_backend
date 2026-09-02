# Presentation comments API

Two surfaces over one comment store:

| Surface | Base path | Auth |
|---|---|---|
| **Editor** | `/api/workspaces/:workspaceId/presentations/:presentationId/comments` | Bearer + workspace member |
| **Preview link** | `/api/p/:token/comments` | Capability token in the URL; `Authorization` optional |

Comments pin to a **slide**, support **one level of replies**, and roots can be **resolved**. Nothing here can edit a deck — a preview visitor with a comment link is still view-only for slide content.

Bodies are plain text, **1–4000** characters. Notifications respect [`commentsAndMentions`](USER_SETTINGS_API.md) and the master `pushNotifications` toggle.

---

## Comment object

```json
{
  "id": "uuid",
  "slideId": "clxyz…",
  "parentId": null,
  "body": "Can we shorten this headline?",
  "mentionedUserIds": ["uuid"],
  "resolvedAt": null,
  "author": {
    "id": "uuid-or-null",
    "name": "Jane Doe",
    "profileImage": "https://…",
    "isAnonymous": false
  },
  "createdAt": "ISO8601",
  "updatedAt": "ISO8601",
  "replies": []
}
```

- `replies` is present on **roots only** (`parentId: null`), oldest first.
- `slideId` is `null` for an **orphaned** thread — its slide was deleted or wiped by a full regenerate. Orphans are visible in the editor only.
- `author.id` is `null` for guests (`isAnonymous: true`) and for deleted accounts (`name: "Deleted user"`).
- A logged-in user with a blank profile name shows as `Anonymous viewer` with `isAnonymous: true`, but still has an `id`.
- `guestSessionId` is never returned on any surface.

---

# Editor surface

All routes require **`Authorization: Bearer <access_token>`** and workspace membership (`OWNER`, `ADMIN`, `MEMBER`). Editor comments keep working even when the share link is view-only, disabled, or was never created.

## List comments

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/comments` |

**Query (optional)**

| Param | Type | Description |
|---|---|---|
| `slideId` | string | Only threads on this slide |
| `limit` | number | 1–100, default 50 (counts **roots**) |
| `cursor` | UUID | Return roots older than this root id |
| `resolved` | boolean | `true` = resolved only, `false` = open only |
| `orphaned` | boolean | `true` = threads whose slide is gone (`slideId: null`) |

Omit `slideId` to get every non-orphaned thread in the deck.

**Response (200)** – `data`: `{ "comments": [ … ], "nextCursor": "uuid-or-null" }`

## Create comment or reply

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/comments` |

Send **exactly one** of `slideId` (new thread) or `parentId` (reply).

```json
{ "body": "Tighten this claim", "slideId": "clxyz…", "mentionedUserIds": ["uuid"] }
```

```json
{ "body": "Agreed", "parentId": "uuid" }
```

| Field | Type | Rules |
|---|---|---|
| `body` | string | Required, 1–4000 |
| `slideId` | string | Root only; must be a slide of this deck |
| `parentId` | UUID | Reply only; must be an **unresolved root** |
| `mentionedUserIds` | string[] | Max 20; must be workspace members |

A reply inherits its root's `slideId`.

**Notifications:** mentioned members → `PRESENTATION_COMMENT_MENTION`. On create, the root author of a reply and the presentation creator (`createdBy`) → `PRESENTATION_COMMENT_ADDED` (each notified once, never the author themselves).

**Response (201)** – `data`: `{ "comment": { … } }`

**Limits (400):** 100 open roots per slide, 50 replies per root.

## Update comment

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `…/comments/:commentId` |

Author only. Body: `{ body, mentionedUserIds? }`. `slideId` and `parentId` cannot change. Only **newly added** mentions notify.

**Response (200)** – `data`: `{ "comment": { … } }` · **403** not the author · **404** unknown comment

## Delete comment

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `…/comments/:commentId` |

Soft-delete. Author, or workspace **OWNER** / **ADMIN**, may delete. Deleting a root also soft-deletes its replies.

**Response (200)** – `data`: `{ "deleted": true }`

## Resolve / reopen a thread

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `…/comments/:commentId/resolve` · `…/comments/:commentId/unresolve` |

**Roots only** (400 on a reply). Any workspace member may resolve. A resolved root rejects new replies until reopened.

**Response (200)** – `data`: `{ "comment": { … } }`

## Mentionable users

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `…/comments/mentionable-users` |

Optional `q` (name or email, case-insensitive, max 20 results). Available to all members.

**Response (200)** – `data`: `{ "users": [ { "id", "name", "email" } ] }`

---

# Preview surface (`/api/p/:token/comments`)

Unauthenticated. Send `Authorization: Bearer <token>` **if** the visitor happens to be logged in; an invalid one is treated as a guest and never 401s. All responses are `Cache-Control: no-store` and carry `Referrer-Policy: no-referrer`.

**Comments must be enabled on the link.** `PUT .../share` mints new links with `access: "COMMENT"`; links created before this feature stay `"VIEW"` until the owner PATCHes `access`. See [PRESENTATION_API.md](PRESENTATION_API.md#view-only-share-links).

| Link state | `GET /comments` | Writes |
|---|---|---|
| Unknown / disabled / expired | **404** | **404** |
| Live, `access: VIEW` | **200** with `comments: []` | **403** `Comments are disabled for this link` |
| Live, `access: COMMENT` | **200** | allowed |

Read `canComment` from **`GET /api/p/:token/session`** to decide whether to render the composer.

**Only comments on current `READY` slides are returned.** Orphaned threads and threads on slides still generating are invisible here, and any attempt to read or write one 404s (a share link must not reveal hidden slides).

### Guest identity

A visitor who is not logged in must send:

| Field | Where | Rules |
|---|---|---|
| `viewerSessionId` | body (query on `DELETE`) | Same id used for the presence heartbeat; persist in `localStorage` |
| `displayName` | body | 1–80 chars; required on create |

`viewerSessionId` is how a guest proves authorship on their own `PATCH` / `DELETE`, so it must be the same value across reloads. For a logged-in visitor, a client-sent `displayName` is **ignored** — the name always comes from the account.

### Guest and outsider limits

| Action | Guest | Logged-in non-member | Member |
|---|---|---|---|
| List / create / reply | yes | yes | yes |
| Edit / delete own | yes (via `viewerSessionId`) | yes | yes |
| `@mention` | no (silently dropped) | no (silently dropped) | yes |
| Resolve / reopen | **403** | **403** | yes |
| `mentionable-users` | **404** | **404** | yes |

### Routes

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/p/:token/comments` | Same query params as the editor (no `orphaned`) |
| `POST` | `/api/p/:token/comments` | `{ body, slideId \| parentId, viewerSessionId?, displayName? }` |
| `PATCH` | `/api/p/:token/comments/:commentId` | Own comment only |
| `DELETE` | `/api/p/:token/comments/:commentId` | Own comment; members/admins may delete any |
| `POST` | `/api/p/:token/comments/:commentId/resolve` | Members only |
| `POST` | `/api/p/:token/comments/:commentId/unresolve` | Members only |
| `GET` | `/api/p/:token/comments/mentionable-users` | Members only, else 404 |

### Live updates

Every presence response (`PUT` / `GET /api/p/:token/presence`) includes **`commentsUpdatedAt`**. Refetch the comment list only when it changes — do not poll `GET /comments` on a timer.

### Rate limits

**429** with a `Retry-After` header.

| Endpoint | Default |
|---|---|
| `GET` comments, `mentionable-users` | 120/min per IP |
| Comment writes | 20/min per IP, 60/min per link |

Configurable — see [ENVIRONMENT.md](ENVIRONMENT.md).

---

## Common statuses

| Code | When |
|---|---|
| `400` | Validation, both/neither `slideId` and `parentId`, reply to a reply or resolved root, thread limits, guest without a display name |
| `403` | Not the author; guest resolving; comments disabled on the link |
| `404` | Unknown presentation, slide, comment, or share link; hidden-slide comment on the public surface |
| `429` | Rate limited |

---

**[← API index](README.md)** · [Presentations API](PRESENTATION_API.md) · [Notifications frontend guide](../NOTIFICATIONS_FRONTEND_INTEGRATION.md)
