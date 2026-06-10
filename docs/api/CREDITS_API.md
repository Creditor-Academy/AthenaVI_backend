# Credits API

> **Frontend integration guide:** [`docs/CREDITS_FRONTEND_INTEGRATION.md`](../CREDITS_FRONTEND_INTEGRATION.md) — pools, pricing logic, charge timing, idempotency, editor flows, and UI checklist.

Base path: **`/api/credits`**

All routes require **`Authorization: Bearer <access_token>`**.

**Credit pools**

- **`User.credits`** (personal pool) – superadmin grants; consumed by PRIVATE workspaces, user-scoped HeyGen (voices/avatars), and TEAM allocation source.
- **`Workspace.credits`** (TEAM only) – OWNER allocates from personal pool; consumed by scene HeyGen videos and Remotion exports in that workspace.

**Billing**

- Insufficient balance → **402** with `INSUFFICIENT_CREDITS`.
- HeyGen videos / Remotion: charge on **success** only.
- Voice/avatar HeyGen routes: charge **`User.credits`** (`scope: user`); workspace routes use workspace pool (`scope: workspace`).

---

## Personal balance

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/me` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "personalCredits": 0 }`

---

## Personal history (user-scoped usage)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/me/history` |
| **Auth** | Bearer |

Query: `page`, `limit` (optional).

---

## Personal estimate

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/me/estimate` |
| **Auth** | Bearer |

Query: `feature` = `voice_clone` \| `voice_design` \| `voice_preview` \| `avatar_create`; optional `text` for preview.

---

## Workspace balance

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id` |
| **Auth** | Bearer |
| **Role** | OWNER, ADMIN, or MEMBER |

**Response (200)** – `data`: `{ workspaceId, personalCredits, workspaceCredits, workspaceType }`

---

## Allocate / deallocate (TEAM, OWNER only)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/credits/:id/allocate` or `/deallocate` |
| **Body** | `{ "amount": 1000 }` (positive integer AC) |

Moves credits personal → workspace (allocate) or workspace → personal (deallocate).

---

## Workspace history (workspace-scoped only)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/history` |
| **Role** | OWNER or ADMIN |

---

## My workspace usage

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/my-history` |
| **Role** | Any member |

---

## Usage by member (TEAM)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/usage-by-member` |
| **Role** | OWNER or ADMIN |

---

## Workspace estimate

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/estimate` |
| **Role** | Any member |

Query: `feature` = `heygen_video` \| `remotion_export`; for video: `avatarEngine`, optional `script`; for render: optional `durationInFrames`, `fps`.

Transaction `type` values include: `usage`, `platform_grant`, `platform_revoke`, `allocation`, `deallocation`, `refund`.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

