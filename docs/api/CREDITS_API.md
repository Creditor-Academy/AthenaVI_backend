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

Query: `page`, `limit` (optional, same as history).

**TEAM workspaces only** — **400** on `PRIVATE` (`Usage by member is only available for team workspaces`).

**Response (200)** – `data`: `{ members: [...], pagination: { total, page, limit, totalPages } }`  
Each member: `userId`, `user` (`id`, `email`, `name`), `totalUsageAc`, `transactionCount`.

---

## Workspace estimate

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/credits/:id/estimate` |
| **Role** | Any member |

Query: `feature` = `heygen_video` \| `speech_generation` \| `remotion_export`.

For **`heygen_video`**: optional `avatarEngine`, `avatarType` (`photo_avatar` \| `studio_avatar` \| `digital_twin`), `resolution` (`720p` \| `1080p`), `script`.

For **`speech_generation`**: optional `script`.

For **`remotion_export`**: optional `durationInFrames`, `fps`.

Estimate **`breakdown`** includes `heygenRatePerSec`, `avatarType`, `resolution`, `billingMode`.

Transaction `type` values include: `usage`, `platform_grant`, `platform_revoke`, `allocation`, `deallocation`, `refund`.

### History `usageDetail` (consumption context)

All history endpoints attach **`usageDetail`** on each transaction (null for unknown types).

**Usage (`type: usage`)** — examples:

| `feature` | `usageDetail` fields (typical) |
|-----------|--------------------------------|
| `heygen_video` | `consumptionType`: `Avatar video`, **`displayName`** / `label` (e.g. `Avatar video scene “Intro” in “Q1 Training”`), `where` (e.g. `Scene: Intro · Project: Q1 Training`), `sceneName`, `projectName`, `sceneId`, `videoTitle`, … |
| `speech_generation` | `consumptionType`: `Speech generation`, `displayName`, `where`, `sceneName`, `projectName`, `voiceId`, `scriptPreview`, … |
| `remotion_export` | `consumptionType`: `Video export`, **`displayName`** / `label` (e.g. `Video export — “Q1 Training”`), `where`, `videoName` (= project name), `projectName`, `renderId`, … |
| `voice_clone` | `label`, `voiceName`, `voiceId` |
| `voice_design` | `label`, `promptPreview`, `voiceId` |
| `avatar_create` | `label`, `avatarName`, `avatarType`, `avatarGroupId` |
| `voice_preview` | `label`, `previewText`, `voiceId`, `durationSeconds` |

**Non-usage** — `usageDetail` includes a human `label` (e.g. `Credits granted`, `Allocated to workspace`) and optional `reason` / `workspaceId`.

Older ledger rows are enriched at read time from `reference` + linked `heygen_responses` / `project_renders` / `projects` when metadata is sparse.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

