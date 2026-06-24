# Storage API

Base paths:

- **`/api/user/storage`** (current user quota + history + upgrade requests)
- **`/api/workspaces/:workspaceId/storage`** (workspace footprint + owner quota)

All routes require **`Authorization: Bearer <access_token>`**.

### Byte units

- All `*Bytes` fields are **binary bytes** (powers of 1024), not decimal GB.
- Examples: 1 GiB = `1073741824`; 10 GiB = `10737418240`; 50 GiB = `53687091200`.
- API JSON uses **numbers** (not strings). Quotas are stored as PostgreSQL `BIGINT` server-side.

Preset tiers (for display / superadmin `tierId`): `free` (1 GiB default), `plus_10gb`, `pro_50gb`. Superadmin may grant **any positive** `additionalBytes` without a fixed upper cap.

---

## Get my storage quota

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/storage` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "userId": "user-uuid",
  "limitBytes": 1073741824,
  "usedBytes": 123456789,
  "availableBytes": 950285035,
  "percentUsed": 11.5,
  "tier": { "id": "free", "label": "Free" },
  "activeUpgradeRequest": {
    "requestId": "req-uuid",
    "status": "pending",
    "requestedAdditionalGb": 25,
    "requestedAdditionalBytes": 26843545600,
    "reason": "Upcoming campaign with large 4K assets.",
    "urgency": "flexible",
    "currentUsedBytes": 5368709120,
    "currentLimitBytes": 10737418240,
    "tierId": "starter",
    "tierLabel": "Starter",
    "workspaceId": "workspace-uuid",
    "workspaceName": "Acme Team",
    "workspaceFootprintBytes": 2147483648,
    "submittedAt": "2026-06-22T10:30:00.000Z",
    "reviewedAt": null,
    "reviewNote": null
  }
}
```

`activeUpgradeRequest` is the user's latest **pending** request, or `null` if none.

---

## Get my storage ledger

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/storage/history` |
| **Auth** | Bearer |

**Query (optional)**

- `page` (default `1`)
- `limit` (`1..100`, default `20`)
- `type` (`initial` \| `platform_grant` \| `platform_revoke` \| `purchase`)

**Response (200)** – `data.history`:

```json
{
  "transactions": [
    {
      "id": "tx-uuid",
      "userId": "user-uuid",
      "amountBytes": 1073741824,
      "type": "initial",
      "tierId": "free",
      "createdAt": "2026-06-17T10:00:00.000Z"
    }
  ],
  "pagination": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  }
}
```

---

## Request storage upgrade

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/user/storage/request` |
| **Auth** | Bearer |
| **Content-Type** | `application/json` |

Submits a storage upgrade request and emails the platform superadmin inbox. Does **not** change the user's quota automatically.

**Request body**

| Field | Type | Notes |
|-------|------|-------|
| `requestedAdditionalGb` | number | Required. Positive. |
| `requestedAdditionalBytes` | number | Required. Must equal `requestedAdditionalGb × 1024³` (±1 byte). |
| `reason` | string | Required. Min 10 characters. |
| `urgency` | string | Required. `flexible` \| `week` \| `urgent`. |
| `currentUsedBytes` | number | Snapshot from `GET /api/user/storage`. |
| `currentLimitBytes` | number | Snapshot from `GET /api/user/storage`. |
| `tierId` | string \| null | Current tier id, if available. |
| `tierLabel` | string \| null | e.g. Starter, Pro. |
| `workspaceId` | string \| null | UUID of workspace context, if any. |
| `workspaceName` | string \| null | Display name for workspace context. |
| `workspaceFootprintBytes` | number \| null | Workspace storage footprint if loaded. |

**Example request**

```json
{
  "requestedAdditionalGb": 25,
  "requestedAdditionalBytes": 26843545600,
  "reason": "Upcoming campaign with large 4K assets and multiple exports per week.",
  "urgency": "flexible",
  "currentUsedBytes": 5368709120,
  "currentLimitBytes": 10737418240,
  "tierId": "starter",
  "tierLabel": "Starter",
  "workspaceId": "workspace-uuid-or-null",
  "workspaceName": "Acme Team",
  "workspaceFootprintBytes": 2147483648
}
```

**Response (201)** – `data`:

```json
{
  "requestId": "req-uuid",
  "submittedAt": "2026-06-22T10:30:00.000Z",
  "status": "pending"
}
```

**Errors**

| Status | When |
|--------|------|
| `400` | Validation failure (e.g. reason too short, invalid urgency, bytes mismatch) |
| `401` | Missing or invalid Bearer token |
| `429` | One successful request per user per cooldown window (default 24h); includes `Retry-After` header |
| `500` | Notification email not configured (`PLATFORM_SUPERADMIN_NOTIFICATION_EMAIL` / `PLATFORM_SUPERADMIN_EMAILS`) or SMTP failure |

Requests are persisted with status `pending`. When a platform superadmin grants storage to the user, the latest pending request is automatically marked `approved`. Superadmins can list and reject requests via [`SUPERADMIN_API.md`](SUPERADMIN_API.md) (`GET /api/superadmin/storage/requests`, `POST .../reject`). Rejected requests notify the user via inbox (`STORAGE_UPGRADE_REJECTED`).

---

## List my storage upgrade requests

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/storage/requests` |
| **Auth** | Bearer |

**Query (optional)**

- `page` (default `1`)
- `limit` (`1..100`, default `20`)
- `status` (`pending` \| `approved` \| `rejected`)

**Response (200)** – `data`:

```json
{
  "requests": [
    {
      "requestId": "req-uuid",
      "status": "pending",
      "requestedAdditionalGb": 25,
      "requestedAdditionalBytes": 26843545600,
      "reason": "Upcoming campaign with large 4K assets.",
      "urgency": "flexible",
      "currentUsedBytes": 5368709120,
      "currentLimitBytes": 10737418240,
      "tierId": "starter",
      "tierLabel": "Starter",
      "workspaceId": "workspace-uuid",
      "workspaceName": "Acme Team",
      "workspaceFootprintBytes": 2147483648,
      "submittedAt": "2026-06-22T10:30:00.000Z",
      "reviewedAt": null,
      "reviewNote": null
    }
  ],
  "pagination": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  }
}
```

---

## Get workspace storage summary

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/storage` |
| **Auth** | Bearer + workspace member |

**Response (200)** – owner quota plus workspace footprint:

```json
{
  "workspaceId": "workspace-uuid",
  "workspaceType": "TEAM",
  "owner": {
    "id": "owner-uuid",
    "email": "owner@example.com",
    "name": "Owner"
  },
  "quota": {
    "limitBytes": 1073741824,
    "usedBytes": 123456789
  },
  "footprint": {
    "assetBytes": 100,
    "heygenBytes": 200,
    "renderBytes": 300,
    "totalBytes": 600
  }
}
```

---

**[← API index](README.md)** · [Project root README](../../README.md)
