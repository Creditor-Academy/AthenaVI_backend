# Storage API

Base paths:

- **`/api/user/storage`** (current user quota + history)
- **`/api/workspaces/:workspaceId/storage`** (workspace footprint + owner quota)

All routes require **`Authorization: Bearer <access_token>`**.

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
  "tier": { "id": "free", "label": "Free" }
}
```

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
  "submittedAt": "2026-06-22T10:30:00.000Z"
}
```

**Errors**

| Status | When |
|--------|------|
| `400` | Validation failure (e.g. reason too short, invalid urgency, bytes mismatch) |
| `401` | Missing or invalid Bearer token |
| `429` | One successful request per user per cooldown window (default 24h); includes `Retry-After` header |
| `500` | Notification email not configured (`PLATFORM_SUPERADMIN_NOTIFICATION_EMAIL` / `PLATFORM_SUPERADMIN_EMAILS`) or SMTP failure |

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
