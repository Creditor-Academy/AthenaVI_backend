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
