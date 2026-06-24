# Platform Superadmin API

> **Frontend integration guide:** [`docs/SUPERADMIN_FRONTEND_INTEGRATION.md`](docs/SUPERADMIN_FRONTEND_INTEGRATION.md) — portal login, OAuth, capabilities toggle, and credit admin API examples.

Base path: **`/api/superadmin`**

**Portal auth (single login page):** use normal `POST /api/auth/login` or `GET /api/auth/google`, then `GET /api/user/capabilities` to show the admin toggle. Optional dedicated admin login: `POST /api/auth/superadmin/login`, `GET /api/auth/superadmin/google`. All use the same JWT; this document covers **credit** and **storage** admin routes.

Requires **`Authorization: Bearer`** plus platform superadmin (`User.isPlatformSuperadmin` or email in **`PLATFORM_SUPERADMIN_EMAILS`** comma-separated). Not the same as workspace **ADMIN** role.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/superadmin/users` | List users with credits + storage (`page`, `limit`, `search`) |
| `GET` | `/api/superadmin/users/:userId/credits` | User personal balance |
| `GET` | `/api/superadmin/users/:userId/credits/history` | Full user ledger |
| `POST` | `/api/superadmin/users/:userId/credits/grant` | Body: `{ amount, reason? }` |
| `POST` | `/api/superadmin/users/:userId/credits/revoke` | Body: `{ amount, reason? }` |
| `GET` | `/api/superadmin/users/:userId/storage` | User storage quota summary |
| `POST` | `/api/superadmin/users/:userId/storage/grant` | Body: `{ additionalBytes, reason? }` or `{ tierId, reason? }` |
| `POST` | `/api/superadmin/users/:userId/storage/revoke` | Body: `{ amountBytes, reason? }` |
| `GET` | `/api/superadmin/workspaces/:workspaceId/credits` | TEAM workspace pool summary |
| `POST` | `/api/superadmin/workspaces/:workspaceId/credits/grant` | Direct workspace top-up |
| `GET` | `/api/superadmin/reports/credits/usage` | Usage report (`from`, `to`, optional filters) |
| `GET` | `/api/superadmin/heygen/account` | HeyGen API account billing (prepaid USD wallet via `HEYGEN_API_KEY`) |
| `GET` | `/api/superadmin/alerts/summary` | Unread platform alerts + HeyGen wallet snapshot |

### Platform alerts summary

```http
GET /api/superadmin/alerts/summary
Authorization: Bearer <accessToken>
```

**200** – `data`:

```json
{
  "unreadPlatformCount": 1,
  "heygenWallet": {
    "remainingBalanceUsd": 42.5,
    "currency": "usd",
    "thresholdUsd": 50,
    "isLow": false
  },
  "fetchedAt": "ISO8601"
}
```

Platform HeyGen wallet low alerts are also written to the superadmin user's **`/api/user/inbox`** (`type: PLATFORM_HEYGEN_WALLET_LOW`). A background job re-checks the wallet on `PLATFORM_ALERTS_JOB_INTERVAL_MS` (default 1h).

### HeyGen API wallet (platform COGS)

Proxies HeyGen **`GET /v3/users/me`** using server **`HEYGEN_API_KEY`** (`x-api-key`). With API key auth, HeyGen bills the **prepaid USD wallet** (pay-as-you-go tier).

```http
GET /api/superadmin/heygen/account
Authorization: Bearer <accessToken>
```

**200** — `data.account`:

```json
{
  "username": "jane_doe",
  "email": "jane@example.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "billingType": "wallet",
  "wallet": {
    "currency": "usd",
    "remainingBalanceUsd": 42.5,
    "autoReload": { "enabled": false }
  },
  "subscription": null,
  "usageBased": null,
  "fetchedAt": "2026-06-05T12:00:00.000Z"
}
```

| `billingType` | Populated field | Meaning |
|---------------|-----------------|--------|
| `wallet` | `wallet.remainingBalanceUsd` | Prepaid USD balance (API tier) |
| `subscription` | `subscription.credits` | OAuth / enterprise credit pools |
| `usage_based` | `usageBased` | Metered billing |

**500** if `HEYGEN_API_KEY` is missing. **401/502** if HeyGen rejects the key.

---

### Storage admin

Byte fields use **binary bytes** (1024³ per GiB). No fixed upper cap on grant/revoke amounts (positive integers only).

#### List users (includes storage)

```http
GET /api/superadmin/users?page=1&limit=20&search=optional@email.com
Authorization: Bearer <accessToken>
```

Each user in `data.users` includes `storageLimit` and `storageUsed` (bytes).

#### Get user storage summary

```http
GET /api/superadmin/users/:userId/storage
Authorization: Bearer <accessToken>
```

**200** — same shape as [`GET /api/user/storage`](STORAGE_API.md) (`limitBytes`, `usedBytes`, `availableBytes`, `percentUsed`, `tier`, `activeUpgradeRequest`).

#### Grant storage

```http
POST /api/superadmin/users/:userId/storage/grant
Authorization: Bearer <accessToken>
Content-Type: application/json
```

Provide **either** `tierId` **or** `additionalBytes` (not both required; `tierId` takes precedence when both are sent — prefer one mode per request).

| Mode | Body | Effect |
|------|------|--------|
| Preset tier | `{ "tierId": "plus_10gb", "reason": "..." }` | Sets **absolute** limit to tier size |
| Add bytes | `{ "additionalBytes": 107374182400, "reason": "..." }` | **Increments** current limit by that many bytes |

| `tierId` | Limit (bytes) | Label |
|----------|---------------|--------|
| `free` | `1073741824` | Free (1 GiB) |
| `plus_10gb` | `10737418240` | Plus 10 GB |
| `pro_50gb` | `53687091200` | Pro 50 GB |

| Field | Required | Rules |
|-------|----------|--------|
| `tierId` | One of `tierId` / `additionalBytes` | `free` \| `plus_10gb` \| `pro_50gb` |
| `additionalBytes` | One of `tierId` / `additionalBytes` | Positive integer (any size) |
| `reason` | No | Max 500 characters |

**200** — `data`:

```json
{
  "user": {
    "id": "user-uuid",
    "storageLimit": 10737418240,
    "storageUsed": 123456789
  },
  "transaction": {
    "id": "tx-uuid",
    "amountBytes": 10737418240,
    "type": "platform_grant",
    "tierId": "plus_10gb",
    "reference": "Manual upgrade",
    "createdAt": "2026-06-24T12:00:00.000Z"
  }
}
```

Approves the user's latest **pending** storage upgrade request (if any).

#### Revoke storage

```http
POST /api/superadmin/users/:userId/storage/revoke
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "amountBytes": 1073741824,
  "reason": "Plan downgrade"
}
```

| Field | Required | Rules |
|-------|----------|--------|
| `amountBytes` | Yes | Positive integer — subtracted from current `storageLimit` |
| `reason` | No | Max 500 characters |

**400** if the new limit would be below `storageUsed`.

**200** — same shape as grant (`user` + `transaction` with negative `amountBytes`).

User-facing storage contracts: [`STORAGE_API.md`](STORAGE_API.md).

---

**[← API index](README.md)** · [Project root README](../../README.md)

