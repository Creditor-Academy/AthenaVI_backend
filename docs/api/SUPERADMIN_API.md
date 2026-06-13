# Platform Superadmin API

> **Frontend integration guide:** [`docs/SUPERADMIN_FRONTEND_INTEGRATION.md`](docs/SUPERADMIN_FRONTEND_INTEGRATION.md) — portal login, OAuth, capabilities toggle, and credit admin API examples.

Base path: **`/api/superadmin`**

**Portal auth (single login page):** use normal `POST /api/auth/login` or `GET /api/auth/google`, then `GET /api/user/capabilities` to show the admin toggle. Optional dedicated admin login: `POST /api/auth/superadmin/login`, `GET /api/auth/superadmin/google`. All use the same JWT; this section documents **credit admin** routes only.

Requires **`Authorization: Bearer`** plus platform superadmin (`User.isPlatformSuperadmin` or email in **`PLATFORM_SUPERADMIN_EMAILS`** comma-separated). Not the same as workspace **ADMIN** role.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/superadmin/users` | List users with balances (`page`, `limit`, `search`) |
| `GET` | `/api/superadmin/users/:userId/credits` | User personal balance |
| `GET` | `/api/superadmin/users/:userId/credits/history` | Full user ledger |
| `POST` | `/api/superadmin/users/:userId/credits/grant` | Body: `{ amount, reason? }` |
| `POST` | `/api/superadmin/users/:userId/credits/revoke` | Body: `{ amount, reason? }` |
| `GET` | `/api/superadmin/workspaces/:workspaceId/credits` | TEAM workspace pool summary |
| `POST` | `/api/superadmin/workspaces/:workspaceId/credits/grant` | Direct workspace top-up |
| `GET` | `/api/superadmin/reports/credits/usage` | Usage report (`from`, `to`, optional filters) |
| `GET` | `/api/superadmin/heygen/account` | HeyGen API account billing (prepaid USD wallet via `HEYGEN_API_KEY`) |

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

---

**[← API index](README.md)** · [Project root README](../../README.md)

