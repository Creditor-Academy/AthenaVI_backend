# Platform Superadmin API

> **Frontend integration guide:** [`docs/SUPERADMIN_FRONTEND_INTEGRATION.md`](docs/SUPERADMIN_FRONTEND_INTEGRATION.md) — portal login, OAuth, capabilities toggle, and admin API examples.

Base path: **`/api/superadmin`**

**Portal auth (single login page):** use normal `POST /api/auth/login` or `GET /api/auth/google`, then `GET /api/user/capabilities` to show the admin toggle. Optional dedicated admin login: `POST /api/auth/superadmin/login`, `GET /api/auth/superadmin/google`. All use the same JWT.

Requires **`Authorization: Bearer`** plus platform superadmin (`User.isPlatformSuperadmin` or email in **`PLATFORM_SUPERADMIN_EMAILS`**). Not the same as workspace **ADMIN** role.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/superadmin/users` | List users with credits + storage (`page`, `limit`, `search` on email or name) |
| `PATCH` | `/api/superadmin/users/:userId/platform-access` | Body: `{ isPlatformSuperadmin }` |
| `GET` | `/api/superadmin/users/:userId/credits` | User personal balance |
| `GET` | `/api/superadmin/users/:userId/credits/history` | Full user ledger |
| `POST` | `/api/superadmin/users/:userId/credits/grant` | Body: `{ amount, reason? }` |
| `POST` | `/api/superadmin/users/:userId/credits/revoke` | Body: `{ amount, reason? }` |
| `GET` | `/api/superadmin/users/:userId/storage` | User storage quota summary |
| `GET` | `/api/superadmin/users/:userId/storage/history` | User storage ledger |
| `POST` | `/api/superadmin/users/:userId/storage/grant` | Body: `{ additionalBytes, reason? }` or `{ tierId, reason? }` |
| `POST` | `/api/superadmin/users/:userId/storage/revoke` | Body: `{ amountBytes, reason? }` |
| `GET` | `/api/superadmin/storage/tiers` | Storage tier presets (`id`, `label`, `limitBytes`) |
| `GET` | `/api/superadmin/storage/requests` | Storage upgrade queue (`status` = `pending` \| `approved` \| `rejected`) |
| `POST` | `/api/superadmin/storage/requests/:requestId/reject` | Body: `{ reviewNote? }` |
| `GET` | `/api/superadmin/workspaces` | List TEAM workspaces (`page`, `limit`, `search`) |
| `GET` | `/api/superadmin/workspaces/:workspaceId/credits` | TEAM workspace pool summary |
| `GET` | `/api/superadmin/workspaces/:workspaceId/credits/history` | Workspace credit ledger |
| `GET` | `/api/superadmin/workspaces/:workspaceId/credits/usage-by-member` | Usage aggregated by member |
| `POST` | `/api/superadmin/workspaces/:workspaceId/credits/grant` | Direct workspace top-up |
| `POST` | `/api/superadmin/workspaces/:workspaceId/credits/revoke` | Revoke workspace pool credits |
| `GET` | `/api/superadmin/reports/credits/usage` | Usage report (`from`, `to`, filters, `topLimit`) |
| `GET` | `/api/superadmin/reports/credits/platform-actions` | Platform grant/revoke audit |
| `GET` | `/api/superadmin/heygen/account` | HeyGen API account billing |
| `GET` | `/api/superadmin/alerts/summary` | Unread platform alerts + HeyGen wallet snapshot |

---

### Platform access management

```http
PATCH /api/superadmin/users/:userId/platform-access
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "isPlatformSuperadmin": true }
```

**400** — cannot demote yourself or remove the last accessible superadmin.

**Note:** `PLATFORM_SUPERADMIN_EMAILS` env allowlist still grants access independently of the DB flag.

---

### Storage upgrade triage

```http
GET /api/superadmin/storage/requests?status=pending&page=1&limit=20
```

**200** — `data.requests[]` includes request fields plus `user: { id, email, name }`.

```http
POST /api/superadmin/storage/requests/:requestId/reject
Content-Type: application/json

{ "reviewNote": "Optional reason shown to user" }
```

**404** if request not found. **400** if not `pending`. Notifies user via inbox (`STORAGE_UPGRADE_REJECTED`).

New user requests also notify superadmins via inbox (`PLATFORM_STORAGE_UPGRADE_REQUEST`) in addition to email.

---

### Workspace admin

```http
GET /api/superadmin/workspaces?page=1&limit=20&search=acme
```

**200** — `data.workspaces[]`: `workspaceId`, `name`, `type`, `workspaceCredits`, `owner`, `memberCount`, `createdAt`.

```http
POST /api/superadmin/workspaces/:workspaceId/credits/revoke
Content-Type: application/json

{ "amount": 500, "reason": "Correction" }
```

**402** if workspace pool insufficient. Notifies workspace owner (`CREDITS_WORKSPACE_REVOKE`).

---

### Usage report (extended)

`GET /api/superadmin/reports/credits/usage` returns backward-compatible totals plus:

- `byFeature` — grouped by `metadata.feature`
- `byDay` — UTC date buckets
- `topUsers` / `topWorkspaces` — top N by usage (query `topLimit`, default 10, max 25)

### Platform actions audit

`GET /api/superadmin/reports/credits/platform-actions` — paginated `platform_grant` / `platform_revoke` transactions with `user`, `workspace`, and `actor` enrichment.

Query: `page`, `limit`, `from`, `to`, optional `type`, optional `scope` (`user` \| `workspace`).

---

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

Platform alerts (`PLATFORM_HEYGEN_WALLET_LOW`, `PLATFORM_STORAGE_UPGRADE_REQUEST`) appear in **`/api/user/inbox`** with `category: platform`. Background job re-checks HeyGen wallet on `PLATFORM_ALERTS_JOB_INTERVAL_MS` (default 1h).

---

### Product email broadcast

```http
POST /api/superadmin/broadcasts/product-email
Authorization: Bearer <accessToken>
Content-Type: application/json
```

**Request body**

```json
{
  "subject": "New feature: …",
  "html": "<p>…</p>",
  "text": "optional plain text",
  "confirm": "send"
}
```

Sends to all users with **`productEmails: true`** in notification settings. Requires `confirm` exactly `"send"`.

**200** – `data`:

```json
{
  "recipientCount": 42,
  "sentCount": 40,
  "failedCount": 2
}
```

Email-only channel (no inbox notification). See [`SUPERADMIN_FRONTEND_INTEGRATION.md`](../SUPERADMIN_FRONTEND_INTEGRATION.md).

---

### HeyGen API wallet (platform COGS)

Proxies HeyGen **`GET /v3/users/me`** using server **`HEYGEN_API_KEY`**.

**500** if `HEYGEN_API_KEY` is missing. **401/502** if HeyGen rejects the key.

---

### Storage grant / revoke notes

- Storage grant and revoke update `User.storageLimit`.
- Every change writes a `storage_transactions` ledger row.
- Revoke is blocked if the new limit would be below current `storageUsed`.
- Grant auto-approves the user's latest pending upgrade request.

User-facing storage: [`STORAGE_API.md`](STORAGE_API.md).

---

**[← API index](README.md)** · [Project root README](../../README.md)
