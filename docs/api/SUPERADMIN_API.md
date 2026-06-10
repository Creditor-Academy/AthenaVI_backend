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

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

