# Athena VI — API documentation index

Canonical HTTP contracts for the backend. Start with [Overview](OVERVIEW.md) (base URL, envelopes, authentication), then open the domain you need.

## Getting started

| Doc | Contents |
|-----|----------|
| [OVERVIEW.md](OVERVIEW.md) | Base URL, success/error envelopes, Bearer + refresh cookie |
| [ENVIRONMENT.md](ENVIRONMENT.md) | Env vars for frontend and deployment |
| [QUICK_REFERENCE.md](QUICK_REFERENCE.md) | One-table route list |

## API by domain

| Doc | Base path | Topics |
|-----|-----------|--------|
| [AUTH_API.md](AUTH_API.md) | `/api/auth` | OTP, register, login, refresh, logout, password reset, Google OAuth |
| [USER_API.md](USER_API.md) | `/api/user` | Profile, capabilities, profile image |
| [STORAGE_API.md](STORAGE_API.md) | `/api/user/storage` | Storage quota, history, workspace footprint |
| [USER_INBOX_API.md](USER_INBOX_API.md) | `/api/user/inbox` | Notifications, unread count |
| [USER_SETTINGS_API.md](USER_SETTINGS_API.md) | `/api/user/settings` | Appearance, notifications, security, account deletion |
| [WORKSPACE_API.md](WORKSPACE_API.md) | `/api/workspaces` | Workspaces, members, invitations, folders, projects, Remotion renders |
| [ASSETS_API.md](ASSETS_API.md) | `/api/assets` | Workspace file uploads |
| [STOCK_API.md](STOCK_API.md) | `/api/stock` | Stock library search (Pexels, Unsplash, Pixabay) and import |
| [CREDITS_API.md](CREDITS_API.md) | `/api/credits` | Balances, history, estimates, TEAM allocation |
| [SUPERADMIN_API.md](SUPERADMIN_API.md) | `/api/superadmin` | Platform credit admin (superadmin only) |
| [HEYGEN_API.md](HEYGEN_API.md) | `/api/heygen` | User-scoped avatars, voices, previews |
| [HEYGEN_PROJECT_VIDEOS_API.md](HEYGEN_PROJECT_VIDEOS_API.md) | `.../projects/:projectId/heygen` | Project avatar videos, stream/download |
| [PROJECT_SPEECH_API.md](PROJECT_SPEECH_API.md) | `.../projects/:projectId/speech` | Project speech (TTS audio), stream/download |

## Frontend integration guides

| Doc | Use when |
|-----|----------|
| [PROJECT_EDITOR_INTEGRATION.md](../PROJECT_EDITOR_INTEGRATION.md) | Editor save/load, playback, HeyGen in projects |
| [STOCK_FRONTEND_INTEGRATION.md](../STOCK_FRONTEND_INTEGRATION.md) | Stock library search, import-on-use, attribution |
| [CREDITS_FRONTEND_INTEGRATION.md](../CREDITS_FRONTEND_INTEGRATION.md) | Credits: balances, estimates, billing logic, editor & voice/avatar UX |
| [SUPERADMIN_FRONTEND_INTEGRATION.md](../SUPERADMIN_FRONTEND_INTEGRATION.md) | Admin portal, capabilities toggle, credit admin UI |

## Agent / repo handbook

Stack, module layout, and patterns: [AGENTS.md](../../AGENTS.md) at repo root.

---

**[← Project README](../../README.md)**
