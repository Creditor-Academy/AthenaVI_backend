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
| [EARLY_ACCESS_API.md](EARLY_ACCESS_API.md) | `/api/early-access` | Public early access interest form |
| [USER_API.md](USER_API.md) | `/api/user` | Profile, capabilities, profile image |
| [STORAGE_API.md](STORAGE_API.md) | `/api/user/storage` | Storage quota, history, workspace footprint |
| [USER_INBOX_API.md](USER_INBOX_API.md) | `/api/user/inbox` | Notifications, unread count |
| [USER_SETTINGS_API.md](USER_SETTINGS_API.md) | `/api/user/settings` | Appearance, notifications, security, account deletion |
| [WORKSPACE_API.md](WORKSPACE_API.md) | `/api/workspaces` | Workspaces, members, invitations, folders, projects, Remotion renders |
| [PRESENTATION_API.md](PRESENTATION_API.md) | `.../presentations`, `/api/p` | AI PPT: create, outline, theme, generate, packs, brand apply, slides, export, view-only share links + presence |
| [BRAND_KIT_API.md](BRAND_KIT_API.md) | `.../brand-kits` | Workspace Brand Kits (colors, fonts, logos, photos, voice) |
| [PROJECT_COMMENTS_API.md](PROJECT_COMMENTS_API.md) | `.../projects/:projectId/comments` | Project comments and @mentions |
| [ASSETS_API.md](ASSETS_API.md) | `/api/assets` | Workspace file uploads |
| [STOCK_API.md](STOCK_API.md) | `/api/stock` | Stock library search (Pexels, Unsplash, Pixabay) and import |
| [FONTS_API.md](FONTS_API.md) | `/api/fonts` | Shared Google Fonts catalog + CSS helper (Brand Kit, video editor, PPT) |
| [IMAGE_GEN_API.md](IMAGE_GEN_API.md) | `/api/image-gen` | AI image studio: folder chats, generate, regen/tweak, download |
| [CREDITS_API.md](CREDITS_API.md) | `/api/credits` | Balances, history, estimates, TEAM allocation |
| [SUPERADMIN_API.md](SUPERADMIN_API.md) | `/api/superadmin` | Platform credit + storage admin (superadmin only) |
| [HEYGEN_API.md](HEYGEN_API.md) | `/api/heygen` | User-scoped avatars, voices, previews |
| [HEYGEN_PROJECT_VIDEOS_API.md](HEYGEN_PROJECT_VIDEOS_API.md) | `.../projects/:projectId/heygen` | Project avatar videos, stream/download |
| [PROJECT_SPEECH_API.md](PROJECT_SPEECH_API.md) | `.../projects/:projectId/speech` | Project speech (TTS audio), stream/download |

## Frontend integration guides

| Doc | Use when |
|-----|----------|
| [FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md](../FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md) | **All-in-one** — PPT + Image Gen + Brand Kit (superadmin → user, APIs, flows; self-contained) |
| [AI_PPT_GENERATION_COMPLETE.md](../AI_PPT_GENERATION_COMPLETE.md) | **How AI PPT generation works** — every path, outline/generate/images/layouts/credits |
| [IMAGE_GEN_COMPLETE.md](../IMAGE_GEN_COMPLETE.md) | **How Image Gen works** — pipelines, data model, credits + Infographics |
| [INFOGRAPHIC_MODE_PRD.md](../INFOGRAPHIC_MODE_PRD.md) | Infographic mode PRD (locked decisions + eval) |
| [INFOGRAPHIC_EVAL_SET.md](../INFOGRAPHIC_EVAL_SET.md) | Infographic eval briefs + pass thresholds |
| [PRESENTATION_FRONTEND_INTEGRATION.md](../PRESENTATION_FRONTEND_INTEGRATION.md) | **PPT / canvas + packs + Brand Kit** — AI/blank/pack/template, canvas, export, admin |
| [PROJECT_EDITOR_INTEGRATION.md](../PROJECT_EDITOR_INTEGRATION.md) | Editor save/load, playback, HeyGen in projects |
| [STOCK_FRONTEND_INTEGRATION.md](../STOCK_FRONTEND_INTEGRATION.md) | Stock library search, import-on-use, attribution |
| [IMAGE_GEN_FRONTEND_INTEGRATION.md](../IMAGE_GEN_FRONTEND_INTEGRATION.md) | AI image studio (folder chats, models, regen/tweak, download) |
| [CREDITS_FRONTEND_INTEGRATION.md](../CREDITS_FRONTEND_INTEGRATION.md) | Credits: balances, estimates, billing logic, editor & voice/avatar UX |
| [PRESENTATION_CREDITS_FRONTEND.md](../PRESENTATION_CREDITS_FRONTEND.md) | AI PPT credits: `ppt_*` features, outline reconcile, charge-on-success, estimate |
| [PRESENTATION_PROMPTS.md](../PRESENTATION_PROMPTS.md) | Prompt bundle version, prompt files, when to bump |
| [NOTIFICATIONS_FRONTEND_INTEGRATION.md](../NOTIFICATIONS_FRONTEND_INTEGRATION.md) | Notifications settings, inbox, comments |
| [SUPERADMIN_FRONTEND_INTEGRATION.md](../SUPERADMIN_FRONTEND_INTEGRATION.md) | Admin portal, capabilities toggle, credit + storage admin UI |

## Agent / repo handbook

Stack, module layout, and patterns: [AGENTS.md](../../AGENTS.md) at repo root.

---

**[← Project README](../../README.md)**
