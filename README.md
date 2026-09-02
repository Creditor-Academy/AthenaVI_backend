# Athena VI Backend

Backend API for **Athena VI** (Virtual Instructor) — workspaces, editor projects, assets, credits, HeyGen, and Remotion renders.

**Stack:** Express 5 · Prisma · PostgreSQL · Redis · S3 · CommonJS

For coding agents and contributors, see **[AGENTS.md](AGENTS.md)** (module layout, auth, validation, patterns).

---

## API documentation

Full HTTP contracts are split under **`docs/api/`** so you can jump to one area without loading a 2.5k-line file.

**Start here:** [docs/api/README.md](docs/api/README.md)

### Quick links

| Topic | Document |
|-------|----------|
| Base URL, auth, response format | [docs/api/OVERVIEW.md](docs/api/OVERVIEW.md) |
| Login, register, OTP, OAuth | [docs/api/AUTH_API.md](docs/api/AUTH_API.md) |
| User profile & capabilities | [docs/api/USER_API.md](docs/api/USER_API.md) |
| Inbox notifications | [docs/api/USER_INBOX_API.md](docs/api/USER_INBOX_API.md) |
| Project comments | [docs/api/PROJECT_COMMENTS_API.md](docs/api/PROJECT_COMMENTS_API.md) |
| Settings & account security | [docs/api/USER_SETTINGS_API.md](docs/api/USER_SETTINGS_API.md) |
| Workspaces, folders, projects, renders | [docs/api/WORKSPACE_API.md](docs/api/WORKSPACE_API.md) |
| AI presentations (PPT) | [docs/api/PRESENTATION_API.md](docs/api/PRESENTATION_API.md) |
| Presentation comments | [docs/api/PRESENTATION_COMMENTS_API.md](docs/api/PRESENTATION_COMMENTS_API.md) |
| Assets | [docs/api/ASSETS_API.md](docs/api/ASSETS_API.md) |
| Credits | [docs/api/CREDITS_API.md](docs/api/CREDITS_API.md) |
| Platform superadmin | [docs/api/SUPERADMIN_API.md](docs/api/SUPERADMIN_API.md) |
| HeyGen (user-scoped) | [docs/api/HEYGEN_API.md](docs/api/HEYGEN_API.md) |
| HeyGen project videos | [docs/api/HEYGEN_PROJECT_VIDEOS_API.md](docs/api/HEYGEN_PROJECT_VIDEOS_API.md) |
| All routes (table) | [docs/api/QUICK_REFERENCE.md](docs/api/QUICK_REFERENCE.md) |
| Environment variables | [docs/api/ENVIRONMENT.md](docs/api/ENVIRONMENT.md) |

### Frontend integration guides

| Guide | Purpose |
|-------|---------|
| [docs/PROJECT_EDITOR_INTEGRATION.md](docs/PROJECT_EDITOR_INTEGRATION.md) | Editor project model, save/load, playback, HeyGen |
| [docs/FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md](docs/FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md) | **All-in-one** — PPT + Image Gen + Brand Kit (superadmin → user, self-contained) |
| [docs/PRESENTATION_FRONTEND_INTEGRATION.md](docs/PRESENTATION_FRONTEND_INTEGRATION.md) | **PPT / canvas + templates** — AI/blank/template, canvas, export, admin templates |
| [docs/CREDITS_FRONTEND_INTEGRATION.md](docs/CREDITS_FRONTEND_INTEGRATION.md) | Credits: pools, pricing, billing logic, editor & library UX |
| [docs/PRESENTATION_CREDITS_FRONTEND.md](docs/PRESENTATION_CREDITS_FRONTEND.md) | AI PPT credits (`ppt_*`, separate from HeyGen) |
| [docs/PRESENTATION_PROMPTS.md](docs/PRESENTATION_PROMPTS.md) | Presentation prompt bundle versioning |
| [docs/NOTIFICATIONS_FRONTEND_INTEGRATION.md](docs/NOTIFICATIONS_FRONTEND_INTEGRATION.md) | Notifications settings, inbox bell, project comments |
| [docs/SUPERADMIN_FRONTEND_INTEGRATION.md](docs/SUPERADMIN_FRONTEND_INTEGRATION.md) | Admin portal login, capabilities, credit admin |

### Deployment

| Guide | Purpose |
|-------|---------|
| [docs/DEVOPS_DEPLOYMENT.md](docs/DEVOPS_DEPLOYMENT.md) | **Production AWS** — ALB + EC2 + Nginx, GoDaddy DNS (`vi.api.lmsathena.com`) |
| [docs/DEPLOY_RENDER.md](docs/DEPLOY_RENDER.md) | Render staging (testing) |

---

## Run locally

```bash
npm install
# Configure .env.development (DATABASE_URL, REDIS_URL, JWT_SECRET, …)
npm run dev
```

Default port: **9000** (`http://localhost:9000/api`).

---

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run dev` | Development server (nodemon) |
| `npm start` | Production server |
| `npm run lint` | ESLint |
| `npm run format` | Prettier |
| `npm run prisma:studio:development` | Prisma Studio |
| `npm run seed:presentation-templates` | Seed DECK_LAYOUT templates |
| `npm run seed:presentation-deck-packs` | Seed DECK_PACK multi-slide packs (after layouts) |
| `npm run seed:video-templates` | Seed VIDEO_SCENE templates (video editor only) |
| `npm run eval:presentation` | Offline presentation eval harness |

---

**Canonical API source of truth:** [docs/api/](docs/api/) (formerly a single monolithic README)
