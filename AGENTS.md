# AGENTS.md — Athena VI Backend

> Context for AI coding assistants (Cursor, Copilot, Antigravity, etc.). **Read this before making changes.**  
> Full HTTP contracts (paths, bodies, status codes) are in **`docs/api/`** — use the index below instead of loading every file.

**Keeping the knowledge graph in sync:** after agent sessions that change code, you can run **`graphify update .`** manually, or add a **local** Cursor hook in `.cursor/hooks.json` (that folder is **gitignored** — each machine keeps its own hooks/rules).

---

## Project overview

| | |
|---|---|
| **Product** | **Athena VI** (Virtual Instructor) — backend for workspaces, a video/editor project model, assets, credits, HeyGen (avatars, voices, project videos), and **Remotion** server-side renders. |
| **Stack position** | Monolith **Express 5** API; **CommonJS** (`require` / `module.exports`). |
| **API docs** | [`docs/api/README.md`](docs/api/README.md) — fragmented API reference (auth, user, workspace, HeyGen, …). |

---

## Tech stack

| Layer | Technology | Notes |
|---|---|---|
| **Runtime** | Node.js | CommonJS (`"type": "commonjs"` in `package.json`). |
| **Framework** | Express.js **5** | `src/app.js` wires global middleware and `/api/*` routers. |
| **Language** | JavaScript | No TypeScript compile step for `src/`. |
| **ORM** | Prisma **7** | `@prisma/adapter-pg`, client in `src/shared/config/prismaClient.js`. |
| **Database** | PostgreSQL | Schema: `prisma/schema.prisma`; CLI config: `prisma.config.ts`. |
| **Cache** | **Redis** (`redis` npm package) | `src/shared/config/redis.js` — **required** at app startup (`app.js`). |
| **Object storage** | AWS S3 | `@aws-sdk/client-s3`, `src/modules/s3/s3.service.js`. |
| **Validation** | **Joi** | Schemas under `src/modules/validations/` + `validate.middleware.js`. |
| **Auth** | JWT **Bearer** access token + **httpOnly** refresh cookie | See [`docs/api/OVERVIEW.md`](docs/api/OVERVIEW.md) → Authentication. |
| **Email** | Nodemailer | `src/shared/notification/email.service.js`, templates in `src/shared/templates/`. |
| **Video / render** | Remotion **4** + React **19** | `src/modules/render/remotion/`. |
| **External video AI** | HeyGen API v3-style client | `src/shared/services/heygenV3.client.js`. |

### Key dependencies (abridged)

```
express, prisma, @prisma/adapter-pg, redis, @aws-sdk/client-s3, joi, jsonwebtoken,
bcrypt, multer, helmet, cors, cookie-parser, morgan, winston, axios, nodemailer,
remotion, @remotion/bundler, @remotion/renderer, react, react-dom
```

---

## Repository structure

```
AthenaVI_backend/
├── prisma/
│   └── schema.prisma              # DB schema (source of truth)
├── prisma.config.ts               # Prisma CLI / migrate config
├── README.md                      # Project intro + links to docs/api/
├── docs/api/                      # Canonical API documentation (by domain)
├── AGENTS.md                      # This file — agent handbook
├── agent.md                       # Short pointer → AGENTS.md
├── .cursor/                       # Local only (gitignored): rules, hooks, etc.
├── .graphifyignore                # What graphify indexes (not Git)
├── graphify-out/                  # Generated graph (gitignored)
├── package.json
└── src/
    ├── server.js                  # Entry: env load, Prisma connect, listen (default PORT 9000)
    ├── app.js                     # Express app, Redis, mount routes, errorHandler
    ├── middlewares/               # auth, validate, error, upload, workspace RBAC
    ├── modules/
    │   ├── auth/                  # OTP, login, register, Google OAuth, password reset
    │   ├── sessions/              # Session + refresh token helpers
    │   ├── user/
    │   ├── workspace/             # Workspaces, members, invitations; mounts nested routers
    │   ├── folder/
    │   ├── project/
    │   ├── asset/
    │   ├── credit/
    │   ├── heygen/                # User-scoped HeyGen (avatars/voices, etc.)
    │   ├── video/                 # Project-scoped HeyGen video routes + services
    │   ├── render/                # Remotion pipeline, render DAO/service
    │   ├── s3/
    │   └── validations/           # Shared Joi schemas by domain
    └── shared/
        ├── config/                # prismaClient, redis, s3
        ├── utils/                 # AppError, asyncHandler, apiResponse, jwt, logger, messages
        ├── services/heygenV3.client.js
        ├── notification/
        └── templates/             # email HTML/text
```

---

## Architecture patterns

### Module pattern (follow existing code)

Each feature area uses a **4-layer** style (file names vary slightly):

```
src/modules/<feature>/
├── <feature>.routes.js       # express.Router, middleware chain, HTTP verbs
├── <feature>.controller.js   # async handlers; call services; successResponse / next(err)
├── <feature>.service.js      # business rules; calls DAO + other services; throws AppError
├── <feature>.dao.js          # Prisma only
└── ../validations/<feature>.validations.js   # Joi schemas (some features colocate *.validation.js)
```

| Layer | Knows about | Typical pattern |
|---|---|---|
| **Routes** | Express, `authMiddleware`, `requireWorkspaceRole`, `validate` | `router.post('/', authMiddleware, validate(schema), controller.create)` |
| **Controller** | `req`/`res`, service functions | `asyncHandler(async (req, res) => { ... successResponse(...) })` |
| **Service** | DAO, S3, other modules | `throw new AppError('...', 404)` for expected failures |
| **DAO** | `prisma` from `prismaClient` | Returns plain Prisma results |

**Nested routers** are mounted from `workspace.routes.js` (folders, projects, per-project heygen + renders). Always trace **full path** from `app.js` → `workspace.routes.js` → feature routes.

### Route registration

- **Top-level:** `src/app.js` mounts `/api/user`, `/api/auth`, `/api/workspaces`, `/api/credits`, `/api/assets`, `/api/heygen`.
- **Under workspaces:** `src/modules/workspace/workspace.routes.js` mounts `/:workspaceId/folders`, `/:workspaceId/projects`, `/:workspaceId/projects/:projectId/heygen`, `/:workspaceId/projects/:projectId/renders`.

---

## Error handling

- **`AppError`** (`src/shared/utils/AppError.js`): sets `isOperational`, `statusCode`, `message`, optional `errors` array (e.g. Joi list).
- **`errorHandler`** (`src/middlewares/errorHandler.js`): maps `AppError` and `multer.MulterError` to **`errorResponse`**; unknown → 500 with generic message.
- **Controllers:** prefer `asyncHandler` so async errors reach `errorHandler`; or `next(err)` explicitly.

### API envelope

Use **`successResponse`** / **`errorResponse`** from `src/shared/utils/apiResponse.js`:

```json
// success
{ "success": true, "message": "...", "data": { } }

// error
{ "success": false, "message": "...", "errors": [] }
```

---

## Authentication & authorization

1. **Access:** `Authorization: Bearer <accessToken>` on protected routes (see [`docs/api/OVERVIEW.md`](docs/api/OVERVIEW.md)).
2. **Refresh:** httpOnly cookie `refreshToken`; `POST /api/auth/refresh` rotates tokens.
3. **Workspace:** `requireWorkspaceRole([...])` enforces `OWNER` | `ADMIN` | `MEMBER` on nested workspace routes.
4. **Implementation files:** `auth.middlware.js` (note filename spelling), `requireWorkspaceRole.js`, `workspaceAccess.js`, `session.service.js`, `jwt.js`.

---

## Validation

- **Joi** schemas in `src/modules/validations/*.js` or module-local `*.validation.js`.
- **`validate(schema)`** middleware (`validate.middleware.js`) attaches validated payload; on failure throws **`AppError`** with 400 + structured errors.

---

## Database (Prisma)

### Schema change workflow

1. Edit `prisma/schema.prisma`.
2. Create/apply migrations per your team process (`prisma migrate` / `db push`).
3. `npx prisma generate` if needed.

### Model groups (mental map)

| Group | Models |
|---|---|
| Identity | `User`, `Account`, `Session`, `RefreshToken`, `PasswordResetToken` |
| Workspaces | `Workspace`, `WorkspaceMember`, `Invitation` |
| Editor | `Folder`, `Project` (large JSON `data`), `Asset` |
| HeyGen | `HeygenResponse`, `HeygenAvatar`, `HeygenVoice` |
| Renders | `ProjectRender`, `SceneRenderCache` |
| Billing | `CreditTransaction`, `User.credits`, `Workspace.credits` (TEAM pool), `/api/superadmin`, `/api/credits` — rates in `src/shared/config/creditPricing.js` aligned with HeyGen PAYG/Enterprise tables |

**Prisma client:** import `src/shared/config/prismaClient.js` in DAOs/services (follow existing imports).

---

## Redis

- Standard **`redis`** package; `connectRedis()` runs during `app.js` load — failure **exits** the process.
- Use existing helpers in `redis.js`; follow established key patterns when adding new cache usage.

---

## S3

- Config: `src/shared/config/s3.js`.
- Shared operations: `src/modules/s3/s3.service.js` (upload, delete, presigned URLs as implemented).
- Assets and render outputs use workspace/user-scoped keys — follow existing services.

---

## Environment variables

Do **not** duplicate the full list here (drift risk). Use:

1. **`docs/api/ENVIRONMENT.md`**
2. Repo search: `process.env.` under `src/`

Typical categories: database URL, Redis, JWT secrets, S3, SMTP, Google OAuth, HeyGen keys, `PORT`, `NODE_ENV`.

---

## Graphify (code map)

- **Optional local rule:** e.g. `.cursor/rules/graphify.mdc` — remind yourself to read **`graphify-out/GRAPH_REPORT.md`** for god nodes / communities. Prefer `graphify-out/wiki/index.md` if present. (Not in git; create on your machine.)
- **Update:** `graphify update .` from repo root (AST-only, no API cost by default).
- **Indexer:** `.graphifyignore` — includes `src/**` and `AGENTS.md` / `agent.md` as configured.
- **Git:** `graphify-out/` is **gitignored** — do not commit generated outputs.

---

## API documentation index (token-efficient)

| Topic | File |
|---|---|
| Index (start here) | [`docs/api/README.md`](docs/api/README.md) |
| Base URL, envelopes, auth | [`docs/api/OVERVIEW.md`](docs/api/OVERVIEW.md) |
| Auth API | [`docs/api/AUTH_API.md`](docs/api/AUTH_API.md) |
| User API | [`docs/api/USER_API.md`](docs/api/USER_API.md) |
| User inbox | [`docs/api/USER_INBOX_API.md`](docs/api/USER_INBOX_API.md) |
| User settings | [`docs/api/USER_SETTINGS_API.md`](docs/api/USER_SETTINGS_API.md) |
| Workspaces, folders, projects, renders | [`docs/api/WORKSPACE_API.md`](docs/api/WORKSPACE_API.md) |
| Assets | [`docs/api/ASSETS_API.md`](docs/api/ASSETS_API.md) |
| Credits | [`docs/api/CREDITS_API.md`](docs/api/CREDITS_API.md) |
| **Credits (frontend)** | [`docs/CREDITS_FRONTEND_INTEGRATION.md`](docs/CREDITS_FRONTEND_INTEGRATION.md) |
| Platform superadmin | [`docs/api/SUPERADMIN_API.md`](docs/api/SUPERADMIN_API.md) |
| HeyGen (user-scoped) | [`docs/api/HEYGEN_API.md`](docs/api/HEYGEN_API.md) |
| HeyGen project videos | [`docs/api/HEYGEN_PROJECT_VIDEOS_API.md`](docs/api/HEYGEN_PROJECT_VIDEOS_API.md) |
| Route table | [`docs/api/QUICK_REFERENCE.md`](docs/api/QUICK_REFERENCE.md) |
| Environment | [`docs/api/ENVIRONMENT.md`](docs/api/ENVIRONMENT.md) |
| **Editor / project integration (frontend)** | [`docs/PROJECT_EDITOR_INTEGRATION.md`](docs/PROJECT_EDITOR_INTEGRATION.md) |
| **Superadmin portal (frontend)** | [`docs/SUPERADMIN_FRONTEND_INTEGRATION.md`](docs/SUPERADMIN_FRONTEND_INTEGRATION.md) |

---

## Middleware pipeline (typical)

```
Request
 → helmet()
 → cors()
 → express.json()
 → cookieParser()
 → express.urlencoded()
 → morgan('dev')
 → <route-specific: authMiddleware, requireWorkspaceRole, validate, multer>
 → controller (asyncHandler)
 → errorHandler (last)
```

---

## Common gotchas (this repo)

1. **`auth.middlware.js`** — filename is intentionally that spelling; imports must match.
2. **Bearer + cookie** — not cookie-only auth; clients must send `Authorization` for most protected routes and cookies for refresh.
3. **Workspace nesting** — project and render routes live under `/api/workspaces/:workspaceId/projects/...`, not top-level.
4. **Redis required** — local dev must have Redis up or the server exits on boot.
5. **CommonJS only** — use `require` / `module.exports`; no ESM `import` in `src/` without a wider migration.
6. **Joi, not Zod** — validation style matches existing Joi modules.
7. **`Project.data`** — large JSON editor state; avoid loading entire blobs in logs or responses unnecessarily.
8. **Remotion** — render path uses bundled JSX; changing composition often touches `render.service.js` and `remotion/` together.

---

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | `nodemon src/server.js` (`NODE_ENV=development`) |
| `npm start` | Production `node src/server.js` |
| `npm run lint` | ESLint |
| `npm run format` | Prettier |
| `npm run prisma:studio:development` | Prisma Studio with `.env.development` |

---

## Testing

There is **no** `npm test` script in `package.json` today. If you add tests, document the runner here and in `package.json`.

---

## Quick reference: adding a new HTTP feature

1. Add or extend **Prisma** models if persistence changes.
2. Add **Joi** schema(s) under `validations/`.
3. Add **DAO** methods (`*.dao.js`).
4. Add **service** methods (`*.service.js`) — throw `AppError` for domain failures.
5. Add **controller** handlers using `asyncHandler` + `successResponse`.
6. Wire **routes**; mount in `app.js` or under `workspace.routes.js` as appropriate.
7. Document the contract in the relevant **`docs/api/*.md`** file (same PR).
8. Run **`graphify update .`** (or rely on the **stop** hook below).

---

## Automation: refresh graph after agent work (optional, local)

If you want this, create **`.cursor/hooks.json`** locally (not committed) and point the **`stop`** event at e.g. **`node .cursor/hooks/refresh-graphify.mjs`** so `graphify-out/GRAPH_REPORT.md` updates after agent turns.

- This does **not** rewrite `AGENTS.md`.
- Requires **`graphify`** on PATH (or use `npx` in the script).

---

## Related files

| File | Role |
|---|---|
| `docs/api/README.md` | API documentation index |
| `README.md` | Project intro + links to `docs/api/` |
| `docs/PROJECT_EDITOR_INTEGRATION.md` | Frontend editor integration (project save/load, HeyGen, payload V2, playback) |
| `docs/CREDITS_FRONTEND_INTEGRATION.md` | Frontend credits guide (pools, pricing, editor, voice/avatar, TEAM allocation) |
| `docs/SUPERADMIN_FRONTEND_INTEGRATION.md` | Frontend superadmin portal (login, toggle, credit admin APIs) |
| `AGENTS.md` | This handbook |
| `agent.md` | Pointer for `@agent.md` users |
| `.cursor/rules/*.mdc` | Optional; local Cursor rules (gitignored) |
