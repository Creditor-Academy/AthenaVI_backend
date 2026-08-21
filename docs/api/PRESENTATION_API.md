# Presentation (AI PPT) API

> **Frontend credits:** [`docs/PRESENTATION_CREDITS_FRONTEND.md`](../PRESENTATION_CREDITS_FRONTEND.md)  
> **Prompt bundle:** [`docs/PRESENTATION_PROMPTS.md`](../PRESENTATION_PROMPTS.md)  
> **Eval:** `npm run eval:presentation`

Base path: **`/api/workspaces/:workspaceId/presentations`**

Creates a **`Project`** with **`type: PRESENTATION`** (not video). Deck/slides live in related tables (`decks`, `slides`, `deck_exports`). Billing uses presentation-specific features (`ppt_*`) via `presentationCreditPricing.js` — separate from HeyGen/Remotion rates, but charged against the same workspace credit pool.

For workspace UI tabs (Videos / PPT / Images), prefer **`GET /api/workspaces/:workspaceId/library`** — see [WORKSPACE_API.md](WORKSPACE_API.md) → Workspace library.

---

## Auth & roles

| | |
|---|---|
| **Auth** | `Authorization: Bearer <access_token>` |
| **Role** | Workspace **OWNER**, **ADMIN**, or **MEMBER** (`requireWorkspaceRole`) |

Envelope: [OVERVIEW.md](OVERVIEW.md) — `{ success, message, data }` / `{ success, false, message, errors }`.

Insufficient credits → **402**. Rate limits on generate/regenerate may return **429**.

---

## List presentations

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations` |
| **Auth** | Bearer + member |

**Query (optional):** `folderId`

**Response (200)** – `data.presentations`: summary cards (`type: PRESENTATION`), ordered by `lastModifiedAt` desc. Includes `deckId`, `deckStatus`, `slideCount`, `aspectRatio`, `locale`, `partial`, plus the usual project list fields (`owner`, `folder`, `storageBytes`, …). Full deck/slides: get-by-id.

---

## Create presentation

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations` |
| **Status** | **201** |

**Body**

```json
{
  "folderId": "<uuid>",
  "themeId": "midnight_blue",
  "themeTokens": null,
  "locale": "en",
  "aspectRatio": "16:9",
  "createMode": "blank",
  "templateId": null,
  "packId": null,
  "brandKitId": null
}
```

- **`title`** / **`name`** optional. If omitted, project is created as **`Untitled Presentation`** (AI flow fills a real title on outline).
- **`folderId`** required (must belong to workspace).
- **`themeId`** and/or **`themeTokens`** optional; tokens resolved from catalog when `themeId` is set.
- **`brandKitId`** optional — workspace Brand Kit overrides theme (see [BRAND_KIT_API.md](BRAND_KIT_API.md)).
- **`aspectRatio`**: `16:9` (default) \| `4:3` only (native **1920×1080** / **1600×1200**). Can also be set later via `generationFlow.selections.canvasSize` on generate. `9:16` → **400**.
- **`createMode`**:
  - `blank` (default) — **one** READY slide with default canvas text
  - `template` — requires active `DECK_LAYOUT` **`templateId`**; one READY slide
  - `pack` — requires active `DECK_PACK` **`packId`**; clones multi-slide branded skeleton (uses `snapshot.elements` when present, else layout compile)
- AI path: create blank (or with `packId`/`brandKitId`) → outline → generate with optional `generationFlow.selections.packId` / `brandKitId`. Canvas-published packs with roles/`meta.aiReady` **rebind** generated text/images into the designed canvas instead of full layout recompile.

**Canvas publish (superadmin):** design in the presentation editor, then `POST /api/superadmin/presentations/:presentationId/publish-as-pack` — see [SUPERADMIN_API.md](SUPERADMIN_API.md).

**Response `data`:** `{ project, deck, slides, id, title, status, themeTokens, … }` — `project.type` is `PRESENTATION`; `presentationId` for subsequent routes is the **project id**. Flat `id`/`title`/`status` mirror project/deck for FE canvas contract.

---

## Caps

| Limit | Value |
|---|---|
| AI outline / generate | **5–20** slides |
| Deck total (manual add/duplicate) | **40** slides |
| Elements per slide | **50** |

After AI generates ≤20 slides, users may add more by hand until 40.

---

## Workspace pickers (not under `/presentations/:id`)

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/workspaces/:workspaceId/presentation-templates?contentType=&category=` | Active `DECK_LAYOUT` templates + `categories[]` gallery tabs |
| `GET` | `/api/workspaces/:workspaceId/presentation-deck-packs` | Active `DECK_PACK` multi-slide packs (summary picker) |
| `GET` | `/api/workspaces/:workspaceId/presentation-deck-packs/:packId` | One active `DECK_PACK` with full `schema.slides` + `slidePreviews[]` |
| `GET` | `/api/workspaces/:workspaceId/presentation-themes` | Curated theme catalog |
| `GET` | `/api/workspaces/:workspaceId/presentation-elements` | Element library presets for the canvas palette |
| `GET` | `/api/workspaces/:workspaceId/brand-kits` | Workspace Brand Kits (see [BRAND_KIT_API.md](BRAND_KIT_API.md)) |

### Layout gallery categories

`GET .../presentation-templates` returns `categories[]` (picker tabs) and `templates[]`.

- **Tabs:** render `categories[].label` / `id`.
- **Filter:** `?category=simple_slides` (or `?contentType=agenda` for one AI tag).
- Each template includes `contentType` (AI tag) and `categories` (which tabs it belongs to).
- Do **not** send display labels as `contentType`.

Category ids: `all`, `simple_slides`, `grid`, `charts_and_data`, `timeline_and_plans`, `pricing`, `agenda`, `people_and_team`, `quotes_and_testimonials`, `device_frames`, `closing`.

New seed types: `grid`, `pricing`, `device_frames` (3 layouts each). Re-seed: `npm run seed:presentation-templates`. See `src/modules/presentation/templates/COVERAGE.md`.

### Seeded deck packs

`npm run seed:presentation-deck-packs` installs system packs (**schemaVersion 2**). Each pack carries `themeId`,
`meta`, `narrative`, per-slide `intent` / `designTokens` / `generationHints`, designed placeholders,
and `generationDefaults` (`layoutWhitelist`, `slideOrder: fixed`, `contentDistribution`).

Visual slides may include `placeholder.imagePrompt`. Seed also acquires **durable system photos** into
`TemplateMedia` (stock-once → S3). **Pack clone** fills image element URLs from that media (no empty frames).
List packs includes `previewImageUrl` + `media[]` (presigned). **List does not include `schema.slides`** — use `GET .../presentation-deck-packs/:packId` for drill-down (full `schema`, hydrated snapshot URLs, and `slidePreviews[]` per slide). AI image brief prefers
`content.imagePrompt` or `generationHints.imagePromptStyle` (prompt bundle **v1.5+**).

| pack_id | Theme | Slides | Use case |
|---|---|---|---|
| `corp_pitch_midnight` | Midnight Blue | 5 | Short corporate pitch |
| `marketing_clean_light` | Clean Light | 5 | Campaign story |
| `portfolio_forest` | Forest Slate | 5 | Studio portfolio |
| `consulting_report_paper` | Paper Ink | 8 | Text-first consulting report |
| `investor_deck_violet` | Violet Noir | 8 | Fundraising deck |
| `product_launch_ocean` | Ocean Mist | 8 | Product launch |
| `executive_review_charcoal` | Charcoal Gold | 8 | QBR / board review |
| `brand_story_sand` | Warm Sand | 8 | Brand / editorial story |
| `company_meeting_clean` | Clean Light | 10 | Internal company meeting (title/closing image slots) |
| `website_launch_paper_v1` | Paper Ink | 7 | Website launch announcement |

List response includes `meta`, `narrative`, `preview`, `previewImageUrl`, `media`, `generationDefaults`.

### Slide media (manual edit)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `.../presentations/:id/slides/:slideId/media` | Multipart `file` (+ optional `elementId`) — upload and attach to image element |
| `POST` | `.../presentations/:id/slides/:slideId/attach-asset` | `{ assetId, elementId? }` — attach workspace Asset |
| `POST` | `.../presentations/:id/slides/:slideId/insert-stock` | `{ query }` or `{ provider, externalId }` — stock → S3 → slide |

### Freeform canvas shape (`slide.elements`)

Elements may include **gradient** shape fills and rich text (`fontWeight`, `letterSpacing`, `lineHeight`, `colorRole`). Pack clone and AI generate emit decoration backgrounds / accent bars. Frontend canvas should render `content.fill.type === "gradient"` as CSS `linear-gradient`.

---

## Get presentation

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId` |
| **Status** | **200** |

**Response `data`:** `{ project, deck, slides, id, title, status, themeTokens, aspectRatio, locale, folderId }`

- Nested: `project`, `deck`, `slides` (canonical)
- **Flat FE compatibility fields** (same payload): `id` (= project id), `title` (= project.name), `status` / `themeTokens` / `aspectRatio` / `locale` / `folderId` mirrored from deck/project
- `deck`: themeTokens, outline, status, aspectRatio, locale, promptBundleVersion, generationMetrics, partial, creditsChargedSoFar, …
- slides: ordered slide rows (`content`, `layoutId`, `imageRef`, **`elements`** freeform canvas doc, status, manuallyEdited, …). Each slide also includes helper `title` ← `content.title` and `description` ← `content.bullets` when present.
- `imageRef.status`: `ready` \| `failed` \| `skipped`. On `failed`, `imageRef.error` explains the provider/upload error; slide content can still be `READY`.
- Image URLs in API responses are **presigned** (~1h). Prefer `elements[].content.url` (or `src` alias) for canvas render.
- Element `type`: `text` | `image` | `shape` | `icon` | `chart` | `table` | `embed`. Shape kinds include `rect`, `rounded-rect`, `circle`, `ellipse`, `pill`, `triangle`, `diamond`, `star`, `line`, `plus`, arrows. Shape `fill` may be a token string or `{ type: "solid"|"gradient", ... }`; optional `stroke` / `strokeWidth`.

Also: `GET .../slides/:slideId` returns a single presigned slide.

**Frontend outcome vs API:** A single mega JSON “final deck” blob is **not** accepted as one POST. Map UI prompt/vibe into outline/theme calls; store/edit via slide + canvas APIs.

---

## Credit estimate

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/credit-estimate` |
| **Status** | **200** |

**Query:** optional `slideCount` (5–20). If omitted, uses outline slide count (fallback **12**).

**Response `data` (shape):**

```json
{
  "slideCount": 12,
  "outline": { "athenaCredits": 0, "usdCost": 0, "breakdown": {} },
  "generate": { "athenaCredits": 0, "breakdown": {} },
  "export": { "athenaCredits": 3, "feature": "ppt_export" },
  "totalEstimatedCredits": 0
}
```

Estimate only — does not charge. Generate estimate assumes Path A image cost per slide (see credits guide).

---

## Generate / update outline

### Generate outline

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/outline` |
| **Status** | **200** |

**Body (JSON)** when `source` is `prompt` or `outline`:

```json
{
  "source": "prompt",
  "prompt": "Pitch deck for …",
  "slideCount": 12,
  "density": "balanced",
  "locale": "en"
}
```

| `source` | Required fields |
|----------|-----------------|
| `prompt` | `prompt` |
| `outline` | `outlineText` |
| `document` | multipart field **`file`** (PDF/DOCX/DOC, max 20 MB) and/or `documentText` |

Optional: `slideCount` (default 12, range 5–20), `density` (`concise` \| `balanced` \| `detailed`), `locale`.

The outline LLM also returns a **deck title** derived from the full prompt (concise, natural; not a truncated prompt). That title is:
1. Stored on `outline.title`
2. Saved as **`project.name`** before the response is returned
3. Returned as `data.presentation`

Fallback title if generation/sanitization fails: **`Untitled Presentation`**.

**Response `data` (typical):**

```json
{
  "presentation": {
    "id": "<projectId>",
    "title": "AI in Modern Healthcare"
  },
  "outline": {
    "title": "AI in Modern Healthcare",
    "slideCount": 10,
    "density": "balanced",
    "locale": "en",
    "slides": [
      { "order": 1, "title": "…", "summary": "…", "suggestedContentType": "title" }
    ]
  },
  "deckId": "…",
  "promptBundleVersion": "…",
  "creditsCharged": 0
}
```

Charges **`ppt_outline`** on success (token reconcile; see credits guide).

### Patch outline

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/outline` |
| **Status** | **200** |

**Body:** full outline object:

```json
{
  "title": "Deck title",
  "slideCount": 12,
  "density": "balanced",
  "locale": "en",
  "slides": [
    { "order": 1, "title": "…", "summary": "…", "suggestedContentType": "title" }
  ]
}
```

No LLM charge for manual patch. If `title` is present, it is also saved to **`project.name`**. Response includes `presentation: { id, title }` plus `outline`.

---

## Set theme

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/theme` |
| **Status** | **200** |

**Body:** at least one of `themeId`, `themeTokens`:

```json
{
  "themeId": "clean_light",
  "themeTokens": {
    "palette": { "bg": "#FFFFFF", "text": "#0F172A" }
  }
}
```

---

## Apply Brand Kit

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/apply-brand-kit` |
| **Status** | **200** |

**Body:** `{ "brandKitId": "<id>" }`

Updates `deck.themeTokens` from the kit and injects/updates `role: logo` image elements. Does **not** wipe slide text content.

---

## Generate deck

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/generate` |
| **Status** | **202** |

**Body (optional):**

```json
{
  "density": "concise",
  "overwriteManualEdits": false,
  "generationFlow": {
    "version": 1,
    "source": "ai_ppt_wizard",
    "selections": {
      "prompt": "Create an investor pitch for our new health app",
      "title": "Investor Pitch — Health App",
      "outlineNotes": "Focus on traction and market size",
      "voiceAndTone": "Professional",
      "audience": "Investors",
      "purpose": "Persuade",
      "style": "Modern",
      "color": "Blue",
      "industries": ["Healthcare", "Technology"],
      "baseTemplate": "corp-pitch",
      "colorTheme": "modern-professional",
      "canvasSize": "16:9",
      "imageType": "ai",
      "imageStyle": "photo",
      "imageStyleFilter": "Suggested",
      "textContent": "Concise",
      "density": "concise",
      "slideCount": 10,
      "locale": "en",
      "packId": optional,
      "brandKitId": optional
    },
    "availableOptions": {}
  }
}
```

- Top-level `density` / `overwriteManualEdits` remain supported (backwards compatible).
- **`generationFlow`** (optional): full AI PPT wizard snapshot. Persisted on `deck.generationMetrics.generationFlow` and applied to generation.
- **`selections.slideCount`**: metadata only — does **not** resize the deck (outline slides are the source of truth).
- **`selections.locale`**: updates `deck.locale` when present.
- **`selections.title`**: updates `project.name` when present.
- **`selections.colorTheme`**: kebab-case wizard theme id → `themeTokens` (overrides prior theme for this generate).
- **`selections.packId`**: active `DECK_PACK` id — layout whitelist + pack defaults for generation.
- **`selections.brandKitId`**: workspace Brand Kit — overrides theme, injects voice into prompts, prefers brand photos for slide images.
- **`selections.canvasSize`**: `16:9` | `4:3` → `deck.aspectRatio` + canvas pixel size.
- **`selections.imageType`**:
  - `ai` — AI-first image generation (stock fallback)
  - `stock` / `web` — stock providers only
  - `placeholders` — shared system placeholder image (no AI/stock charge)
  - `none` — no images (`imageRef.status: skipped`)
- Voice/audience/purpose/style/industries/outlineNotes feed slide + image brief prompts.
- Per-slide regenerate reuses saved `generationFlow` from metrics.

Starts async slide generation. Poll **status**. Pre-checks affordability; charges per slide/image **on success** (`ppt_slide_content`, `ppt_image_path_a` / `ppt_image_path_b`, cache hits free). Placeholder / `none` image modes do not charge image features.

**Response `data` (typical):** `{ deckId, status, slideCount, estimatedCredits }`

---

## Status

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/status` |
| **Status** | **200** |

**Response `data`:**

```json
{
  "deckId": "…",
  "status": "GENERATING",
  "partial": false,
  "progress": 40,
  "etaSeconds": 24,
  "creditsChargedSoFar": 12,
  "slides": [
    { "id": "…", "order": 1, "status": "READY", "contentType": "title", "layoutId": "…", "manuallyEdited": false }
  ]
}
```

Deck `status` values include `DRAFT`, `GENERATING`, `READY`, `FAILED` (and similar). Slide statuses: `PENDING`, `GENERATING`, `READY`, `FAILED`.

---

## Slides

Structural mutations return **409** while deck `status === GENERATING`.

### Add slide

`POST .../presentations/:presentationId/slides` → **201**

```json
{
  "afterSlideId": optional,
  "templateId": optional,
  "layoutId": optional,
  "content": {},
  "generate": false,
  "prompt": "optional AI brief (max 2000)",
  "target": "all"
}
```

- Manual (default): user-authored → `status: READY`, `manuallyEdited: true`. Response `{ slide, deckId }`.
- **`generate: true`**: creates the slide then starts AI regenerate (same billing as regenerate). Requires **`prompt`** or **`content.title`**. Response includes `{ slide, deckId, status: "GENERATING", target, estimatedCredits }`. Poll `GET .../status` until the slide is `READY`.
- Rejects if deck already has **40** slides.

### Delete / duplicate / reorder

| Method | Path |
|---|---|
| `DELETE` | `.../slides/:slideId` |
| `POST` | `.../slides/:slideId/duplicate` (rejects at 40) |
| `PATCH` | `.../slides/reorder` body `{ "slideIds": ["…"] }` |

### Apply layout

`POST .../slides/:slideId/apply-layout` body `{ "templateId" }` — recompiles freeform `elements` from `DECK_LAYOUT` + existing content; sets `manuallyEdited: true`.

### Canvas / elements

| Method | Path |
|---|---|
| `PUT` | `.../slides/:slideId/canvas` — full `{ version, canvas, elements }` replace |
| `POST` | `.../slides/:slideId/elements` — flat `{ type, placement, content, presetId? }` **or** `{ presetId }` / `{ element }` |
| `PATCH` | `.../slides/:slideId/elements/:elementId` |
| `DELETE` | `.../slides/:slideId/elements/:elementId` |
| `PATCH` | `.../slides/:slideId/elements/reorder` — `{ "elementIds": [] }` |

Cannot delete the last remaining slide (**400**). While `deck.status === GENERATING`, structure/canvas mutations → **409**.

`POST .../elements` accepts FE flat bodies; image `content.src` is stored as `url`. Charts accept nested `data.labels/series`; tables accept `cells` or `rows`. Regenerate `target` accepts `content` \| `image` \| `all` \| `full` (`full` ≡ `all`).

### Patch slide

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId` |
| **Status** | **200** |

**Body** (at least one field):

```json
{
  "content": { "title": "…", "bullets": ["…"] },
  "layoutId": "bullet_list_…",
  "contentType": "bullet_list",
  "imageRef": null,
  "elements": { "version": 1, "canvas": { "width": 1920, "height": 1080 }, "elements": [] },
  "manuallyEdited": true
}
```

### Regenerate slide

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/regenerate` |
| **Status** | **202** |

**Body (optional):**

```json
{
  "target": "all",
  "overwriteManualEdits": true,
  "prompt": "Competitive landscape for Athena VI vs Loom"
}
```

- `target`: `content` \| `image` \| `all` (default `all`)
- `prompt`: optional (max 2000). Used as LLM title/summary seed — especially useful on blank decks with no outline. For `content` / `all`, you must provide **`prompt`**, an existing slide **`content.title`**, or a matching outline title (**400** otherwise).
- Manual edits blocked unless `overwriteManualEdits` is true (**409**)
- Successful regen rebuilds `elements` from layout + content
- Subject to regenerate rate limits. Charges on success for regenerated pieces.

---

## Export

### Queue export

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export` |
| **Status** | **202** |

**Body:**

```json
{ "format": "PPTX", "slideId": optional }
```

- **`format`**: `PPTX` \| `PDF` \| `PNG` \| `JPEG`
- Prefer freeform `elements` placement when present; legacy title/bullets/`imageRef` fallback otherwise
- **PNG/JPEG**: single slide → one image; full deck → **ZIP** of slide images
- Optional **`slideId`** to export one slide only

**Response `data`:** `{ exportId, format, status: "QUEUED", estimatedCredits, slideId }`

Charges **`ppt_export`** on successful export.

### Get export

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export/:exportId` |
| **Status** | **200** |

Poll until `READY` / `FAILED`. Ready responses include download metadata (presigned URL / S3 key as implemented).

Export statuses: `QUEUED`, `PROCESSING` / `RENDERING`, `READY`, `FAILED`.

---

## View-only share links

Canva-style preview links. The **token in the URL is the permission** (capability URL): no login and no workspace membership are required, and viewers can never edit. Owner management lives under the presentation; viewers use the unauthenticated **`/api/p`** surface documented below.

Only a **SHA-256 hash** of the token is stored. The raw token is returned **once**, on create and on rotate — see the disclosure rules below.

### Enable share link

| | |
|---|---|
| **Method** | `PUT` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share` |
| **Auth** | Bearer + member |

Idempotent. Mints a token on **first** create; on an existing link it re-enables (and clears a lapsed `expiresAt`) without minting.

**Response `data` (first create):**

```json
{
  "share": {
    "exists": true,
    "enabled": true,
    "expired": false,
    "access": "VIEW",
    "tokenPrefix": "Xk3nQ1pR",
    "urlDisplay": "https://app.example.com/p/Xk3nQ1pR…",
    "expiresAt": null,
    "rotateCount": 0,
    "createdBy": "<uuid>",
    "createdAt": "2026-08-20T09:00:00.000Z",
    "updatedAt": "2026-08-20T09:00:00.000Z"
  },
  "token": "8Kd… (raw base64url token, shown once)",
  "url": "https://app.example.com/p/8Kd…"
}
```

On an already-enabled link the response omits `token` and `url`.

**409** if the deck is `GENERATING` (`PRESENTATION_ALREADY_GENERATING`).

### Get share link

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share` |

Metadata only — **never** the raw token. When no link was ever created: `data.share` is `{ "enabled": false, "exists": false }`.

`urlDisplay` is a masked label for the UI. It is **not** a working link; never build an `href` from `tokenPrefix`.

### Update share link

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share` |

**Body** (at least one key):

```json
{ "enabled": false, "expiresAt": "2026-09-01T00:00:00.000Z" }
```

- `expiresAt`: ISO date, or `null` to clear.
- Disabling keeps the same hash (so a previously shared URL works again after re-enable) and immediately flushes the viewer room.
- Re-enabling while the deck is `GENERATING` → **409**.
- Returns metadata only, never the raw token.

### Rotate share link

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share/rotate` |

Mints a new token and **invalidates every URL already shared**. Returns `token` + `url` like first create. Allowed even while the deck is `GENERATING`, so a leaked link can always be killed.

**404** if no link exists yet.

### Token disclosure rules

| Operation | Returns raw `token` + `url` |
|---|---|
| `PUT` first create | Yes |
| `PUT` on existing link | No |
| `GET` | No |
| `PATCH` (including re-enable) | No |
| `POST /rotate` | Yes |

The server cannot recover a token it has already issued. If the owner navigates away before copying, **rotate** is the only way to get a pasteable link — so the share modal must force a copy-to-clipboard moment on create and rotate.

---

## Public preview API (`/api/p`)

Unauthenticated. `Authorization: Bearer <access_token>` is **optional** — send it when present so the viewer appears by name instead of `Anonymous viewer`. An invalid or expired Bearer token never causes a 401 here; it is simply treated as a guest.

Unknown, disabled, and expired tokens all return an identical **404** (`Share link not found`) so the endpoint cannot be used to discover presentations.

All responses carry `Referrer-Policy: no-referrer`. The hosting `/p/:token` page must do the same, or the token can leak through the `Referer` header on presigned image loads.

### Get shared presentation

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/p/:token` |
| **Cache** | `ETag` + `Cache-Control: private, max-age=30` |

Send back the `ETag` as `If-None-Match` to get a **304**.

**Response `data`:**

```json
{
  "id": "<presentationId>",
  "title": "Q3 Business Review",
  "permission": "view",
  "status": "READY",
  "aspectRatio": "16:9",
  "locale": "en",
  "themeTokens": { },
  "contentUpdatedAt": "2026-08-20T08:59:12.000Z",
  "slideCount": 12,
  "slides": [
    { "id": "…", "order": 0, "status": "READY", "title": "…", "description": ["…"], "elements": { } }
  ]
}
```

- **Only `READY` slides are included.** During a regeneration the call still returns **200** with `status: "GENERATING"` and whatever slides survive, so the UI can show "Updating…" instead of an error.
- Image URLs are freshly presigned per request, including per-element images on multi-image slides.
- Editor-only data is stripped: outline, generation metrics, credits, prompt bundle version, folder, workspace, owner, jobs, comments, and internal S3 keys.

### Get viewer session

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/p/:token/session` |
| **Cache** | `no-store` |

Personalized companion to the cacheable deck payload.

```json
{
  "self": { "displayName": "Priya Shah", "isAnonymous": false, "userId": "<uuid>" },
  "permission": "view",
  "canOpenInEditor": true,
  "workspaceId": "<uuid>",
  "presentationId": "<uuid>"
}
```

`canOpenInEditor` is true only when the caller is a member of the owning workspace; `workspaceId` / `presentationId` appear only in that case, so the UI can offer "Open in editor".

Display names are always computed server-side from `User.name`. A logged-in user with a blank name is shown as `Anonymous viewer`. Email is never exposed.

### Presence heartbeat

| | |
|---|---|
| **Method** | `PUT` |
| **Path** | `/api/p/:token/presence` |
| **Cache** | `no-store` |

**Body:**

```json
{ "viewerSessionId": "b1f7c0de-…", "slideIndex": 3 }
```

`viewerSessionId` is a client-generated id (persist it in `localStorage`) used to identify guests. Any `displayName` sent by the client is ignored.

**Response `data`:**

```json
{
  "self": { "displayName": "Anonymous viewer", "isAnonymous": true },
  "viewerCount": 62,
  "viewers": [
    { "key": "user:…", "displayName": "Priya Shah", "isAnonymous": false, "slideIndex": 3, "lastSeen": "2026-08-20T09:00:03.000Z" }
  ],
  "contentUpdatedAt": "2026-08-20T08:59:12.000Z"
}
```

- Heartbeat about every **15s**; a viewer is dropped after **45s** of silence.
- Logged-in viewers collapse across tabs (keyed by user); guests are keyed by `viewerSessionId`.
- `viewerCount` is the full room size. `viewers` is capped at the **50 most recently active** — a display cap only, nobody is turned away, so render "+N more" from `viewerCount - viewers.length`.
- Refetch the deck only when `contentUpdatedAt` changes.

### List / leave presence

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/p/:token/presence` | Same payload without recording a heartbeat |
| `DELETE` | `/api/p/:token/presence?viewerSessionId=…` | Explicit leave; the TTL covers missed calls |

### Rate limits

**429** with a `Retry-After` header.

| Endpoint | Default |
|---|---|
| `GET /api/p/:token` | 60/min per IP, 300/min per link |
| Presence + session | 120/min per IP |

Configurable — see [ENVIRONMENT.md](ENVIRONMENT.md).

---

## Notes

- Presentation routes are nested under workspaces (same pattern as projects/folders).
- Credits are **presentation-specific feature keys** but use the **workspace** credit ledger (`SCOPE.WORKSPACE`).
- Offline structural checks: `npm run eval:presentation` (see `scripts/presentation-eval/`).
- Share links are **view-only** and free (no credit charge). Presence is polled over HTTP; there is no WebSocket/SSE channel.
- Deferred (not this API surface): password-protected links, frozen publish snapshots, comments on the preview, brand kits, server version history, studio isolation.

---

**[← API index](README.md)** · [Environment](ENVIRONMENT.md) · [Credits API](CREDITS_API.md)
