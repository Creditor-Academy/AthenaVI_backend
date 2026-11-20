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

**Query (optional):** `folderId`, and mutually exclusive assignment filters `assignedTo=me` \| `assigneeId=<uuid>` \| `unassigned=true`

**Response (200)** – `data.presentations`: summary cards (`type: PRESENTATION`), ordered by `lastModifiedAt` desc. Includes `deckId`, `deckStatus`, `slideCount`, `aspectRatio`, `locale`, `partial`, plus the usual project list fields (`owner`, `assignee`, `assignedBy`, `assignedAt`, `folder`, `storageBytes`, …). `thumbnail` / `thumbnailUrl` use the deck cover captured from the live preview when one exists (see [deck cover capture](#deck-cover-capture)); otherwise they fall back to an image extracted from the first slide. Full deck/slides: get-by-id. Dashboard click modal: [`GET .../preview`](#deck-preview-my-work--dashboard-modal).

Assignment uses the shared project endpoint: `PATCH /api/workspaces/:workspaceId/projects/:presentationId/assignee` (OWNER/ADMIN, TEAM only). See [WORKSPACE_API.md](WORKSPACE_API.md#assign-project-team-only).

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
| `GET` | `/api/workspaces/:workspaceId/presentation-templates/:templateId` | One active `DECK_LAYOUT` → `{ template }` (same row shape as the list; **404** if inactive / not a layout) |
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

**Response `data`:** `{ project, deck, slides, id, title, status, themeTokens, aspectRatio, locale, folderId, assignee, assignedBy, assignedAt, assignedToId, assignedById }`

- Nested: `project`, `deck`, `slides` (canonical). `project` includes hydrated `owner` / `assignee` / `assignedBy` (no editor `data` blob).
- **Flat FE compatibility fields** (same payload): `id` (= project id), `title` (= project.name), `status` / `themeTokens` / `aspectRatio` / `locale` / `folderId` mirrored from deck/project, plus assignment fields (`assignee`, `assignedBy`, `assignedAt`)
- `deck`: themeTokens, outline, status, aspectRatio, locale, promptBundleVersion, generationMetrics, partial, creditsChargedSoFar, …
- slides: ordered slide rows (`content`, `layoutId`, `imageRef`, **`elements`** freeform canvas doc, status, **`progressStatus`** (`null` \| `TODO` \| `IN_PROGRESS` \| `COMPLETED`), manuallyEdited, …). Each slide also includes helper `title` ← `content.title` and `description` ← `content.bullets` when present.
- `imageRef.status`: `ready` \| `failed` \| `skipped`. On `failed`, `imageRef.error` explains the provider/upload error; slide content can still be `READY`.
- Image URLs in API responses are **presigned** (~1h). Prefer `elements[].content.url` (or `src` alias) for canvas render.
- Element `type`: `text` | `image` | `shape` | `icon` | `chart` | `table` | `embed` | `graphic` | `group`. Groups store `childIds` and children store `groupId`. Optional `locked` is persisted. Shape kinds include `rect`, `rounded-rect`, `circle`, `ellipse`, `pill`, `triangle`, `diamond`, `star`, `line`, `plus`, arrows. Shape `fill` may be a token string or `{ type: "solid"|"gradient", ... }`; optional `stroke` / `strokeWidth`.
- Image/icon `content.flipHorizontal` / `content.flipVertical` (optional) and `placement.rotation` (degrees, images **and** text) are persisted on canvas write and honored on PPTX/PDF/PNG/JPEG export. Live editor rotation snaps every 90°.

Also: `GET .../slides/:slideId` returns a single presigned slide.

**Frontend outcome vs API:** A single mega JSON “final deck” blob is **not** accepted as one POST. Map UI prompt/vibe into outline/theme calls; store/edit via slide + canvas APIs.

---

## Deck preview (My Work / dashboard modal)

Returns the **slide documents the frontend renderer draws** — the same payload the public share link serves. Nothing is rasterized server-side, so the modal is pixel-identical to the editor by construction. Use this for the dashboard click modal and for present/view mode; use full get-by-id only when opening the editor.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/preview` |
| **Auth** | Bearer + member |
| **Query** | `offset` (int ≥ 0, default `0`), `limit` (int 1–**40** (`DECK_SLIDE_MAX`), default `8`) |
| **Cache** | `ETag` + `Cache-Control: private, no-cache` — send `If-None-Match` to get **304** |

**Response `data` (200):**

```json
{
  "id": "<presentationId>",
  "title": "Distributed Team",
  "status": "READY",
  "aspectRatio": "16:9",
  "locale": "en",
  "themeTokens": { },
  "fontCssUrl": "https://fonts.googleapis.com/css2?…",
  "contentUpdatedAt": "2026-09-04T06:58:11.089Z",
  "slideCount": 9,
  "offset": 0,
  "limit": 8,
  "nextOffset": 8,
  "coverStale": true,
  "nextPollMs": 0,
  "slides": [
    {
      "id": "…",
      "order": 0,
      "status": "READY",
      "title": "…",
      "description": ["…"],
      "elements": { "version": 1, "canvas": { "width": 1920, "height": 1080 }, "elements": [] }
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `slideCount` | Total **READY** slides in the deck, not the length of this page |
| `offset` / `limit` | Echo of the page actually served (values are clamped, never rejected mid-read) |
| `nextOffset` | Offset for the next page, or `null` when the deck is fully served |
| `coverStale` | `true` when the dashboard card thumbnail is missing or older than slide 1. Capture and `PUT .../thumbnail/image` only when this is `true` |
| `nextPollMs` | `1500` while `status === "GENERATING"`, otherwise `0`. No polling once READY |
| `fontCssUrl` | Load once before mounting slides so text measures correctly |
| `slides[].elements` | Canvas document for the renderer. Internal storage pointers (`s3Key`, `assetId`) are stripped; image URLs are presigned per request |
| `slides[].speakerNotes` | **Member preview only.** Presenter notes for Present chrome. Key is omitted on `GET /api/p/:token` (guest builder never passes `includeNotes`) |

**Behavior**

- **Pure read.** No snapshot job, no thumbnail write, no background work of any kind.
- Media URLs are presigned **per request** and never cached, so a link cannot be served past its own TTL.
- The unsigned slide page is cached in Redis keyed by content version, so an unchanged deck does not re-read slide rows.
- Re-opening an unchanged deck is a **304** with no body — answered before a single slide row is read.
- **Not** charged (`ppt_export` is only for user-initiated export).

---


## Member Present presence

Workspace members run Present on the same Redis presence room guests already use. Auth is **any workspace member** (`OWNER|ADMIN|MEMBER`) — same mount as other presentation routes. No WebSocket; heartbeat every ~10–15s.

| Method | Path | Notes |
|---|---|---|
| `PUT` | `/api/workspaces/:workspaceId/presentations/:presentationId/presence` | Heartbeat. Body `{ slideIndex, presenting }`. `Cache-Control: no-store` |
| `POST` | `/api/workspaces/:workspaceId/presentations/:presentationId/presence/leave` | Release lock. Body/query `leaveToken` and/or Bearer holder. Optional-auth twin exists for `sendBeacon` |

**Body**

```json
{ "slideIndex": 0, "presenting": true }
```

- `presenting` defaults to `false`. `slideIndex` is `0..DECK_SLIDE_MAX-1` and is clamped to `readySlideCount - 1` on write.
- First writer wins a Redis NX lock (TTL ≈ viewer TTL). Same user keeps the lock and bumps monotonic `seq`.
- Another member → **409** with message matching `PRESENTATION_ALREADY_PRESENTING` and `errors: [{ message, presentingUserId, displayName }]` (identity lives on `errors` because the error envelope has no `data`).
- On NX acquire the response includes `leaveToken` **once**. Store it for `sendBeacon`; later heartbeats do not remint it. Bearer `POST .../leave` still works if the token is lost.
- `presenting: false` from the holder releases the lock (they stay in the viewer zset until leave/TTL).

**Response `data` (200)**

```json
{
  "self": { "displayName": "Alex", "isAnonymous": false },
  "viewerCount": 3,
  "viewers": [],
  "presenter": {
    "slideIndex": 2,
    "displayName": "Alex",
    "seq": 4,
    "updatedAt": "2026-09-14T10:00:00.000Z"
  },
  "leaveToken": "<only on first acquire>"
}
```

`presenter` is `null` when nobody holds the lock. It never includes `userId` or `leaveToken`. Followers apply the cursor only when `seq` is greater than their last applied seq.

Winston: `ppt_present_started` / `ppt_present_ended` (with duration on end) only.
## Deck cover capture

One rendered thumbnail per deck for the My Work card grid, captured by the frontend from the live preview it already has on screen. This is the only image the backend stores for a presentation.

| | |
|---|---|
| **Method** | `PUT` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/thumbnail/image` |
| **Auth** | Bearer + member |
| **Body** | `multipart/form-data`, field `file` — `image/jpeg`, `image/png` or `image/webp`, max **2 MB** |

Send it only when `/preview` reports `coverStale: true`. The server re-encodes to a small JPEG (640×360 for 16:9, aspect-matched otherwise, quality 75, metadata stripped), stores it under `presentations/{workspaceId}/{deckId}/cover-{ts}.jpg`, and points `Project.thumbnail` at the **public** URL.

**Response `data` (200):**

```json
{
  "id": "<presentationId>",
  "skipped": false,
  "thumbnail": "https://…",
  "thumbnailUrl": "https://…",
  "thumbnailUpdatedAt": "2026-09-04T09:59:28.172Z"
}
```

`skipped: true` means a cover for this deck was already accepted within the last 10 seconds and this upload was ignored — treat it as success. Only covers this deck wrote itself are swept from S3; a `thumbnail` pointing at a slide's own image is left alone.

**Distinct from** `PUT .../thumbnail` (JSON), which just points the card at an existing URL or slide.

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
    { "id": "…", "order": 1, "status": "READY", "progressStatus": null, "contentType": "title", "layoutId": "…", "manuallyEdited": false }
  ]
}
```

Deck `status` values include `DRAFT`, `GENERATING`, `READY`, `FAILED` (and similar). Slide statuses: `PENDING`, `GENERATING`, `READY`, `FAILED`.

`status` is a progress poll. It does **not** include per-slide error text. When a slide is `FAILED`, the reason is on `GET .../slides/:slideId` as `imageRef.error` (and on `slide_generation_jobs.error`). A deck can be `READY` with `partial: true` if some slides failed. Whole-deck compiler crashes are also stored on `deck.generationMetrics.error`.

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

### Duplicate presentation

`POST /api/workspaces/:workspaceId/presentations/:presentationId/duplicate` (no body, any workspace member) — clones the project, deck (theme tokens, outline, aspect ratio) and every slide into the same folder as `"<name> (Copy)"`. **201**, same flat shape as create (`id`, `title`, `slides[]`, …).

- **Not copied:** assignees (project and slide), comments, share links, exports, stored cover thumbnail (the library falls back to the first slide).
- Media S3 keys are shared with the source (same as slide duplicate).
- **409** while the source deck is `GENERATING`; **404** if the presentation is not in the workspace.

### Assign slide (TEAM only)

`PATCH /api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/assignee` body `{ "assigneeId": "<member user.id>" | null }` — OWNER/ADMIN only; **400** on PRIVATE workspaces or a non-member assignee. Workflow metadata only (never gates open/edit). Inbox: `SLIDE_ASSIGNED` / `SLIDE_UNASSIGNED`. Response `data.slide` carries hydrated `assignee` / `assignedBy` / `assignedAt`; every other slide-returning route hydrates them too, so the assignee never appears to reset after an unrelated edit. Removing a member from the workspace clears their slide assignments.

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
| `PATCH` | `.../slides/:slideId/elements/batch` — `{ "patches": [{ "id", "placement?", "locked?", "content?" }] }` (one write, no lost-update races) |
| `POST` | `.../slides/:slideId/elements/group` — `{ "elementIds": ["…"] }` (≥2 unlocked, not already grouped) |
| `POST` | `.../slides/:slideId/elements/ungroup` — `{ "elementId": "group_…" }` |
| `POST` | `.../slides/:slideId/elements/align` — `{ "elementIds": ["…"], "alignment": "left\|center\|right\|top\|middle\|bottom" }` |
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
  "manuallyEdited": true,
  "progressStatus": "IN_PROGRESS"
}
```

- **`progressStatus`**: `TODO` \| `IN_PROGRESS` \| `COMPLETED` \| `null` (clear / no status). Editor workflow for reviewers — **not** generation `status`.
- Progress-only PATCH (body is only `progressStatus`) does **not** set `manuallyEdited: true`.
- Allowed while the deck is `GENERATING`.
- Duplicate copies `progressStatus`; AI regenerate **preserves** it.
- Public `/api/p`: included on **reviewer** links only; omitted on viewer links.
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

Exports run as jobs: queue one, then poll it until it finishes. The file is kept for **7 days**; each status request returns a fresh download link that lasts **1 hour**. PNG / JPEG of selected slides can also be drawn in the browser (no job): see [Browser image download](#browser-image-download).

### Queue export

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export` |
| **Status** | **202** |

**Body:**

```json
{
  "format": "PNG",
  "slideIds": ["slide-uuid-2", "slide-uuid-5"],
  "scale": 2,
  "quality": 90,
  "transparent": false,
  "pptxTarget": "powerpoint"
}
```

| Field | Type | Formats | Notes |
|---|---|---|---|
| `format` | `PPTX` \| `PDF` \| `PNG` \| `JPEG` | all | Required. |
| `slideIds` | string[] | all | The slides to export: 1–40 unique ids of this deck, any order (the file keeps deck order). Missing = the whole deck. An unknown id → **404**. |
| `slideId` | string \| null | all | Older clients: one slide. `null` / `""` = the whole deck. `slideIds` is preferred. |
| `scale` | `1` \| `2` \| `3` | PNG, JPEG | Image size: 1× is the canvas size (1920×1080 for 16:9). Default `1`. |
| `quality` | integer 60–100 | JPEG | Default `90`. |
| `transparent` | boolean | PNG | Leave the slide background out. Ignored for JPEG. Default `false`. |
| `pptxTarget` | `powerpoint` \| `google-slides` | PPTX | Who will open the file. `google-slides` turns gradients, glow and hollow text into pictures (Google Slides can't draw them) and doesn't embed fonts (it uses Google Fonts by name). Default `powerpoint`. |

- **PNG / JPEG:** one slide → one image (`<deck>.png`); several → a **ZIP** with one file per slide, named by page number (`1.png`, `3.png`, …).
- The workspace must be able to afford the export fee up front (**402** otherwise). `ppt_export` is charged once, only when the file is saved; cancelled and failed exports cost nothing.

**Response `data`:** `{ exportId, format, status: "QUEUED", estimatedCredits, slideId, slideIds }`

### Get export

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export/:exportId` |
| **Status** | **200** |

Poll every few seconds until the status is final (`READY`, `FAILED`, `CANCELLED`, `EXPIRED`).

| Status | Meaning |
|---|---|
| `QUEUED` | Waiting for a free spot. |
| `RENDERING` | Being drawn and built. |
| `SAVING` | The file is made and is being uploaded; it can no longer be cancelled. |
| `READY` | Done: download fields below. |
| `FAILED` | `error` says why, in words fit for the user. |
| `CANCELLED` | Cancelled; nothing charged. |
| `EXPIRED` | Finished more than 7 days ago; the file has been deleted. Export again. |

**Response `data`:**

```json
{
  "exportId": "…",
  "format": "PPTX",
  "status": "RENDERING",
  "error": null,
  "creditsCharged": null,
  "createdAt": "…",
  "updatedAt": "…",
  "progress": { "stage": "drawing", "percent": 42, "done": 3, "total": 8 }
}
```

- **`progress`** (while `QUEUED`, `RENDERING` or `SAVING`): `stage` is `queued` · `preparing` · `drawing` (per slide) · `building` · `saving` · `done`; `percent` is 0–100. It is `null` when this server can't see the job's progress (rare: an in-process job on another server).
- **When `READY`:** `presignedUrl` (also as `url` and `downloadUrl`), `filename` (from the deck name, e.g. `Q3 Plan.pptx`; a multi-slide image export is `.zip`), `expiresIn` (seconds the link lasts: 3600) and `s3Key`. Ask again for a new link once it has expired.
- **PPTX `report`** (when `READY`): what the file contains, for the export dialog. `null` for exports made before reports existed.

```json
{
  "editable": 54,
  "pictures": [{ "label": "photo filters", "count": 2 }, { "label": "curved text", "count": 1 }],
  "missing": 0,
  "fonts": ["Inter", "Playfair Display"],
  "fontsMissing": [],
  "groups": 3,
  "grownText": 0
}
```

  `editable` = native PowerPoint objects; `pictures` = elements PowerPoint (or Google Slides) can't draw, exported as pictures, by reason; `missing` = media that couldn't be fetched; `fonts` = fonts embedded; `fontsMissing` = fonts that couldn't be embedded (PowerPoint substitutes them); `grownText` = text boxes made taller so their text fits.

Time limits: a job may wait in the queue up to 15 minutes and then runs within a limit that grows with the slide count (2 minutes plus 8–20 s per slide, at most 30 minutes). Past either, it fails with a plain message, and the user is told in the inbox.

### Cancel export

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export/:exportId` |
| **Status** | **200** |

Cancels a `QUEUED` or `RENDERING` export. Nothing is charged and no inbox message is sent. Cancelling an export that is already `CANCELLED` or `FAILED` returns its status again (safe to repeat).

**Response `data`:** `{ exportId, format, status: "CANCELLED", creditsCharged: 0 }`

**409** when the export is `READY` or `SAVING`: it has finished (or is being saved) and will be ready in a moment.

### Browser image download

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export/browser` |
| **Status** | **200** |

The editor can draw PNG / JPEG slides itself (instant, no job). This call charges the same export fee for such a download, once per `downloadId`, so a retried request isn't charged twice.

**Body:** `{ "format": "PNG" | "JPEG", "slideIds": ["…"], "downloadId": "<uuid v4 chosen by the browser>" }`

**Response `data`:** `{ format, slideCount, creditsCharged }`

### Export notifications

When an export finishes after its dialog was closed, the user gets an inbox message (ready, failed or timed out; not cancelled). Its link opens the editor at `/dashboard/editor?workspaceId=…&presentationId=…&export=<exportId>`, which reopens the export dialog on that export.

### Export pipeline (server settings)

Every export uses one pipeline: the editor's own renderer (the frontend's `export-render.html`) draws PDF and images and measures the slides for PPTX, PowerPoint files embed the deck's fonts, and jobs run on the queue. If the render page can't be reached, the export still completes with the server's own renderer (a plainer drawing) and logs `export_renderer_unavailable` or, for PPTX, `pptx_renderer_capture_failed`; the finished log line then has `rendererVersion: "legacy"`. `GET /health/export` reports the queue, browser and last-hour metrics. All export settings: [`ENVIRONMENT.md`](ENVIRONMENT.md).

---

## Share links (viewer + reviewer)

Canva-style preview links. Each presentation may have up to **two independent capability URLs**:

| Link | Public capability |
|---|---|
| **Viewer** | Page through the deck + unified presence — **no comments** |
| **Reviewer** | Same as viewer **+ read/post/edit own comments** (guest or logged-in outsider) |

Neither link can edit slides — only the workspace editor can mutate the deck. Owner management lives under the presentation; viewers use the unauthenticated **`/api/p`** surface documented below.

Public resolve looks up a **SHA-256 hash** of the token. The raw token is also stored so **workspace members can reopen the share modal and copy the same URL any time**. Only owner share APIs return `token` / `url`; public `/api/p` never echoes them.

Each link type is **enabled independently** (viewer only, reviewer only, both, or neither). No row/token exists until the owner first enables that type. There is **no expiry** — a link works until disabled or rotated.

Comment contracts: [PRESENTATION_COMMENTS_API.md](PRESENTATION_COMMENTS_API.md).

### Get share links

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share` |
| **Auth** | Bearer + member |

**Response `data`:**

```json
{
  "viewer": {
    "exists": true,
    "enabled": true,
    "role": "VIEWER",
    "token": "8Kd…",
    "url": "https://app.example.com/p/8Kd…",
    "rotateCount": 0,
    "createdBy": "<uuid>",
    "createdAt": "2026-08-20T09:00:00.000Z",
    "updatedAt": "2026-08-20T09:00:00.000Z"
  },
  "reviewer": {
    "exists": false
  }
}
```

When a link type was never minted: `{ "exists": false }`. Legacy rows created before token persistence may omit `token` / `url` — call **rotate** once for that role to mint a recoverable link.

### Enable share link (per role)

| | |
|---|---|
| **Method** | `PUT` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share/viewer` or `…/share/reviewer` |
| **Auth** | Bearer + member |

Idempotent. Mints a token on **first** enable for that role; on an existing link it re-enables without minting.

**Response `data` (first create):**

```json
{
  "link": {
    "exists": true,
    "enabled": true,
    "role": "REVIEWER",
    "token": "8Kd…",
    "url": "https://app.example.com/p/8Kd…",
    "rotateCount": 0,
    "createdBy": "<uuid>",
    "createdAt": "2026-08-20T09:00:00.000Z",
    "updatedAt": "2026-08-20T09:00:00.000Z"
  },
  "token": "8Kd…",
  "url": "https://app.example.com/p/8Kd…"
}
```

Top-level `token` / `url` are also present on first create (and on rotate) for convenience. On an already-enabled link they appear only inside `link`.

**409** if the deck is `GENERATING` (`PRESENTATION_ALREADY_GENERATING`).

### Update share link (per role)

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share/viewer` or `…/share/reviewer` |
| **Auth** | Bearer + member |

**Body:**

```json
{ "enabled": false }
```

- Disabling keeps the same token (so a previously shared URL works again after re-enable). `link.url` remains copyable while disabled; public `/api/p` still 404s until re-enabled. **Presence is not cleared** when one link is disabled — viewer and reviewer URLs share one room per presentation.
- Re-enabling while the deck is `GENERATING` → **409**.
- **404** if that link type was never minted.

### Rotate share link (per role)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/share/viewer/rotate` or `…/share/reviewer/rotate` |
| **Auth** | Bearer + member |

Mints a new token for that role and **invalidates every URL already shared for that link**. Returns `token` + `url` (top-level and inside `link`). Sets `enabled: true`. Allowed even while the deck is `GENERATING`, so a leaked link can always be killed. Rotating one link does not affect the other link's URL or the unified presence room.

**404** if that link type was never minted.

---

## Public preview API (`/api/p`)

Unauthenticated. `Authorization: Bearer <access_token>` is **optional** — send it when present so the viewer appears by name instead of `Anonymous viewer`. An invalid or expired Bearer token never causes a 401 here; it is simply treated as a guest.

Unknown and disabled tokens all return an identical **404** (`Share link not found`) so the endpoint cannot be used to discover presentations.

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
    { "id": "…", "order": 0, "status": "READY", "progressStatus": "IN_PROGRESS", "title": "…", "description": ["…"], "elements": { } }
  ]
}
```

- **Only `READY` slides are included.** During a regeneration the call still returns **200** with `status: "GENERATING"` and whatever slides survive, so the UI can show "Updating…" instead of an error.
- Image URLs are freshly presigned per request, including per-element images on multi-image slides.
- Editor-only data is stripped: outline, generation metrics, credits, prompt bundle version, folder, workspace, owner, jobs, and internal S3 keys. Comments are **not** inlined here — they have their own uncached endpoint so this payload stays ETag-stable.
- **`progressStatus`** appears on slides **only for reviewer links** (`null` = no status). Viewer links omit the key entirely.
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
  "linkRole": "reviewer",
  "permission": "review",
  "canComment": true,
  "canResolveComments": true,
  "canOpenInEditor": true,
  "workspaceId": "<uuid>",
  "presentationId": "<uuid>"
}
```

`canOpenInEditor` is true only when the caller is a member of the owning workspace; `workspaceId` / `presentationId` appear only in that case, so the UI can offer "Open in editor".

`linkRole` is `"viewer"` or `"reviewer"` depending on which token was used. `permission` is `"review"` on reviewer links and `"view"` on viewer links — neither permits editing slides. Gate the comment composer on **`canComment`**, and the resolve control on **`canResolveComments`** (members only). A workspace member on a **viewer** link still gets `canOpenInEditor: true` but `canComment: false`. See [PRESENTATION_COMMENTS_API.md](PRESENTATION_COMMENTS_API.md).

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
  "contentUpdatedAt": "2026-08-20T08:59:12.000Z",
  "commentsUpdatedAt": "2026-08-20T09:00:01.000Z"
}
```

- Heartbeat about every **15s**; a viewer is dropped after **45s** of silence.
- Logged-in viewers collapse across tabs (keyed by user); guests are keyed by `viewerSessionId`.
- `viewerCount` is the full room size. `viewers` is capped at the **50 most recently active** — a display cap only, nobody is turned away, so render "+N more" from `viewerCount - viewers.length`.
- Refetch the deck only when `contentUpdatedAt` changes, and the comment list only when `commentsUpdatedAt` changes (`null` until the first comment).

### List / leave presence

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/p/:token/presence` | Same payload without recording a heartbeat |
| `DELETE` | `/api/p/:token/presence?viewerSessionId=…` | Explicit leave; the TTL covers missed calls |
| `POST` | `/api/p/:token/presence/leave?viewerSessionId=…` | `sendBeacon`-friendly alias for DELETE (same query) |

### Rate limits

**429** with a `Retry-After` header.

| Endpoint | Default |
|---|---|
| `GET /api/p/:token` | 60/min per IP, 300/min per link |
| Presence + session | 120/min per IP |
| Comment reads | 120/min per IP |
| Comment writes | 20/min per IP, 60/min per link |

Configurable — see [ENVIRONMENT.md](ENVIRONMENT.md).

---

## Notes

- Presentation routes are nested under workspaces (same pattern as projects/folders).
- Credits are **presentation-specific feature keys** but use the **workspace** credit ledger (`SCOPE.WORKSPACE`).
- Offline structural checks: `npm run eval:presentation` (see `scripts/presentation-eval/`).
- Share links never allow editing and are free (no credit charge). Presence and comments are polled over HTTP; there is no WebSocket/SSE channel. Viewer and reviewer URLs share one presence room per presentation.
- Share-link visitors may comment only on **reviewer** links — see [PRESENTATION_COMMENTS_API.md](PRESENTATION_COMMENTS_API.md).
- Deferred (not this API surface): password-protected links, frozen publish snapshots, brand kits, server version history, studio isolation.

---

**[← API index](README.md)** · [Environment](ENVIRONMENT.md) · [Credits API](CREDITS_API.md)
