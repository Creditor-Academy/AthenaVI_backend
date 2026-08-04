# Presentation (AI PPT) API

> **Frontend credits:** [`docs/PRESENTATION_CREDITS_FRONTEND.md`](../PRESENTATION_CREDITS_FRONTEND.md)  
> **Prompt bundle:** [`docs/PRESENTATION_PROMPTS.md`](../PRESENTATION_PROMPTS.md)  
> **Eval:** `npm run eval:presentation`

Base path: **`/api/workspaces/:workspaceId/presentations`**

Creates a **`Project`** with **`type: PRESENTATION`** (not video). Deck/slides live in related tables (`decks`, `slides`, `deck_exports`). Billing uses presentation-specific features (`ppt_*`) via `presentationCreditPricing.js` — separate from HeyGen/Remotion rates, but charged against the same workspace credit pool.

---

## Auth & roles

| | |
|---|---|
| **Auth** | `Authorization: Bearer <access_token>` |
| **Role** | Workspace **OWNER**, **ADMIN**, or **MEMBER** (`requireWorkspaceRole`) |

Envelope: [OVERVIEW.md](OVERVIEW.md) — `{ success, message, data }` / `{ success, false, message, errors }`.

Insufficient credits → **402**. Rate limits on generate/regenerate may return **429**.

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
| `GET` | `/api/workspaces/:workspaceId/presentation-templates?contentType=` | Active `DECK_LAYOUT` templates |
| `GET` | `/api/workspaces/:workspaceId/presentation-deck-packs` | Active `DECK_PACK` multi-slide packs |
| `GET` | `/api/workspaces/:workspaceId/presentation-themes` | Curated theme catalog |
| `GET` | `/api/workspaces/:workspaceId/presentation-elements` | Element library presets for the canvas palette |
| `GET` | `/api/workspaces/:workspaceId/brand-kits` | Workspace Brand Kits (see [BRAND_KIT_API.md](BRAND_KIT_API.md)) |

### Seeded deck packs

`npm run seed:presentation-deck-packs` installs 9 system packs (**schemaVersion 2**). Each pack carries `themeId`,
`meta`, `narrative`, per-slide `intent` / `designTokens` / `generationHints`, designed placeholders,
and `generationDefaults` (`layoutWhitelist`, `slideOrder: fixed`, `contentDistribution`).

Visual slides may include `placeholder.imagePrompt`. Seed also acquires **durable system photos** into
`TemplateMedia` (stock-once → S3). **Pack clone** fills image element URLs from that media (no empty frames).
List packs includes `previewImageUrl` + `media[]` (presigned). AI image brief prefers
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

## Notes

- Presentation routes are nested under workspaces (same pattern as projects/folders).
- Credits are **presentation-specific feature keys** but use the **workspace** credit ledger (`SCOPE.WORKSPACE`).
- Offline structural checks: `npm run eval:presentation` (see `scripts/presentation-eval/`).
- Deferred (not this API surface): share links, brand kits, server version history, studio isolation.

---

**[← API index](README.md)** · [Environment](ENVIRONMENT.md) · [Credits API](CREDITS_API.md)
