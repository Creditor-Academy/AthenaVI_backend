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
  "templateId": null
}
```

- **`title`** / **`name`** optional. If omitted, project is created as **`Untitled Presentation`** (AI flow fills a real title on outline).
- **`folderId`** required (must belong to workspace).
- **`themeId`** and/or **`themeTokens`** optional; tokens resolved from catalog when `themeId` is set.
- **`aspectRatio`**: only `16:9` today.
- **`createMode`**: `blank` (default, zero slides) | `template` (requires active `DECK_LAYOUT` **`templateId`**; creates one READY slide with freeform `elements`).
- AI path: create blank (no title needed) → outline (generates title) → theme → generate.

**Response `data`:** `{ project, deck, slides }` — `project.type` is `PRESENTATION`; `presentationId` for subsequent routes is the **project id**.

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
| `GET` | `/api/workspaces/:workspaceId/presentation-themes` | Curated theme catalog |
| `GET` | `/api/workspaces/:workspaceId/presentation-elements` | Element library presets for the canvas palette |

---

## Get presentation

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId` |
| **Status** | **200** |

**Response `data`:** `{ project, deck, slides }`

- `deck`: themeTokens, outline, status, aspectRatio, locale, promptBundleVersion, generationMetrics, partial, creditsChargedSoFar, …
- slides: ordered slide rows (`content`, `layoutId`, `imageRef`, **`elements`** freeform canvas doc, status, manuallyEdited, …)
- `imageRef.status`: `ready` \| `failed` \| `skipped`. On `failed`, `imageRef.error` explains the provider/upload error; slide content can still be `READY`.
- Image URLs in API responses are **presigned** (~1h). Prefer `elements[].content.url` for canvas render.

### Freeform canvas shape (`slide.elements`)

```json
{
  "version": 1,
  "canvas": { "width": 1920, "height": 1080 },
  "elements": [
    {
      "id": "el_…",
      "type": "text",
      "layer": 1,
      "placement": { "x": 100, "y": 200, "width": 800, "height": 120, "rotation": 0, "opacity": 1 },
      "content": { "text": "Hello", "fontSize": 42, "bold": true },
      "role": "title"
    }
  ]
}
```

Element `type`: `text` | `image` | `shape` | `icon` | `chart` | `table`. Drag/snap are frontend-only; backend stores absolute geometry.

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

## Generate deck

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/generate` |
| **Status** | **202** |

**Body (optional):**

```json
{
  "density": "balanced",
  "overwriteManualEdits": false,
  "requestHash": "optional-idempotency-hint"
}
```

Starts async slide generation. Poll **status**. Pre-checks affordability; charges per slide/image **on success** (`ppt_slide_content`, `ppt_image_path_a` / `ppt_image_path_b`, cache hits free).

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
| `POST` | `.../slides/:slideId/elements` — `{ presetId }` and/or `{ element }` |
| `PATCH` | `.../slides/:slideId/elements/:elementId` |
| `DELETE` | `.../slides/:slideId/elements/:elementId` |
| `PATCH` | `.../slides/:slideId/elements/reorder` — `{ "elementIds": [] }` |

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
