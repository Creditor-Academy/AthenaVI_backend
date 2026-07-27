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
  "title": "My deck",
  "folderId": "<uuid>",
  "themeId": "midnight_blue",
  "themeTokens": null,
  "locale": "en",
  "aspectRatio": "16:9"
}
```

- Provide **`title`** and/or **`name`** (at least one required).
- **`folderId`** required (must belong to workspace).
- **`themeId`** and/or **`themeTokens`** optional; tokens resolved from catalog when `themeId` is set.
- **`aspectRatio`**: only `16:9` today.

**Response `data`:** `{ project, deck }` — `project.type` is `PRESENTATION`; `presentationId` for subsequent routes is the **project id**.

---

## Get presentation

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId` |
| **Status** | **200** |

**Response `data`:** `{ project, deck, slides }`

- `deck`: themeTokens, outline, status, aspectRatio, locale, promptBundleVersion, generationMetrics, partial, creditsChargedSoFar, …
- `slides`: ordered slide rows (content, layoutId, imageRef, status, manuallyEdited, …)

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

No LLM charge for manual patch.

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
  "overwriteManualEdits": true
}
```

- `target`: `content` \| `image` \| `all` (default `all`)
- Manual edits blocked unless `overwriteManualEdits` is true (**409**)

Subject to regenerate rate limits. Charges on success for regenerated pieces.

---

## Export

### Queue export

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export` |
| **Status** | **202** |

**Body:** `{ "format": "PPTX" }` or `"PDF"`

**Response `data`:** `{ exportId, format, status: "QUEUED", estimatedCredits }`

Charges **`ppt_export`** on successful export.

### Get export

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/presentations/:presentationId/export/:exportId` |
| **Status** | **200** |

Poll until `READY` / `FAILED`. Ready responses include download metadata (presigned URL / S3 key as implemented).

Export statuses: `QUEUED`, `PROCESSING`, `READY`, `FAILED`.

---

## Notes

- Presentation routes are nested under workspaces (same pattern as projects/folders).
- Credits are **presentation-specific feature keys** but use the **workspace** credit ledger (`SCOPE.WORKSPACE`).
- Offline structural checks: `npm run eval:presentation` (see `scripts/presentation-eval/`).

---

**[← API index](README.md)** · [Environment](ENVIRONMENT.md) · [Credits API](CREDITS_API.md)
