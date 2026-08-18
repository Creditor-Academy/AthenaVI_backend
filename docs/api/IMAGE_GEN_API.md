# Image Gen API

Base path: **`/api/image-gen`**

OpenAI-only workspace image studio: general images, infographics, and social creatives (LinkedIn, Instagram, Facebook, X, YouTube). Results are saved as workspace **Assets** (`source: "ai_gen"`) and downloadable as PNG / JPG / JPEG / PDF.

**Auth:** `Authorization: Bearer <access_token>` on all routes.  
**Workspace routes:** `checkWorkspaceAccess` (PRIVATE = owner; TEAM = any member).

**Credits:** charged **on success only** from the workspace billing pool (PRIVATE → owner personal; TEAM → workspace). Insufficient → **402**. Downloads are free. Rate limits → **429**.

---

## Catalogs

### Models

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/models` |

**Response (200)** – `data.models[]`: `id`, `name`, `description`, `modes`, `recommended`, `recommendedForModes`, `supportsEdit`, `creditEstimate`.

| `id` | OpenAI | Notes |
|------|--------|--------|
| `gpt-image-1` | `gpt-image-1` medium | Default for `image` / `social` |
| `gpt-image-1-hd` | `gpt-image-1` high | **Default for `infographic`** when `modelId` is omitted. `recommendedForModes: ["infographic"]` |
| `dall-e-3` | `gpt-image-1` high | Compatibility alias (OpenAI retired DALL·E 3); image/social only |

### Formats

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/formats` |

**Response (200)** – `data.formats[]`: `id`, `name`, `category` (`generic`|`social`), `width`, `height`, `safeZone`, `overlayInsets`, `overlayAlign`, `recommendedTextMode`.

Social ids include: `linkedin_banner`, `linkedin_post`, `instagram_post`, `instagram_story`, `instagram_landscape`, `facebook_post`, `facebook_cover`, `x_post`, `x_header`, `youtube_thumbnail`. Generic: `square`, `landscape`, `portrait` (`overlayInsets` / `overlayAlign` / `recommendedTextMode` are `null`).

Social overlay fields (fractions of cropped WxH):

| Format | `overlayAlign` | `recommendedTextMode` |
|--------|----------------|------------------------|
| Most posts / landscape / YouTube | `center` | `overlay` except `youtube_thumbnail` → `baked` |
| `linkedin_banner` | `center-right` (left inset 0.25 for profile overlap) | `overlay` |
| `instagram_story` | `middle` | `overlay` |
| `facebook_cover` | `center` | `overlay` |
| `x_header` | `center` (larger bottom inset for avatar) | `overlay` |

### Styles

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/styles` |

**Response (200)** – `data.styles[]`: `id`, `name` (vibe presets).

---

## Credit estimate

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/estimate` |
| **Query** | `modelId`, `mode` (`image`\|`infographic`\|`social`), `tweak` (`true`/`false`) |

When `mode=infographic` and `modelId` is omitted, the estimate uses **`gpt-image-1-hd`** (default **14 AC** = 12 + 2 surcharge). Explicit `modelId=gpt-image-1` remains **8 AC**.

**Response (200)** – `data`: `{ athenaCredits, breakdown }`.

---

## Context bundles

Upload documents / reference images (or reference workspace assets) **before** generate. Context create is **free** (rate-limited). Generate/regenerate charge as usual.

### Create context

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/context` |
| **Status** | **201** |
| **Content-Type** | `multipart/form-data` |

| Part | Rules |
|------|--------|
| `files` | 0–N files (field name `files`). Max **5** combined with `assetIds`. Max **20 MB** each. |
| `payload` | JSON string: `{ "inlineText"?: string, "assetIds"?: uuid[] }` |

**Allowed types:** PDF, DOCX, MD, TXT, PNG, JPG, JPEG, WebP.  
**Validation:** at least one of `files`, `assetIds`, `inlineText`. `assetIds` must be **image** assets in the workspace.

**Response `data.context`:**

```json
{
  "id": "uuid",
  "status": "READY",
  "expiresAt": "ISO",
  "pinnedAt": null,
  "createdAt": "ISO",
  "previews": {
    "inlineText": "...",
    "documents": [{ "name": "brief.pdf", "excerpt": "...", "truncated": false }],
    "images": [{ "name": "ref.png", "summary": "..." }],
    "assetRefs": [{ "assetId": "...", "name": "...", "role": "reference_image" }]
  },
  "warnings": []
}
```

### Get context

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/context/:contextId` |

Same preview shape. **404** if missing, expired (and unpinned), or PRIVATE workspace mismatch.

### Delete context

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/context/:contextId` |
| **Status** | **200** |

**409** if context is pinned (already used by a generation). Only deletes uploaded S3 keys (never workspace Asset keys).

---

## Generate

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generate` |
| **Status** | **201** (synchronous — allow a long client timeout; infographic can exceed 90s because of planner + optional quality edit) |

**Body**

```json
{
  "mode": "image",
  "modelId": "gpt-image-1",
  "formatId": "instagram_post",
  "style": "cinematic",
  "prompt": "Product launch visual for Athena VI",
  "headline": "Create faster",
  "subheadline": "AI instructor studio",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "textMode": "overlay",
  "infographic": {
    "layout": "process",
    "title": "Onboarding",
    "sections": [{ "title": "Sign up", "bullets": ["Email", "Verify"] }]
  },
  "name": "launch.png",
  "contextId": "optional-context-uuid"
}
```

| Field | Rules |
|-------|--------|
| `mode` | `image` \| `infographic` \| `social` (default `image`) |
| `modelId` | Optional. Default **`gpt-image-1`** for image/social; default **`gpt-image-1-hd`** for infographic. Explicit values always win. |
| `formatId` | **Required** for `social`. Optional aspect for `image` (`square`/`landscape`/`portrait`). Infographic default **`landscape`** (1536×1024) when omitted. |
| `prompt` | Required unless `infographic.sections` is provided, or `mode=social` with `headline` and/or `subheadline`. Max **16,000** chars. For social, put **visible copy** in `headline` / `subheadline` — `prompt` is the visual brief only. |
| `headline` / `subheadline` | Social on-canvas copy (max 200 / 300). Overlay typesets these after crop. |
| `textMode` | Social only: `overlay` \| `baked`. **Do not rely on a Joi default** — omitted social requests use **`overlay`** in the service. Catalog `recommendedTextMode` is `baked` only for `youtube_thumbnail` (client should opt in). |
| `infographic` | Optional structured form. `title` max 200; up to **24** sections; section `title` 200; `content` max **8,000**; up to **20** bullets × **1,000** chars. |
| `style` / `styleId` | Optional vibe from `/styles`. Infographic mode ignores photoreal/cinematic/watercolor/3d/neon suffixes (flat-vector craft is always applied). |
| `name` | Optional display filename. If omitted, derived from the prompt (kebab-case, e.g. `cute-coffee-cup-emoji.png`). S3 keys stay UUID-based. |
| `contextId` | Optional. Uses document text + vision summaries in the prompt; reference images go through `images.edit` |

**Infographic pipeline (server):** plans layout/copy with a chat model, typesets via `gpt-image-1`, contain-crops (does not cover-clip steps), vision-QA against the planned labels, and if text/numbering is broken runs **one in-place image edit included in the original charge** (no extra AC). User-initiated Tweak / Regenerate still charge as usual.

**Response `data`:** `{ generation, asset, creditsCharged, downloadFormats: ["png","jpg","jpeg","pdf"] }`.

`generation` includes `contextId` and `contextPreview` when context was used. A snapshot is stored in `generation.request.contextSnapshot` for regenerate.

Infographic generations also include `generation.infographicQuality` (same object on `generation.request.infographicQuality`):

```json
{
  "passed": false,
  "retried": true,
  "issues": ["step 03 missing"],
  "suggestedTweak": "Restore badge 03 and the heading Pickup Scheduled."
}
```

Show a non-blocking “review text” banner when `passed === false`. `suggestedTweak` may prefill the Tweak modal (Tweak still bills — the free fix already ran).

**Social pipeline (server):** default **`textMode: overlay`** — the image model is instructed not to paint letters; after **cover-crop** the server Sharp/SVG-typesets `headline` / `subheadline` inside `overlayInsets`. If vision still sees letters, **one in-place wipe is included** (no extra AC), then overlay always runs. Empty headline/subheadline → background only (`socialOverlay.composited: false`). Opt-in **`textMode: baked`** quotes the headline into the model (YouTube-style huge type), then vision-QA (exact spelling, cutoff, sequence) with **one free edit**. Overlay, wipe, and baked retry are **not** extra AC. Tweak does **not** re-run overlay — change copy via Regenerate.

Social generate/regenerate also include:

`generation.socialOverlay` (overlay path; also on `generation.request.socialOverlay`):

```json
{
  "textMode": "overlay",
  "headline": "Create faster",
  "subheadline": "AI instructor studio",
  "insets": { "top": 0.1, "right": 0.1, "bottom": 0.1, "left": 0.1 },
  "align": "center",
  "composited": true
}
```

`generation.socialQuality` (baked path only; same object on `generation.request.socialQuality`):

```json
{
  "passed": false,
  "retried": true,
  "issues": ["headline misspelled"],
  "suggestedTweak": "Restore the exact headline Ship courses 10x faster."
}
```

`generation.request.textMode` is stored for regenerate inherit.

Master file is always **PNG** on S3.

---

## List / get generations

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations` |
| **Query** | `take` (1–100), `skip`, `mode` (`image` \| `infographic` \| `social`) |

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId` |

PRIVATE workspaces only return the current user’s generations.

---

## Regenerate

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/regenerate` |
| **Status** | **201** |

Body fields optional — omitted fields reuse the parent generation’s request (including `contextId` and `textMode`). Creates a new generation + asset (`action: "regenerate"`), linked via `parentId` / `rootId`. Charges again.

If the live context expired, regenerate still applies **text** context from `request.contextSnapshot` (visual reference images require a live/pinned context).

---

## Tweak

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/tweak` |
| **Status** | **201** |

```json
{ "instruction": "Make the background darker and move the logo left" }
```

Uses OpenAI **image edit** on the parent PNG. Charges model AC (no mode surcharge). Context bundles are **not** applied on tweak (v1). `instruction` max **4,000** chars. Social overlay is **not** re-applied — change copy via Regenerate.

---

## Download

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/download` |
| **Query** | `format=png` \| `jpg` \| `jpeg` \| `pdf` (default **png**) |

Returns file attachment (`Content-Disposition: attachment`). Filename is `asset.name` (prompt-derived kebab-case unless the client sent `name`). **No credit charge.**

| format | Content-Type |
|--------|----------------|
| `png` | `image/png` |
| `jpg` / `jpeg` | `image/jpeg` |
| `pdf` | `application/pdf` (single page) |

---

## Credits (defaults)

| Feature | Default AC | Env override |
|---------|------------|--------------|
| `image_gen_gpt_image` | 6 | `IMAGE_GEN_GPT_IMAGE_AC` |
| `image_gen_gpt_image_hd` | 12 | `IMAGE_GEN_GPT_IMAGE_HD_AC` |
| `image_gen_dall_e_3` | 12 | `IMAGE_GEN_DALL_E_3_AC` (alias → same quality as HD) |
| Infographic surcharge | +2 | `IMAGE_GEN_INFOGRAPHIC_SURCHARGE_AC` |
| Social surcharge | +1 | `IMAGE_GEN_SOCIAL_SURCHARGE_AC` |

Infographic **default** (HD + landscape, `modelId` omitted): **14 AC**. Explicit medium (`gpt-image-1`): **8 AC**. The silent quality edit after a broken first image is **not** a second charge. Social overlay, hasText wipe, and baked silent edit are also **not** extra AC (social surcharge +1 still applies to generate/regenerate).

Context create is **free**. Rate limits: `IMAGE_GEN_RATE_LIMIT_MAX` / `IMAGE_GEN_RATE_LIMIT_WINDOW_SEC`, `IMAGE_GEN_REGENERATE_RATE_LIMIT_MAX` / `IMAGE_GEN_REGENERATE_RATE_LIMIT_WINDOW_SEC`, `IMAGE_GEN_CONTEXT_RATE_LIMIT_MAX` / `IMAGE_GEN_CONTEXT_RATE_LIMIT_WINDOW_SEC`. Silent infographic QA edits and social overlay wipe / baked QA edits do **not** increment regenerate rate-limit counters.

Requires **`OPENAI_API_KEY`**.

---

## Assets library

AI outputs appear in `GET /api/assets/:workspaceId?source=ai_gen` with `stockMetadata.generationId` for linking back to studio history.

---

**[← API index](README.md)** · Frontend: [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](../IMAGE_GEN_FRONTEND_INTEGRATION.md)
