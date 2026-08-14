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

**Response (200)** – `data.models[]`: `id`, `name`, `description`, `modes`, `recommended`, `supportsEdit`, `creditEstimate`.

| `id` | OpenAI | Notes |
|------|--------|--------|
| `gpt-image-1` | `gpt-image-1` medium | Default |
| `gpt-image-1-hd` | `gpt-image-1` high | HD |
| `dall-e-3` | `gpt-image-1` high | Compatibility alias (OpenAI retired DALL·E 3); image/social only |

### Formats

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/formats` |

**Response (200)** – `data.formats[]`: `id`, `name`, `category` (`generic`|`social`), `width`, `height`, `safeZone`.

Social ids include: `linkedin_banner`, `linkedin_post`, `instagram_post`, `instagram_story`, `instagram_landscape`, `facebook_post`, `facebook_cover`, `x_post`, `x_header`, `youtube_thumbnail`. Generic: `square`, `landscape`, `portrait`.

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
| **Status** | **201** (synchronous — allow long client timeout) |

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
| `formatId` | **Required** for `social`. Optional aspect for `image` (`square`/`landscape`/`portrait`). |
| `prompt` | Required unless `infographic.sections` provided. Max **16,000** chars (image, infographic, and social). Use this for the full brief — audience, story, labels, panel copy. |
| `infographic` | Optional structured form. `title` max 200; up to **12** sections; section `title` 200; `content` max **8,000**; up to **20** bullets × **1,000** chars. |
| `style` / `styleId` | Optional vibe from `/styles` |
| `name` | Optional display filename. If omitted, derived from the prompt (kebab-case, e.g. `cute-coffee-cup-emoji.png`). S3 keys stay UUID-based. |
| `contextId` | Optional. Uses document text + vision summaries in the prompt; reference images go through `images.edit` |

**Response `data`:** `{ generation, asset, creditsCharged, downloadFormats: ["png","jpg","jpeg","pdf"] }`.

`generation` includes `contextId` and `contextPreview` when context was used. A snapshot is stored in `generation.request.contextSnapshot` for regenerate.

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

Body fields optional — omitted fields reuse the parent generation’s request (including `contextId`). Creates a new generation + asset (`action: "regenerate"`), linked via `parentId` / `rootId`. Charges again.

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

Uses OpenAI **image edit** on the parent PNG. Charges model AC (no mode surcharge). Context bundles are **not** applied on tweak (v1). `instruction` max **4,000** chars.

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

Context create is **free**. Rate limits: `IMAGE_GEN_RATE_LIMIT_MAX` / `IMAGE_GEN_RATE_LIMIT_WINDOW_SEC`, `IMAGE_GEN_REGENERATE_RATE_LIMIT_MAX` / `IMAGE_GEN_REGENERATE_RATE_LIMIT_WINDOW_SEC`, `IMAGE_GEN_CONTEXT_RATE_LIMIT_MAX` / `IMAGE_GEN_CONTEXT_RATE_LIMIT_WINDOW_SEC`.

Requires **`OPENAI_API_KEY`**.

---

## Assets library

AI outputs appear in `GET /api/assets/:workspaceId?source=ai_gen` with `stockMetadata.generationId` for linking back to studio history.

---

**[← API index](README.md)** · Frontend: [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](../IMAGE_GEN_FRONTEND_INTEGRATION.md)
