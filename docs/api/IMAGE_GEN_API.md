# Image Gen API

Base path: **`/api/image-gen`**

**Internal complete guide + Infographics research:** [`docs/IMAGE_GEN_COMPLETE.md`](../IMAGE_GEN_COMPLETE.md).  
**Infographic PRD:** [`docs/INFOGRAPHIC_MODE_PRD.md`](../INFOGRAPHIC_MODE_PRD.md).

Workspace image studio for **general images**, **infographics**, and **social media posts**, backed by **OpenAI** and **Google Gemini** models. Results are saved as workspace **Assets** (`source: "ai_gen"`) and downloadable as PNG / JPG / JPEG / PDF.

**Auth:** `Authorization: Bearer <access_token>` on all routes.  
**Workspace routes:** `checkWorkspaceAccess` (PRIVATE = owner; TEAM = any member).

**Credits:** charged **on success only** from the workspace billing pool (PRIVATE → owner personal; TEAM → workspace). Insufficient → **402**. Opening a saved chat, viewing, and downloads are free. Rate limits → **429**. Infographic pricing uses feature `image_gen_infographic` and social pricing uses `image_gen_social`. Both charge the selected model's AC until the margin pass; override with `IMAGE_GEN_INFOGRAPHIC_AC` / `IMAGE_GEN_SOCIAL_AC`.

**Modes:** `image` | `infographic` | `social`.  
- `image` (Mode 1): general scenes. Default format `square`, default model `gpt-image-1-hd` (OpenAI, **Recommended**), crop `cover`.  
- `infographic` (Mode 2): spec-first typesetting. Default format `landscape`, default model `gemini-3-pro-image`, crop `contain`.  
- `social` (Mode 3): one post for one destination (see [Social destinations](#social-destinations)). `formatId` is **required**. Default model `gemini-3-pro-image`, crop `cover` to the exact destination pixels.

Thread mode is **sticky**: chat and tweak stay on the head's mode. A social thread also stays on its destination.

**Chats:** each successful generate creates a folder-scoped **thread**. Folder cards support View / Download / Open chat. Threads expose `mode`, `archetype`, and `platform` for badges.

**Client timeout:** allow **~120s** for `mode=infographic` and `mode=social` (spec LLM + image). Image mode remains ~30–90s.

---

## Catalogs

### Models

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/models` |

**Response (200)** – `data`:

```json
{
  "models": [{ "id": "gpt-image-1-hd", "name": "…", "provider": "openai", "quality": "high", "modes": ["image", "infographic", "social"], "recommended": true, "supportsEdit": true, "maxImageSize": null, "creditEstimate": { } }],
  "providers": [
    { "id": "openai", "name": "OpenAI", "defaultModelId": "gpt-image-1-hd", "modelIds": ["gpt-image-1-hd", "gpt-image-1", "dall-e-3"] },
    { "id": "gemini", "name": "Gemini", "defaultModelId": "gemini-3-pro-image", "modelIds": ["gemini-3-pro-image", "gemini-3.1-flash-image", "gemini-3.1-flash-lite-image"] }
  ],
  "defaults": {
    "image": { "provider": "openai", "modelId": "gpt-image-1-hd", "recommendedProvider": "openai" },
    "infographic": { "provider": "gemini", "modelId": "gemini-3-pro-image", "recommendedProvider": null },
    "social": { "provider": "gemini", "modelId": "gemini-3-pro-image", "recommendedProvider": null }
  },
  "defaultProviderModel": { "openai": "gpt-image-1-hd", "gemini": "gemini-3-pro-image" }
}
```

**Picker flow:** show the two `providers`. Clicking one lists its three `modelIds` in order (high quality first). Preselect `defaults[mode]`. Show a **Recommended** badge on the provider in `defaults[mode].recommendedProvider` (OpenAI for Mode 1 only). When the user switches provider, select that provider's `defaultModelId`. When `modelId` is omitted on generate, the server uses `defaults[mode].modelId`.

Every model supports all three modes and **edits** (tweak / chat pixel edits stay on the parent's provider).

| `id` | Provider | AC | Notes |
|------|----------|----|-------|
| `gpt-image-1-hd` | openai | 12 | High quality. Default for `image` (Recommended) |
| `gpt-image-1` | openai | 6 | Standard |
| `dall-e-3` | openai | 12 | Compat alias → gpt-image-1 high |
| `gemini-3-pro-image` | gemini | 12 | Nano Banana Pro — best in-image text; up to 4K. Default for `infographic` and `social` |
| `gemini-3.1-flash-image` | gemini | 8 | Nano Banana 2 — balanced; up to 4K |
| `gemini-3.1-flash-lite-image` | gemini | 4 | Nano Banana 2 Lite — **1K only**, draft quality; weaker with multiple reference images |

Gemini models require **`GEMINI_API_KEY`**; without it those ids return **503**. `OPENAI_API_KEY` is still required regardless, because moderation and the infographic spec LLM run on OpenAI.

### Formats

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/formats` |

Generic ids: `square` (1024×1024), `landscape` (1536×1024), `portrait` (1024×1536).  
Infographic uses margin-friendly compose rules (not full-bleed). If the provider returns a mismatched aspect, `contain` letterboxes on a light background rather than clipping labels.  
Gemini renders natively at `1:1` / `3:2` / `2:3` to match these formats. `gemini-3.1-flash-lite-image` caps at 1K, so landscape and portrait outputs are upscaled to the target size and look softer.

Each format carries `id`, `name`, `category` (`generic` \| `social`), `platform` (`null` for generic), `modes`, `width`, `height`, `aspectRatio`, `safeZone`, and `safeArea`. Generic formats accept `image` and `infographic`; social formats accept only `social`. Filter the list by `modes` to build each mode's picker.

### Social destinations

Mode 3 destinations. One generate returns one asset at the exact pixel size.

| `formatId` | Platform | Size | OpenAI render | Gemini render | On-image copy limits (headline / supporting / CTA) |
|------------|----------|------|---------------|---------------|-----------------------------------------------------|
| `youtube-thumbnail` | youtube | 1280×720 | 1536x1024 | 16:9 | 40 / none / none |
| `instagram-post` | instagram | 1080×1350 (4:5) | 1024x1536 | 4:5 | 60 / 110 / 24 |
| `facebook-post` | facebook | 940×788 | 1024x1024 | 5:4 | 60 / 100 / 24 |
| `facebook-cover` | facebook | 851×315 | 1536x1024 | 21:9 | 50 / 80 / none |
| `youtube-banner` | youtube | 2560×1440 | 1536x1024 | 16:9 | 40 / 60 / none |
| `twitter-post` | twitter | 1600×900 | 1536x1024 | 16:9 | 60 / 90 / 24 |
| `linkedin-banner` | linkedin | 1584×396 | 1536x1024 | 21:9 | 50 / 80 / none |

The provider canvas is center-cropped (`cover`) to the destination. The render prompt tells the model which centered band survives that crop, so text and faces stay inside it. For example, `linkedin-banner` on OpenAI keeps the middle 38% of the canvas height. `youtube-banner` also enforces the 1546×423 center safe area that is visible on every device.

### Styles

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/styles` |

Vibe presets. For infographic, FE may send `style` / `styleId` and/or free-text `styleHint` (merged server-side).

### Archetypes (infographic)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/archetypes` |

**Response (200)** – `data.archetypes[]`: `id`, `label`, `description`.

Ids: `process`, `timeline`, `comparison`, `stats`, `hierarchy`, `list`, `cycle`. Optional `archetypeHint` on generate; omit for auto-pick.

---

## Credit estimate

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/estimate` |
| **Query** | `modelId`, `mode` (`image` \| `infographic` \| `social`), `tweak` (`true`/`false`) |

`data.breakdown.feature` is `image_gen_infographic` / `image_gen_social` for Modes 2 and 3.

---

## Context bundles

Same as before: `POST/GET/DELETE .../context`. Free to create. Used by both modes.  
For infographic: document text feeds the **spec LLM**; reference images (if any) go to the **render** call as brand/logo/icon cues only.

---

## Generate

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generate` |
| **Status** | **201** (synchronous) |

### Image body

```json
{
  "mode": "image",
  "folderId": "folder-uuid",
  "modelId": "gpt-image-1-hd",
  "formatId": "square",
  "style": "cinematic",
  "prompt": "Product launch visual",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "name": "launch.png",
  "contextId": "optional-context-uuid"
}
```

### Infographic body

```json
{
  "mode": "infographic",
  "folderId": "folder-uuid",
  "modelId": "gemini-3-pro-image",
  "formatId": "landscape",
  "archetypeHint": "process",
  "styleHint": "minimal, black and white",
  "prompt": "4-step onboarding funnel…",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "contextId": "optional-context-uuid"
}
```

### Social body

```json
{
  "mode": "social",
  "folderId": "folder-uuid",
  "formatId": "youtube-thumbnail",
  "modelId": "gemini-3-pro-image",
  "styleHint": "bold, high contrast, dark background",
  "prompt": "Thumbnail for my video about launching an online course in a weekend",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "contextId": "optional-context-uuid"
}
```

The prompt is free text, as in infographic mode. The server writes the on-image copy.

| Field | Rules |
|-------|--------|
| `mode` | `image` \| `infographic` \| `social` (default `image`) |
| `folderId` | **Required** |
| `formatId` | **Required** for `social` and must be a social destination id. Social ids are rejected in the other modes (400) |
| `prompt` | **Required**. Max **16,000** chars |
| `archetypeHint` | Infographic only; optional archetype id |
| `styleHint` | Infographic and social free-text style; merged with `style`/`styleId` if both sent |
| `headline` / `subheadline` / `textMode` / nested `infographic` | **Forbidden** → 400 |

**Infographic pipeline:** moderate prompt → LLM `InfographicSpec` (Joi + 1 retry → **400** if still invalid) → clamp dense sections → typesetting prompt → `generateImage` → `contain` crop → Asset + thread. Spec is stored in `generation.request.infographicSpec` and also returned as `generation.infographicSpec`.

**Social pipeline:** moderate prompt → LLM `SocialPostSpec` (`headline`, optional `supportingText` / `cta`, `visualSubject`, `composition`, `visualStyle`, `palette`; Joi + 1 retry → **400** if still invalid) → clamp copy to the destination limits (truncated at a word; fields the destination does not allow are dropped) → render prompt with exact copy, safe zone, and crop band → image model → `cover` crop to exact pixels → Asset + thread. The spec is returned as `generation.socialSpec`, and `generation.platform` names the destination platform. Clamp notes appear in `generation.request.warnings`.

**Response `data`:** `{ generation, asset, creditsCharged, downloadFormats, thread, actions }`.

---

## Folder chats (threads)

Same routes as before. Thread payload includes `mode` and `archetype` from the head generation.

### Send message

```json
{ "content": "Swap step 2 and 3", "fromGenerationId": "optional", "editMode": "spec" }
```

- Infographic: server routes to **spec patch + re-render** (content/structure/design language) or **pixel edit** (pure visual). Prefer `editMode: "spec" | "pixel"` to override. Pixel path sets `request.pixelEdited: true`.
- Social: copy and layout changes ("change the headline to…", "remove the CTA") patch the `SocialPostSpec` and re-render at the same destination. Pure visual changes ("darker background") run a pixel edit. `editMode` overrides the routing. Pixel edits keep the exact destination size: the server pads the stored post to the provider canvas before editing, crops back afterwards, and tells the model to keep the existing copy unchanged.
- Image: existing chat edit composition + pixel edit.
- Sticky mode: cannot change mode mid-thread.
- Pixel edits run on the parent generation's provider: Gemini parents edit on the same Gemini model, OpenAI parents on `gpt-image-1`.

---

## List / get generations

`GET .../generations` — omit `mode` to return every studio mode; pass `mode=image`, `mode=infographic`, or `mode=social` to filter.

---

## Regenerate / Tweak / Download

- **Regenerate:** reuses parent mode. Infographic with empty body (or only `modelId`/`formatId`) re-renders stored spec; new `prompt` / hints / `contextId` re-runs spec LLM.
- **Regenerate (social):** the same rules apply to `socialSpec`. A new `prompt`, `styleHint`, `style`, `brandPalette`, or `contextId` rebuilds the spec; `modelId` alone re-renders it. Sending a different `formatId` returns **400**: start a new generate for another destination.
- **Tweak:** `{ "instruction": "...", "editMode": "spec"|"pixel" }` — same routing as chat for infographic and social.
- **Download:** unchanged (`png` \| `jpg` \| `jpeg` \| `pdf`).

---

## Credits (defaults)

| Feature | Default AC | Env |
|---------|------------|-----|
| `image_gen_gpt_image` | 6 | `IMAGE_GEN_GPT_IMAGE_AC` |
| `image_gen_gpt_image_hd` | 12 | `IMAGE_GEN_GPT_IMAGE_HD_AC` |
| `image_gen_dall_e_3` | 12 | `IMAGE_GEN_DALL_E_3_AC` |
| `image_gen_gemini_pro_image` | 12 | `IMAGE_GEN_GEMINI_PRO_AC` |
| `image_gen_gemini_flash_image` | 8 | `IMAGE_GEN_GEMINI_FLASH_AC` |
| `image_gen_gemini_flash_lite_image` | 4 | `IMAGE_GEN_GEMINI_FLASH_LITE_AC` |
| `image_gen_infographic` | model AC until margin pass | `IMAGE_GEN_INFOGRAPHIC_AC` (optional override) |
| `image_gen_social` | model AC until margin pass | `IMAGE_GEN_SOCIAL_AC` (optional override) |

Gemini AC values are placeholders until the margin pass, sized to Google's list-price gaps.

Requires **`OPENAI_API_KEY`**; **`GEMINI_API_KEY`** additionally for Gemini models. Optional `IMAGE_GEN_SPEC_MODEL` for the infographic and social spec LLM (defaults to `PPT_SLIDE_MODEL` / `gpt-4.1-mini`), `IMAGE_GEN_GEMINI_IMAGE_SIZE` (`512` \| `1K` \| `2K` \| `4K`, default `2K`, clamped per model), `IMAGE_GEN_GEMINI_TIMEOUT_MS` (default 300000).

---

**[← API index](README.md)** · Frontend: [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](../IMAGE_GEN_FRONTEND_INTEGRATION.md)
