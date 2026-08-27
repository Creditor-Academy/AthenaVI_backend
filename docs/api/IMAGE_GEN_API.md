# Image Gen API

Base path: **`/api/image-gen`**

**Internal complete guide + Infographics research:** [`docs/IMAGE_GEN_COMPLETE.md`](../IMAGE_GEN_COMPLETE.md).  
**Infographic PRD:** [`docs/INFOGRAPHIC_MODE_PRD.md`](../INFOGRAPHIC_MODE_PRD.md).

Workspace image studio for **general images** and **infographics**, backed by **OpenAI** and **Google Gemini** models. Results are saved as workspace **Assets** (`source: "ai_gen"`) and downloadable as PNG / JPG / JPEG / PDF.

**Auth:** `Authorization: Bearer <access_token>` on all routes.  
**Workspace routes:** `checkWorkspaceAccess` (PRIVATE = owner; TEAM = any member).

**Credits:** charged **on success only** from the workspace billing pool (PRIVATE → owner personal; TEAM → workspace). Insufficient → **402**. Opening a saved chat, viewing, and downloads are free. Rate limits → **429**. Infographic pricing uses feature `image_gen_infographic` (placeholder via model AC until the margin pass; override with `IMAGE_GEN_INFOGRAPHIC_AC`).

**Modes:** `image` | `infographic`.  
- `image` — general scenes (default format `square`, default model `gpt-image-1`, crop `cover`).  
- `infographic` — spec-first typesetting (default format `landscape`, default model `gpt-image-1-hd`, crop `contain`). Thread mode is **sticky** (chat/tweak stay on the head’s mode).

**Chats:** each successful generate creates a folder-scoped **thread**. Folder cards support View / Download / Open chat. Threads expose `mode` and `archetype` for badges.

**Client timeout:** allow **~120s** for `mode=infographic` (spec LLM + image). Image mode remains ~30–90s.

---

## Catalogs

### Models

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/models` |

**Response (200)** – `data.models[]`: `id`, `name`, `description`, `provider` (`openai` \| `gemini`), `maxImageSize` (Gemini only, else `null`), `modes` (`["image","infographic"]`), `recommended`, `supportsEdit`, `creditEstimate`.

All models support **both modes** and **edits** (tweak / chat pixel edits stay on the parent's provider).

| `id` | Provider | AC | Notes |
|------|----------|----|-------|
| `gpt-image-1` | openai | 6 | Default for `image` |
| `gpt-image-1-hd` | openai | 12 | Default for `infographic` |
| `dall-e-3` | openai | 12 | Compat alias → gpt-image-1 high |
| `gemini-3-pro-image` | gemini | 12 | Nano Banana Pro — best in-image text; up to 4K |
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
| **Query** | `modelId`, `mode` (`image` \| `infographic`), `tweak` (`true`/`false`) |

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
  "modelId": "gpt-image-1",
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
  "modelId": "gpt-image-1-hd",
  "formatId": "landscape",
  "archetypeHint": "process",
  "styleHint": "minimal, black and white",
  "prompt": "4-step onboarding funnel…",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "contextId": "optional-context-uuid"
}
```

| Field | Rules |
|-------|--------|
| `mode` | `image` \| `infographic` (default `image`) |
| `folderId` | **Required** |
| `prompt` | **Required**. Max **16,000** chars |
| `archetypeHint` | Infographic only; optional archetype id |
| `styleHint` | Infographic free-text style; merged with `style`/`styleId` if both sent |
| `headline` / `subheadline` / `textMode` / nested `infographic` | **Forbidden** → 400 |

**Infographic pipeline:** moderate prompt → LLM `InfographicSpec` (Joi + 1 retry → **400** if still invalid) → clamp dense sections → typesetting prompt → `generateImage` → `contain` crop → Asset + thread. Spec is stored in `generation.request.infographicSpec` and also returned as `generation.infographicSpec`.

**Response `data`:** `{ generation, asset, creditsCharged, downloadFormats, thread, actions }`.

---

## Folder chats (threads)

Same routes as before. Thread payload includes `mode` and `archetype` from the head generation.

### Send message

```json
{ "content": "Swap step 2 and 3", "fromGenerationId": "optional", "editMode": "spec" }
```

- Infographic: server routes to **spec patch + re-render** (content/structure/design language) or **pixel edit** (pure visual). Prefer `editMode: "spec" | "pixel"` to override. Pixel path sets `request.pixelEdited: true`.
- Image: existing chat edit composition + pixel edit.
- Sticky mode: cannot change mode mid-thread.
- Pixel edits run on the parent generation's provider: Gemini parents edit on the same Gemini model, OpenAI parents on `gpt-image-1`.

---

## List / get generations

`GET .../generations` — omit `mode` to return **both** studio modes; pass `mode=image` or `mode=infographic` to filter.

---

## Regenerate / Tweak / Download

- **Regenerate:** reuses parent mode. Infographic with empty body (or only `modelId`/`formatId`) re-renders stored spec; new `prompt` / hints / `contextId` re-runs spec LLM.
- **Tweak:** `{ "instruction": "...", "editMode": "spec"|"pixel" }` — same routing as chat for infographic.
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

Gemini AC values are placeholders until the margin pass, sized to Google's list-price gaps.

Requires **`OPENAI_API_KEY`**; **`GEMINI_API_KEY`** additionally for Gemini models. Optional `IMAGE_GEN_SPEC_MODEL` for the infographic spec LLM (defaults to `PPT_SLIDE_MODEL` / `gpt-4.1-mini`), `IMAGE_GEN_GEMINI_IMAGE_SIZE` (`512` \| `1K` \| `2K` \| `4K`, default `2K`, clamped per model), `IMAGE_GEN_GEMINI_TIMEOUT_MS` (default 300000).

---

**[← API index](README.md)** · Frontend: [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](../IMAGE_GEN_FRONTEND_INTEGRATION.md)
