# Image Gen API

Base path: **`/api/image-gen`**

OpenAI-only workspace image studio for **general images**. Results are saved as workspace **Assets** (`source: "ai_gen"`) and downloadable as PNG / JPG / JPEG / PDF.

**Auth:** `Authorization: Bearer <access_token>` on all routes.  
**Workspace routes:** `checkWorkspaceAccess` (PRIVATE = owner; TEAM = any member).

**Credits:** charged **on success only** from the workspace billing pool (PRIVATE → owner personal; TEAM → workspace). Insufficient → **402**. Opening a saved chat, viewing, and downloads are free. Rate limits → **429**.

**Mode:** `image` only. `infographic` and `social` return **400**. List/get only return `mode=image` (404 for other stored rows).

**Chats:** each successful generate creates a folder-scoped **thread** (workspace → folder → image chat). Folder cards support View (head URL), Download (generation download), and Open chat. Follow-up messages edit the **latest hop** and charge like tweak.

---

## Catalogs

### Models

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/models` |

**Response (200)** – `data.models[]`: `id`, `name`, `description`, `modes` (`["image"]`), `recommended`, `supportsEdit`, `creditEstimate`.

| `id` | OpenAI | Notes |
|------|--------|--------|
| `gpt-image-1` | `gpt-image-1` medium | Default when `modelId` is omitted |
| `gpt-image-1-hd` | `gpt-image-1` high | Higher AC |
| `dall-e-3` | `gpt-image-1` high | Compatibility alias (OpenAI retired DALL·E 3) |

### Formats

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/formats` |

**Response (200)** – `data.formats[]`: `id`, `name`, `category` (`generic`), `width`, `height`, `safeZone`.

Generic ids: `square` (1024×1024), `landscape` (1536×1024), `portrait` (1024×1536). Default when omitted: **`square`**.

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
| **Query** | `modelId`, `mode` (`image` only), `tweak` (`true`/`false`) |

Default model **`gpt-image-1`** → **6 AC**. HD → **12 AC**. Tweak = model AC, no surcharge.

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
| **Status** | **201** (synchronous — allow ~30–90s client timeout) |

**Body**

```json
{
  "mode": "image",
  "folderId": "folder-uuid",
  "modelId": "gpt-image-1",
  "formatId": "square",
  "style": "cinematic",
  "prompt": "Product launch visual for Athena VI",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "name": "launch.png",
  "contextId": "optional-context-uuid"
}
```

| Field | Rules |
|-------|--------|
| `mode` | `image` only (default `image`). Other values **400**. |
| `folderId` | **Required.** Folder in this workspace. The saved chat lives here. |
| `modelId` | Optional. Default **`gpt-image-1`**. |
| `formatId` | Optional `square` / `landscape` / `portrait`. Default **`square`**. |
| `prompt` | **Required**. Max **16,000** chars. |
| `style` / `styleId` | Optional vibe from `/styles`. |
| `brandPalette` | Optional hex list. |
| `name` | Optional display filename. If omitted, derived from the prompt (kebab-case). S3 keys stay UUID-based. |
| `contextId` | Optional. Uses document text + vision summaries in the prompt; reference images go through `images.edit` |

`mode` other than `image`, social `formatId`s, and leftover fields (`headline`, `subheadline`, `textMode`, `infographic`) return **400**.

**Pipeline:** style-wrapped prompt → OpenAI `gpt-image-1` → cover-crop to format → PNG asset → **thread** in `folderId`.

**Response `data`:** `{ generation, asset, creditsCharged, downloadFormats, thread, actions }`.

`actions`: `{ viewUrl, downloadPath, threadId }` for View / Download / Open chat.

`generation` includes `threadId`, `contextId`, and `contextPreview` when context was used. A snapshot is stored in `generation.request.contextSnapshot` for regenerate.

Master file is always **PNG** on S3.

---

## Folder chats (threads)

Hierarchy: **workspace → folder → image chat**. One library row per conversation (not per hop).

### List threads

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/threads` |
| **Query** | `folderId` (optional), `take` (1–100), `skip` |

**Response (200)** – `data.threads[]`: `id`, `threadId` (same as `id`), `title`, `folderId`, `head` (`generationId`, `url`, `asset`), `messageCount`, `versionCount`, `updatedAt`, `downloadFormats`.

PRIVATE: current user’s threads only. Same payload as `GET /api/workspaces/:workspaceId/library?category=image&folderId=`.

### Get thread

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/threads/:threadId` |

**Response (200)** – `data.thread` including `messages[]` (`role` `user`\|`assistant`, `type`, `content`, `generationId`, `url`) and `head`. **No credit charge.**

### Send message

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/threads/:threadId/messages` |
| **Status** | **201** |

```json
{ "content": "Make the background darker", "fromGenerationId": "optional-hop-uuid" }
```

Edits the **head** PNG (or `fromGenerationId` if it belongs to the thread) via `images.edit`. Composes OpenAI instruction from original prompt + prior user turns + this line. Charges **tweak AC** (same as model). Rate limit: regenerate/tweak bucket.

### Rename / move / delete

| Method | Path | Notes |
|--------|------|--------|
| `PATCH` | `.../threads/:threadId` | Body `{ "title" }`. Free. |
| `POST` | `.../threads/:threadId/move-folder` | Body `{ "folderId" }`. FK only (no S3 rewrite). Free. |
| `DELETE` | `.../threads/:threadId` | Unlinks generations; **does not** delete Assets. Free. |

---

## List / get generations

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations` |
| **Query** | `take` (1–100), `skip`, `mode` (`image` only, optional), `threadId` (optional — hops in one chat) |

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId` |

PRIVATE workspaces only return the current user’s generations. Non-image stored rows → **404**.

---

## Regenerate

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/regenerate` |
| **Status** | **201** |

Body fields optional — omitted fields reuse the parent generation’s request (including `contextId`). Parent must be `mode=image` (**400** otherwise). Creates a new generation + asset (`action: "regenerate"`), linked via `parentId` / `rootId` / `threadId`. Charges again. Appends chat messages and advances the thread **head**.

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

Uses OpenAI **image edit** on the parent PNG. Parent must be `mode=image` (**400** otherwise). Charges model AC. Appends the instruction to the saved chat and advances **head**. Prefer `POST .../threads/:threadId/messages` for conversation-aware edits. `instruction` max **4,000** chars.

---

## Download

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/download` |
| **Query** | `format=png` \| `jpg` \| `jpeg` \| `pdf` (default **png**) |

Returns file attachment (`Content-Disposition: attachment`). Filename is `asset.name` (prompt-derived kebab-case unless the client sent `name`). **No credit charge.** Non-image rows → **404**.

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

Context create is **free**. Rate limits: `IMAGE_GEN_RATE_LIMIT_MAX` / `IMAGE_GEN_RATE_LIMIT_WINDOW_SEC`, `IMAGE_GEN_REGENERATE_RATE_LIMIT_MAX` / `IMAGE_GEN_REGENERATE_RATE_LIMIT_WINDOW_SEC`, `IMAGE_GEN_CONTEXT_RATE_LIMIT_MAX` / `IMAGE_GEN_CONTEXT_RATE_LIMIT_WINDOW_SEC`.

Requires **`OPENAI_API_KEY`**.

---

## Assets library

AI outputs appear in `GET /api/assets/:workspaceId?source=ai_gen` with `stockMetadata.generationId` for linking back to studio history.

---

**[← API index](README.md)** · Frontend: [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](../IMAGE_GEN_FRONTEND_INTEGRATION.md)
