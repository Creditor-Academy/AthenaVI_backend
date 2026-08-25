# Image Gen — complete internal guide + Infographics mode research

This document explains **how Athena VI Image Gen works today**, end to end, and how to **design and ship the next mode: Infographics**.

It is written from the **backend implementation** (`src/modules/imageGen/`).  
HTTP contracts stay in [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).  
Frontend wiring stays in [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](IMAGE_GEN_FRONTEND_INTEGRATION.md).  
Broader A→Z (with PPT + Brand Kit): [`FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md`](FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md).

**Status today (as of this writing):**

| Mode | Status |
|------|--------|
| `image` | **Live** — general images |
| `infographic` | **Live** — spec-first typesetting; see [`INFOGRAPHIC_MODE_PRD.md`](INFOGRAPHIC_MODE_PRD.md) |
| `social` | **Not shipped** — formats/fields removed; crop helper name is legacy only |

Use **Parts 1–10** to review the current product. Use **Part 11** as the Infographics research + development plan.

---

## Part 1 — What Image Gen is

Image Gen is an **OpenAI-only workspace image studio** for **general images**. It is **not** a slide deck, **not** Remotion, and **not** HeyGen video.

```
Workspace
  └── Folder
        └── Image chat (ImageGenThread)     ← one library card per conversation
              ├── Messages (ImageGenMessage[])
              └── Generation hops (ImageGeneration[])
                    └── Asset (source: "ai_gen")  ← PNG master on S3
```

| Concept | Stored as | Used for |
|---------|-----------|----------|
| Chat / conversation | `ImageGenThread` | Folder library card; View / Download / Open chat |
| Hop / version | `ImageGeneration` | One OpenAI call result (generate / regenerate / tweak) |
| Chat line | `ImageGenMessage` | User + assistant turns in the thread UI |
| Context bundle | `ImageGenContext` + files | Docs / refs / pasted text attached **before** generate |
| Downloadable file | `Asset` | Library + download PNG/JPG/PDF |

**Mental model for product:**

```
Workspace → Folder → Image chat
  → (optional) attach context
  → pick model / format / style
  → Generate (sync, 30–90s) → Asset + thread
  → Folder card: View | Download | Open chat
  → Chat send → edits latest hop (charges like tweak)
```

---

## Part 2 — Product rules (current)

| Rule | Behavior |
|------|----------|
| Mode | `image` only. `infographic` / `social` → **400** |
| Auth | `Authorization: Bearer <accessToken>` on all routes |
| Workspace access | `checkWorkspaceAccess` (PRIVATE = owner; TEAM = any member) |
| Folder | `folderId` **required** on generate — chat lives in that folder |
| Credits | Charged **on success only** from workspace billing pool |
| Insufficient credits | **402** |
| Opening chat / view / download | Free |
| Rate limits | Generate, regenerate/tweak, context create → **429** |
| Sync generate | Client should allow **30–90s** timeout |
| Master file | Always **PNG** on S3; other download formats converted on the fly |
| PRIVATE workspace | Only the current user’s threads/generations/contexts |
| List/get generations | Non-`image` stored rows → **404** (defense in depth) |

Leftover request fields that were planned for other modes are **explicitly forbidden** today:

- `headline`, `subheadline`, `textMode`, `infographic` → Joi `.forbidden()` → **400**

---

## Part 3 — Module map (who does what)

Mounted at **`/api/image-gen`** from `src/app.js` (not under `/api/workspaces`).

| File | Role |
|------|------|
| `imageGen.routes.js` | HTTP verbs, multer for context uploads, payload parse |
| `imageGen.controller.js` | Catalogs, estimate, generate, threads, generations, download |
| `imageGen.context.controller.js` | Create / get / delete context |
| `imageGen.service.js` | **Main engine:** pipeline, tweak, threads, list/get |
| `imageGen.context.service.js` | Parse uploads, pin/TTL, resolve for generate, enrichment |
| `imageGen.contextParse.service.js` | Doc text + vision summaries for refs |
| `imageGenCredit.service.js` | Afford + flat AC charge |
| `imageGenRateLimit.service.js` | Redis generate / regenerate buckets |
| `imageGen.contextRateLimit.service.js` | Redis context-create bucket |
| `imageGen.dao.js` / `thread.dao` / `message.dao` / `context.dao` | Prisma |
| `imageGenExport.service.js` | PNG / JPG / PDF download stream |
| `imageGenFilename.js` | Display name from prompt / client `name` |
| `socialCrop.service.js` | Sharp resize to format (name is legacy; used for all formats) |
| `catalogs/models.js` | Model catalog + credit estimate |
| `catalogs/formats.js` | square / landscape / portrait |
| `catalogs/styles.js` | Vibe presets → prompt suffixes |
| `prompts/imageStyle.prompt.js` | Prompt + style wrap |
| `prompts/contextEnrichment.prompt.js` | Append context block + ref index hints |
| `prompts/chatEdit.prompt.js` | Compose chat edit instruction for OpenAI |
| `validations/imageGen.validations.js` | Joi schemas |
| `shared/services/ai/image.service.js` | `generateImage`, `editImage`, `generateImageWithReferences` |
| `shared/config/imageGenCreditPricing.js` | Flat AC per feature / env overrides |
| `shared/jobs/imageGenContextCleanup.job.js` | Purge expired unpinned contexts |
| `workspaceLibrary.service.js` | Folder library `category=image` → threads |

---

## Part 4 — Data model

### 4.1 `ImageGenContext`

Ephemeral (or pinned) bundle used to enrich the next generate.

| Field | Meaning |
|-------|---------|
| `status` | Typically `READY` |
| `inlineText` | Pasted brief |
| `derived` JSON | Previews + warnings |
| `expiresAt` | Default TTL **7 days** (`IMAGE_GEN_CONTEXT_TTL_DAYS`) |
| `pinnedAt` | Set after first successful generate that uses it — blocks delete |

### 4.2 `ImageGenContextFile`

| `source` | `upload` or `asset` |
| `role` | `document` or `reference_image` |
| `extractedText` / `imageSummary` | Used in prompt enrichment |

Uploaded files get their own S3 keys (not workspace Asset keys). Delete context never deletes Asset keys.

### 4.3 `ImageGenThread`

One **library card** per conversation.

| Field | Meaning |
|-------|---------|
| `folderId` | Where the chat lives |
| `rootGenerationId` | First hop |
| `headGenerationId` | Latest hop (View / Download target) |
| `title` | Derived from prompt (or renamed) |
| `contextId` / `modelId` / `formatId` / `styleId` | Snapshot of chat settings |

Unique on `rootGenerationId`.

### 4.4 `ImageGenMessage`

| `role` | `user` \| `assistant` |
| `type` | Message kind (generate / chat / etc.) |
| `content` | Text |
| `generationId` | Linked hop when an image was produced |
| `creditsCharged` | AC for that turn |

### 4.5 `ImageGeneration`

One successful (or recorded) OpenAI hop.

| Field | Meaning |
|-------|---------|
| `mode` | Today always `"image"` |
| `action` | `generate` \| `regenerate` \| `tweak` |
| `parentId` / `rootId` | Version chain |
| `threadId` | Owning chat |
| `request` JSON | Replay snapshot: prompt, style, palette, `contextId`, `contextSnapshot`, tweak instruction |
| `s3Key` / `url` | Master PNG |
| `exportWidth` / `exportHeight` | After crop |
| `creditsCharged` | AC actually billed |
| `status` | Typically `SUCCEEDED` (sync path) |

Assets link back via `stockMetadata.generationId` (+ mode, model, format, action, threadId).

---

## Part 5 — Catalogs

### 5.1 Models — `GET /api/image-gen/models`

| `id` | OpenAI under the hood | Quality | Default AC | Notes |
|------|----------------------|---------|------------|--------|
| `gpt-image-1` | `gpt-image-1` | medium | **6** | Default; recommended |
| `gpt-image-1-hd` | `gpt-image-1` | high | **12** | |
| `dall-e-3` | `gpt-image-1` | high | **12** | Compat alias (DALL·E 3 retired) |

Each model lists `modes: ["image"]`, `supportsEdit: true`, `creditEstimate`.

### 5.2 Formats — `GET /api/image-gen/formats`

| `id` | Size | OpenAI size (gpt-image) |
|------|------|-------------------------|
| `square` (default) | 1024×1024 | `1024x1024` |
| `landscape` | 1536×1024 | `1536x1024` |
| `portrait` | 1024×1536 | `1024x1536` |

Category is `generic` only. Formats include `composeRules` / `safeZone` used when wrapping prompts (full-bleed guidance).

### 5.3 Styles — `GET /api/image-gen/styles`

Vibe ids (examples): `cinematic`, `photoreal`, `flat_illustration`, `3d_render`, `watercolor`, `corporate`, `playful`, `dark_moody`, `minimal`, `neon`.

Each appends a fixed **prompt suffix** in `buildImagePrompt`.

---

## Part 6 — End-to-end pipelines

### 6.1 Generate (happy path)

**Route:** `POST /api/image-gen/workspaces/:workspaceId/generate` → **201**

```
validate (mode=image, folderId, prompt, …)
  → assert folder in workspace
  → rate limit (generate bucket)
  → resolve context (optional; pin later)
  → assertAfford
  → buildImagePrompt(prompt + style)
  → append context text block
  → if reference images: generateImageWithReferences
    else: generateImage
  → cropToFormat (cover) → PNG
  → persistWorkspaceAsset (source: ai_gen)
  → create ImageGeneration
  → pin context if used
  → chargeFlat (feature = model feature)
  → create ImageGenThread + seed messages
  → return { generation, asset, creditsCharged, thread, actions }
```

**`actions` for UI:**

```json
{
  "viewUrl": "https://…",
  "downloadPath": "/api/image-gen/workspaces/…/generations/…/download",
  "threadId": "uuid"
}
```

### 6.2 Context create (free)

**Route:** `POST .../context` multipart → **201**

Inputs (at least one required):

- `files` — PDF, DOCX, MD, TXT, PNG, JPG, JPEG, WebP (max **5** combined with assets; **20 MB** each)
- `payload` JSON — `{ inlineText?, assetIds? }` (`assetIds` = workspace **image** assets)

Pipeline:

1. Rate limit context create  
2. Parse documents → excerpts; vision-summarize reference images  
3. Moderate text where applicable  
4. Upload file bytes to context S3 keys  
5. Store `ImageGenContext` + files; return `previews` + `warnings`

On generate:

- **Text** from context goes into the prompt block  
- **Reference images** go through OpenAI images edit / references API  
- Context is **pinned** after first successful use  
- On regenerate: if live context expired, **text snapshot** from `request.contextSnapshot` still applies; **visual refs** need live/pinned context  

Cleanup job deletes expired **unpinned** contexts and their upload keys.

### 6.3 Regenerate

**Route:** `POST .../generations/:generationId/regenerate` → **201**

- Parent must be `mode=image`  
- Omitted body fields reuse parent `request` (including `contextId`)  
- New hop: `action: "regenerate"`, same `rootId` / `threadId`  
- Charges again (model AC)  
- Appends chat messages; advances thread **head**

### 6.4 Tweak vs chat message

| API | Body | Behavior |
|-----|------|----------|
| `POST .../generations/:id/tweak` | `{ instruction }` | Edit parent PNG via `editImage`; advance head |
| `POST .../threads/:id/messages` | `{ content, fromGenerationId? }` | Preferred: compose instruction from original prompt + prior user turns + this line; edit head (or branch from hop) |

Both charge **tweak AC** (= same as model AC today, no surcharge). Rate limit = regenerate bucket.

### 6.5 Download (free)

`GET .../generations/:id/download?format=png|jpg|jpeg|pdf`

- Master is PNG; JPG/PDF converted in `imageGenExport.service.js`  
- Filename from asset name (prompt kebab-case or client `name`)

### 6.6 Folder library

`GET /api/workspaces/:workspaceId/library?category=image&folderId=`

Returns **threads** (one card per chat), not every hop. Card uses `head.url` / `head.generationId` / thread `id`.

Also: `GET /api/image-gen/workspaces/:workspaceId/threads?folderId=`

---

## Part 7 — Credits & rate limits

### 7.1 Pricing

| Feature key | Default AC | Env |
|-------------|------------|-----|
| `image_gen_gpt_image` | 6 | `IMAGE_GEN_GPT_IMAGE_AC` |
| `image_gen_gpt_image_hd` | 12 | `IMAGE_GEN_GPT_IMAGE_HD_AC` |
| `image_gen_dall_e_3` | 12 | `IMAGE_GEN_DALL_E_3_AC` |
| `image_gen_tweak` | same as model | (charged via tweak path; label “AI image tweak”) |

Context create = **0 AC**. Estimate: `GET .../estimate?modelId=&mode=image&tweak=`.

Billing pool:

- PRIVATE → owner personal credits  
- TEAM → workspace credits  

Idempotency keys look like `imageGen:{generationId}:{action}`.

Credit history labels (enriched): “AI image generation”, “AI image generation (HD)”, “AI image tweak”, etc.

### 7.2 Rate limits (Redis)

| Bucket | Env defaults |
|--------|----------------|
| Generate | `IMAGE_GEN_RATE_LIMIT_MAX` 30 / window `3600`s |
| Regenerate / tweak / chat send | `IMAGE_GEN_REGENERATE_RATE_LIMIT_MAX` 60 / `3600`s |
| Context create | `IMAGE_GEN_CONTEXT_RATE_LIMIT_MAX` 20 / `3600`s |

Keys are per user and per workspace.

---

## Part 8 — Environment checklist

Requires **`OPENAI_API_KEY`**.

| Variable | Role | Typical default |
|----------|------|-----------------|
| `IMAGE_GEN_GPT_IMAGE_AC` | AC for gpt-image-1 | 6 |
| `IMAGE_GEN_GPT_IMAGE_HD_AC` | AC for HD | 12 |
| `IMAGE_GEN_DALL_E_3_AC` | AC for alias | 12 |
| `IMAGE_GEN_RATE_LIMIT_*` | Generate throttle | 30 / 3600 |
| `IMAGE_GEN_REGENERATE_RATE_LIMIT_*` | Regen/tweak throttle | 60 / 3600 |
| `IMAGE_GEN_CONTEXT_*` | Files, TTL, cleanup, preview URL TTL | see ENVIRONMENT.md |
| `IMAGE_GEN_VISION_MODEL` | Ref image summaries | falls back to `PPT_VISION_MODEL` |
| `IMAGE_GEN_REFERENCE_INPUT_FIDELITY` | Ref image fidelity hint | optional |

Full list: [`docs/api/ENVIRONMENT.md`](api/ENVIRONMENT.md).

---

## Part 9 — API surface (quick map)

| Method | Path | Cost |
|--------|------|------|
| GET | `/models` `/formats` `/styles` | Free |
| GET | `/workspaces/:id/estimate` | Free |
| POST | `/workspaces/:id/context` | Free |
| GET/DELETE | `/workspaces/:id/context/:contextId` | Free |
| POST | `/workspaces/:id/generate` | Model AC |
| GET | `/workspaces/:id/threads` | Free |
| GET | `/workspaces/:id/threads/:threadId` | Free |
| POST | `/workspaces/:id/threads/:threadId/messages` | Tweak AC |
| PATCH | `/workspaces/:id/threads/:threadId` | Free (rename) |
| POST | `/workspaces/:id/threads/:threadId/move-folder` | Free |
| DELETE | `/workspaces/:id/threads/:threadId` | Free (unlink hops; **does not** delete Assets) |
| GET | `/workspaces/:id/generations` | Free |
| GET | `/workspaces/:id/generations/:generationId` | Free |
| POST | `.../regenerate` | Model AC |
| POST | `.../tweak` | Tweak AC |
| GET | `.../download` | Free |

Errors to expect in UI: **400**, **402**, **404**, **409** (pinned context delete), **429**, **502/503**.

---

## Part 10 — How Image Gen relates to other features

```
Brand Kit ──────────┐
                    │  (palette / logo — optional future for Image Gen;
Presentations ──────┤   PPT Path B already does “infographic-style” diagrams
  Path B diagrams   │   inside slides via layout + generateImage)
                    │
Image Gen (studio) ─┴── Assets (ai_gen) ── reusable in PPT / editor / library
```

**Important distinction for Infographics mode:**

| Surface | What “infographic” means today |
|---------|--------------------------------|
| **PPT Path B** | Multi-panel diagram **as a slide image**, typeset from `pathBSpec` (`pathB.prompt.js`), charged as `ppt_image_path_b` |
| **Image Gen (planned)** | Standalone studio mode: user wants a **downloadable infographic asset** (and chat), not a deck slide |

Reuse learnings from Path B (structured spec → typesetting prompt → HD image). Do **not** conflate the two products; share prompt patterns and OpenAI client only.

---

## Part 11 — Infographics mode: research & how to develop it

### 11.1 Product definition (decide in review)

**Proposed product goal**

> User picks **Infographic** in the Image Gen studio, supplies a topic / data / brief (and optional context docs), and gets a **readable, structured visual** (process, comparison, timeline, stats, hierarchy) saved as an Asset + chat — same folder UX as general images.

**Non-goals (v1)**

- Editable vector canvas with independently movable text boxes (that is closer to PPT)  
- Multi-page PDF reports  
- Live chart engines (Chart.js etc.) inside the PNG  

**v1 success criteria**

1. Readable labels (numbers, short titles) more reliable than freeform `image` mode  
2. Predictable layouts (user picks a **layout archetype**, not only a vibe style)  
3. Same thread / regenerate / tweak / download UX as `image`  
4. Credits transparent; charge on success only  
5. Context (CSV/PDF/brief) can drive factual content  

### 11.2 Why the current `image` mode is not enough

General image prompts optimize for **scene aesthetics**. Infographics need:

| Need | Gap in current `image` mode |
|------|-----------------------------|
| Exact copy / numbers | Model invents or garbles text |
| Layout structure | No archetype (timeline vs funnel vs comparison) |
| Data fidelity | Context is soft enrichment, not a typed “facts” block |
| Negative space / legend | Full-bleed compose rules fight chart-like layouts |
| Iteration | Chat edits work, but without a stored **spec**, regen drifts |

Legacy Joi fields (`headline`, `subheadline`, `textMode`, `infographic`) show an earlier design that assumed **structured request fields**. That direction is still the right instinct.

### 11.3 Architecture options

#### Option A — Prompt-only mode (fastest ship)

Unlock `mode: "infographic"`, add layout + text fields, wrap with a strong system prompt, call same `generateImage`.

| Pros | Cons |
|------|------|
| Smallest code change | Weakest text accuracy |
| Reuses entire thread/credit stack | Hard to guarantee data fidelity |
| Days, not weeks | Users will compare badly to Canva |

**Verdict:** Good for a **spike / A-B**, not recommended as the only long-term path.

#### Option B — Spec-first (recommended for v1)

Two-step pipeline inside Image Gen:

```
User input (topic + optional data + context)
  → LLM (chatJson): InfographicSpec
       { archetype, title, sections[], facts[], palette, doNotInvent }
  → buildInfographicPrompt(spec)   // like PPT pathB.prompt.js
  → generateImage (prefer HD)
  → crop (contain or cover — see below)
  → Asset + thread (mode=infographic)
```

| Pros | Cons |
|------|------|
| Separates **facts** from **pixels** | Extra LLM call (+ small AC or bundled) |
| Reuses Path B lessons | Still raster text (not editable) |
| Snapshot `spec` in `request` for stable regen | Need QA prompts + eval set |
| Chat can edit **spec** then re-render | Slightly longer latency |

**Verdict: recommended.**

#### Option C — Hybrid canvas (later)

Generate a structured canvas (text + shapes + icons as elements), render server-side (SVG/Skia/Remotion still), export PNG/PDF.

| Pros | Cons |
|------|------|
| Perfect text; editable later | Large new subsystem |
| Brand Kit fonts truly apply | Not needed to validate product-market |

**Verdict:** v2+ if raster quality or editability becomes the blocker.

### 11.4 Recommended v1 design (Option B)

#### Request shape (proposal)

```json
{
  "mode": "infographic",
  "folderId": "uuid",
  "modelId": "gpt-image-1-hd",
  "formatId": "landscape",
  "archetype": "process",
  "prompt": "Explain our 4-step onboarding funnel using the attached metrics",
  "brandPalette": ["#0B1F3A", "#3DDC97"],
  "contextId": "optional-uuid",
  "infographic": {
    "title": "optional override",
    "mustInclude": ["Step 1: Sign up", "Step 2: Verify", "…"],
    "tone": "corporate"
  }
}
```

Re-enable structured `infographic` object (today `.forbidden()`). Keep `headline`/`subheadline` only if product wants them; otherwise drop permanently in favor of `infographic.title` + sections from the LLM.

#### Archetype catalog (new)

Suggested ids:

| `archetype` | Use |
|-------------|-----|
| `process` | Numbered steps / funnel |
| `timeline` | Chronological milestones |
| `comparison` | A vs B columns |
| `stats` | KPI cards + big numbers |
| `hierarchy` | Org / pyramid / tree |
| `list` | Icon list / checklist |
| `cycle` | Circular loop |

Expose via `GET /api/image-gen/archetypes` (or nest under formats for infographic).

#### Formats for infographic

Reuse `square` / `landscape` / `portrait`, but:

- Prefer **`contain`** crop (or skip aggressive cover crop) so labels are not clipped — today pipeline uses `cover`  
- Add compose rules that allow **margins, cards, legends** (opposite of current full-bleed rules)  
- Optional later: `story` 1080×1920 if social returns as a separate mode

#### Models

- Default for infographic: **`gpt-image-1-hd`** (text-heavy)  
- Catalog: `modes: ["image", "infographic"]` or dedicated models with `modes: ["infographic"]`  
- Edit/tweak still via `editImage` (same as image)

#### Spec schema (store in `generation.request.infographicSpec`)

```json
{
  "archetype": "process",
  "title": "Customer onboarding",
  "subtitle": "Q3 funnel",
  "sections": [
    { "label": "1. Sign up", "body": "Email + SSO", "metric": "12k" },
    { "label": "2. Verify", "body": "Confirm email", "metric": "9.1k" }
  ],
  "legend": [],
  "palette": ["#0B1F3A", "#3DDC97"],
  "constraints": {
    "doNotInventNumbers": true,
    "language": "en"
  }
}
```

Regenerate / chat:

- Prefer **mutate spec with LLM**, then re-render (stable)  
- Fallback: pixel-only `editImage` for “make background darker”

#### Credits (proposal)

| Feature | Suggested default | Notes |
|---------|-------------------|--------|
| Spec LLM | 1–2 AC **or** bundled | Only if charged separately |
| Infographic render (HD) | 12 AC | Align with HD image |
| Infographic tweak (pixel) | 12 AC | Same as HD |
| Spec revise + re-render | 12–14 AC | Product call |

Add `IMAGE_GEN_INFOGRAPHIC_AC` / `IMAGE_GEN_INFOGRAPHIC_SPEC_AC` in `imageGenCreditPricing.js`. Keep charge-on-success.

#### Context

Reuse existing context pipeline. Add guidance:

- Prefer **tables / bullet facts** in enrichment for `mode=infographic`  
- Optional: allow CSV in context MIME list later  
- Spec builder must mark unknown numbers as “—” rather than inventing when `doNotInventNumbers`

### 11.5 Code touch list (implementation checklist)

When you start coding, change in this order:

1. **Product contracts**  
   - Update Joi: `mode: image|infographic`, allow `infographic` object + `archetype`  
   - Catalogs: models.modes, formats composeRules for infographic, new archetypes file  

2. **Prompts**  
   - `prompts/infographicSpec.prompt.js` — LLM → InfographicSpec  
   - `prompts/infographicRender.prompt.js` — Spec → image prompt (mirror Path B style)  
   - Chat: `infographicChat.prompt.js` — user message → patched spec  

3. **Service**  
   - Branch in `runPipeline` on `mode` (stop hardcoding `const mode = 'image'`)  
   - `requireImageGeneration` → `requireStudioGeneration` allowing both modes  
   - Crop policy: `contain` for infographic  
   - Persist `infographicSpec` in `request`  

4. **Credits / estimate / history enrich**  
   - New feature keys + labels  

5. **Library / UI contracts**  
   - Threads already mode-agnostic if generation.mode is stored  
   - Folder cards may show a badge from `head` / generation mode  
   - Frontend: mode toggle, archetype picker, optional must-include chips  

6. **Docs + Postman**  
   - `IMAGE_GEN_API.md`, frontend guide, ENVIRONMENT.md, this file’s “status” table  

7. **Eval set**  
   - 20 fixed briefs (process / stats / comparison)  
   - Score: text legibility, number fidelity vs input, layout match to archetype  

### 11.6 Suggested delivery phases

| Phase | Deliverable | Outcome |
|-------|-------------|---------|
| **P0 Research spike (3–5 days)** | Prompt-only vs Spec-first prototypes; side-by-side on 10 briefs | Pick Option B (or document why not) |
| **P1 API unlock** | `mode=infographic` + archetypes + HD default + contain crop + docs | FE can wire mode toggle |
| **P2 Spec pipeline** | LLM spec → render; store snapshot; regenerate from spec | Quality bar for “v1” |
| **P3 Chat-on-spec** | Thread messages revise spec then re-render | Iteration feels intentional |
| **P4 Brand Kit** | Optional `brandKitId` → palette / logo watermark rules | Consistency with PPT |
| **P5 (optional)** | Social mode or editable canvas | Separate PRD |

### 11.7 Open decisions for your review

Please decide these before implementation starts:

1. **Scope of v1 archetypes** — all 7 above, or ship 3 (`process`, `stats`, `comparison`)?  
2. **Default model** — force HD for infographic, or let user pick?  
3. **Credits** — single flat AC vs (spec + render) breakdown in UI?  
4. **Data honesty** — hard fail if context lacks numbers, or allow “illustrative” placeholders?  
5. **Crop** — `contain` with light background vs letterbox-free `cover`?  
6. **Relationship to PPT Path B** — share prompt modules, or keep Image Gen prompts independent?  
7. **Social mode** — park forever, or schedule after infographic?  
8. **Brand Kit** — in v1 or v1.1?  

### 11.8 Suggested spike experiments (do this first)

1. Take one PDF brief + metrics → run **current** `image` mode with a hand-written “infographic” prompt. Capture failures (garbled text, invented numbers).  
2. Manually build an InfographicSpec JSON → Path-B-style prompt → `gpt-image-1` medium vs high. Compare.  
3. Same spec → tweak with chat (“swap step 2 and 3”) via **spec edit** vs **pixel edit**.  
4. Decide: is raster quality good enough for launch marketing screenshots?

If step 2 fails text quality badly, escalate Option C earlier (or reduce to “illustration with short labels only”).

### 11.9 What already exists to reuse

| Existing piece | Reuse for Infographics |
|----------------|------------------------|
| Threads / messages / library | Unchanged UX shell |
| Context upload + vision | Feed the spec LLM |
| `generateImage` / `editImage` | Render + pixel tweak |
| Path B `pathB.prompt.js` | Template for typesetting prompts |
| Brand palette field | Already on generate body |
| Credit ledger + rate limits | Extend with new feature keys |
| Export PNG/JPG/PDF | Unchanged |

| Do not reuse blindly | Why |
|----------------------|-----|
| Full-bleed `composeRules` | Fight chart layouts |
| `mode` hardcoded to `image` in `runPipeline` | Must branch |
| Joi `.forbidden()` on `infographic` | Must become the structured payload |
| PPT slide canvas | Wrong product surface for v1 |

---

## Part 12 — Review checklist (send this around)

**Current Image Gen (Parts 1–10)**

- [ ] Folder → chat → hop model is clear  
- [ ] Credits / rate limits / context TTL match product expectations  
- [ ] Sync 30–90s latency is acceptable for FE  
- [ ] Download formats and library cards are enough for GA of `image` mode  

**Infographics (Part 11)**

- [ ] Agree Option B (spec-first) or choose another  
- [ ] Answer open decisions §11.7  
- [ ] Approve phase plan §11.6  
- [ ] Assign owner for P0 spike eval set  

---

## Related docs

| Doc | Role |
|-----|------|
| [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md) | HTTP contract |
| [`IMAGE_GEN_FRONTEND_INTEGRATION.md`](IMAGE_GEN_FRONTEND_INTEGRATION.md) | FE flows |
| [`docs/api/ENVIRONMENT.md`](api/ENVIRONMENT.md) | Env vars |
| [`AI_PPT_GENERATION_COMPLETE.md`](AI_PPT_GENERATION_COMPLETE.md) | PPT Path B (related diagram technique) |
| [`CREDITS_FRONTEND_INTEGRATION.md`](CREDITS_FRONTEND_INTEGRATION.md) | Shared credit UX |

---

*This file is the review + planning source of truth for Image Gen and Infographics mode. Update the status table at the top when Infographics ships.*
