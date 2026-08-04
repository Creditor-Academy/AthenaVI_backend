# Presentations & templates — frontend integration guide

Single guide for frontend / UI work on **AI PPT (Canvas)** and **templates**.  
Canonical HTTP details: [`docs/api/PRESENTATION_API.md`](api/PRESENTATION_API.md) · credits: [`PRESENTATION_CREDITS_FRONTEND.md`](PRESENTATION_CREDITS_FRONTEND.md) · video editor templates (separate product): see [Video templates](#video-templates-do-not-mix-with-ppt) below.

---

## Mental model

```
Workspace → Folder → Project (type: PRESENTATION)
                        └── Deck + Slides
                              └── each slide: content + freeform elements[] (canvas)
```

| Concept | ID to use in routes |
|---------|---------------------|
| Presentation | **`project.id`** (`presentationId`) |
| Deck | `deck.id` (rarely needed in URLs) |
| Slide | `slide.id` |
| Element | `element.id` inside `slide.elements.elements[]` |

**Do not** send one mega “final deck JSON” as a single create body. Keep prompt/vibe in UI state; call the multi-step APIs below.

**Auth:** `Authorization: Bearer <accessToken>`  
**Roles:** workspace `OWNER` | `ADMIN` | `MEMBER`  
**Envelope:** `{ success, message, data }` / `{ success: false, message, errors }`

---

## Caps (show in UI)

| Limit | Value | UX hint |
|-------|-------|---------|
| AI outline / generate | **5–20** slides | Slide-count stepper on AI create |
| Deck total (manual add/duplicate) | **40** | Disable “Add slide” at 40 |
| Elements per slide | **50** | Disable palette insert at 50 |

After AI fills ≤20 slides, user can still **add more manually** up to 40.

---

## Product flows (wire the UI to these)

### A — Create with AI

1. `POST .../presentations` `{ folderId, themeId?, createMode: "blank" }` — **title optional** (defaults to `Untitled Presentation`)  
2. Optional: show credit estimate `GET .../credit-estimate`  
3. `POST .../outline` `{ source: "prompt", prompt: "<flattened string>", slideCount, density }`  
   - Flatten voice/tone/audience into the **string** `prompt` (no nested prompt object).  
   - Response includes **`presentation.title`** (generated from the prompt) and `outline`. Persist/use that title in the UI.  
4. Optional: `PATCH .../outline` if user edits outline cards (also updates presentation title when `outline.title` changes)  
5. `POST .../theme` `{ themeId }` and/or `themeTokens`  
6. `POST .../generate` → **202** → optionally include **`generationFlow`** (wizard selections: tone, colorTheme, imageType, canvasSize, …) → poll `GET .../status` until `READY` / `FAILED`  
7. Open canvas editor on `GET .../presentations/:id` (slides include `elements`)

`generationFlow` is additive. Without it, generate behaves as before. With it, backend persists the flow and applies theme / image mode / canvas / copy brief. `selections.slideCount` does not resize the deck.

### B — Create blank (Canva-style)

1. `POST .../presentations` `{ title?, folderId, createMode: "blank" }`  
2. `POST .../slides` to add slides (manual), or with AI:

```json
{
  "generate": true,
  "prompt": "Competitive landscape for Athena VI",
  "target": "all"
}
```

3. Insert elements from palette / drag on canvas → `PUT .../canvas` or element CRUD  
4. On an existing slide, rewrite with AI:

```json
POST .../slides/:slideId/regenerate
{ "target": "content", "prompt": "…", "overwriteManualEdits": true }
```

5. Export when ready

Poll `GET .../status` (or refetch the presentation) while a slide is `GENERATING`.

### C — Create from layout template

1. `GET .../presentation-templates` → picker
2. `POST .../presentations` `{ title, folderId, createMode: "template", templateId }`
3. Edit the first slide’s canvas; add more slides as needed

### D — Create from deck pack (Canva-style) + Brand Kit

1. Settings: create Brand Kit via `/brand-kits` (colors, fonts, logos, photos, voice) — see [`docs/api/BRAND_KIT_API.md`](api/BRAND_KIT_API.md)
2. `GET .../presentation-deck-packs` → pack picker
3. `POST .../presentations` `{ folderId, createMode: "pack", packId, brandKitId? }`
4. Edit canvas; optional `POST .../apply-brand-kit` later
5. For AI: outline → generate with `generationFlow.selections.packId` + `brandKitId` (content + images fill the branded layouts; brand photos preferred)

Canvas-published packs (`meta.authoredVia: "canvas"`) clone designed `snapshot.elements`. When `meta.aiReady` / role-tagged elements exist, generate **rebinds** text/images in place instead of recompiling from layout slots.

**Superadmin authoring:** design in the editor → `POST /api/superadmin/presentations/:presentationId/publish-as-pack` (see [`SUPERADMIN_API.md`](api/SUPERADMIN_API.md)). JSON seed/admin create still works.

All paths share the **same editor** surface.

---

## Workspace pickers (load once for editor chrome)

Base: `/api/workspaces/:workspaceId`

| UI | Method | Path |
|----|--------|------|
| Layout / template gallery | `GET` | `/presentation-templates?category=` (tabs from `categories[]`) or `?contentType=` |
| Deck packs (multi-slide) | `GET` | `/presentation-deck-packs` |
| Brand Kits | `GET` | `/brand-kits` |
| Theme picker | `GET` | `/presentation-themes` |
| Insert palette | `GET` | `/presentation-elements` |

Theme ids look like `midnight_blue` (underscores), not `dark-professional`.

**Layout gallery tabs:** use `data.categories` from `/presentation-templates` (`id` + `label`). Filter with `?category=people_and_team`. Each template has `contentType` (AI tag) and `categories[]`. New types: `grid`, `pricing`, `device_frames`.

Element catalog returns presets (`presetId`, `type`, `label`, `defaultPlacement`, `defaultContent`).  
On insert: `POST .../slides/:slideId/elements` with `{ "presetId": "text_title" }` (and optional overrides).

---

## Canvas data (render & save)

Default canvas: **1920 × 1080** (16:9). Create/generate also accept **`4:3`** (1600 × 1200) via `aspectRatio` / `generationFlow.selections.canvasSize`. PPT aspect ratios are **`16:9` and `4:3` only**.

**schemaVersion 2 elements:** shapes may use `content.fill` as `{ type: "solid"|"gradient", ... }`; text may include `fontWeight`, `letterSpacing`, `lineHeight`, `colorRole`. Resolve palette tokens from `deck.themeTokens.palette` (includes `accent`, `cardBg`, `gradientStart`, `gradientEnd`). Pack clone emits background + accent decorations without AI.

GET presentation returns nested `{ project, deck, slides }` **plus** flat `id`, `title`, `status`, `themeTokens`, … for FE PDF contract compatibility.

### Visuals / images

AI generate **prefers a supporting image on nearly every slide** (stock → AI Path A) unless the outline/prompt opts out (`text-only` / `no images`) or the slide is a chart/path_b diagram.

After generate, each slide should include either:

- `elements.elements[]` item with `type: "image"` and `content.url` (presigned), or
- `imageRef: { source: "ai_gen"|"stock"|"path_b", url, s3Key, status: "ready" }`

| `imageRef.status` | Meaning |
|-------------------|---------|
| `ready` | Image URL available |
| `failed` | Image generation/upload failed — see `imageRef.error` (slide content may still be READY) |
| `skipped` | No image required for this slide (`visual_need` chart/none/etc.) |

FE: show “No visuals” only when `status === "skipped"` or there is no image element. For `failed`, show the error / retry (`POST .../regenerate` with `target: "image"`).

```json
{
  "version": 1,
  "canvas": { "width": 1920, "height": 1080 },
  "elements": [
    {
      "id": "el_…",
      "type": "text",
      "layer": 1,
      "placement": {
        "x": 160,
        "y": 200,
        "width": 1600,
        "height": 140,
        "rotation": 0,
        "opacity": 1
      },
      "content": { "text": "Title", "fontSize": 44, "bold": true, "align": "left" },
      "role": "title"
    }
  ]
}
```

| `type` | Typical `content` |
|--------|-------------------|
| `text` | `text`, `fontSize`, `bold`, `italic`, `color`, `align` |
| `image` / `icon` | `url` (presigned S3 GET, ~1h TTL — refetch presentation if expired), `fit`, `alt` / `icon` |

**Images / “Visual failed”:** After generate, refetch `GET .../presentations/:id`. Render canvas `type: "image"` via `content.url`, or `slide.imageRef.url`. If `imageRef.source === "none"` and `imageRef.error` is set, that slide’s visual failed on the server (content timeout or image provider). Many slides legitimately have no image (`source: "none"` without `error`) when the classifier picks text/chart layouts.
| `shape` | `shape`: `rect` \| `ellipse` \| `line`, `fill`, `line` |
| `chart` | `chartType`, `labels`, `series` |
| `table` | `rows`: string[][] |

**Drag / resize / snap / guides:** frontend only. Persist with:

- Autosave whole slide: `PUT .../slides/:slideId/canvas` (body = canvas doc above)  
- Or granular: `POST` / `PATCH` / `DELETE` `.../elements...` and `PATCH .../elements/reorder`

Writes set `manuallyEdited: true` on the slide.

Sort draw order by `layer` ascending.

---

## Slide structure APIs

Base: `/api/workspaces/:workspaceId/presentations/:presentationId`

| Action | Method | Path | Notes |
|--------|--------|------|-------|
| Add slide | `POST` | `/slides` | Optional `afterSlideId`, `templateId`, `content`; set `generate: true` + `prompt` (or `content.title`) for add+AI |
| Delete | `DELETE` | `/slides/:slideId` | |
| Duplicate | `POST` | `/slides/:slideId/duplicate` | Fails at deck cap 40 |
| Reorder | `PATCH` | `/slides/reorder` | `{ "slideIds": ["…"] }` all ids once |
| Apply layout | `POST` | `/slides/:slideId/apply-layout` | `{ "templateId" }` rebuilds `elements` |
| Patch fields | `PATCH` | `/slides/:slideId` | `content`, `layoutId`, `imageRef`, `elements`, … |
| AI regen one slide | `POST` | `/slides/:slideId/regenerate` | `{ target, overwriteManualEdits, prompt? }` |

While `deck.status === "GENERATING"`, structure/canvas mutations → **409**. Show a blocking “Generating…” state.

---

## AI outline / generate (status UX)

| Step | Call |
|------|------|
| Outline | `POST .../outline` — `source`: `prompt` \| `outline` \| `document` (multipart `file`) |
| Edit outline | `PATCH .../outline` — full outline object |
| Theme | `POST .../theme` |
| Start generate | `POST .../generate` → **202** |
| Poll | `GET .../status` → `progress`, `etaSeconds`, `slides[].status`, `creditsChargedSoFar` |

Slide statuses: `PENDING` | `GENERATING` | `READY` | `FAILED`  
Deck: `DRAFT` | `GENERATING` | `READY` | `FAILED`

Regenerate respects `manuallyEdited` unless `overwriteManualEdits: true` (**409** otherwise). Confirm in UI before overwrite.

On blank decks (no outline), pass **`prompt`** on regenerate (or set `content.title` first) so the content LLM has context.

---

## Export

`POST .../export`

```json
{ "format": "PPTX", "slideId": null }
```

| `format` | Result |
|----------|--------|
| `PPTX` / `PDF` | Single file (elements-aware; legacy fallback if no `elements`) |
| `PNG` / `JPEG` | One slide → image; full deck → **ZIP** of slides |

Then poll `GET .../export/:exportId` until `READY` → use `presignedUrl`.

Inbox may notify `PRESENTATION_EXPORT_COMPLETED` / `FAILED`.

---

## Credits (short)

- Same **workspace** credit pool as the rest of the app; feature keys are `ppt_*` (not HeyGen).  
- Estimate: `GET .../credit-estimate?slideCount=`  
- **402** = insufficient credits. Refresh balances after outline / generate / export.  
- Slide CRUD / canvas edits are **free**; AI outline, generate pieces, and export charge.  

Details: [`PRESENTATION_CREDITS_FRONTEND.md`](PRESENTATION_CREDITS_FRONTEND.md).

---

## Listing projects in a folder

`GET /api/workspaces/:workspaceId/projects?folderId=`

Filter UI by `project.type === "PRESENTATION"` vs `"VIDEO"`.  
Open presentations in the PPT editor; video projects in the video editor.

---

## Templates: PPT vs video (do not mix)

| | PPT layout (`DECK_LAYOUT`) | PPT pack (`DECK_PACK`) | Video (`VIDEO_SCENE`) |
|--|----------------------------|------------------------|------------------------|
| Workspace list | `GET .../presentation-templates` | `GET .../presentation-deck-packs` | `GET .../video-templates` |
| Apply | `createMode: "template"` / `apply-layout` | `createMode: "pack"` + AI whitelist | Create project `templateId` / `scenes/from-template` |
| Schema | `layout_id`, `grid`, `slots[]` | `pack_id`, `slides[]`, `themeId` | `scene.elements` with frames |

Brand Kit is separate (workspace-owned look). Docs: [`BRAND_KIT_API.md`](api/BRAND_KIT_API.md).

### Superadmin template CRUD (admin portal)

`/api/superadmin/templates` — platform superadmin only.

- **`type` required** on create: `DECK_LAYOUT` | `DECK_PACK` | `VIDEO_SCENE`  
- Activate: `PATCH { "isActive": true|false }`  
- Can update `contentType`, `variant`, `name`, `schema`  

**DECK_LAYOUT create body example:**

```json
{
  "type": "DECK_LAYOUT",
  "name": "Title Centered",
  "contentType": "title",
  "variant": "v1",
  "schema": {
    "layout_id": "title_centered_v1",
    "content_type": "title",
    "grid": "12-col",
    "slots": [
      { "id": "title", "region": "cols 2-11, rows 4-7", "max_lines": 3 }
    ]
  }
}
```

---

## Video templates (video studio only)

Not part of the PPT canvas. For the video editor:

| Action | Path |
|--------|------|
| List | `GET /api/workspaces/:workspaceId/video-templates` |
| Get one | `GET .../video-templates/:templateId` |
| New project from template | `POST .../projects` + `templateId` |
| Append scene | `POST .../projects/:projectId/scenes/from-template` `{ "templateId" }` |

Docs: [`WORKSPACE_API.md`](api/WORKSPACE_API.md) · [`PROJECT_EDITOR_INTEGRATION.md`](PROJECT_EDITOR_INTEGRATION.md).

---

## Common HTTP statuses

| Code | Meaning |
|------|---------|
| 400 | Validation / bad body / caps exceeded |
| 401 | Missing/invalid token |
| 402 | Not enough credits |
| 403 | Not a workspace member / not superadmin |
| 404 | Presentation, slide, template, export missing |
| 409 | Generating in progress, or manual-edit overwrite blocked |
| 429 | Generate/regenerate rate limit |

---

## Suggested UI checklist

- [ ] Create modal: **AI | Blank | Template**  
- [ ] Theme + layout pickers from workspace GET endpoints  
- [ ] AI: outline review → generate progress bar (`status`)  
- [ ] Canvas: 1920×1080 stage, palette from `presentation-elements`, autosave canvas  
- [ ] Slide rail: add / delete / duplicate / reorder; disable add at 40  
- [ ] Per-slide “Regenerate” with `prompt` (blank decks) + overwrite confirm if `manuallyEdited`  
- [ ] “Add slide with AI” → `POST .../slides` `{ generate: true, prompt }` then poll status  
- [ ] Export menu: PPTX, PDF, PNG, JPEG; poll + download  
- [ ] Credit estimate before AI generate / export; handle 402  
- [ ] Folder list: badge/filter by `project.type`  
- [ ] Admin: separate screens for `DECK_LAYOUT` vs `VIDEO_SCENE` template forms  

---

## Quick route map (PPT)

```
POST   /api/workspaces/:workspaceId/presentations
GET    /api/workspaces/:workspaceId/presentation-templates
GET    /api/workspaces/:workspaceId/presentation-themes
GET    /api/workspaces/:workspaceId/presentation-elements

GET    /api/workspaces/:workspaceId/presentations/:presentationId
GET    .../status
GET    .../credit-estimate
POST   .../outline
PATCH  .../outline
POST   .../theme
POST   .../generate

POST   .../slides
DELETE .../slides/:slideId
POST   .../slides/:slideId/duplicate
PATCH  .../slides/reorder
POST   .../slides/:slideId/apply-layout
PUT    .../slides/:slideId/canvas
POST   .../slides/:slideId/elements
PATCH  .../slides/:slideId/elements/:elementId
DELETE .../slides/:slideId/elements/:elementId
PATCH  .../slides/:slideId/elements/reorder
PATCH  .../slides/:slideId
POST   .../slides/:slideId/regenerate

POST   .../export
GET    .../export/:exportId
```

Postman collection `postman/collections/AthenaVI Backend/` (v3 YAML):

- Folder **Presentations (AI PPT)** — subfolders `0. Pickers` … `6. Export` (URLs use `/api/...`)
- Folder **Superadmin templates** — `DECK_LAYOUT` / `VIDEO_SCENE` admin CRUD
- Folder **Video templates** — video editor only (do not use for PPT)
