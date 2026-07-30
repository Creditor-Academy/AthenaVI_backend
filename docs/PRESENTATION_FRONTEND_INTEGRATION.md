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

1. `POST .../presentations` `{ title, folderId, themeId?, createMode: "blank" }`  
2. Optional: show credit estimate `GET .../credit-estimate`  
3. `POST .../outline` `{ source: "prompt", prompt: "<flattened string>", slideCount, density }`  
   - Flatten voice/tone/audience into the **string** `prompt` (no nested prompt object).  
4. Optional: `PATCH .../outline` if user edits outline cards  
5. `POST .../theme` `{ themeId }` and/or `themeTokens`  
6. `POST .../generate` → **202** → poll `GET .../status` until `READY` / `FAILED`  
7. Open canvas editor on `GET .../presentations/:id` (slides include `elements`)

### B — Create blank (Canva-style)

1. `POST .../presentations` `{ title, folderId, createMode: "blank" }`  
2. `POST .../slides` to add slides  
3. Insert elements from palette / drag on canvas → `PUT .../canvas` or element CRUD  
4. Export when ready

### C — Create from layout template

1. `GET .../presentation-templates` → picker  
2. `POST .../presentations` `{ title, folderId, createMode: "template", templateId }`  
3. Edit the first slide’s canvas; add more slides as needed

All three paths share the **same editor** surface.

---

## Workspace pickers (load once for editor chrome)

Base: `/api/workspaces/:workspaceId`

| UI | Method | Path |
|----|--------|------|
| Layout / template gallery | `GET` | `/presentation-templates?contentType=` |
| Theme picker | `GET` | `/presentation-themes` |
| Insert palette | `GET` | `/presentation-elements` |

Theme ids look like `midnight_blue` (underscores), not `dark-professional`.

Element catalog returns presets (`presetId`, `type`, `label`, `defaultPlacement`, `defaultContent`).  
On insert: `POST .../slides/:slideId/elements` with `{ "presetId": "text_title" }` (and optional overrides).

---

## Canvas data (render & save)

Default canvas: **1920 × 1080** (16:9).

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
| `image` / `icon` | `url`, `fit`, `alt` / `icon` |
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
| Add slide | `POST` | `/slides` | Optional `afterSlideId`, `templateId`, `content` |
| Delete | `DELETE` | `/slides/:slideId` | |
| Duplicate | `POST` | `/slides/:slideId/duplicate` | Fails at deck cap 40 |
| Reorder | `PATCH` | `/slides/reorder` | `{ "slideIds": ["…"] }` all ids once |
| Apply layout | `POST` | `/slides/:slideId/apply-layout` | `{ "templateId" }` rebuilds `elements` |
| Patch fields | `PATCH` | `/slides/:slideId` | `content`, `layoutId`, `imageRef`, `elements`, … |
| AI regen one slide | `POST` | `/slides/:slideId/regenerate` | `{ target, overwriteManualEdits }` |

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

| | PPT (`DECK_LAYOUT`) | Video (`VIDEO_SCENE`) |
|--|---------------------|------------------------|
| Workspace list | `GET .../presentation-templates` | `GET .../video-templates` |
| Apply | `createMode: "template"` / `apply-layout` | Create project `templateId` / `scenes/from-template` |
| Schema | `layout_id`, `grid`, `slots[]` | `scene.elements` with frames |

### Superadmin template CRUD (admin portal)

`/api/superadmin/templates` — platform superadmin only.

- **`type` required** on create: `DECK_LAYOUT` | `VIDEO_SCENE`  
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
- [ ] Per-slide “Regenerate” with overwrite confirm if `manuallyEdited`  
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

Postman: folder **Presentations (AI PPT)** in `postman/AthenaVI_Backend.postman_collection.json`.
