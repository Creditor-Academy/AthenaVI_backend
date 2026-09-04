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
2. `GET .../presentation-deck-packs` → pack picker (summary cards)
3. On pack drill-down: `GET .../presentation-deck-packs/:packId` → slide grid (`slidePreviews[]`, full `schema.slides`)
4. `POST .../presentations` `{ folderId, createMode: "pack", packId, brandKitId? }`
5. Edit canvas; optional `POST .../apply-brand-kit` later
6. For AI: outline → generate with `generationFlow.selections.packId` + `brandKitId` (content + images fill the branded layouts; brand photos preferred)

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
| Deck pack detail (slide grid) | `GET` | `/presentation-deck-packs/:packId` |
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
| `image` / `icon` | `url` (presigned S3 GET, ~1h TTL — refetch presentation if expired), `fit`, `alt` / `icon`, optional `flipHorizontal` / `flipVertical` |
| `shape` | `shape`: `rect` \| `ellipse` \| `line`, `fill`, `line` |
| `chart` | `chartType`, `labels`, `series` |
| `table` | `rows`: string[][] |

**Flip / rotate (canvas editor):** Persist image flips on `content.flipHorizontal` / `content.flipVertical` (also `scaleX` / `scaleY` of `-1`). Persist rotation on `placement.rotation` (degrees) for **images and text**. The editor snaps live mouse rotation to 90° detents.

**Images / “Visual failed”:** After generate, refetch `GET .../presentations/:id`. Render canvas `type: "image"` via `content.url`, or `slide.imageRef.url`. If `imageRef.source === "none"` and `imageRef.error` is set, that slide’s visual failed on the server (content timeout or image provider). Many slides legitimately have no image (`source: "none"` without `error`) when the classifier picks text/chart layouts.

**Drag / resize / snap / guides:** frontend only. Persist with:

- Autosave whole slide: `PUT .../slides/:slideId/canvas` (body = canvas doc above)  
- Or granular: `POST` / `PATCH` / `DELETE` `.../elements...` and `PATCH .../elements/reorder`

Writes set `manuallyEdited: true` on the slide (except progress-only `PATCH` of `progressStatus`).

### Slide progress status (for reviewers)

Editors mark each slide’s workflow progress. Default is **no status** (`progressStatus: null`).

| Value | UI label |
|---|---|
| `null` | None |
| `TODO` | Todo |
| `IN_PROGRESS` | In progress |
| `COMPLETED` | Completed |

```
PATCH …/slides/:slideId
{ "progressStatus": "IN_PROGRESS" }   // set
{ "progressStatus": null }            // clear
```

- Show a chip/dropdown on the **editor** slide rail.
- On `/p/:token`, show chips **only** when `linkRole === "reviewer"` (deck slides include `progressStatus`). Viewer links omit the field — hide the UI.
- Guests cannot set progress. AI regenerate preserves the value. Duplicate copies it.

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
| Patch fields | `PATCH` | `/slides/:slideId` | `content`, `layoutId`, `imageRef`, `elements`, `progressStatus` (`TODO`\|`IN_PROGRESS`\|`COMPLETED`\|`null`), … |
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

## Share & present mode (viewer + reviewer links + live viewers + comments)

Canva-style preview sharing. The owner enables **viewer** and/or **reviewer** links independently. Anyone with a link can page through the deck; only the **reviewer** link allows public comments. Nobody on a link can edit slides. Viewers on either URL appear in the **same live viewer list**. Guests appear as `Anonymous viewer`.

### Owner: the share modal

Two cards — **Viewer** and **Reviewer** — each with Enable toggle, Copy URL, and Regenerate. No expiry UI.

| Action | Call |
|---|---|
| Open modal | `GET .../presentations/:id/share` → `{ viewer, reviewer }` |
| Enable viewer link | `PUT .../presentations/:id/share/viewer` |
| Enable reviewer link | `PUT .../presentations/:id/share/reviewer` |
| Disable / re-enable | `PATCH .../share/viewer` or `.../share/reviewer` `{ enabled }` |
| Reset link | `POST .../share/viewer/rotate` or `.../share/reviewer/rotate` |

Each card reads from `data.viewer` or `data.reviewer`. When `exists: false`, show Enable (calls `PUT`). When `exists: true`, show `link.url` + `link.token` in a copyable field.

- Rotate = **"Reset link"** for that card only. Say plainly that everyone who already has the old URL for that link type loses access.
- Turning a link **off** and back **on** keeps the same URL working — use disable (not rotate) for a temporary pause. `link.url` is still shown while disabled; guests get 404 until you re-enable.
- `PUT` / re-enable via `PATCH { enabled: true }` returns **409** while the deck is generating.
- If an older link has no `link.url` (pre-persistence rows), call **rotate** once for that role to mint a recoverable URL.
- You can enable viewer only, reviewer only, or both. Do not auto-enable the other type when one is turned on.

### Viewer: the `/p/:token` page

Public route in your app. Send `Authorization: Bearer <accessToken>` **if** the user happens to be logged in; omit it otherwise. Never redirect a guest to login.

1. `GET /api/p/:token` → deck. Cache the response `ETag` and send it as `If-None-Match` on refetch (**304** = nothing changed).
2. `GET /api/p/:token/session` → `linkRole`, `self.displayName`, `canComment` / `canResolveComments`, and `canOpenInEditor` (+ `workspaceId` / `presentationId`) for members.
3. `PUT /api/p/:token/presence` every **10–15s** with `{ viewerSessionId, slideIndex }` → live viewer list (unified across viewer and reviewer URLs).
4. `DELETE /api/p/:token/presence?viewerSessionId=…` on unload (best-effort; the server drops silent viewers after 45s anyway).
5. If `canComment` (reviewer link only), `GET /api/p/:token/comments?slideId=…` for the current slide and render the composer.

**`viewerSessionId`**: generate a UUID once, persist in `localStorage`, reuse across reloads. It identifies guests for presence **and proves comment authorship**, so the same value must survive reloads or a guest loses the ability to edit their own comments. Logged-in users are keyed by account so multiple tabs collapse into one avatar.

**Rendering the room:** `viewerCount` is the true total; `viewers` holds at most the 50 most recently active. Render avatars from `viewers` and "+N more" from `viewerCount - viewers.length`. Each viewer carries `slideIndex`, so you can show who is on which slide. Do not display a name you computed yourself — `displayName` is always server-side, and any `displayName` you send is ignored.

**Live updates:** every presence response includes `contentUpdatedAt` and `commentsUpdatedAt`. Refetch the deck **only** when `contentUpdatedAt` differs from the value you rendered, and the comment list only when `commentsUpdatedAt` differs. Do not poll `GET /api/p/:token` on a timer; it is the expensive call.

### Viewer comments

Only when session `canComment` is true (`linkRole === "reviewer"`). Full contract: [`PRESENTATION_COMMENTS_API.md`](api/PRESENTATION_COMMENTS_API.md).

| Action | Call |
|---|---|
| Load slide thread | `GET /api/p/:token/comments?slideId=…` |
| Post thread | `POST /api/p/:token/comments` `{ body, slideId, viewerSessionId, displayName }` |
| Reply | `POST /api/p/:token/comments` `{ body, parentId, viewerSessionId, displayName }` |
| Edit own | `PATCH /api/p/:token/comments/:commentId` `{ body, viewerSessionId }` |
| Delete own | `DELETE /api/p/:token/comments/:commentId?viewerSessionId=…` |

- **Guests need a name.** Prompt once for `displayName` (1–80 chars), keep it in `localStorage` next to `viewerSessionId`, and send both on every write. Without a name the server returns **400**.
- For a logged-in visitor, skip `displayName` — the account name always wins and anything you send is ignored.
- Guests and logged-in non-members cannot `@mention` (the field is dropped) and get **403** on resolve. Gate those controls on `canResolveComments`.
- Only comments on finished slides come back here, so a thread can be invisible on the link while still present in the editor.
- A viewer link answers `GET /comments` with an empty list rather than an error — hide the panel entirely when `canComment: false` (including members on a viewer URL).
- After a successful write, refetch the slide's thread; the next presence tick will also show the new `commentsUpdatedAt`.

**During a regeneration:** the deck call still returns 200, but `status` is `GENERATING` and `slides` holds only finished slides. Show an "Updating…" state instead of an error, and let the presence poll tell you when new slides land.

**Security requirements for the page:**

- Send `Referrer-Policy: no-referrer` on the `/p/:token` document. Slide images are presigned S3 URLs, and without this the token can leak into access logs through the `Referer` header.
- Keep the token out of analytics events, error reports, and page titles.
- Treat slide content as read-only: no editor API calls and no autosave. Comments are the only write this page may make, and only through `/api/p/:token/comments`.
- Unknown and disabled links return **404** with the same message. Show one "This link isn't available" screen — don't try to distinguish them.
- **429** means the link is being hammered; back off using `Retry-After` rather than retrying immediately.

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
- [ ] Comments sidebar filtered by selected slide; replies + resolve; `@` picker from `mentionable-users`  
- [ ] Editor shows orphaned threads (`orphaned=true`) so feedback survives a full regenerate  
- [ ] Share modal: two cards (Viewer | Reviewer) bound to `data.viewer` / `data.reviewer`
- [ ] Slide progress chip in editor (`progressStatus`); show on `/p` only for reviewer links  
- [ ] `/p/:token` page: composer gated on `canComment` / `linkRole`, guest name prompt, refetch on `commentsUpdatedAt`  
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

GET    .../share
PUT    .../share/viewer
PUT    .../share/reviewer
PATCH  .../share/viewer
PATCH  .../share/reviewer
POST   .../share/viewer/rotate
POST   .../share/reviewer/rotate

GET    .../comments
POST   .../comments
PATCH  .../comments/:commentId
DELETE .../comments/:commentId
POST   .../comments/:commentId/resolve
POST   .../comments/:commentId/unresolve
GET    .../comments/mentionable-users

GET    /api/p/:token
GET    /api/p/:token/session
PUT    /api/p/:token/presence
GET    /api/p/:token/presence
DELETE /api/p/:token/presence
GET    /api/p/:token/comments
POST   /api/p/:token/comments
PATCH  /api/p/:token/comments/:commentId
DELETE /api/p/:token/comments/:commentId
POST   /api/p/:token/comments/:commentId/resolve
POST   /api/p/:token/comments/:commentId/unresolve
```

Postman collection `postman/collections/AthenaVI Backend/` (v3 YAML):

- Folder **Presentations (AI PPT)** — subfolders `0. Pickers` … `7. Share` (URLs use `/api/...`)
- Folder **Superadmin templates** — `DECK_LAYOUT` / `VIDEO_SCENE` admin CRUD
- Folder **Video templates** — video editor only (do not use for PPT)
