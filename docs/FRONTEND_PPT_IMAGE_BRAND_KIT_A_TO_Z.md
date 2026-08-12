# Athena VI — PPT · Image Gen · Brand Kit  
## Frontend integration guide (A → Z, self-contained)

This document is the **single source** for frontend engineers integrating three new product surfaces:

1. **Brand Kit** — Canva-style workspace branding (colors, fonts, logos, photos, voice)
2. **Presentations (AI PPT)** — create / outline / generate / canvas edit / export, including **deck packs** and Brand Kit apply
3. **Image Gen** — AI image studio (general, infographic, social) with regenerate / tweak / download

Everything needed for integration is **in this file**: auth, roles, envelopes, request/response shapes, flows, credits, caps, seeded catalogs, superadmin template CRUD, and UI checklists. Do not rely on other docs to ship these three features.

---

# Part 0 — Shared platform conventions

## 0.1 Base URL

All routes are under `/api`.

Examples:

- Local: `http://localhost:9000/api`
- Production: `https://<your-api-domain>/api`

Default local server port: **9000**.

## 0.2 Response envelope

**Success**

```json
{
  "success": true,
  "message": "Human-readable message or null",
  "data": { }
}
```

**Error**

```json
{
  "success": false,
  "message": "Error summary",
  "errors": []
}
```

HTTP status is set on the response. `errors` may be a Joi validation list or empty.

## 0.3 Authentication

| Piece | How |
|-------|-----|
| Access | `Authorization: Bearer <accessToken>` on every protected route |
| Refresh | httpOnly cookie `refreshToken`; `POST /api/auth/refresh` with `credentials: 'include'` |
| Login | Normal app login (`POST /api/auth/login` or Google OAuth). Same JWT for users and platform superadmins |

On **401**, refresh then retry once. Do not store refresh tokens in JS — cookie only.

## 0.4 Roles (do not confuse these)

| Role | Scope | Used for |
|------|-------|----------|
| Workspace **OWNER** / **ADMIN** / **MEMBER** | `/api/workspaces/:workspaceId/...` | Brand Kit write vs read; presentations; packs |
| Platform **superadmin** | `/api/superadmin/...` | Template CRUD (`DECK_LAYOUT`, `DECK_PACK`, `VIDEO_SCENE`, `VIDEO_PACK`), canvas publish, credits/storage admin |

Platform superadmin ≠ workspace ADMIN. Superadmin is checked server-side (`User.isPlatformSuperadmin` or email in `PLATFORM_SUPERADMIN_EMAILS`). UI may show a portal toggle from `GET /api/user/capabilities` (`canAccessSuperadminPortal`) — never trust that flag for security.

## 0.5 Credits (shared pool)

All three features bill against the **same Athena Credits (AC) workspace billing pool**:

- **PRIVATE** workspace → owner's personal credits  
- **TEAM** workspace → workspace pool  

Insufficient → **402**. Refresh balances after successful AI/export charges. Slide canvas edits and Brand Kit CRUD (except storage) are free. Image Gen downloads are free.

## 0.6 Common HTTP statuses

| Code | Meaning |
|------|---------|
| 400 | Validation / bad body / caps |
| 401 | Missing or invalid access token |
| 402 | Insufficient credits |
| 403 | Not a workspace member / not superadmin / insufficient workspace role |
| 404 | Resource missing |
| 409 | Conflict (e.g. generating in progress; manual-edit overwrite blocked) |
| 429 | Rate limited |
| 502 / 503 | Upstream AI provider failure / not configured |

## 0.7 How the three features relate

```
┌─────────────────────────────────────────────────────────────────┐
│ Superadmin                                                       │
│  POST/PATCH /api/superadmin/templates                            │
│   → DECK_LAYOUT (single-slide layouts)                           │
│   → DECK_PACK   (multi-slide packs referencing layouts + theme)  │
└────────────────────────────┬────────────────────────────────────┘
                             │ active templates appear in workspace pickers
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Workspace settings                                               │
│  Brand Kits  /api/workspaces/:id/brand-kits                      │
│  (colors, fonts, logos, photos, voice)                           │
└────────────────────────────┬────────────────────────────────────┘
                             │ brandKitId / themeTokens
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Presentations (AI PPT)                                           │
│  create blank | template | pack + optional brandKitId            │
│  outline → generate (packId + brandKitId in generationFlow)      │
│  canvas edit → export PPTX/PDF/PNG/JPEG                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Image Gen (separate studio, same workspace + credits)            │
│  /api/image-gen/...  → Asset (source: ai_gen)                    │
│  Optional: brandPalette / headlines inspired by Brand Kit colors │
│  Outputs usable in assets library; not auto-wired into PPT yet   │
└─────────────────────────────────────────────────────────────────┘
```

**Theme precedence on a presentation:**  
Brand Kit → deck pack `themeId` → wizard `colorTheme` / explicit `themeId` → catalog default.

---

# Part 1 — Brand Kit (workspace branding)

Canva-style **workspace Brand Kits**. Scoped to one workspace. Used by presentations on create, generate, and apply.

## 1.1 Base path & auth

```
/api/workspaces/:workspaceId/brand-kits
```

| Action | Role |
|--------|------|
| List / get | OWNER, ADMIN, MEMBER |
| Create / update / delete / set-default / media | OWNER or ADMIN |

## 1.2 Data shape (`data` JSON on the kit)

```json
{
  "colors": [
    { "id": "c1", "name": "Navy", "hex": "#0B1220" },
    { "id": "c2", "name": "Blue", "hex": "#3B82F6" },
    { "id": "c3", "name": "White", "hex": "#F8FAFC" }
  ],
  "colorRoles": {
    "bg": "c1",
    "text": "c3",
    "primary": "c2",
    "secondary": "c2",
    "muted": "c3",
    "accent": "c2"
  },
  "fonts": {
    "heading": { "fontPairingId": "inter_space", "family": "Inter" },
    "body": { "fontPairingId": "inter_space", "family": "Inter" },
    "tertiary": { "fontPairingId": null, "family": null }
  },
  "voice": {
    "tone": "Professional, confident",
    "audience": "Enterprise buyers",
    "dos": ["Use short sentences"],
    "donts": ["No slang"],
    "vocabulary": ["Athena VI"]
  },
  "chartStyles": { "colorIds": ["c2", "c3"] },
  "imageStyle": "clean product photography, brand-safe"
}
```

### Validation rules (enforce in forms)

| Field | Rules |
|-------|--------|
| `colors` | 2–32 entries; each needs `id`, `name`, `hex` (`#RGB` or `#RRGGBB`) |
| `colorRoles.bg`, `.text`, `.primary` | **Required**; must reference a color `id` |
| `colorRoles.secondary`, `.accent`, `.muted` | Optional |
| Contrast | Server checks bg/text (WCAG AA) on create/update — show friendly error on 400 |
| `fonts.*.fontPairingId` / `family` | Optional strings (no custom font file upload in v1) |
| `voice` | Optional tone/audience/dos/donts/vocabulary |
| `chartStyles.colorIds` | Optional list of color ids |
| `imageStyle` | Optional free text for AI image briefs |

## 1.3 Routes

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/api/workspaces/:workspaceId/brand-kits` | member | List kits (summary + mediaCount) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits` | OWNER/ADMIN | Create |
| `GET` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` | member | Full kit + media (presigned URLs) |
| `PATCH` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` | OWNER/ADMIN | Update name / data / isDefault |
| `DELETE` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` | OWNER/ADMIN | Delete kit + S3 media (existing decks keep snapshotted `themeTokens`) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/set-default` | OWNER/ADMIN | Mark as workspace default (clears other defaults) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media` | OWNER/ADMIN | Multipart upload |
| `DELETE` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media/:mediaId` | OWNER/ADMIN | Remove one media item |
| `GET` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media/:mediaId/stream` | member | Stream media |
| `GET` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/health` | member | Completeness score |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/suggest/colors` | OWNER/ADMIN | AI palette (credits) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/suggest/fonts` | OWNER/ADMIN | AI fonts (credits) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/suggest/voice` | OWNER/ADMIN | AI voice (credits) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/suggest/image-style` | OWNER/ADMIN | AI image brief (credits) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/suggest/logo-variants` | OWNER/ADMIN | Logo variants (credits when applying) |
| `POST` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines/generate` | OWNER/ADMIN | 6-slide guideline deck (regenerates in place if linked) |
| `GET` | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines` | member | Guideline link |

### Brand Kit credits

Flat workspace-scoped AC per action (defaults: colors **2**, fonts/voice/image-style **1**, logo variants **2**, guideline **3**). See [`CREDITS_FRONTEND_INTEGRATION.md`](CREDITS_FRONTEND_INTEGRATION.md) and [`CREDITS_API.md`](api/CREDITS_API.md#brand-kit-ai-flat-ac).

| UX | Billing |
|----|---------|
| Logo variant preview (no `applyRoles`) | **Free** — base64 previews only |
| Logo variant apply (`applyRoles: [...]`) | Charged when variants are committed |
| Guideline generate | Charged each run; **reuses** existing linked presentation when `guidelineProjectId` is valid |
| Suggest colors/fonts/voice/image-style | Charged after successful AI response; failed validation = no charge |

Handle **402** before billable Brand Kit POSTs; refresh balance after success.

### Create body

```json
{
  "name": "Acme Brand",
  "isDefault": true,
  "data": { "...see data shape above..." }
}
```

### Media upload (`multipart/form-data`)

| Field | Required | Notes |
|-------|----------|--------|
| `file` | yes | jpeg / png / webp / svg, max **50MB** |
| `kind` | yes | `logo` \| `photo` \| `graphic` |
| `role` | logos | `primary` \| `secondary` \| `icon` \| `light` \| `dark` |
| `name` | no | Display label |

**UX:** Offer separate upload zones for logos (with role chips), brand photos, and graphics. Preview with returned presigned `url`.

## 1.4 What the kit becomes on a deck (`themeTokens`)

When applied, the backend maps the kit into `deck.themeTokens`, including roughly:

```json
{
  "palette": {
    "bg": "#…",
    "surface": "#…",
    "primary": "#…",
    "secondary": "#…",
    "text": "#…",
    "muted": "#…"
  },
  "fontPairingId": "inter_space",
  "fonts": { "heading": "Inter", "body": "Inter", "tertiary": null },
  "imageStyle": "…",
  "brand": {
    "brandKitId": "…",
    "name": "Acme Brand",
    "voice": { },
    "chartColors": ["#…"],
    "logos": {
      "primary": { "url": "https://…", "s3Key": "…" },
      "light": { },
      "dark": { }
    },
    "photos": [{ "url": "…", "name": "…" }],
    "graphics": [],
    "namedColors": []
  }
}
```

Frontend canvas / export should resolve symbolic fills like `"primary"` from `themeTokens.palette` when rendering shapes.

## 1.5 Using a Brand Kit with presentations

| Action | API |
|--------|-----|
| Create with kit | `POST .../presentations` + `brandKitId` (any `createMode`) |
| Create from pack + kit | `createMode: "pack"`, `packId`, `brandKitId` |
| Apply to existing deck | `POST .../presentations/:presentationId/apply-brand-kit` `{ "brandKitId" }` |
| AI generate | `generationFlow.selections.brandKitId` (+ optional `packId`) |

**Apply brand kit** updates `themeTokens` and injects/updates logo image elements (`role: logo`) on title / closing / section_divider slides. It does **not** wipe slide text.

**AI behavior with kit:**

- Theme/voice override catalog theme  
- Brand voice appended to LLM briefs  
- Brand **photos** preferred before stock / AI images for slide visuals  
- Logos injected where layout allows  

## 1.6 Brand Kit UI checklist

- [ ] Settings → Brand Kits list (default badge)
- [ ] Create / edit form: colors + roles, fonts, voice, chart colors, image style
- [ ] Media: logo roles, photos, graphics; delete media
- [ ] Set default
- [ ] On PPT create: Brand Kit dropdown (optional)
- [ ] On PPT editor: “Apply Brand Kit” action
- [ ] On AI wizard: optional Brand Kit + Deck Pack pickers
- [ ] Handle 403 for MEMBER trying to write

---

# Part 2 — Presentations (AI PPT)

Creates a **`Project`** with `type: "PRESENTATION"` (not video). Deck + slides live in related tables. Canvas is freeform `elements[]`.

## 2.1 Mental model & IDs

```
Workspace → Folder → Project (type: PRESENTATION)
                        └── Deck + Slides
                              └── each slide: content + elements (canvas)
```

| Concept | ID in routes |
|---------|----------------|
| Presentation | **`project.id`** → path param `presentationId` |
| Deck | `deck.id` (rarely in URLs) |
| Slide | `slide.id` |
| Element | `element.id` inside `slide.elements.elements[]` |

**Do not** POST one mega “final deck JSON”. Keep wizard state in the UI; call the multi-step APIs below.

Auth: Bearer. Role: workspace OWNER | ADMIN | MEMBER.

## 2.2 Caps (show in UI)

| Limit | Value | UX |
|-------|-------|-----|
| AI outline / generate | **5–20** slides | Stepper on AI create |
| Deck total (manual add/duplicate) | **40** | Disable “Add slide” at 40 |
| Elements per slide | **50** | Disable palette insert at 50 |

After AI fills ≤20 slides, users can still add more manually up to 40.

## 2.3 Canvas sizes

| `aspectRatio` / `canvasSize` | Pixels |
|------------------------------|--------|
| `16:9` (default) | 1920 × 1080 |
| `4:3` | 1600 × 1200 |

PPT supports **`16:9` and `4:3` only**. FE must use `slide.elements.canvas` for stage size.

## 2.4 Workspace pickers (load once for chrome)

Base: `/api/workspaces/:workspaceId`

| UI | Method | Path |
|----|--------|------|
| Single-slide layout gallery | `GET` | `/presentation-templates?category=` (tabs) or `?contentType=` |
| Multi-slide deck packs | `GET` | `/presentation-deck-packs` |
| Deck pack detail (slide grid) | `GET` | `/presentation-deck-packs/:packId` |
| Brand Kits | `GET` | `/brand-kits` |
| Theme picker | `GET` | `/presentation-themes` |
| Insert palette | `GET` | `/presentation-elements` |

Theme catalog ids use **underscores** (e.g. `midnight_blue`), not kebab-case.

### Seeded themes (catalog)

| id | Name |
|----|------|
| `midnight_blue` | Midnight Blue |
| `clean_light` | Clean Light |
| `forest_slate` | Forest Slate |
| `warm_sand` | Warm Sand |
| `charcoal_gold` | Charcoal Gold |
| `ocean_mist` | Ocean Mist |
| `violet_noir` | Violet Noir |
| `paper_ink` | Paper Ink |
| `sunset_coral` | Sunset Coral |
| `mint_clinic` | Mint Clinic |

### Seeded deck packs (`DECK_PACK`)

Installed by backend seed (`npm run seed:presentation-deck-packs`). Each pack is **schemaVersion 2** with `themeId`, `meta`, `narrative`, designed placeholders, per-slide `intent` / `designTokens` / `generationHints`, and `generationDefaults` (`layoutWhitelist`, `slideOrder: "fixed"`, `contentDistribution`). Visual slides may set `placeholder.imagePrompt`. Seed acquires **system `TemplateMedia`** (durable S3). Pack list includes `previewImageUrl` + `media[]`. **Pack clone fills image URLs** — templates look finished; user replaces via slide media APIs or regenerate.

| pack_id | Theme | slides | Use case |
|---------|-------|--------|----------|
| `corp_pitch_midnight` | Midnight Blue | 5 | Short corporate pitch |
| `marketing_clean_light` | Clean Light | 5 | Campaign story |
| `portfolio_forest` | Forest Slate | 5 | Studio portfolio |
| `consulting_report_paper` | Paper Ink | 8 | Text-first consulting report |
| `investor_deck_violet` | Violet Noir | 8 | Fundraising deck |
| `product_launch_ocean` | Ocean Mist | 8 | Product launch |
| `executive_review_charcoal` | Charcoal Gold | 8 | QBR / board review |
| `brand_story_sand` | Warm Sand | 8 | Brand / editorial story |
| `company_meeting_clean` | Clean Light | 10 | Internal company meeting (title/closing images) |

**Important:** List packs via `GET .../presentation-deck-packs` (summary only — **no `schema.slides`**). For pack drill-down / slide grid, call `GET .../presentation-deck-packs/:packId` (`schema.slides`, `slidePreviews[]`, presigned `media[]`). The `packId` you send on create/generate is the **template row id** returned by list/detail (cuid). Display pack thumbnails from **`previewImageUrl`** or **`preview.imageUrl`** / **`preview.thumbnailUrl`** (same presigned URL). Per-slide thumbnails: **`slidePreviews[].previewImageUrl`** or `media[]` with `slotHint: slide:{order}`. Fall back to `preview.color` / `preview.accentColor` when those are null (text-first packs like consulting/QBR). Do **not** expect an image on `preview` color fields alone.

### Canvas publish as pack (superadmin)

Superadmin can design a finished deck in the presentation canvas, then:

`POST /api/superadmin/presentations/:presentationId/publish-as-pack` with `{ name, packId, themeId?, variant?, isActive? }`.

Creates a hybrid `DECK_PACK` with `snapshot.elements` per slide + `TemplateMedia`. Response `schema.meta.authoredVia` = `canvas`; `meta.aiReady` when slides have `layout_id` or role-tagged elements. Clone uses the snapshot; AI generate rebinds by `role`. JSON seed/admin create remains supported. Video: publish scene → `VIDEO_SCENE`, or whole project → `VIDEO_PACK` (no AI). See [SUPERADMIN_API.md](api/SUPERADMIN_API.md).

### Manual slide media (replace template photos)

| Call | Use |
|------|-----|
| `POST .../slides/:slideId/media` | Multipart upload onto slide image |
| `POST .../slides/:slideId/attach-asset` | `{ assetId }` from workspace Assets |
| `POST .../slides/:slideId/insert-stock` | `{ query }` or stock provider+id |

### Pack slide design contract

| Field | Purpose |
|-------|---------|
| `intent` | Plain-English purpose — fed into AI slide prompts |
| `designTokens` | Chrome only: `backgroundStyle` (`solid`\|`gradient`), `accentPosition` (`none`\|`left-bar`\|`top-bar`\|`bottom-bar`), `imagePosition` (hint), `overlayOpacity`, `textContrast` |
| `placeholder` | Structured object mapped to layout slots; may include `imagePrompt` for visual slides |
| `generationHints` | `maxTitleWords`, `maxBodyWords`, `itemCountMin/Max`, `imagePromptStyle`, plus prose hints |

`layout_id` owns geometry; `designTokens` do not re-layout image splits.

### Layout content types (39 layouts)

| content_type | Example layout_ids |
|--------------|-------------------|
| title | `title_centered_v1`, `title_left_accent_v2`, `title_hero_image_v3` |
| agenda | `agenda_numbered_v1`, `agenda_two_column_v2`, `agenda_side_image_v3` |
| bullet_list | `bullet_list_classic_v1`, `bullet_list_dense_v2`, `bullet_list_cards_v3`, `numbered_four_up_v1`, `policy_numbered_split_v1`, `achievement_three_up_v1` |
| comparison | `comparison_side_by_side_v1`, `comparison_pros_cons_v2`, `comparison_table_v3` |
| stat | `stat_big_number_v1`, `stat_three_up_v2`, `stat_with_context_v3` |
| quote | `quote_centered_v1`, `quote_portrait_v2`, `quote_banner_v3` |
| image+text | `image_text_split_v1`, `image_text_split_v2`, `image_text_overlay_v3` |
| timeline | `timeline_horizontal_v1`, `timeline_vertical_v2`, `timeline_alternating_v3` |
| team | `team_grid_four_v1`, `team_featured_lead_v2`, `team_row_v3` |
| chart | `chart_full_width_v1`, `chart_with_callouts_v2`, `chart_compact_v3` |
| closing | `closing_centered_cta_v1`, `closing_contact_v2`, `closing_thank_you_image_v3` |
| section_divider | `section_divider_centered_v1`, `section_divider_numbered_v2`, `section_divider_band_v3` |

## 2.5 Product flows

### A — Create with AI

1. `POST .../presentations` `{ folderId, themeId?, brandKitId?, createMode: "blank" }` — title optional → defaults to `Untitled Presentation`
2. Optional: `GET .../credit-estimate`
3. `POST .../outline` `{ source: "prompt", prompt: "<flattened string>", slideCount, density }`
   - Flatten voice/tone/audience into the **string** `prompt` (no nested prompt object)
   - Response includes `presentation.title` — persist it in UI
4. Optional: `PATCH .../outline` if user edits outline cards
5. Optional: `POST .../theme` `{ themeId }` and/or `themeTokens`
6. `POST .../generate` → **202** — optionally include `generationFlow` with `packId` / `brandKitId` → poll `GET .../status`
7. Open editor: `GET .../presentations/:id`

### B — Create blank (Canva-style)

1. `POST .../presentations` `{ folderId, createMode: "blank", brandKitId? }`
2. `POST .../slides` to add slides, or with AI:

```json
{
  "generate": true,
  "prompt": "Competitive landscape for Athena VI",
  "target": "all"
}
```

3. Insert elements → `PUT .../canvas` or element CRUD  
4. Per-slide AI: `POST .../slides/:slideId/regenerate`  
5. Export when ready  

### C — Create from single layout template

1. `GET .../presentation-templates` → picker  
2. `POST .../presentations` `{ folderId, createMode: "template", templateId, brandKitId? }`  
3. Edit first slide; add more as needed  

### D — Create from deck pack + Brand Kit

1. Ensure Brand Kit exists (Part 1)  
2. `GET .../presentation-deck-packs` → pack picker (summary)  
3. `GET .../presentation-deck-packs/:packId` → slide drill-down when user opens a pack
3. `POST .../presentations` `{ folderId, createMode: "pack", packId, brandKitId? }`  
4. Edit canvas; optional later `POST .../apply-brand-kit`  
5. For AI fill: outline → generate with `generationFlow.selections.packId` + `brandKitId`  

All paths share the **same editor**.

## 2.6 Create presentation API

| | |
|---|---|
| Method | `POST` |
| Path | `/api/workspaces/:workspaceId/presentations` |
| Status | **201** |

```json
{
  "folderId": "<uuid>",
  "title": "optional",
  "themeId": "midnight_blue",
  "themeTokens": null,
  "locale": "en",
  "aspectRatio": "16:9",
  "createMode": "blank",
  "templateId": null,
  "packId": null,
  "brandKitId": null
}
```

| `createMode` | Requires | Result |
|--------------|----------|--------|
| `blank` | — | **One** READY slide (default canvas text) |
| `template` | `templateId` (active `DECK_LAYOUT`) | One READY slide |
| `pack` | `packId` (active `DECK_PACK`) | Multi-slide skeleton with placeholders + optional logos |

**Response `data`:** `{ project, deck, slides, id, title, status, themeTokens, aspectRatio, locale, folderId }` — `project.type === "PRESENTATION"`. Use `project.id` (or flat `id`) as `presentationId`.

## 2.7 Get presentation

`GET /api/workspaces/:workspaceId/presentations/:presentationId`

**Response `data`:** `{ project, deck, slides }` **plus flat** `id`, `title`, `status`, `themeTokens`, `aspectRatio`, `locale`, `folderId`

- `deck`: `themeTokens`, `outline`, `status`, `aspectRatio`, `locale`, `generationMetrics`, `partial`, `creditsChargedSoFar`, …
- slides: `content`, `layoutId`, `imageRef`, **`elements`**, `status`, `manuallyEdited`, … (+ helper `title` / `description`)
- Also: `GET .../slides/:slideId` for a single slide

Image URLs are **presigned (~1h)**. Prefer `elements[].content.url` (or `src`) for canvas. Refetch presentation if images 403.

### Freeform canvas shape (`slide.elements`)

```json
{
  "version": 1,
  "canvas": { "width": 1920, "height": 1080 },
  "elements": [
    {
      "id": "el_…",
      "type": "shape",
      "layer": 0,
      "placement": { "x": 0, "y": 0, "width": 1920, "height": 1080, "rotation": 0, "opacity": 1 },
      "content": {
        "shape": "rect",
        "fill": {
          "type": "gradient",
          "direction": "135deg",
          "stops": [
            { "color": "#0B1220", "colorRole": "gradientStart", "position": 0 },
            { "color": "#121A2B", "colorRole": "gradientEnd", "position": 100 }
          ]
        }
      },
      "role": "background"
    },
    {
      "id": "el_…",
      "type": "text",
      "layer": 2,
      "placement": { "x": 160, "y": 200, "width": 1600, "height": 140, "rotation": 0, "opacity": 1 },
      "content": {
        "text": "Title",
        "fontSize": 64,
        "bold": true,
        "fontWeight": 800,
        "align": "center",
        "color": "#F8FAFC",
        "colorRole": "text",
        "letterSpacing": -0.03,
        "lineHeight": 1.1
      },
      "role": "heading"
    }
  ]
}
```

| `type` | Typical `content` |
|--------|-------------------|
| `text` | `text`, `fontSize`, `bold`, `fontWeight`, `italic`, `color`, `colorRole`, `align`, `letterSpacing`, `lineHeight`, `fontFamily` |
| `image` / `icon` | `url` or `src`, `fit`, `alt` / `icon`, optional `assetId`, `provider` |
| `shape` | `shape`: `rect` \| `rounded-rect` \| `circle` \| `ellipse` \| `pill` \| `triangle` \| `diamond` \| `star` \| `line` \| `plus` \| arrows; `fill` string/token/gradient; optional `stroke`, `strokeWidth`, `borderRadius` |
| `chart` | `chartType` (incl. `column-grouped`, `pie`, …), `labels`/`series` **or** nested `data`, optional `colors` |
| `table` | `rows` string[][] **or** `cells` + `hasHeader` (max 8×8) |
| `embed` | `provider`, `url`, `title` (export as link card) |

**Frontend must render** gradient fills (`linear-gradient`), accent bars, and typography fields. Resolve `colorRole` / palette tokens from `deck.themeTokens.palette` (`bg`, `surface`, `primary`, `secondary`, `text`, `muted`, `accent`, `divider`, `cardBg`, `gradientStart`, `gradientEnd`).

Sort draw order by `layer` ascending. Drag / resize / snap / guides are **frontend-only**; persist with canvas/element APIs.

### `imageRef` statuses

| status | Meaning |
|--------|---------|
| `ready` | Image URL available |
| `failed` | Provider/upload failed — see `imageRef.error`; content may still be READY |
| `skipped` | No image required for this slide |

Show “No visuals” only for `skipped` or missing image. For `failed`, offer retry via regenerate `target: "image"`.

## 2.8 Credit estimate

`GET .../presentations/:presentationId/credit-estimate?slideCount=`

Optional `slideCount` 5–20; else outline count (fallback 12).

```json
{
  "slideCount": 12,
  "outline": { "athenaCredits": 0, "usdCost": 0, "breakdown": {} },
  "generate": { "athenaCredits": 0, "breakdown": {} },
  "export": { "athenaCredits": 3, "feature": "ppt_export" },
  "totalEstimatedCredits": 0
}
```

Estimate only — does not charge. Generate estimate assumes Path A image cost per slide.

### PPT credit feature keys

| Feature | Key | Typical default |
|---------|-----|-----------------|
| Outline | `ppt_outline` | Token reconcile (estimate then actual) |
| Slide body | `ppt_slide_content` | **2** AC |
| Image Path A | `ppt_image_path_a` | **4** AC |
| Image Path B | `ppt_image_path_b` | **9** AC |
| Export | `ppt_export` | **3** AC |
| Image cache hit | `ppt_image_cache_hit` | **0** |

Charge **on success** per piece. Failed pieces do not charge. Outline cost is approximate until response returns — then refresh balances. Prefer estimate endpoint over hard-coding AC in the client.

## 2.9 Outline

### Generate outline

`POST .../outline` → **200**

```json
{
  "source": "prompt",
  "prompt": "Pitch deck for …",
  "slideCount": 12,
  "density": "balanced",
  "locale": "en"
}
```

| `source` | Required |
|----------|----------|
| `prompt` | `prompt` |
| `outline` | `outlineText` |
| `document` | multipart `file` (PDF/DOCX/DOC, max 20 MB) and/or `documentText` |

`density`: `concise` \| `balanced` \| `detailed`. `slideCount` default 12, range 5–20.

Response includes `presentation: { id, title }`, `outline`, `creditsCharged`. Title is saved to `project.name`.

### Patch outline

`PATCH .../outline` — full outline object. No LLM charge. Title updates `project.name`.

## 2.10 Theme

`POST .../theme`

```json
{
  "themeId": "clean_light",
  "themeTokens": {
    "palette": { "bg": "#FFFFFF", "text": "#0F172A" }
  }
}
```

At least one of `themeId`, `themeTokens`.

## 2.11 Apply Brand Kit

`POST .../apply-brand-kit` → **200**

```json
{ "brandKitId": "<id>" }
```

## 2.12 Generate deck

`POST .../generate` → **202**

```json
{
  "density": "concise",
  "overwriteManualEdits": false,
  "generationFlow": {
    "version": 1,
    "source": "ai_ppt_wizard",
    "selections": {
      "prompt": "Create an investor pitch for our new health app",
      "title": "Investor Pitch — Health App",
      "outlineNotes": "Focus on traction and market size",
      "voiceAndTone": "Professional",
      "audience": "Investors",
      "purpose": "Persuade",
      "style": "Modern",
      "color": "Blue",
      "industries": ["Healthcare", "Technology"],
      "baseTemplate": "corp-pitch",
      "colorTheme": "modern-professional",
      "canvasSize": "16:9",
      "imageType": "ai",
      "imageStyle": "photo",
      "imageStyleFilter": "Suggested",
      "textContent": "Concise",
      "density": "concise",
      "slideCount": 10,
      "locale": "en",
      "packId": "<deck pack template id>",
      "brandKitId": "<brand kit id>"
    },
    "availableOptions": {}
  }
}
```

Notes:

- `generationFlow` is optional / additive; without it, generate still works  
- `selections.slideCount` is **metadata only** — does **not** resize the deck (outline is source of truth)  
- `packId` → layout whitelist + pack defaults  
- `brandKitId` → theme + voice + brand photos  
- `imageType`: `ai` \| `stock` \| `web` \| `placeholders` \| `none`  
- Persisted on `deck.generationMetrics.generationFlow` for later regenerates  

Response typical: `{ deckId, status, slideCount, estimatedCredits }`

## 2.13 Status (poll)

`GET .../status` → **200**

```json
{
  "deckId": "…",
  "status": "GENERATING",
  "partial": false,
  "progress": 40,
  "etaSeconds": 24,
  "creditsChargedSoFar": 12,
  "slides": [
    {
      "id": "…",
      "order": 1,
      "status": "READY",
      "contentType": "title",
      "layoutId": "…",
      "manuallyEdited": false
    }
  ]
}
```

| Deck status | Slide status |
|-------------|--------------|
| `DRAFT`, `GENERATING`, `READY`, `FAILED` | `PENDING`, `GENERATING`, `READY`, `FAILED` |

While `deck.status === "GENERATING"`, structure/canvas mutations → **409**. Show blocking “Generating…” UI.

## 2.14 Slides

Base: `/api/workspaces/:workspaceId/presentations/:presentationId`

### Add slide

`POST .../slides` → **201**

```json
{
  "afterSlideId": null,
  "templateId": null,
  "layoutId": null,
  "content": {},
  "generate": false,
  "prompt": "optional AI brief (max 2000)",
  "target": "all"
}
```

- Manual: `READY`, `manuallyEdited: true`  
- `generate: true`: requires `prompt` or `content.title`; returns GENERATING; poll status  
- Rejects at **40** slides  

### Delete / duplicate / reorder

| Method | Path |
|--------|------|
| `DELETE` | `/slides/:slideId` |
| `POST` | `/slides/:slideId/duplicate` (fails at 40) |
| `PATCH` | `/slides/reorder` body `{ "slideIds": ["…"] }` (all ids once) |

### Apply layout

`POST .../slides/:slideId/apply-layout` `{ "templateId" }` — rebuilds `elements` from `DECK_LAYOUT` + content; sets `manuallyEdited: true`.

### Canvas / elements

| Method | Path |
|--------|------|
| `PUT` | `/slides/:slideId/canvas` — full `{ version, canvas, elements }` replace |
| `POST` | `/slides/:slideId/elements` — flat `{ type, placement, content, presetId? }` **or** `{ presetId }` / `{ element }` |
| `PATCH` | `/slides/:slideId/elements/:elementId` |
| `DELETE` | `/slides/:slideId/elements/:elementId` |
| `PATCH` | `/slides/:slideId/elements/reorder` — `{ "elementIds": [] }` |

Element catalog presets: `GET .../presentation-elements` → `{ presets: [{ id, presetId, type, label, content, defaultContent }] }`. Insert with `{ "presetId": "text_title" }` or a full flat element body. Types: `text` \| `image` \| `icon` \| `shape` \| `chart` \| `table` \| `embed`.

Cannot delete the last slide (**400**).

### Patch slide

`PATCH .../slides/:slideId` — any of `title`, `content`, `layoutId`, `contentType`, `imageRef`, `elements`, `manuallyEdited`, `background: { color, imageUrl }` (stored on `content.background`).

### Regenerate slide

`POST .../slides/:slideId/regenerate` → **202**

```json
{
  "target": "all",
  "overwriteManualEdits": true,
  "prompt": "Competitive landscape for Athena VI vs Loom"
}
```

- `target`: `content` \| `image` \| `all` \| `full` (`full` ≡ `all`; default `all`)  
- Manual edits blocked unless `overwriteManualEdits: true` (**409**)  
- Confirm in UI before overwrite  
- On blank decks, pass `prompt` or set `content.title` first  

## 2.15 Export

`POST .../export` → **202**

```json
{ "format": "PPTX", "slideId": null }
```

| format | Result |
|--------|--------|
| `PPTX` / `PDF` | Single file (elements-aware) |
| `PNG` / `JPEG` | One slide → image; full deck → **ZIP** |

Then poll `GET .../export/:exportId` until `READY` → use `presignedUrl`.  
Statuses: `QUEUED`, `PROCESSING` / `RENDERING`, `READY`, `FAILED`.  
Charges `ppt_export` on success. Inbox may notify `PRESENTATION_EXPORT_COMPLETED` / `FAILED`.

## 2.16 Listing in folders

`GET /api/workspaces/:workspaceId/projects?folderId=`

Filter UI by `project.type === "PRESENTATION"` vs `"VIDEO"`. Open presentations in the PPT editor only.

## 2.17 PPT vs video templates (do not mix)

| | PPT layout `DECK_LAYOUT` | PPT pack `DECK_PACK` | Video `VIDEO_SCENE` / `VIDEO_PACK` |
|--|--------------------------|----------------------|-------------------------------------|
| Workspace list | `GET .../presentation-templates` | `GET .../presentation-deck-packs` (`previewImageUrl`, `media[]`; detail: `.../:packId`) | `GET .../video-templates?type=` (`previewImageUrl`, `media[]`) |
| Apply | `createMode: "template"` / `apply-layout` | `createMode: "pack"` + AI whitelist | Project `templateId` (scene or pack) / `scenes/from-template` (scene only) |
| Schema | `layout_id`, `grid`, `slots[]` | `pack_id`, `slides[]`, `themeId` | `scene.elements` / pack `scenes[]` with frames |
| Canvas publish | — | `publish-as-pack` → `TemplateMedia` `slide:n` | `publish-as-template` / `publish-as-video-pack` → `TemplateMedia` `scene:n` |

Brand Kit is workspace-owned look — separate from templates.

## 2.18 Presentation UI checklist

- [ ] Create modal: **AI | Blank | Template | Pack** (+ optional Brand Kit)
- [ ] Theme + layout + pack + brand pickers from workspace GETs
- [ ] AI: outline review → generate progress (`status` + `creditsChargedSoFar`)
- [ ] Canvas: aspect stage, palette from `presentation-elements`, autosave
- [ ] Slide rail: add / delete / duplicate / reorder; disable add at 40
- [ ] Per-slide Regenerate + overwrite confirm if `manuallyEdited`
- [ ] Add slide with AI → poll status
- [ ] Apply Brand Kit action
- [ ] Export menu PPTX / PDF / PNG / JPEG; poll + download
- [ ] Credit estimate before outline / generate / export; handle 402
- [ ] Folder list filter by `project.type`
- [ ] Presigned image refresh on expiry

## 2.19 Presentation route map

```
POST   /api/workspaces/:workspaceId/presentations
GET    /api/workspaces/:workspaceId/presentation-templates
GET    /api/workspaces/:workspaceId/presentation-deck-packs
GET    /api/workspaces/:workspaceId/presentation-deck-packs/:packId
GET    /api/workspaces/:workspaceId/presentation-themes
GET    /api/workspaces/:workspaceId/presentation-elements
GET    /api/workspaces/:workspaceId/brand-kits

GET    /api/workspaces/:workspaceId/presentations/:presentationId
GET    .../status
GET    .../credit-estimate
POST   .../outline
PATCH  .../outline
POST   .../theme
POST   .../apply-brand-kit
POST   .../generate

POST   .../slides
GET    .../slides/:slideId
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

---

# Part 3 — Image Gen (AI image studio)

OpenAI-only workspace image studio: general images, infographics, and social creatives. Results save as workspace **Assets** (`source: "ai_gen"`) and are downloadable as PNG / JPG / JPEG / PDF.

## 3.1 Base path & auth

```
/api/image-gen
```

- Bearer on all routes  
- Workspace routes: workspace access (PRIVATE = owner; TEAM = any member)  
- Credits charged **on success only**; downloads free  
- Generate is **synchronous** — use a long client timeout (30–90s)  

## 3.2 Mental model

```
Workspace → Image Gen studio
  → mode (image | infographic | social)
  → model + format + style
  → Generate (sync) → Asset + generation row
  → Regenerate | Tweak | Download | Library (already saved)
```

Versions share `rootId` / `parentId` chains.

## 3.3 Catalogs (load once)

### Models — `GET /api/image-gen/models`

`data.models[]`: `id`, `name`, `description`, `modes`, `recommended`, `supportsEdit`, `creditEstimate`.

| id | Notes |
|----|--------|
| `gpt-image-1` | Default (medium) |
| `gpt-image-1-hd` | HD (higher AC) |
| `dall-e-3` | Compat alias → GPT Image HD; image/social only |

Respect each model’s `modes` array (e.g. hide DALL·E for `infographic` if not listed).

### Formats — `GET /api/image-gen/formats`

`data.formats[]`: `id`, `name`, `category` (`generic` \| `social`), `width`, `height`, `safeZone`.

**Social ids:**  
`linkedin_banner`, `linkedin_post`, `instagram_post`, `instagram_story`, `instagram_landscape`, `facebook_post`, `facebook_cover`, `x_post`, `x_header`, `youtube_thumbnail`

**Generic:** `square`, `landscape`, `portrait`

### Styles — `GET /api/image-gen/styles`

`data.styles[]`: `id`, `name` (vibe presets).

## 3.4 Credit estimate

`GET /api/image-gen/workspaces/:workspaceId/estimate?modelId=&mode=&tweak=`

`mode`: `image` \| `infographic` \| `social`  
`tweak`: `true` / `false`

Response: `{ athenaCredits, breakdown }`.

### Default AC (do not hard-code; prefer estimate)

| Feature | Default AC |
|---------|------------|
| `image_gen_gpt_image` | 6 |
| `image_gen_gpt_image_hd` | 12 |
| `image_gen_dall_e_3` | 12 (alias → HD quality) |
| Infographic surcharge | +2 |
| Social surcharge | +1 |

Requires server `OPENAI_API_KEY`. Rate limits return **429**.

## 3.4b Context bundles

`POST /api/image-gen/workspaces/:workspaceId/context` → **201** (`multipart/form-data`)

- Parts: `files` (PDF/DOCX/MD/TXT/PNG/JPG/WebP), `payload` JSON string `{ inlineText?, assetIds? }`
- Free (rate-limited). Max 5 files+assets combined.
- Response: `data.context` with `id`, `previews`, `warnings`, `expiresAt`
- Also: `GET/DELETE .../context/:contextId` (DELETE → 409 if pinned)

Pass `contextId` on generate/regenerate. See [`IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md#context-bundles).

## 3.5 Generate

`POST /api/image-gen/workspaces/:workspaceId/generate` → **201** (sync)

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
| `formatId` | **Required** for `social`. Optional aspect for `image` |
| `prompt` | Required unless `infographic.sections` provided |
| `style` / `styleId` | Optional from `/styles` |
| `brandPalette` | Optional hex list — can mirror Brand Kit colors in UI |
| `contextId` | Optional context bundle from §3.4b |

**Response `data`:**  
`{ generation, asset, creditsCharged, downloadFormats: ["png","jpg","jpeg","pdf"] }`

Master file is always **PNG** on S3. Preview `data.asset.url` / `data.generation.url`. Generation may include `contextId` / `contextPreview`.

## 3.6 List / get generations

```
GET /api/image-gen/workspaces/:workspaceId/generations?take=&skip=
GET /api/image-gen/workspaces/:workspaceId/generations/:generationId
```

PRIVATE workspaces only return the current user’s generations.

## 3.7 Regenerate

`POST .../generations/:generationId/regenerate` → **201**

Body fields optional — omitted fields reuse parent request. Creates new generation + asset (`action: "regenerate"`), linked via `parentId` / `rootId`. Charges again.

## 3.8 Tweak

`POST .../generations/:generationId/tweak` → **201**

```json
{ "instruction": "Make the background darker and move the logo left" }
```

Uses OpenAI image edit on the parent PNG. Charges model AC (no mode surcharge).

## 3.9 Download

`GET .../generations/:generationId/download?format=png|jpg|jpeg|pdf`

Returns file attachment (`Content-Disposition: attachment`). **No credit charge.**

| format | Content-Type |
|--------|----------------|
| `png` | `image/png` |
| `jpg` / `jpeg` | `image/jpeg` |
| `pdf` | `application/pdf` (single page) |

Use blob download with filename from `Content-Disposition`.

## 3.10 Assets library

AI outputs appear in:

```
GET /api/assets/:workspaceId?source=ai_gen
```

`stockMetadata.generationId` links back to studio history.

## 3.11 Image Gen flows (UI)

### A — General image

Mode `image`, optional `formatId` (`square`/`landscape`/`portrait`), `style`, `prompt` → generate → preview / download.

### B — Infographic

Mode `infographic`, prefer `gpt-image-1` / HD. Form: `infographic.layout`, `title`, `sections[]`, optional `brandPalette` + prompt → generate → PNG/PDF.

### C — Social creative

Mode `social`, required `formatId`. Optional `headline` / `subheadline` / `brandPalette`. Server crops to exact platform pixels.

### D — Iterate

Regenerate (edited params) or Tweak (`instruction` modal).

### E — Brand Kit optional polish

When user has a default Brand Kit, prefill `brandPalette` from kit colors and suggest brand voice keywords in the prompt — Image Gen does not auto-load the kit; the UI can bridge them.

## 3.12 Image Gen UI checklist

- [ ] Load `/models`, `/formats`, `/styles` once
- [ ] Model picker (default `gpt-image-1`); respect `modes`
- [ ] Mode tabs: Image / Infographic / Social
- [ ] Social → format chips `category === "social"`
- [ ] Estimate on model/mode change
- [ ] Generate with long timeout + loading state
- [ ] Preview; Regenerate; Tweak modal; Download menu
- [ ] History list with version chains (`rootId`)
- [ ] Library filter `source=ai_gen`
- [ ] Handle 400 / 402 / 429 / 502–503
- [ ] Optional: prefill palette from Brand Kit

## 3.13 Image Gen route map

```
GET  /api/image-gen/models
GET  /api/image-gen/formats
GET  /api/image-gen/styles
GET  /api/image-gen/workspaces/:workspaceId/estimate
POST /api/image-gen/workspaces/:workspaceId/generate
GET  /api/image-gen/workspaces/:workspaceId/generations
GET  /api/image-gen/workspaces/:workspaceId/generations/:generationId
POST /api/image-gen/workspaces/:workspaceId/generations/:generationId/regenerate
POST /api/image-gen/workspaces/:workspaceId/generations/:generationId/tweak
GET  /api/image-gen/workspaces/:workspaceId/generations/:generationId/download
```

---

# Part 4 — Superadmin (templates that feed PPT)

Platform superadmins manage the **system templates** users see in workspace pickers. Same login as the main app; show admin UI when `GET /api/user/capabilities` indicates portal access.

## 4.1 Auth reminder

```
Authorization: Bearer <accessToken>
```

Plus platform superadmin check on every `/api/superadmin/*` call. Workspace ADMIN cannot call these.

Optional dedicated login: `POST /api/auth/superadmin/login` / Google — same JWT type.

## 4.2 Template CRUD (PPT-relevant)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/superadmin/templates` | List (`type` filter: `DECK_LAYOUT` \| `DECK_PACK` \| `VIDEO_SCENE`) |
| `POST` | `/api/superadmin/templates` | Create — **`type` required** |
| `GET` | `/api/superadmin/templates/:templateId` | Get one |
| `PATCH` | `/api/superadmin/templates/:templateId` | Update `name` / `schema` / `isActive` / `contentType` / `variant` |

Activate/deactivate with `PATCH { "isActive": true|false }`. Only **active** templates appear in workspace lists.

### Template types

| `type` | Product | Schema requirements |
|--------|---------|---------------------|
| `DECK_LAYOUT` | AI PPT | `layout_id`, `content_type`, `grid`, `slots[]` (`id` + `region`). No `scene` / `videoSettings` |
| `DECK_LAYOUT` | AI PPT | `schemaVersion?`, `layout_id`, `content_type`, `grid`, `slots[]` with `id`, `region`, optional `role`, `typography`, `shape`, `layer`. No `scene` / `videoSettings` |
| `DECK_PACK` | AI PPT multi-slide | `schemaVersion?`, `pack_id`, `themeId?`, `aspectRatio`, `meta?`, `narrative?` (`arc`, `summary`), `slides[{ order, layout_id, contentType, intent?, designTokens?, generationHints?, placeholder }]`, `generationDefaults?` (includes `layoutWhitelist`, `slideOrder`, `contentDistribution`), `preview?`. Every `layout_id` must exist as an active `DECK_LAYOUT` |
| `VIDEO_SCENE` | Video editor only | Different product — do not use in PPT UI |

### Create `DECK_LAYOUT` example

```json
{
  "type": "DECK_LAYOUT",
  "name": "Title Centered",
  "contentType": "title",
  "variant": "v1",
  "isActive": true,
  "schema": {
    "layout_id": "title_centered_v1",
    "content_type": "title",
    "grid": "12-col",
    "slots": [
      { "id": "title", "region": "cols 2-11, rows 4-7", "max_lines": 3 },
      { "id": "subtitle", "region": "cols 3-10, rows 8-9", "max_lines": 2 }
    ]
  }
}
```

### Create `DECK_PACK` example

```json
{
  "type": "DECK_PACK",
  "name": "Investor Deck — Violet Noir",
  "contentType": "pack",
  "variant": "investor_deck_violet",
  "isActive": true,
  "schema": {
    "pack_id": "investor_deck_violet",
    "themeId": "violet_noir",
    "aspectRatio": "16:9",
    "slides": [
      {
        "order": 1,
        "layout_id": "title_hero_image_v3",
        "contentType": "title",
        "placeholder": {
          "title": "Series A",
          "subtitle": "Company name · One line on what you do"
        }
      },
      {
        "order": 2,
        "layout_id": "stat_three_up_v2",
        "contentType": "stat",
        "placeholder": {
          "title": "Traction",
          "stats": [
            { "value": "$4.2M", "label": "ARR" },
            { "value": "142%", "label": "NRR" },
            { "value": "61", "label": "Logos" }
          ]
        }
      }
    ],
    "generationDefaults": {
      "baseTemplate": "corp-pitch",
      "imageStyle": "photo",
      "preferVisuals": true
    },
    "preview": { "label": "Investor Deck — Violet Noir" }
  }
}
```

**Admin UI:** Separate forms for `DECK_LAYOUT` vs `DECK_PACK` vs `VIDEO_SCENE`. For packs, validate that referenced layout ids exist (server also enforces).

## 4.3 Superadmin UI checklist (for these features)

- [ ] Portal toggle from capabilities (same session)
- [ ] Templates list with type filter tabs
- [ ] Create/edit DECK_LAYOUT (slots editor or JSON)
- [ ] Create/edit DECK_PACK (slide list + layout picker + placeholders + themeId)
- [ ] Activate / deactivate
- [ ] Confirm packs appear in user `GET .../presentation-deck-packs` after activate
- [ ] Do not mix VIDEO_SCENE into PPT screens

(Other superadmin surfaces — credits grant/revoke, storage, early access — exist but are outside these three features.)

---

# Part 5 — End-to-end user journeys

## Journey 1 — Branded pack → AI fill → export

1. OWNER creates Brand Kit + uploads logos/photos  
2. User opens Create → Pack → picks pack + Brand Kit  
3. `POST presentations` `createMode: pack`  
4. Optional outline + `POST generate` with same `packId` + `brandKitId`  
5. Poll status → edit canvas → export PPTX  

## Journey 2 — Blank Canva-style

1. Create blank (+ optional brand)  
2. Add slides / insert elements / autosave canvas  
3. Apply Brand Kit later  
4. Export  

## Journey 3 — AI from prompt

1. Create blank  
2. Outline from prompt → review cards  
3. Theme or Brand Kit  
4. Generate with wizard `generationFlow`  
5. Fix failed images via regenerate `target: image`  
6. Export  

## Journey 4 — Image studio for social

1. Open Image Gen  
2. Mode social → Instagram post → generate  
3. Tweak instruction → download JPG  
4. Asset already in library (`ai_gen`)  

## Journey 5 — Superadmin ships a new pack

1. Ensure layouts exist (`DECK_LAYOUT`)  
2. `POST /api/superadmin/templates` type `DECK_PACK`  
3. `isActive: true`  
4. Users see it in pack picker immediately  

---

# Part 6 — Master checklists

## Frontend epic checklist

### Shared
- [ ] Bearer + refresh with credentials  
- [ ] Envelope + 402 / 409 / 429 handling  
- [ ] Credit balance refresh after AI success  

### Brand Kit
- [ ] Full CRUD + media + default  
- [ ] MEMBER read-only UX  
- [ ] AI suggest: colors, fonts, voice, image-style, logo variants (preview free; apply charged)
- [ ] Show flat AC cost + handle 402 on billable Brand Kit actions  
- [ ] Health score on Overview tab  
- [ ] Generate guideline deck + export PDF/PPTX  
- [ ] Wire into PPT create / apply / generate (default kit when omitted)  

### Presentations
- [ ] Four create modes: blank, AI, template, pack  
- [ ] Outline → generate → status  
- [ ] Canvas autosave + element palette  
- [ ] Slide CRUD + regenerate  
- [ ] Export poll + download  
- [ ] Caps 20 / 40 / 50 shown in UI  

### Image Gen
- [ ] Catalogs + modes + estimate  
- [ ] Sync generate UX  
- [ ] Regenerate / tweak / download  
- [ ] History + library filter  

### Superadmin
- [ ] Template CRUD for DECK_LAYOUT and DECK_PACK  
- [ ] Activate toggle; no video schemas on PPT forms  

---

# Part 7 — Quick reference tables

## Brand Kit

| Method | Path |
|--------|------|
| GET | `/api/workspaces/:workspaceId/brand-kits` |
| POST | `/api/workspaces/:workspaceId/brand-kits` |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` |
| PATCH | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` |
| DELETE | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/set-default` |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media` |
| DELETE | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media/:mediaId` |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media/:mediaId/stream` |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/health` |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/colors` |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/fonts` |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/voice` |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/image-style` |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/suggest/logo-variants` |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines/generate` |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines` |

## Presentations (core)

| Method | Path |
|--------|------|
| POST | `/api/workspaces/:workspaceId/presentations` |
| GET | `/api/workspaces/:workspaceId/presentation-templates` |
| GET | `/api/workspaces/:workspaceId/presentation-deck-packs` |
| GET | `/api/workspaces/:workspaceId/presentation-deck-packs/:packId` |
| GET | `/api/workspaces/:workspaceId/presentation-themes` |
| GET | `/api/workspaces/:workspaceId/presentation-elements` |
| GET | `/api/workspaces/:workspaceId/presentations/:presentationId` |
| GET | `.../status` |
| GET | `.../credit-estimate` |
| POST | `.../outline` |
| PATCH | `.../outline` |
| POST | `.../theme` |
| POST | `.../apply-brand-kit` |
| POST | `.../generate` |
| POST/DELETE/PATCH | `.../slides…` (see Part 2.19) |
| POST/GET | `.../export…` |

## Image Gen

| Method | Path |
|--------|------|
| GET | `/api/image-gen/models` |
| GET | `/api/image-gen/formats` |
| GET | `/api/image-gen/styles` |
| GET | `/api/image-gen/workspaces/:workspaceId/estimate` |
| POST | `/api/image-gen/workspaces/:workspaceId/context` |
| GET | `/api/image-gen/workspaces/:workspaceId/context/:contextId` |
| DELETE | `/api/image-gen/workspaces/:workspaceId/context/:contextId` |
| POST | `/api/image-gen/workspaces/:workspaceId/generate` |
| GET | `/api/image-gen/workspaces/:workspaceId/generations` |
| GET | `/api/image-gen/workspaces/:workspaceId/generations/:generationId` |
| POST | `.../regenerate` |
| POST | `.../tweak` |
| GET | `.../download` |

## Superadmin templates

| Method | Path |
|--------|------|
| GET | `/api/superadmin/templates` |
| POST | `/api/superadmin/templates` |
| GET | `/api/superadmin/templates/:templateId` |
| PATCH | `/api/superadmin/templates/:templateId` |

---

**Document version:** 2026-08-01  
**Scope:** Brand Kit + Presentations (AI PPT / packs) + Image Gen + Superadmin templates that feed PPT.  
**Audience:** Frontend / full-stack integrators. Self-contained — no external doc required to implement.
