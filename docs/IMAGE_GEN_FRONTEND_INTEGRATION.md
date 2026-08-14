# Image Gen — frontend integration

Studio for AI images, infographics, and social creatives (OpenAI).  
HTTP details: [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).

**Auth:** `Authorization: Bearer <accessToken>`  
**Envelope:** `{ success, message, data }`  
**Base:** `/api/image-gen`

---

## Mental model

```
Workspace → Image Gen studio
  → (optional) attach context: files / assets / pasted text → POST /context
  → pick mode (image | infographic | social)
  → pick model (OpenAI catalog)
  → pick format / style
  → Generate with contextId (sync) → preview Asset
  → Regenerate | Tweak | Download (png/jpg/pdf) | Save already in library
```

Every success creates an **Asset** (`source: "ai_gen"`) and a **generation** row (history + version chain).

---

## UI checklist

1. Load catalogs once: `GET /models`, `/formats`, `/styles`.
2. Show **model picker** from `/models` (default `gpt-image-1`).
3. Mode tabs: Image / Infographic / Social.
4. Social → format chips from `/formats` where `category === "social"`.
5. Optional **context attach zone**: files (PDF/DOCX/MD/TXT/images) + library asset picks + pasted text → `POST .../context` → show `previews` / `warnings`.
6. Call `GET .../estimate` when model/mode changes; show AC cost (context create is free).
7. Generate: `POST .../generate` with optional `contextId` — **long timeout** (image gen can take 30–90s).
8. After success: preview `data.asset.url` / `data.generation.url`; show `contextPreview` badge if present.
9. Actions: Regenerate (inherits context), Tweak (instruction modal; no context in v1), Download menu (`png` | `jpg` | `pdf`).
10. History: `GET .../generations` (`?mode=image|infographic|social` optional) — versions share `rootId`.
11. Workspace **Images** tab: prefer `GET /api/workspaces/:workspaceId/library?category=image` (see [WORKSPACE_API.md](api/WORKSPACE_API.md)).
12. Library filter: assets `source=ai_gen`.

---

## Flows

### A — General image

1. Mode `image`, optional `formatId` (`square`/`landscape`/`portrait`), `style`, `prompt`.
2. Optional: create context, then pass `contextId`.
3. `POST .../generate`.
4. Preview → download or keep in library (already saved).

### B — Infographic

1. Mode `infographic`, prefer `gpt-image-1` / HD.
2. Structured form: `infographic.layout`, `title`, `sections[]`, optional `brandPalette` + freeform `prompt`.
3. Optional context PDF/MD for brief text (no auto-structure in v1 — text is injected into the prompt).
4. Generate → download PNG/PDF for decks/docs.

### C — Social creative

1. Mode `social`, required `formatId` (e.g. `instagram_post`, `linkedin_banner`).
2. Optional `headline` / `subheadline` / `brandPalette` / `contextId`.
3. Generate (server **cover-crops** to exact platform pixels for full-bleed — no letterbox side panels).
4. Prefer sending `headline` / `subheadline` for readable on-canvas copy; keep copy short.
5. For banners/covers, remind users the design is panoramic full-bleed; empty side bars mean regenerate.
6. Download JPG/PNG for upload to the network.

### D — Context (briefs + references)

1. `POST .../context` as `multipart/form-data`:
   - `files`: up to 5 combined with assets
   - `payload`: JSON string `{ inlineText?, assetIds? }`
2. Show document excerpts + image vision summaries from `data.context.previews`.
3. Pass `data.context.id` as `contextId` on generate.
4. Regenerate: omit `contextId` to inherit; text snapshot survives TTL; visual refs need live/pinned context.

### E — Iterate

- **Regenerate:** same or edited params → new asset + child generation (inherits context).
- **Tweak:** `{ instruction }` → image edit on prior PNG → new asset (no context in v1).

### F — Download

```
GET .../generations/:id/download?format=png|jpg|jpeg|pdf
```

Use blob download with filename from `Content-Disposition` (prompt-derived kebab-case, e.g. `cute-coffee-cup-emoji.png`). Optional generate `name` overrides that. Do not invent technical names client-side. No credits.

Library and history should show `asset.name` / `generation.request.name`. `stockMetadata.generationId` is unchanged for internal linking.

---

## Errors to handle in UI

| Status | Meaning |
|--------|---------|
| 400 | Validation / invalid model/format / empty context / expired context on generate |
| 402 | Insufficient credits |
| 409 | Delete context while pinned |
| 429 | Rate limited — show retry |
| 502/503 | OpenAI failure / not configured |

Successful charges appear in workspace credit history with `metadata.feature` like `image_gen_gpt_image` / `image_gen_tweak`; UI should show `usageDetail.label` (e.g. “AI image generation”).

---

## Caps / UX hints

| Topic | Hint |
|-------|------|
| Sync generate | Loading state + cancel only client-side (request may still complete/charge) |
| HD (`gpt-image-1-hd`) | Best quality; higher AC — show estimate |
| DALL·E 3 (`dall-e-3`) | Still offered for UI compat; backend runs GPT Image HD. Hide for `infographic` (`modes` from catalog) |
| Context | Free to create; max 5 files+assets; TTL ~7 days; pinned after first generate |
| Library | Filter AI assets; open generation via `stockMetadata.generationId` |
