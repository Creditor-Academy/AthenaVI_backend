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
  → pick mode (image | infographic | social)
  → pick model (OpenAI catalog)
  → pick format / style
  → Generate (sync) → preview Asset
  → Regenerate | Tweak | Download (png/jpg/pdf) | Save already in library
```

Every success creates an **Asset** (`source: "ai_gen"`) and a **generation** row (history + version chain).

---

## UI checklist

1. Load catalogs once: `GET /models`, `/formats`, `/styles`.
2. Show **model picker** from `/models` (default `gpt-image-1`).
3. Mode tabs: Image / Infographic / Social.
4. Social → format chips from `/formats` where `category === "social"`.
5. Call `GET .../estimate` when model/mode changes; show AC cost.
6. Generate: `POST .../generate` — **long timeout** (image gen can take 30–90s).
7. After success: preview `data.asset.url` / `data.generation.url`.
8. Actions: Regenerate, Tweak (instruction modal), Download menu (`png` | `jpg` | `pdf`).
9. History: `GET .../generations` — versions share `rootId`.
10. Library filter: assets `source=ai_gen`.

---

## Flows

### A — General image

1. Mode `image`, optional `formatId` (`square`/`landscape`/`portrait`), `style`, `prompt`.
2. `POST .../generate`.
3. Preview → download or keep in library (already saved).

### B — Infographic

1. Mode `infographic`, prefer `gpt-image-1` / HD.
2. Structured form: `infographic.layout`, `title`, `sections[]`, optional `brandPalette` + freeform `prompt`.
3. Generate → download PNG/PDF for decks/docs.

### C — Social creative

1. Mode `social`, required `formatId` (e.g. `instagram_post`, `linkedin_banner`).
2. Optional `headline` / `subheadline` / `brandPalette`.
3. Generate (server **cover-crops** to exact platform pixels for full-bleed — no letterbox side panels).
4. Prefer sending `headline` / `subheadline` for readable on-canvas copy; keep copy short.
5. For banners/covers, remind users the design is panoramic full-bleed; empty side bars mean regenerate.
6. Download JPG/PNG for upload to the network.

### D — Iterate

- **Regenerate:** same or edited params → new asset + child generation.
- **Tweak:** `{ instruction }` → image edit on prior PNG → new asset.

### E — Download

```
GET .../generations/:id/download?format=png|jpg|jpeg|pdf
```

Use blob download with filename from `Content-Disposition`. No credits.

---

## Errors to handle in UI

| Status | Meaning |
|--------|---------|
| 400 | Validation / invalid model/format |
| 402 | Insufficient credits |
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
| Library | Filter AI assets; open generation via `stockMetadata.generationId` |
