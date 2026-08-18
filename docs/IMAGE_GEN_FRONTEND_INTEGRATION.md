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
2. Show **model picker** from `/models`. Default `gpt-image-1` for Image/Social. For Infographic, preselect the model whose `recommendedForModes` includes `"infographic"` (`gpt-image-1-hd`).
3. Mode tabs: Image / Infographic / Social. Infographic format default: `landscape`.
4. Social → format chips from `/formats` where `category === "social"`. Default `textMode: overlay`. Preselect `textMode: baked` only when `recommendedTextMode === "baked"` (`youtube_thumbnail`). Always-on hint: overlay PNG already has Sharp typeset copy; step lists belong in Infographic (or baked + QA).
5. Optional **context attach zone**: files (PDF/DOCX/MD/TXT/images) + library asset picks + pasted text → `POST .../context` → show `previews` / `warnings`.
6. Call `GET .../estimate` when model/mode changes; show AC cost (context create is free). Infographic + HD default is **14 AC**. Social overlay / hasText wipe / baked retry are **not** extra AC.
7. Generate: `POST .../generate` with optional `contextId` — **long timeout** (image gen 30–90s; **infographic 90–180s** because of planner + optional quality edit; social overlay can add a wipe).
8. After success: preview `data.asset.url` / `data.generation.url`; show `contextPreview` badge if present. For infographic, read `data.generation.infographicQuality`. For social overlay, read `socialOverlay`; for baked, read `socialQuality`.
9. Actions: Regenerate (inherits context and `textMode`), Tweak (instruction modal; no context in v1; **does not re-typeset overlay** — change headline via Regenerate), Download menu (`png` | `jpg` | `pdf`).
10. History: `GET .../generations` (`?mode=image|infographic|social` optional) — versions share `rootId`.
11. Workspace **Images** tab: prefer `GET /api/workspaces/:workspaceId/library?category=image` (see [WORKSPACE_API.md](api/WORKSPACE_API.md)).
12. Library filter: assets `source=ai_gen`.
13. Infographic: always-on hint that text is auto-checked. If `infographicQuality.passed === false`, show a non-blocking banner with `issues` and optionally prefill Tweak from `suggestedTweak` (Tweak still bills; the free in-place fix already ran).
14. Social: always-on hint that overlay typesets `headline`/`subheadline`. Stronger warning if `textMode=baked`. If `socialQuality.passed === false`, show a review banner.

---

## Flows

### A — General image

1. Mode `image`, optional `formatId` (`square`/`landscape`/`portrait`), `style`, `prompt`.
2. Optional: create context, then pass `contextId`.
3. `POST .../generate`.
4. Preview → download or keep in library (already saved).

### B — Infographic

1. Mode `infographic`. Preselect `gpt-image-1-hd` and `formatId: "landscape"` (user may switch to medium/square/portrait).
2. Structured form: `infographic.layout`, `title`, `sections[]` (up to **24**), optional `brandPalette` + freeform `prompt` (max 16,000 — put the full story and labels here).
3. Optional context PDF/MD for brief text (injected into the planner + image prompt).
4. Soft hint: dense on-canvas text is auto-checked; remaining errors can use Tweak.
5. Generate (timeout **90–180s**) → download PNG/PDF for decks/docs.
6. If `infographicQuality.passed === false`, show issues; optional Tweak prefills `suggestedTweak`.

### C — Social creative

1. Mode `social`, required `formatId` (e.g. `instagram_post`, `linkedin_banner`).
2. Put **visible copy** in `headline` / `subheadline` (not `prompt`). Optional `brandPalette` / `contextId`. Social is valid with headline only (no prompt).
3. Default `textMode: overlay` — PNG already has Sharp typeset copy after cover-crop. Preselect `baked` only when `recommendedTextMode === "baked"` (YouTube thumbnail). Prefer HD for baked; do not change the social model default (`gpt-image-1`).
4. Always-on hint: overlay is the launch path. Stronger warning if `textMode=baked`. Numbered step lists → Infographic mode (or baked + QA).
5. Generate (server **cover-crops** to exact platform pixels, then overlays). Empty headline → background only (`socialOverlay.composited === false`).
6. If `socialQuality.passed === false` (baked), show issues. To change copy, **Regenerate** (Tweak does not re-overlay).
7. Download JPG/PNG for upload to the network.

### D — Context (briefs + references)

1. `POST .../context` as `multipart/form-data`:
   - `files`: up to 5 combined with assets
   - `payload`: JSON string `{ inlineText?, assetIds? }`
2. Show document excerpts + image vision summaries from `data.context.previews`.
3. Pass `data.context.id` as `contextId` on generate.
4. Regenerate: omit `contextId` to inherit; text snapshot survives TTL; visual refs need live/pinned context.

### E — Iterate

- **Regenerate:** same or edited params → new asset + child generation (inherits context and `textMode`). Overlay re-typesets headline.
- **Tweak:** `{ instruction }` → image edit on prior PNG → new asset (no context in v1). Does **not** re-run social overlay.

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
| Prompt | Max **16,000** chars. Show a counter; this is the brief (story, labels, panel copy), not a one-liner. |
| Infographic sections | Optional structure on top of prompt: **24** panels; panel body 8,000; bullets 1,000 each. |
| Tweak | `instruction` max **4,000** chars |
| Sync generate | Loading state + cancel only client-side (request may still complete/charge) |
| Infographic generate | Allow **90–180s**; server may run a planner + one free quality edit |
| Infographic default | `gpt-image-1-hd` + `landscape` → estimate **14 AC**. Explicit medium is **8 AC**. |
| HD (`gpt-image-1-hd`) | Best quality; higher AC — show estimate. Preselect on Infographic tab (`recommendedForModes`). |
| DALL·E 3 (`dall-e-3`) | Still offered for UI compat; backend runs GPT Image HD. Hide for `infographic` (`modes` from catalog) |
| Infographic quality | `generation.infographicQuality.passed === false` → banner; do not charge again for the silent retry |
| Social overlay | Default `textMode: overlay`. PNG is already typeset. `socialOverlay.composited` false = background only. |
| Social baked | Opt-in; `socialQuality.passed === false` → banner. Prefer HD for YouTube. |
| Social copy changes | Regenerated overlay re-typesets. Tweak v1 does **not** re-overlay. |
| Context | Free to create; max 5 files+assets; TTL ~7 days; pinned after first generate |
| Library | Filter AI assets; open generation via `stockMetadata.generationId` |
