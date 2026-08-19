# Image Gen — frontend integration

Studio for AI **images** (OpenAI). Infographic and social modes are not offered.  
HTTP details: [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).

**Auth:** `Authorization: Bearer <accessToken>`  
**Envelope:** `{ success, message, data }`  
**Base:** `/api/image-gen`

---

## Mental model

```
Workspace → Image Gen studio
  → (optional) attach context: files / assets / pasted text → POST /context
  → pick model, format (square / landscape / portrait), style
  → Generate with contextId (sync) → preview Asset
  → Regenerate | Tweak | Download (png/jpg/pdf) | Save already in library
```

Every success creates an **Asset** (`source: "ai_gen"`) and a **generation** row (history + version chain).

---

## UI checklist

1. Load catalogs once: `GET /models`, `/formats`, `/styles`.
2. Show **model picker** from `/models`. Default `gpt-image-1`.
3. Formats are generic only: `square`, `landscape`, `portrait`.
4. Optional **context attach zone**: files (PDF/DOCX/MD/TXT/images) + library asset picks + pasted text → `POST .../context` → show `previews` / `warnings`.
5. Call `GET .../estimate` when model changes; show AC cost (context create is free). Default generate is **6 AC**.
6. Generate: `POST .../generate` with `mode: "image"` (or omit), required `prompt`, optional `contextId` — timeout **30–90s**.
7. After success: preview `data.asset.url` / `data.generation.url`; show `contextPreview` badge if present.
8. Actions: Regenerate (inherits context), Tweak (instruction modal; no context in v1), Download menu (`png` | `jpg` | `pdf`).
9. History: `GET .../generations` — always `mode=image`; versions share `rootId`.
10. Workspace **Images** tab: prefer `GET /api/workspaces/:workspaceId/library?category=image` (see [WORKSPACE_API.md](api/WORKSPACE_API.md)).
11. Library filter: assets `source=ai_gen`.

---

## Flows

### A — General image

1. Optional `formatId` (`square`/`landscape`/`portrait`), `style`, required `prompt`.
2. Optional: create context, then pass `contextId`.
3. `POST .../generate` with `mode: "image"`.
4. Preview → download or keep in library (already saved).

### B — Context (briefs + references)

1. `POST .../context` as `multipart/form-data`:
   - `files`: up to 5 combined with assets
   - `payload`: JSON string `{ inlineText?, assetIds? }`
2. Show document excerpts + image vision summaries from `data.context.previews`.
3. Pass `data.context.id` as `contextId` on generate.
4. Regenerate: omit `contextId` to inherit; text snapshot survives TTL; visual refs need live/pinned context.

### C — Iterate

- **Regenerate:** same or edited params → new asset + child generation (inherits context). Parent must be image (**400** otherwise).
- **Tweak:** `{ instruction }` → image edit on prior PNG → new asset (no context in v1).

### D — Download

```
GET .../generations/:id/download?format=png|jpg|jpeg|pdf
```

Use blob download with filename from `Content-Disposition` (prompt-derived kebab-case, e.g. `cute-coffee-cup-emoji.png`). Optional generate `name` overrides that. Do not invent technical names client-side. No credits.

Library and history should show `asset.name` / `generation.request.name`. `stockMetadata.generationId` is unchanged for internal linking.

---

## Errors to handle in UI

| Status | Meaning |
|--------|---------|
| 400 | Validation / invalid model/format / empty context / expired context on generate / non-image parent on regen/tweak |
| 402 | Insufficient credits |
| 404 | Generation not found or not `mode=image` |
| 409 | Delete context while pinned |
| 429 | Rate limited — show retry |
| 502/503 | OpenAI failure / not configured |

Successful charges appear in workspace credit history with `metadata.feature` like `image_gen_gpt_image` / `image_gen_tweak`; UI should show `usageDetail.label` (e.g. “AI image generation”).

---

## Caps / UX hints

| Topic | Hint |
|-------|------|
| Prompt | Required. Max **16,000** chars. |
| Tweak | `instruction` max **4,000** chars |
| Sync generate | Loading state + cancel only client-side (request may still complete/charge). Allow **30–90s**. |
| Default | `gpt-image-1` + `square` → **6 AC**. HD is **12 AC**. |
| DALL·E 3 (`dall-e-3`) | Compat alias; backend runs GPT Image HD. |
| Context | Free to create; max 5 files+assets; TTL ~7 days; pinned after first generate |
| Library | Filter AI assets; open generation via `stockMetadata.generationId` |
