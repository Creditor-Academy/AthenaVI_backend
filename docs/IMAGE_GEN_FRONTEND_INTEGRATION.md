# Image Gen — frontend integration

Studio for AI **images**, **infographics**, **social media posts**, and **printables** (OpenAI + Gemini models).  
HTTP details: [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).  
**Complete backend guide:** [`IMAGE_GEN_COMPLETE.md`](IMAGE_GEN_COMPLETE.md).  
**Infographic PRD:** [`INFOGRAPHIC_MODE_PRD.md`](INFOGRAPHIC_MODE_PRD.md).

**Auth:** `Authorization: Bearer <accessToken>`  
**Envelope:** `{ success, message, data }`  
**Base:** `/api/image-gen`

---

## Mental model

```
Workspace → Folder → Image / Infographic / Social / Printable chat
  → (optional) attach context
  → pick mode (1 image | 2 infographic | 3 social | 4 printable)
      → Mode 3: pick one of seven destinations (formatId)
      → Mode 4: pick one of eight print sizes (formatId)
  → pick provider (OpenAI | Gemini) → pick one of its 3 models
  → Generate (sync) → saved chat + Asset
  → Folder card: View | Download | Open chat  (+ badge mode / platform)
  → Chat send → image: pixel edit; infographic + social + printable: spec patch or pixel (server-routed)
```

---

## UI checklist

1. Load catalogs: `GET /models`, `/formats`, `/styles`, `/archetypes`.
2. **Mode toggle:** Mode 1 `image` | Mode 2 `infographic` | Mode 3 `social` | Mode 4 `printable`.
3. User is inside a **folder**. Generate requires `folderId`.
4. **Image (Mode 1):** default provider OpenAI with a **Recommended** badge, model `gpt-image-1-hd`, format `square`. Timeout **30–90s**.
5. **Infographic (Mode 2):** default provider Gemini, model `gemini-3-pro-image`, format `landscape`. Optional archetype picker (or “auto”). Style = free-text `styleHint` and/or existing style chips. Timeout **≥ 120s**.
6. **Social (Mode 3):** show the seven destinations from `/formats` where `modes` includes `social` (card = `name`, `width`×`height`, `platform` icon). The user must pick one before Generate; send it as `formatId`. Default provider Gemini, model `gemini-3-pro-image`. Prompt is free text (same as infographic); style = `styleHint` and/or style chips; optional `brandPalette`. Timeout **≥ 120s**.
6b. **Printable (Mode 4):** show the eight sizes from `/formats` where `modes` includes `printable`, grouped by `print.kind` (Posters A4 / A3 / A2 with a portrait/landscape toggle, Business card, Invitation). Label cards with physical size from `print` (`widthMm`×`heightMm` mm, or `widthIn`×`heightIn` in for the card) and `print.dpi`. The user must pick one; send it as `formatId`. Defaults are the same as Mode 3: Gemini, `gemini-3-pro-image`, no Recommended badge. Hint in the prompt box: "Include every date, venue, name, phone, email, and URL you want printed." Timeout **≥ 120s**.
7. **Model picker** (all modes), driven by `GET /models` → `data.providers`, `data.defaults`, `data.models`:
   - Step 1 shows two provider cards, OpenAI and Gemini. Preselect `defaults[mode].provider`. Put the **Recommended** badge on `defaults[mode].recommendedProvider` (OpenAI in Mode 1; none in Modes 2, 3, and 4).
   - Step 2 appears after a provider click and lists that provider's three `modelIds` in order (high quality first), with names and `creditEstimate` from `models`. Preselect `defaults[mode].modelId` for the default provider, or `provider.defaultModelId` after a switch.
   - When the mode changes, reset to that mode's defaults unless the user already picked a model in this session.
   - Gemini notes: `gemini-3-pro-image` has the best in-image text. `gemini-3.1-flash-lite-image` has `maxImageSize: "1K"`; label it draft quality, because larger outputs are upscaled. Credits vary (4–12 AC).
8. Optional context attach → `POST .../context` → pass `contextId`.
9. `GET .../estimate?mode=&modelId=&tweak=`.
10. After success: preview `actions.viewUrl`; open `actions.threadId`. Optional collapsible spec: `generation.infographicSpec`, `generation.socialSpec` (headline, supporting line, CTA), or `generation.printSpec` (headline, subheadline, `details[]` lines, CTA). Show `request.warnings` (for example "Headline shortened…") as a dismissible notice.
11. Folder Images tab: `GET /api/workspaces/:workspaceId/library?category=image&folderId=` — use `item.mode` / `item.archetype` / thread `platform` for badges.
12. Chat: `POST .../messages` `{ content, editMode? }`. Infographic, social, and printable copy edits take the spec path; “make background darker” may pixel-edit (`request.pixelEdited`).
13. Download menu on the hop being viewed. For printables (`generation.print` is set) add **PDF for print (with bleed & crop marks)** → `?format=pdf&bleed=true`, shown only when `generation.print.bleedAvailable` is true.
14. Library assets: `source=ai_gen`.

---

## Flows

### A — General image

`POST .../generate` with `mode: "image"`, required `prompt`, `folderId`. Omit `modelId` to get `gpt-image-1-hd`.

### B — Infographic

```json
{
  "mode": "infographic",
  "folderId": "...",
  "prompt": "...",
  "archetypeHint": "comparison",
  "styleHint": "minimal",
  "formatId": "landscape",
  "modelId": "gemini-3-pro-image"
}
```

### C — Social post

```json
{
  "mode": "social",
  "folderId": "...",
  "formatId": "youtube-thumbnail",
  "prompt": "Thumbnail for my video about launching a course in a weekend",
  "styleHint": "bold, high contrast",
  "modelId": "gemini-3-pro-image"
}
```

| Destination | `formatId` | Size |
|-------------|------------|------|
| YouTube thumbnail | `youtube-thumbnail` | 1280×720 |
| Instagram post | `instagram-post` | 1080×1350 (4:5) |
| Facebook post | `facebook-post` | 940×788 |
| Facebook cover | `facebook-cover` | 851×315 |
| YouTube banner | `youtube-banner` | 2560×1440 |
| Twitter/X post | `twitter-post` | 1600×900 |
| LinkedIn banner | `linkedin-banner` | 1584×396 |

The downloaded asset is exactly this size. One generate produces one destination. For another destination, start a new generate (a new chat): regenerate and chat keep the original `formatId`, and sending a different one returns 400.

### D — Printable

```json
{
  "mode": "printable",
  "folderId": "...",
  "formatId": "poster-a4-portrait",
  "prompt": "Poster for the Athena Learning Summit, 14-15 November 2026 at Bengaluru International Centre. Register at athenavi.com/summit",
  "styleHint": "modern, bold typography",
  "modelId": "gemini-3-pro-image"
}
```

| Size | `formatId` | Trim size | DPI | Asset px |
|------|------------|-----------|-----|----------|
| A4 poster, portrait / landscape | `poster-a4-portrait` / `poster-a4-landscape` | 210×297 mm | 300 | 2480×3508 / 3508×2480 |
| A3 poster, portrait / landscape | `poster-a3-portrait` / `poster-a3-landscape` | 297×420 mm | 150 | 1754×2480 / 2480×1754 |
| A2 poster, portrait / landscape | `poster-a2-portrait` / `poster-a2-landscape` | 420×594 mm | 150 | 2480×3508 / 3508×2480 |
| Business card (front) | `business-card` | 3.5×2 in | 300 | 1050×600 |
| Invitation | `invitation-a6-portrait` | 105×148 mm | 300 | 1240×1748 |

The asset (PNG / JPG download and the preview) is the **trim** size, i.e. the finished piece. Downloads:

| Menu item | Request | Result |
|-----------|---------|--------|
| PNG / JPG | `?format=png` / `?format=jpg` | Trim size, DPI in the file |
| PDF | `?format=pdf` | One page at the physical size (A4 = 210×297 mm) |
| PDF for print | `?format=pdf&bleed=true` | Trim + bleed + crop marks, TrimBox/BleedBox set; filename `…_bleed.pdf` |

Like Mode 3, one generate is one size. Regenerate and chat keep the `formatId`; sending another one returns 400 ("This chat is locked to one size…"). Business cards are front only. Copy limits per size are in the API doc; extra detail lines are dropped with a `request.warnings` note.

### E — Context

Unchanged multipart create; pass `contextId` on generate.

### F — Iterate

Opening a chat is free. Sending a message charges tweak AC in Mode 1 and the mode AC in Modes 2, 3, and 4. Prefer regenerate-from-spec after a pixel edit if text fidelity matters (`pixelEdited: true`).

---

## Errors

| Status | Meaning |
|--------|---------|
| 400 | Validation / invalid mode / missing or wrong-mode `formatId` / invalid or failed infographic, social, or print spec / mode mismatch / size change in a social or printable chat / `bleed=true` on a non-PDF or non-printable download / provider safety block |
| 402 | Insufficient credits |
| 404 | Missing generation/thread/folder/expired context |
| 409 | Delete pinned context |
| 429 | Rate limited |
| 502/503 | OpenAI or Gemini failure / provider not configured |

---

## Caps / UX hints

| Topic | Hint |
|-------|------|
| Prompt | Max **16,000** chars |
| Chat / tweak | Max **4,000** chars |
| Infographic / social / printable sync | Loading + **≥ 120s** timeout |
| Thread mode | Sticky: modes never mix in one chat; social and printable chats keep their size |
| Dense content | Server may truncate sections or copy and return `request.warnings` |
| Social copy | Short copy works best. YouTube thumbnails keep only the headline (≤ 40 chars); banners and covers drop the CTA |
| Print copy | Business cards have no CTA and up to 4 contact lines (≤ 48 chars each). Posters fit 4 detail lines, invitations 5 |
| Print preview | Show the trim-size asset with its physical size; the bleed only appears in the "PDF for print" download |
