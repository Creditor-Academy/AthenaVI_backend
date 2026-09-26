# Image Gen — frontend integration

Studio for AI **images**, **infographics**, and **social media posts** (OpenAI + Gemini models).  
HTTP details: [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).  
**Complete backend guide:** [`IMAGE_GEN_COMPLETE.md`](IMAGE_GEN_COMPLETE.md).  
**Infographic PRD:** [`INFOGRAPHIC_MODE_PRD.md`](INFOGRAPHIC_MODE_PRD.md).

**Auth:** `Authorization: Bearer <accessToken>`  
**Envelope:** `{ success, message, data }`  
**Base:** `/api/image-gen`

---

## Mental model

```
Workspace → Folder → Image / Infographic / Social chat
  → (optional) attach context
  → pick mode (1 image | 2 infographic | 3 social)
      → Mode 3 only: pick one of seven destinations (formatId)
  → pick provider (OpenAI | Gemini) → pick one of its 3 models
  → Generate (sync) → saved chat + Asset
  → Folder card: View | Download | Open chat  (+ badge mode / platform)
  → Chat send → image: pixel edit; infographic + social: spec patch or pixel (server-routed)
```

---

## UI checklist

1. Load catalogs: `GET /models`, `/formats`, `/styles`, `/archetypes`.
2. **Mode toggle:** Mode 1 `image` | Mode 2 `infographic` | Mode 3 `social`.
3. User is inside a **folder**. Generate requires `folderId`.
4. **Image (Mode 1):** default provider OpenAI with a **Recommended** badge, model `gpt-image-1-hd`, format `square`. Timeout **30–90s**.
5. **Infographic (Mode 2):** default provider Gemini, model `gemini-3-pro-image`, format `landscape`. Optional archetype picker (or “auto”). Style = free-text `styleHint` and/or existing style chips. Timeout **≥ 120s**.
6. **Social (Mode 3):** show the seven destinations from `/formats` where `modes` includes `social` (card = `name`, `width`×`height`, `platform` icon). The user must pick one before Generate; send it as `formatId`. Default provider Gemini, model `gemini-3-pro-image`. Prompt is free text (same as infographic); style = `styleHint` and/or style chips; optional `brandPalette`. Timeout **≥ 120s**.
7. **Model picker** (all modes), driven by `GET /models` → `data.providers`, `data.defaults`, `data.models`:
   - Step 1 shows two provider cards, OpenAI and Gemini. Preselect `defaults[mode].provider`. Put the **Recommended** badge on `defaults[mode].recommendedProvider` (OpenAI in Mode 1; none in Modes 2 and 3).
   - Step 2 appears after a provider click and lists that provider's three `modelIds` in order (high quality first), with names and `creditEstimate` from `models`. Preselect `defaults[mode].modelId` for the default provider, or `provider.defaultModelId` after a switch.
   - When the mode changes, reset to that mode's defaults unless the user already picked a model in this session.
   - Gemini notes: `gemini-3-pro-image` has the best in-image text. `gemini-3.1-flash-lite-image` has `maxImageSize: "1K"`; label it draft quality, because larger outputs are upscaled. Credits vary (4–12 AC).
8. Optional context attach → `POST .../context` → pass `contextId`.
9. `GET .../estimate?mode=&modelId=&tweak=`.
10. After success: preview `actions.viewUrl`; open `actions.threadId`. Optional collapsible spec: `generation.infographicSpec` or `generation.socialSpec` (headline, supporting line, CTA). Show `request.warnings` (for example "Headline shortened…") as a dismissible notice.
11. Folder Images tab: `GET /api/workspaces/:workspaceId/library?category=image&folderId=` — use `item.mode` / `item.archetype` / thread `platform` for badges.
12. Chat: `POST .../messages` `{ content, editMode? }`. Infographic and social copy edits take the spec path; “make background darker” may pixel-edit (`request.pixelEdited`).
13. Download menu on the hop being viewed.
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

### D — Context

Unchanged multipart create; pass `contextId` on generate.

### E — Iterate

Opening a chat is free. Sending a message charges tweak AC in Mode 1 and the mode AC in Modes 2 and 3. Prefer regenerate-from-spec after a pixel edit if text fidelity matters (`pixelEdited: true`).

---

## Errors

| Status | Meaning |
|--------|---------|
| 400 | Validation / invalid mode / missing or wrong-mode `formatId` / invalid or failed infographic or social spec / mode mismatch / social destination change / provider safety block |
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
| Infographic / social sync | Loading + **≥ 120s** timeout |
| Thread mode | Sticky: image, infographic, and social never mix in one chat; a social chat keeps its destination |
| Dense content | Server may truncate sections or copy and return `request.warnings` |
| Social copy | Short copy works best. YouTube thumbnails keep only the headline (≤ 40 chars); banners and covers drop the CTA |
