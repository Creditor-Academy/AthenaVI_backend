# Image Gen — frontend integration

Studio for AI **images** and **infographics** (OpenAI).  
HTTP details: [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).  
**Complete backend guide:** [`IMAGE_GEN_COMPLETE.md`](IMAGE_GEN_COMPLETE.md).  
**Infographic PRD:** [`INFOGRAPHIC_MODE_PRD.md`](INFOGRAPHIC_MODE_PRD.md).

**Auth:** `Authorization: Bearer <accessToken>`  
**Envelope:** `{ success, message, data }`  
**Base:** `/api/image-gen`

---

## Mental model

```
Workspace → Folder → Image/Infographic chat
  → (optional) attach context
  → pick mode (image | infographic), model, format, style / archetype
  → Generate (sync) → saved chat + Asset
  → Folder card: View | Download | Open chat  (+ badge mode)
  → Chat send → image: pixel edit; infographic: spec patch or pixel (server-routed)
```

---

## UI checklist

1. Load catalogs: `GET /models`, `/formats`, `/styles`, `/archetypes`.
2. **Mode toggle:** `image` | `infographic`.
3. User is inside a **folder**. Generate requires `folderId`.
4. **Image:** default model `gpt-image-1`, format `square`. Timeout **30–90s**.
5. **Infographic:** default model `gpt-image-1-hd`, format `landscape`. Optional archetype picker (or “auto”). Style = free-text `styleHint` and/or existing style chips. Timeout **≥ 120s**.
6. Optional context attach → `POST .../context` → pass `contextId`.
7. `GET .../estimate?mode=&modelId=&tweak=`.
8. After success: preview `actions.viewUrl`; open `actions.threadId`. For infographic, optional collapsible `generation.infographicSpec`.
9. Folder Images tab: `GET /api/workspaces/:workspaceId/library?category=image&folderId=` — use `item.mode` / `item.archetype` for badges.
10. Chat: `POST .../messages` `{ content, editMode? }`. Infographic content edits take the spec path; “make background darker” may pixel-edit (`request.pixelEdited`).
11. Download menu on the hop being viewed.
12. Library assets: `source=ai_gen`.

---

## Flows

### A — General image

`POST .../generate` with `mode: "image"`, required `prompt`, `folderId`.

### B — Infographic

```json
{
  "mode": "infographic",
  "folderId": "...",
  "prompt": "...",
  "archetypeHint": "comparison",
  "styleHint": "minimal",
  "formatId": "landscape",
  "modelId": "gpt-image-1-hd"
}
```

### C — Context

Unchanged multipart create; pass `contextId` on generate.

### D — Iterate

Open chat free; send charges tweak/infographic AC. Prefer regenerate-from-spec after a pixel edit if content fidelity matters (`pixelEdited: true`).

---

## Errors

| Status | Meaning |
|--------|---------|
| 400 | Validation / invalid mode / invalid or failed infographic spec / mode mismatch |
| 402 | Insufficient credits |
| 404 | Missing generation/thread/folder/expired context |
| 409 | Delete pinned context |
| 429 | Rate limited |
| 502/503 | OpenAI failure / not configured |

---

## Caps / UX hints

| Topic | Hint |
|-------|------|
| Prompt | Max **16,000** chars |
| Chat / tweak | Max **4,000** chars |
| Infographic sync | Loading + **≥ 120s** timeout |
| Thread mode | Sticky — do not mix image and infographic in one chat |
| Dense content | Server may truncate sections and return `request.warnings` |
