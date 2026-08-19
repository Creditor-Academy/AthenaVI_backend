# Image Gen — frontend integration

Studio for AI **images** (OpenAI). Infographic and social modes are not offered.  
HTTP details: [`docs/api/IMAGE_GEN_API.md`](api/IMAGE_GEN_API.md).

**Auth:** `Authorization: Bearer <accessToken>`  
**Envelope:** `{ success, message, data }`  
**Base:** `/api/image-gen`

---

## Mental model

```
Workspace → Folder → Image chat
  → (optional) attach context: files / assets / pasted text → POST /context
  → pick model, format (square / landscape / portrait), style
  → Generate with folderId + contextId (sync) → saved chat + Asset
  → Folder card: View | Download | Open chat
  → Chat send → edits latest hop (charges AC)
```

Every success creates an **Asset** (`source: "ai_gen"`), a **generation** hop, and (on first generate) a **thread** in the folder.

From a folder Images row:

| Action | API | Cost |
|--------|-----|------|
| **View** | `item.head.url` | Free |
| **Download** | `GET .../generations/:head.generationId/download` | Free |
| **Open chat** | `GET .../threads/:id` then `POST .../messages` | Open free; next image = tweak AC |

---

## UI checklist

1. Load catalogs once: `GET /models`, `/formats`, `/styles`.
2. User is inside a **folder**. Generate requires `folderId`.
3. Show **model picker** from `/models`. Default `gpt-image-1`.
4. Formats are generic only: `square`, `landscape`, `portrait`.
5. Optional **context attach zone**: files (PDF/DOCX/MD/TXT/images) + library asset picks + pasted text → `POST .../context` → show `previews` / `warnings`.
6. Call `GET .../estimate` when model changes; show AC cost (context create is free). Default generate is **6 AC**. Chat follow-ups: `estimate?tweak=true`.
7. Generate: `POST .../generate` with `folderId`, `mode: "image"` (or omit), required `prompt`, optional `contextId` — timeout **30–90s**.
8. After success: preview `data.actions.viewUrl` / `data.asset.url`; use `data.thread` / `data.actions.threadId` for chat.
9. Folder Images tab: `GET /api/workspaces/:workspaceId/library?category=image&folderId=` (threads, not hops).
10. Open chat: `GET .../threads/:threadId` — render `messages`; composer `POST .../messages` `{ content }`.
11. Download menu (`png` | `jpg` | `pdf`) on the hop being viewed.
12. Library assets filter: `source=ai_gen`.

---

## Flows

### A — General image

1. Required `folderId`. Optional `formatId`, `style`, required `prompt`.
2. Optional: create context, then pass `contextId`.
3. `POST .../generate` with `mode: "image"`.
4. Card actions: View / Download / Open chat.

### B — Context (briefs + references)

1. `POST .../context` as `multipart/form-data`:
   - `files`: up to 5 combined with assets
   - `payload`: JSON string `{ inlineText?, assetIds? }`
2. Show document excerpts + image vision summaries from `data.context.previews`.
3. Pass `data.context.id` as `contextId` on generate.
4. Chat / regenerate: omit `contextId` to inherit; text snapshot survives TTL; visual refs need live/pinned context.

### C — Iterate (chat)

- **Open chat** (free): `GET .../threads/:id`.
- **Send** `{ content }` → new image from **head** (or `fromGenerationId` to branch). Charges tweak AC.
- **Regenerate:** still available on a generation id; also appends to the same thread.
- **Tweak:** `{ instruction }` on a generation id still works; prefer chat send so history is composed for OpenAI.

### D — Download

```
GET .../generations/:id/download?format=png|jpg|jpeg|pdf
```

Use blob download with filename from `Content-Disposition`. No credits.

---

## Errors to handle in UI

| Status | Meaning |
|--------|---------|
| 400 | Validation / missing `folderId` / invalid model/format / empty context / expired context on generate / non-image parent |
| 402 | Insufficient credits |
| 404 | Generation, thread, or folder not found |
| 409 | Delete context while pinned |
| 429 | Rate limited — show retry |
| 502/503 | OpenAI failure / not configured |

Successful charges appear in workspace credit history with `metadata.feature` like `image_gen_gpt_image` / `image_gen_tweak` (includes `threadId`). UI should show `usageDetail.label` (e.g. “AI image generation”).

---

## Caps / UX hints

| Topic | Hint |
|-------|------|
| Prompt | Required. Max **16,000** chars. |
| Chat / tweak | `content` / `instruction` max **4,000** chars |
| Sync generate | Loading state + cancel only client-side (request may still complete/charge). Allow **30–90s**. |
| Default | `gpt-image-1` + `square` → **6 AC**. HD is **12 AC**. Chat follow-up = same model AC. |
| DALL·E 3 (`dall-e-3`) | Compat alias; backend runs GPT Image HD. |
| Context | Free to create; max 5 files+assets; TTL ~7 days; pinned after first generate |
| Folder | Generate requires `folderId`. Move chat with `POST .../threads/:id/move-folder`. |
| Library | One card per chat; `item.head.url` / `item.head.generationId` / `item.id` |
