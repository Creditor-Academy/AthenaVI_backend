# HeyGen video editor — frontend handoff (bug fixes + required frontend changes)

> **Audience:** frontend engineers on the video editor (avatar picker, narration, scene video generation, export).
> **Status:** backend fixes are done and covered by tests. The three frontend items in §3 (**F1, F2, F3**) are **still open** and are needed to fully close the bugs.
> Contracts live in [`docs/api/HEYGEN_API.md`](api/HEYGEN_API.md), [`docs/api/HEYGEN_PROJECT_VIDEOS_API.md`](api/HEYGEN_PROJECT_VIDEOS_API.md), [`docs/api/PROJECT_SPEECH_API.md`](api/PROJECT_SPEECH_API.md), [`docs/api/CREDITS_API.md`](api/CREDITS_API.md). This file is the "what changed and what you must do" summary.

---

## 1. TL;DR

| # | Reported bug | Backend (done) | Frontend (to do) |
|---|---|---|---|
| 1 | `400 This avatar is available only with Avatar 6 Pro or Turbo`. Plan-locked avatars offered, toast showed raw JSON, MP4 export failed | New engines `heygen-avatar-6` / `heygen-avatar-6-turbo` supported. The engine is validated against what the look supports, and falls back to Avatar 6 Turbo on a plan-gate | **F3** pass the look's engine; **F1** stop showing raw JSON |
| 2 | Blank white page after narration, project cannot be reopened. 400s on `/heygen/avatars/looks` and `/heygen/videos` | Validation 400s removed or relaxed (§2.3, §2.4). **Failed narration/video rows are no longer re-attached to scenes on project load** | **F2** error boundary + never let a failed API call or failed row crash the editor |
| 3 | 91 credits deducted for a video/export that was never generated | Credits are charged **last**, only after the result exists and is stored, and are idempotent per job. Failed jobs are free and retry on the same row id | Refresh balance after every attempt, handle `402`, disable buttons while a job is running |

Other behaviour changes you must handle (details in §2): `resolution` is `1080p` or `720p` only, a `409` for a double-clicked generate, retries reuse the same `id`, and narration is now billed per second.

---

## 2. What the backend does now (contract you can rely on)

### 2.1 Error envelope and status codes

Every failure has this body (never a raw HeyGen payload):

```json
{ "success": false, "message": "Validation error", "errors": ["\"resolution\" must be one of [1080p, 720p]"] }
```

| Status | Meaning | What to show |
|---|---|---|
| `400` | Joi validation (`message: "Validation error"`, details in `errors[]`) **or** HeyGen rejected the request | `errors[0]` if present, else `message` |
| `401` | Access token expired | Refresh once via `POST /api/auth/refresh`, retry once |
| `402` | `message: "Insufficient credits"` **or** HeyGen plan-gate whose message mentions "Avatar 6" | Distinguish by `message`. Credits: open the top-up/upgrade flow. Plan: "This avatar needs a HeyGen plan that includes Avatar 6. Pick another avatar." |
| `403` | Not allowed (workspace role, or a look/group that is not yours) | `message` |
| `404` | Row or project not found | `message` |
| `409` | `A video generation request for this scene is already in progress…`, `Video is not ready for download yet`, `Speech audio is not ready for playback yet` | Not an error state. Keep or restore the "generating" UI and keep polling. Never crash |
| `429` | Rate limited (may include `Retry-After`) | "Too many requests, retrying…" and back off |
| `5xx` | Server or upstream failure | Generic "Something went wrong, try again". The job is not charged |

**Always read `message` / `errors[]`. Never render the response body or `JSON.stringify` it.**

### 2.2 Avatar looks (picker data)

`GET /api/heygen/avatars/looks?ownership=public|private|workspace&limit=…&group_id=…&avatar_type=…&token=…`

* `ownership=workspace` is now accepted and treated as `private` (it used to return **400**). Prefer `private` or `public`.
* `limit` above 50 is clamped to 50 (it used to return **400** from HeyGen). Paginate with `token` (see [`HEYGEN_API.md`](api/HEYGEN_API.md)).
* Response `data` includes `looks[]`, `lookCount`, `hasMultipleLooks`, `isSingleLookGroup`, `defaultLookId`, `engineBuckets`, `engineCounts`.

Per look (relevant fields):

| Field | Use |
|---|---|
| `id` | Send as `avatarId` when generating |
| `avatar_type` | Send as `avatarType` (`studio_avatar`, `photo_avatar`, `digital_twin`, …) |
| `supportedApiEngines` | Engines this look can render with, e.g. `["heygen-avatar-6-turbo"]` or `["avatar_iv","avatar_v"]` |
| `defaultAvatarEngine` | **Engine to send as `avatarEngine`** |
| `usesLegacyV2Video` | Legacy look; the backend routes it automatically, nothing special to do |
| `default_voice_id` | Default voice suggestion |
| `preview_image_url`, `name`, `status` | UI |

Valid engine values: `avatar_iii`, `avatar_iv`, `avatar_v`, `heygen-avatar-6`, `heygen-avatar-6-turbo`.
`engineBuckets` groups looks per engine family. A look can appear in **several** buckets, so use per-look `supportedApiEngines` / `defaultAvatarEngine` for logic, not the buckets.

### 2.3 Create an avatar video

`POST /api/workspaces/:workspaceId/projects/:projectId/heygen/videos`

| Field | Rules |
|---|---|
| `sceneId`, `avatarId`, `voiceId`, `script`, `title` | Required. Use the look `id` as `avatarId` |
| `resolution` | **`1080p` or `720p` only.** 2K is not exposed. Other values return 400 |
| `aspectRatio` | `16:9` or `9:16` |
| `backgroundColor` | `#RRGGBB` |
| `avatarEngine` | One of the engines above. **Send the look's `defaultAvatarEngine`.** The backend coerces an engine the look does not support to one it does. It retries once on `heygen-avatar-6-turbo` after a plan-gate |
| `avatarType` | The look's `avatar_type` |
| `motionExpressiveness` | `default` or `less`. **Avatar 6 engines only** |
| `expressiveness` | Avatar IV + `photo_avatar` only. Ignored otherwise |
| `voiceSettings.speed` | 0.5–2 (the backend clamps to ≤ 1.5 for video) |
| `voiceSettings.pitch` | −50…50 |
| `voiceSettings.volume` | 0–2 (the backend clamps to ≤ 1 for video) |
| `voiceSettings.locale` | Language/locale code |
| `removeBackground`, `outputFormat` | Optional |

Success is `201`, `data.heygenVideo`:

```json
{ "id": "<uuid — USE THIS AS heygenVideoId>", "videoId": "<HeyGen id>", "status": "processing",
  "playbackReady": false, "playbackUrl": null, "s3Ready": false, "s3Key": null }
```

Rules that matter for the UI:

* **Idempotent.** The same inputs for the same scene return the **same row** (`id`), they do not create a second job or a second charge.
* **Retry after failure reuses the same `id`.** If the row is `failed` and has no stored file, POSTing again resets that row to in-progress. **Do not treat "same `id` as the old failed one" as stale.** Reset the local state for that `id` to "generating".
* **Double click / two tabs** return `409 A video generation request for this scene is already in progress` (or the existing row). Treat it as "already generating": poll the existing row and do not show an error.
* `status` is whatever HeyGen reports (`waiting`, `pending`, `processing`, …). Treat **anything except `completed` and `failed`** as in progress.

Poll: `GET …/heygen/videos/:id` (default `sync=status`). Every 3–5 s, stop at `completed` or `failed`.
Play: `playbackUrl`, or `GET …/heygen/videos/:id/download` (presigned URL) or `…/stream`. Only do this when `status === 'completed'` and `playbackReady` is true. A completed row without `s3Key` still plays from the HeyGen URL while billing or storage finishes. `409` here means "not ready yet", not an error.
`GET …/heygen/videos/:id?sync=full` returns `402` if the video is complete but the workspace cannot afford it. Prompt for credits, then retry.

### 2.4 Narration (speech)

`POST /api/workspaces/:workspaceId/projects/:projectId/speech`

* Success is `201`.
* On failure the request returns an **error envelope**, but a row with `status: 'failed'` is kept and appears in `GET …/speech`. Retrying the same inputs **reuses that row `id`**.
* Billed **per second of audio** ($0.0024/s, $0.01 minimum per call), charged only after the audio is stored. A failed or unbilled narration costs nothing.
* A scene that references a `failed` or missing narration must show "Generation failed — retry", **not** try to stream audio.

### 2.5 Project load (the "cannot reopen" fix)

`GET …/projects/:projectId` re-attaches generated media to scenes (`heygenVideoId`, `speechGenerationId`, restored avatar element, `generation.status`).

* **Fixed:** failed rows without a file are no longer attached or restored on load, so a failed narration or video can no longer turn a scene into a "completed" scene with nothing to play.
* **Still possible:** a project saved *before* the fix, or saved by the editor itself, can still reference a row id whose row is `failed` (this is what makes retry-on-same-id work). The backend leaves explicit ids untouched. **The frontend must therefore tolerate it (F2).**

### 2.6 Credits and cost display

* Estimate before generating: `GET /api/credits/:workspaceId/estimate` (personal: `/api/credits/me/estimate`). Query: `feature` (`heygen_video` | `speech_generation` | `remotion_export`, required), plus `avatarEngine`, `avatarType`, `resolution` (`heygen_video` only), `script`, and `durationInFrames`/`fps` (export). See [`CREDITS_API.md`](api/CREDITS_API.md). Avatar 6 Turbo and Avatar 6 Pro are priced differently, so always pass the engine.
* Balance: `GET /api/credits/:workspaceId`. **Re-fetch after every generate, retry, export and narration call, successful or not.**
* Charging happens **after** success and is idempotent, so a failed or retried job never double-charges. If the user sees a deduction, a video or audio file exists for it.
* Full model: [`CREDIT_SYSTEM.md`](CREDIT_SYSTEM.md), [`CREDITS_FRONTEND_INTEGRATION.md`](CREDITS_FRONTEND_INTEGRATION.md).

---

## 3. Frontend work items

### F1 — Never show raw backend JSON in toasts (was "item 6")

**Symptom:** toast reads like `{"success":false,"message":"Validation error","errors":[...]}` or a HeyGen payload.
**Cause:** the error handler renders the response body or `error.response.data` directly.

**Do:** one shared helper used by every HeyGen, speech, credits and export call.

```ts
type ApiErrorBody = { success?: false; message?: string; errors?: unknown[] };

export function toUserMessage(err: unknown): { text: string; kind: 'credits' | 'plan' | 'busy' | 'auth' | 'generic' } {
  const status = (err as any)?.response?.status ?? (err as any)?.status;
  const body: ApiErrorBody = (err as any)?.response?.data ?? (err as any)?.data ?? {};
  const first = typeof body.errors?.[0] === 'string' ? (body.errors![0] as string) : undefined;
  const message = first ?? body.message ?? '';

  if (status === 402 && /insufficient credits/i.test(body.message ?? ''))
    return { kind: 'credits', text: 'Not enough credits for this action.' };
  if ([400, 402, 403].includes(status) && /avatar 6/i.test(message))
    return { kind: 'plan', text: 'This avatar needs a HeyGen plan that includes Avatar 6. Please pick another avatar.' };
  if (status === 409)
    return { kind: 'busy', text: 'This is already being generated. Hang tight.' };
  if (status === 401)
    return { kind: 'auth', text: 'Your session expired. Please sign in again.' };
  if (status === 429)
    return { kind: 'generic', text: 'Too many requests. Please try again in a moment.' };
  if (status && status >= 500)
    return { kind: 'generic', text: 'Something went wrong. You have not been charged. Please try again.' };
  return { kind: 'generic', text: message || 'Something went wrong. Please try again.' };
}
```

**Acceptance criteria**
* No toast, banner or modal ever contains `{`, `"success"`, `"errors"` or a stack trace.
* `402 Insufficient credits` opens the credits/upgrade path. A `402`/`400` plan-gate shows the plan message and does **not** open credits.
* `409` never shows a red error.
* The same helper is used for looks, voices, video create/poll, speech, and MP4 export.

### F2 — The editor must never crash to a white page (was "item 7")

**Symptom:** after narration, the page goes blank and the project cannot be reopened (the crash repeats on load).
**Cause (frontend side):** an unhandled rejection or a `null`/`undefined` access (for example `row.playbackUrl` or `data.looks.map`) after a failed call, with no error boundary. The crash then repeated on every load because the scene referenced a dead row. The backend side is fixed (§2.5), but the editor must be defensive too.

**Do**

1. **Error boundary** around the editor route and a **second, smaller one** around each scene's media panel (video and narration). The fallback shows "Something went wrong with this scene" plus **Retry** and **Back to project**, not a blank page. A crash in one scene must not unmount the whole editor.
2. **Wrap every post-generation step in try/catch** (narration → attach to scene → autosave → refresh). A failed API call sets the scene to a `failed` UI state. It never throws out of an event handler or effect.
3. **Project load is non-fatal.** Load the project first. Load the video and narration lists separately (`GET …/heygen/videos`, `GET …/speech`) and **map them by `id`**. If those calls fail, render the project without media status and show a "Couldn't load generation status — retry" chip.
4. **Guard every media read.** Before streaming or downloading:
   ```ts
   const canPlay = row && row.status === 'completed' && (row.playbackReady || row.s3Ready || row.playbackUrl);
   ```
   * `status === 'failed'` → scene state "Generation failed — Retry" (retry = the same POST, §2.3/§2.4).
   * any other non-completed status → "Generating…" and poll.
   * Row id not found in the list (deleted or unknown) → treat as "not generated", clear the stale id locally, and show Generate.
   * `/stream` or `/download` (video: `…/heygen/videos/:id/…`, narration: `…/speech/:speechId/…`) returning `409` → "Not ready yet", poll again.
5. **Optional chaining and defaults** for API data: `data?.looks ?? []`, `row?.playbackUrl ?? null`.
6. **Never autosave** a scene as `generation.status = 'completed'` unless the row is actually `completed`.

**Acceptance criteria**
* Make narration fail on purpose (a very long script, or a stubbed 500) → the scene shows "Generation failed — Retry", the editor stays usable, and no white page appears.
* Reload that project → it opens normally. The failed scene shows a retry state.
* Block `GET …/speech` and `GET …/heygen/videos` in dev tools → the project still opens, with the status chip.
* Throw inside a scene component → only that scene shows the fallback.
* `Retry` on a failed scene succeeds, and the scene keeps the same row `id` with its state reset to "generating".

### F3 — Pass the look's engine from the avatar picker (was "item 8")

**Symptom:** `400 This avatar is available only with Avatar 6 Pro or Turbo` and the export fails.
**Cause:** the editor hard-coded or defaulted `avatarEngine` (typically `avatar_iv`) instead of using what the selected look supports.

**Do**

1. On select, store on the scene presenter: `avatarId = look.id`, `avatarType = look.avatar_type`, `avatarEngine = look.defaultAvatarEngine ?? look.supportedApiEngines?.[0]`.
2. In the video POST, send those three fields every time (omit `avatarEngine` only if it is undefined).
3. Don't pre-filter looks by engine. Avatar-6-only looks work (the backend uses Avatar 6 Turbo). If a plan-gate error does still occur (F1 `plan` kind), show the message and keep the picker open.
4. Show an engine badge (`Avatar IV`, `Avatar 6 Turbo`, …) from `defaultAvatarEngine`. Let the user switch only among `supportedApiEngines`.
5. Show the **"Calmer motion"** toggle (`motionExpressiveness: 'less'`) **only** when the chosen engine starts with `heygen-avatar-6`. Do not send `expressiveness` unless the engine is `avatar_iv` and the look is `photo_avatar`.
6. Resolution control offers **1080p** and **720p** only. Remove 2K.
7. Pass the same `avatarEngine`, `avatarType` and `resolution` to the credit estimate call so the shown price matches the charge.
8. Use `ownership=private` (not `workspace`) and `limit ≤ 50` when listing looks.

**Acceptance criteria**
* Pick an Avatar-6-only look → generate succeeds (or shows the plan message, never raw JSON).
* Pick an Avatar IV look → the request carries `avatarEngine: "avatar_iv"` and works as before.
* The network tab shows `avatarEngine` equal to the look's `defaultAvatarEngine` in every create request.
* The MP4 export of a project containing an Avatar 6 scene succeeds.

---

## 4. QA checklist (run on dev)

| # | Scenario | Expected |
|---|---|---|
| 1 | Generate with an Avatar-6-only look | `201`, completes, plays, credits deducted once |
| 2 | Generate with an Avatar IV look | Works as before |
| 3 | Force a validation error (resolution `2k`) | Friendly message, no JSON in the toast |
| 4 | Generate with a balance below the estimate | `402`, credits prompt, **no deduction** |
| 5 | Double-click Generate | One job and one charge; the second click is `409`/same row, no red error |
| 6 | Kill the network mid-generation, reload | Project opens, the scene polls or shows retry |
| 7 | Failed video → Retry | Same `id`, state resets to "generating", completes, charged once |
| 8 | Failed narration → Retry | Same `id`, completes, charged once |
| 9 | Reopen a project with a failed narration/video scene | Opens, scene shows "Generation failed — Retry" |
| 10 | Block the list endpoints | Project opens, status chip shown |
| 11 | Throw in a scene component | Only that scene shows the fallback |
| 12 | Balance after each of the above | Matches the UI, and failures cost 0 |

---

## 5. Out of scope / notes

* **2K** is intentionally not exposed. Only `1080p` and `720p`.
* **Polling → webhooks** is planned for next week. Keep polling now. Webhooks will change the update mechanism, not these contracts.
* `docs/PROJECT_EDITOR_INTEGRATION.md` §6 describes the editor flow in more depth.
