# HeyGen API

Base path: **`/api/heygen`**

Proxies **[HeyGen](https://www.heygen.com/)** v3 capabilities (avatars, voices — list, design, clone, detail, speech preview). The server must set **`HEYGEN_API_KEY`**; without it, HeyGen calls return **500**. Optional **`HEYGEN_BASE_URL`** overrides the API host (default `https://api.heygen.com`).

**Avatar / lip-sync video generation** (create job, list, status, S3 storage, **stream** & **presigned** playback) is **not** on this path — see **HeyGen avatar videos (workspace project)** later in this document (`/api/workspaces/.../heygen/...`).

All routes in this section require **`Authorization: Bearer <access_token>`**.

### User-scoped private avatars and voices

The backend uses a single **`HEYGEN_API_KEY`**, so HeyGen’s own “private” listings would normally include assets from every user of your app. This API **records ownership per authenticated user** and applies extra rules:

| Case | Behavior |
|------|----------|
| **`GET /api/heygen/avatars/groups?ownership=private`** | Response lists only avatar groups **created with `POST /api/heygen/avatars` while logged in as that user** (persisted after a successful create). |
| **`GET /api/heygen/avatars/looks?ownership=private`** | Response lists only looks whose avatar group id is **owned by that user**. If **`group_id`** is set together with **`ownership=private`**, the user must own that group or the API returns **403** (`message`: **`HEYGEN_FORBIDDEN`**). |
| **`GET /api/heygen/voices?type=private`** | Only voices **recorded for the current user** in `heygen_voices`: from **`POST /api/heygen/voices/select`** (after picking a design suggestion) or **`POST /api/heygen/voices/clone`**. Design suggestions alone are **not** stored. |
| **`POST /api/heygen/avatars/:groupId/consent`** | **403** if `groupId` is not owned by the current user. |
| **`GET /api/heygen/voices/:voiceId`** | **403** only for **another user’s cloned** voice (`source: clone` in `heygen_voices`). Public / selected catalog voices are readable by anyone; **select** can add the same `voiceId` to each user’s My voices separately. |
| **`ownership=public`**, **`type=public`**, or omitted filters | Unchanged passthrough to HeyGen (no user filtering). |

**Legacy:** Avatars/voices created before this ownership tracking was deployed were never recorded and **will not appear** in the filtered private lists until recreated or backfilled.

**Implementation note:** For **`ownership=private`** and **`type=private`**, the server still calls HeyGen with those params, then **filters the JSON locally** so other tenants’ rows disappear from the response. HeyGen’s list payloads vary (e.g. nested **`data`** arrays, **`avatar_group_list`**, **`looks`**, **`voices`**, **`suggestions`**); this backend discovers those containers and keeps only rows whose **group id** or **voice id** is stored for **your** JWT user (`heygen_avatars`, `heygen_voices`). **`POST /api/heygen/avatars`** resolves the avatar **group id** from nested **`data`** / **`avatar_group`** fields in HeyGen’s create response (not only a single top-level object) before writing **`heygen_avatars`**; if the response truly omits a group id until a future poll, nothing is recorded yet and private lists stay empty until creation returns one. It prefers **non-empty** array fields when several keys exist, rewrites pagination totals (**`total`**, **`count`**, **`total_count`**) when present to match the filtered length, and records voice ids from **clone** or **`POST .../voices/select`** so **private voice lists** stay consistent (design suggestions are not auto-recorded). For **`GET .../voices?type=private`**, after filtering HeyGen’s list, the server **merges in** voice ids stored in **`heygen_voices`** for your user that HeyGen did not return (common for some design-selected voices), using each row’s saved **`raw`** from **`/voices/select`** or clone where possible.

---

## List avatar groups

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/avatars/groups` |
| **Auth** | Bearer |

**Query (optional)** – forwarded to HeyGen; common keys include:

- `ownership` – `public` or `private` (**private**: filtered to the current user’s recorded avatar groups — see **User-scoped private avatars and voices** above)
- `limit` – integer **1–50**
- `token` – pagination cursor (string)

**Response (200)** – `data`: HeyGen payload (avatar groups).

**403** – **`HEYGEN_FORBIDDEN`** is not used here; filtering narrows the list instead.

---

## List avatar looks

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/avatars/looks` |
| **Auth** | Bearer |

**Query (optional)**

- `group_id`
- `avatar_type` – `studio_avatar`, `digital_twin`, or `photo_avatar`
- `ownership` – `public` or `private` (**private**: filtered to groups owned by the current user; **`group_id` + private** requires ownership or **403**)
- `limit` – **1–50**
- `token` – pagination cursor

**Response (200)** – `data`: HeyGen payload.

**403** – **`HEYGEN_FORBIDDEN`** — private listing with a **`group_id`** that belongs to another user.

---

## Create avatar

Starts HeyGen avatar creation (`digital_twin`, `photo`, or `prompt`).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/avatars` |
| **Auth** | Bearer |

**Option A — JSON** (`Content-Type: application/json`)

- `type`: **`digital_twin`** | **`photo`** | **`prompt`** (required).
- `name`: string, max **200** chars (required).
- For **`prompt`**: `prompt` text is required (non-empty).
- For **`digital_twin`** or **`photo`**: `file` is required — object shaped per HeyGen v3 (`type`: `url` \| `asset_id` \| `base64`, plus applicable fields).
- Optional: `reference_images` (array, max **20** items), `avatar_group_id`, etc.

**Option B — Multipart file** (`Content-Type: multipart/form-data`)

Use this to upload an image or video directly from Postman or the app without hosting a public URL.

- Form fields: **`type`** (`photo` or **`digital_twin` only**), **`name`** (required).
- Binary field **`file`** (required): **photo** → `image/jpeg`, `image/png`, or `image/webp`; **digital_twin** → same images or **`video/mp4`** / **`video/webm`**.
- Optional text fields: **`avatar_group_id`**, **`reference_images`** as a **JSON string** array (same shape as JSON API).
- Max **32 MB** per file. **`prompt`** avatars — use **JSON** only (no `file`).

The server uploads the file to **S3** and forwards HeyGen **`file`: `{ type: "url", url }`** (not base64).

**Digital twin (recommended)** — for training videos over **32 MB**, use **Upload avatar training file** below, then create with JSON and `file.type: "url"`. For voice clone from the same session, use **Upload voice clone audio** and `POST .../voices/clone` with `audio.type: "url"` — do not send base64 in JSON.

**Response (200)** – `data`: HeyGen creation response. On success, the server persists the new avatar **group id** for the current user (when HeyGen returns it) so it appears under **`ownership=private`** lists (groups and looks).

---

## Upload avatar training file (large)

Stage a photo or training video on S3 and return a **public HTTPS URL** for use in **`POST /api/heygen/avatars`** with `{ "file": { "type": "url", "url": "..." } }`. Use this for Digital Twin training videos **over 50 MB** (workspace asset upload is capped at 50 MB).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/avatars/upload` |
| **Auth** | Bearer |
| **Content-Type** | `multipart/form-data` |

**Form fields**

- **`file`** (required): `image/jpeg`, `image/png`, `image/webp`, `video/mp4`, or `video/webm`.
- Max **900 MB** per file. The file is streamed to a temporary path, then uploaded to S3 (`users/{userId}/heygen-avatar-uploads/…`).

**Response (200)** – `data`:

```json
{
  "url": "https://your-bucket.s3.region.amazonaws.com/users/.../heygen-avatar-uploads/....mp4"
}
```

**Frontend flow**

1. `POST /api/heygen/avatars/upload` with the training video (`file`).
2. `POST /api/heygen/avatars` (JSON) with `type: "digital_twin"`, `name`, and `file: { "type": "url", "url": "<url from step 1>" }`.

Requires **AWS S3** env (`AWS_S3_BUCKET`, `AWS_REGION`, credentials). The bucket (or object prefix) must allow **public read** so HeyGen can fetch the URL.

---

## Upload voice clone audio

Stage audio (or a short clip) on S3 for **`POST /api/heygen/voices/clone`** with `{ "audio": { "type": "url", "url": "..." } }`. Use this during **digital twin** creation when the app extracts audio from the training video — **do not** embed clone audio as base64 in JSON (that hits **`JSON_BODY_LIMIT`** and returns **413**).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/upload` |
| **Auth** | Bearer |
| **Content-Type** | `multipart/form-data` |

**Form fields**

- **`file`** (required): `audio/mpeg`, `audio/wav`, `audio/webm`, `video/mp4`, or `video/webm`.
- Max **100 MB** per file. Uploaded to S3 (`users/{userId}/heygen-voice-uploads/…`).

**Response (200)** – `data`:

```json
{
  "url": "https://your-bucket.s3.region.amazonaws.com/users/.../heygen-voice-uploads/....mp3"
}
```

**Digital twin voice flow**

1. `POST /api/heygen/voices/upload` with extracted audio (`file`).
2. `POST /api/heygen/voices/clone` (JSON) with `voice_name` and `audio: { "type": "url", "url": "<url from step 1>" }`.
3. Poll `GET /api/heygen/voices/:voiceId` until clone status is `complete`.

Same S3 public-read requirement as avatar training upload.

---

## Avatar consent URL

Returns a consent / onboarding URL for a pending avatar group.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/avatars/:groupId/consent` |
| **Auth** | Bearer |

**Request body** (optional)

```json
{
  "reroute_url": "https://your-app.com/after-consent"
}
```

**Response (200)** – `data`: HeyGen payload.

**403** – **`HEYGEN_FORBIDDEN`** — `:groupId` is not owned by the current user.

---

## List voices

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/voices` |
| **Auth** | Bearer |

**Query (optional)**

- `type` – `public` or `private` (**private**: filtered to voices recorded for the current user from **select** or **clone** — see **User-scoped private avatars and voices** above)
- `engine`, `language`, `gender` (`male` \| `female`)
- `limit` – **1–100**
- `token` – pagination cursor

**Response (200)** – `data`: HeyGen voices payload.

---

## Design a voice (semantic search)

Maps to HeyGen **`POST /v3/voices`** — returns up to **3** suggested voices for a natural-language prompt. **Do not send `voice_id` on this route** (that field is for **`POST /api/heygen/voices/select`** after the user picks a suggestion).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices` |
| **Auth** | Bearer |

**Request body**

- `prompt`: string, **1–1000** chars (required) — e.g. “warm, confident female narrator”.
- Optional: `gender` (`male` \| `female`), `locale` (BCP-47), `seed` (integer ≥ 0 for alternate batches).

**Response (200)** – `data`: HeyGen payload (`voices`, `seed`). Suggestion **`voice_id`** values are **not** written to **`heygen_voices`** — same idea as avatar create vs. listing: only an explicit user action persists ownership.

**Frontend:** Show the suggestions, then on **Select** call **`POST /api/heygen/voices/select`** with the chosen id, then refresh **`GET .../voices?type=private`**.

---

## Select voice (persist to My voices)

Call this when the user clicks **Select** on a designed/suggested voice. It records the chosen **`voiceId`** for the current user in **`heygen_voices`** so it appears under **`GET /api/heygen/voices?type=private`**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/select` |
| **Auth** | Bearer |

**Request body**

Either field is accepted (use the id from the design suggestion object — often `voice_id`):

```json
{
  "voice_id": "heygen-voice-id-from-design-response"
}
```

or `{ "voiceId": "..." }`.

**Response (200)** – `data`:

```json
{
  "selected": true,
  "voiceId": "heygen-voice-id-from-design-response",
  "voice": { }
}
```

- `voice` is the proxied HeyGen **`GET /v3/voices/{voice_id}`** payload for that id.
- The server upserts a row in **`heygen_voices`** with `source: "select"`.

**Typical frontend flow**

1. `POST /api/heygen/voices` with `prompt` → show suggestion list.
2. User clicks **Select** on one suggestion → `POST /api/heygen/voices/select` with that `voiceId`.
3. Refresh **My voices** with `GET /api/heygen/voices?type=private`.

---

## Clone a voice

Maps to HeyGen **`POST /v3/voices/clone`**. Poll **`GET /api/heygen/voices/:voiceId`** with the returned **`voice_clone_id`** until status is **`complete`**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/clone` |
| **Auth** | Bearer |

**Request body** (proxied to HeyGen; use snake_case or camelCase for the name field)

- `voice_name` or `voiceName`: string, **1–100** chars (required).
- `audio`: object (required) — HeyGen asset union:
  - `{ "type": "url", "url": "https://..." }`
  - `{ "type": "asset_id", "asset_id": "..." }`
  - `{ "type": "base64", "media_type": "audio/mpeg", "data": "..." }`
- Optional: `language`, `remove_background_noise` / `removeBackgroundNoise` (boolean; HeyGen default **true**).

Example:

```json
{
  "voice_name": "My cloned voice",
  "audio": {
    "type": "url",
    "url": "https://example.com/sample.mp3"
  },
  "remove_background_noise": true
}
```

**Response (200)** – `data` includes HeyGen’s payload plus normalized ids when present:

- `voice_clone_id` from HeyGen (poll with this id).
- `voiceCloneId` / `voiceId` — same id, duplicated for convenience.

The clone id is **stored for the current user** (`source: clone`) so it appears under **`GET .../voices?type=private`** once HeyGen returns it.

**Do not send `voice_id` on clone** — that field is only for **`POST /api/heygen/voices/select`** after design suggestions.

**Troubleshooting (browser / CreateVoice)**

- **Body size** — Base64 audio grows ~4/3 vs raw bytes. The server uses **`express.json`** with limit **`JSON_BODY_LIMIT`** (default **32mb** in code). If the request never reaches HeyGen, you may see **413** with a hint to raise the limit or use **`url`** / **`asset_id`** instead of base64. For **digital twin**, use **`POST /api/heygen/voices/upload`** then clone with **`audio.type: "url"`**.
- **Format** — HeyGen may reject some containers/codecs. **Chrome `MediaRecorder` often outputs WebM**; if clone fails with a HeyGen **400**, try **WAV/MP3** (`audio/wav`, `audio/mpeg`) or upload to HeyGen assets and send **`asset_id`**.
- **Errors** — When HeyGen rejects the payload, the API usually returns **400** with HeyGen’s message in **`errors`** (not a silent **500**).

---

## Get voice by id

Maps to HeyGen **`GET /v3/voices/{voice_id}`** — voice details and clone **status** (`processing` \| `complete` \| `failed`) when applicable.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/heygen/voices/:voiceId` |
| **Auth** | Bearer |

**Response (200)** – `data`: HeyGen voice detail payload.

**403** – **`HEYGEN_FORBIDDEN`** — voice id is another user’s **clone** (not shared public/catalog voices).

---

## Preview speech (voice synthesis)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/heygen/voices/preview-speech` |
| **Auth** | Bearer |

**Request body**

- `text`: string, **1–5000** chars (required).
- `voice_id`: string (required).
- `input_type`: **`text`** (default) or **`ssml`**.
- Optional: `speed` (**0.5–2**), `language`, `locale`.

**Response (200)** – `data`: HeyGen speech preview payload.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

