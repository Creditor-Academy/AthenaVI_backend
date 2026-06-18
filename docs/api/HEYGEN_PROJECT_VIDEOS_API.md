# HeyGen avatar videos (workspace project)

Creates HeyGen **`POST /v3/videos`** avatar jobs per **workspace → folder → project → scene**, polls **`GET /v3/videos/:video_id`**, downloads the finished MP4 to **S3** (`workspaces/{workspaceId}/folders/{folderId}/projects/{projectId}/scenes/{sceneId}/heygen/{heygenVideoId}.mp4`). Playback uses **`/download`** (presigned URL), **`/stream`** (authenticated pipe-through API), or optional **`/s3-location`** metadata—see below.

| | |
|---|---|
| **Base path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen` |
| **Auth** | **Bearer** + workspace **member** (OWNER, ADMIN, or MEMBER via `requireWorkspaceRole`) |
| **Server** | **`HEYGEN_API_KEY`**, **`AWS_S3_BUCKET`**, **`AWS_REGION`**, AWS credentials used by this backend, and optional **`HEYGEN_BASE_URL`** |

**Note:** The legacy unauthenticated `POST /api/video/avatar/generate` route and `POST /api/heygen/generate` have been **removed**; use the routes below only.

---

## App developer checklist (editor & preview)

Use this for the **scene-based editor** and **in-browser preview**. **Batch / offline rendering** workflows are **not** covered here.

**1. Server environment**

| Variable | Purpose |
|----------|---------|
| **`HEYGEN_API_KEY`** | Required. HeyGen API returns **500** if missing. |
| **`HEYGEN_BASE_URL`** | Optional. Override HeyGen API base (default `https://api.heygen.com`). |
| **`AWS_S3_BUCKET`**, **`AWS_REGION`**, **`AWS_ACCESS_KEY_ID`**, **`AWS_SECRET_ACCESS_KEY`** | Required for uploading rendered MP4s from HeyGen and for **`/download`**, **`/stream`**, **`/s3-location`**. |

**2. Auth** — Send **`Authorization: Bearer <access_token>`** on every request under this base path. The user must be a **member** of the workspace in the URL.

**3. Project / scene state** — After **Create**, persist **`heygenVideoId`** (from `data.heygenVideo.id`) in your project or scene model. **Do not** store presigned URLs in saved JSON; they expire. When the user reopens a project **days later**, call **`/download`** or **`/stream`** again to obtain a **fresh** playback source (your app can do this **automatically** on load—no user action required).

**4. Preview: choose one pattern**

- **`GET .../stream`** — The **path** stays the same for the life of the project; the server enforces access on every request. A raw **`<video src="https://.../stream">`** **cannot** send a **Bearer** token, so use **`fetch(url, { headers: { Authorization: … } })`**, then **`URL.createObjectURL(blob)`** for `src` (or use **same-origin cookie** session if you implement it). Supports **`Range`** for seeking.
- **`GET .../download`** — Returns a **`presignedUrl`** you can place directly in **`video.src`**. It **expires**; call **`/download`** again when loading a scene or on playback error (again, automate in the app).

**5. CORS** — Allow your **frontend origin** to call this **API** with the headers you use (e.g. `Authorization`). Traffic for **`/stream`** goes through your **backend**, not straight to S3 in the browser, so align CORS with your API host.

**6. Polling** — After **Create**, HeyGen may still be rendering. Use **`GET .../heygen/videos/:heygenVideoId`** (or **`/download`** / **`/stream`**, which run sync first) until **`status`** is **`completed`** or handle **409** / retry in the UI.

---

## Create avatar video

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` |
| **Auth** | Bearer + member |

**Request body (JSON, camelCase)**

| Field | Required | Description |
|--------|----------|-------------|
| `sceneId` | yes | Client scene key from the editor (1–256 chars); one stored video per idempotent hash per scene |
| `avatarId` | yes | HeyGen avatar id |
| `title` | yes | Video title for HeyGen |
| `resolution` | yes | `1080p` or `720p` |
| `aspectRatio` | yes | `16:9` or `9:16` |
| `backgroundColor` | yes | Solid background, e.g. `#008000` (hex) |
| `voiceId` | yes | HeyGen voice id |
| `script` | yes | Spoken script (TTS + lip sync) |
| `avatarEngine` | no | `avatar_iv` (default) or `avatar_v` — must appear in the look’s **`supported_api_engines`** from **`GET /api/heygen/avatars/looks`**; sent to HeyGen as `engine.type` |
| `avatarType` | no | `studio_avatar`, `digital_twin`, or `photo_avatar` from the look row — used to decide HeyGen payload shape |
| `expressiveness` | no | `low`, `medium`, or `high` — **Avatar IV + `photo_avatar` only**; omit for `avatar_v`, studio, or digital-twin looks |
| `voiceSettings` | no | Optional: `speed`, `pitch`, `volume`, `locale`, `engine_settings` |
| `removeBackground` | no | Boolean — **MP4 only**. Cuts out the avatar and composites onto `backgroundColor` (not transparent). Ignored when `outputFormat` is `webm`. |
| `outputFormat` | no | `mp4` (default) or `webm`. **`webm`** returns an alpha-channel clip (transparent background); requires an avatar trained with matting. HeyGen applies background removal automatically for `webm` — do not rely on `removeBackground`. Legacy v2 studio looks return **400** for `webm`. |

**Response (201)** – `data.heygenVideo`: saved **`HeygenResponse`** row (`id`, `videoId`, `sceneId`, `status`, …). Same script + scene + avatar + voice + **`avatarEngine`** returns the **existing** row (idempotent).

**400** – **`HEYGEN_AVATAR_ENGINE_UNSUPPORTED`** (or message listing supported engines) when the look does not support the requested `avatarEngine`.

---

## List HeyGen videos for project

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` |
| **Auth** | Bearer + member |

**Response (200)** – `data.heygenVideos`: array of stored records for that project.

---

## Get HeyGen video (poll + sync to S3)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId` |
| **Auth** | Bearer + member |

Polls HeyGen (bounded) and, when **completed**, downloads to S3 if not already stored. **Response (200)** – `data.heygenVideo` with updated `status`, `s3Key`, `videoUrl`, etc.

---

## Download HeyGen video (presigned URL)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/download` |
| **Auth** | Bearer + member |

**Query (optional)**

- `expiresIn` – presigned URL lifetime in seconds (**60–3600**; default **300**).

Runs sync first. **Response (200)** – includes `data.presignedUrl`, `data.expiresInSeconds`, and `data.heygenVideo`. **409** if the video is not ready or not yet in S3.

---

## Stream HeyGen video (stable preview URL)

Same **path shape forever**: no presigned query string that expires. The API validates **Bearer** access then pipes bytes from S3. Supports **`Range`** requests (**206 Partial Content**) so browsers can seek in `<video>`.

| | |
|---|---|
| **Method** | `GET` or `HEAD` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` |
| **Auth** | Bearer + member |

**Headers**

- **`Authorization: Bearer <token>`** (required for GET/HEAD).
- **`Range`** (optional, GET only) – forwarded to S3 for seeking; e.g. `bytes=0-1048575`.

Runs sync first. **GET** returns **`video/mp4`** bytes. **HEAD** returns metadata only (`Content-Length`, `ETag`, etc.).

**Preview integration:** See **App developer checklist** above (Bearer + `<video>`, **`fetch` + blob**, **`/download`** alternative).

---

## S3 object metadata (optional, advanced)

This endpoint exists for **automation** that needs the canonical **bucket**, **key**, and **region** after sync (e.g. future batch jobs reading objects with **IAM**). **You do not need it** for the web editor or in-browser preview—use **`/stream`** or **`/download`** above.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/s3-location` |
| **Auth** | Bearer + member |

Runs sync first. **Response (200)** includes `data.bucket`, `data.key`, `data.region`, `data.objectArn`, and `data.heygenVideo`. **409** if not completed / not in S3 yet.

**Offline / batch rendering pipelines** are still under development and are **not** documented here.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

