# Project speech generation (workspace project)

Generates **audio-only narration** per **workspace → folder → project → scene** using HeyGen **`POST /v3/voices/speech`** (TTS Starfish). The MP3 is stored in **S3** at `workspaces/{workspaceId}/folders/{folderId}/projects/{projectId}/scenes/{sceneId}/speech/{speechId}.mp3`. Playback uses **`/download`** (presigned URL) or **`/stream`** (authenticated pipe-through API).

| | |
|---|---|
| **Base path** | `/api/workspaces/:workspaceId/projects/:projectId/speech` |
| **Auth** | **Bearer** + workspace **member** (OWNER, ADMIN, or MEMBER via `requireWorkspaceRole`) |
| **Server** | **`HEYGEN_API_KEY`**, **`AWS_S3_BUCKET`**, **`AWS_REGION`**, AWS credentials, optional **`HEYGEN_BASE_URL`** |

**Note:** For quick voice-picker samples (personal credits, no S3), use **`POST /api/heygen/voices/preview-speech`** instead.

---

## App developer checklist

**1. Server environment** — Same as [HeyGen project videos](HEYGEN_PROJECT_VIDEOS_API.md) (`HEYGEN_API_KEY`, S3, optional `HEYGEN_BASE_URL`).

**2. Auth** — `Authorization: Bearer <access_token>` on every request. User must be a workspace member.

**3. Project / scene state** — After **Create**, persist **`speechGenerationId`** (from `data.speechGeneration.id`) on `scene.generation` / `scene.presenter`. The backend **rehydrates** this id on project GET/PATCH when script + voice match a stored row. **Do not** store presigned URLs in project JSON.

**4. Playback**

- **`GET .../speech/:speechId/stream`** — Stable path; requires Bearer (use `fetch` + blob URL for `<audio>`).
- **`GET .../speech/:speechId/download`** — Returns `presignedUrl` for direct `audio.src` (expires; refetch on load).

**5. Credits** — Billed as workspace-scoped **`speech_generation`** (same TTS Starfish rate as `voice_preview`). Estimate: `GET /api/credits/workspaces/:id/estimate?feature=speech_generation&script=...`

---

## Generate speech

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/speech` |
| **Auth** | Bearer + member |

**Request body (JSON, camelCase)**

| Field | Required | Description |
|--------|----------|-------------|
| `sceneId` | yes | Client scene key (1–256 chars) |
| `voiceId` | yes | HeyGen voice id (Starfish-compatible) |
| `script` | yes | Text to synthesize (1–5000 chars) |
| `inputType` | no | `text` (default) or `ssml` |
| `speed` | no | 0.5–2.0 (default 1) |
| `language` | no | Base language code (e.g. `en`) |
| `locale` | no | BCP-47 locale (e.g. `en-US`) |

**Response (201)** – `data.speechGeneration`: saved row with `id`, `sceneId`, `voiceId`, `script`, `durationSec`, `s3Key`, `wordTimestamps`, `playbackReady`, `s3Ready`, `status` (`completed` or `failed`). Same script + scene + voice + speed + inputType + locale returns the **existing** row (idempotent).

**409** – Speech not ready for playback (failed generation or missing S3) on download/stream.

---

## List speech generations for project

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/speech` |
| **Auth** | Bearer + member |

**Response (200)** – `data.speechGenerations`: array of records for the project.

---

## Get speech generation

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId` |
| **Auth** | Bearer + member |

**Response (200)** – `data.speechGeneration`.

---

## Download speech (presigned URL)

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId/download` |
| **Auth** | Bearer + member |

**Query (optional)**

- `expiresIn` – presigned URL lifetime in seconds (**60–3600**; default **300**).

**Response (200)** – `data.presignedUrl`, `data.expiresInSeconds`, `data.speechGeneration`.

**409** if audio is not ready in S3.

---

## Stream speech (stable preview URL)

Authenticated pipe-through from S3. Supports **`Range`** requests for seeking in `<audio>`.

| | |
|---|---|
| **Method** | `GET` or `HEAD` |
| **Path** | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId/stream` |
| **Auth** | Bearer + member |

**Response** – `audio/mpeg` body (GET) or headers only (HEAD).

---

**[← API index](README.md)** · [Project root README](../../README.md)
