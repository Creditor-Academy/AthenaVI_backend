# Stock Media API

Base path: **`/api/stock`**

Proxied search against **Pexels** (photos + videos), **Unsplash** (photos), and **Pixabay** (photos + videos). Import copies media into workspace **S3** and creates a normal workspace **`Asset`** row so projects reference `assetId` — same as uploads.

All routes require **`Authorization: Bearer <access_token>`**.

Import also requires **workspace access** (`checkWorkspaceAccess` — same rules as [Assets API](ASSETS_API.md)).

**Server env:** at least one of `PEXELS_API_KEY`, `UNSPLASH_ACCESS_KEY`, `PIXABAY_API_KEY`. Optional size caps: `STOCK_PHOTO_MAX_BYTES` (default 15 MB), `STOCK_VIDEO_MAX_BYTES` (default 100 MB).

---

## Search stock media

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/stock/search` |
| **Auth** | Bearer |

**Query**

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `q` | string | required | Search query, 1–200 chars |
| `type` | `photo` \| `video` | `photo` | Media type |
| `provider` | `pexels` \| `unsplash` \| `pixabay` \| `all` | `all` | Search source(s) |
| `page` | integer | `1` | Page number, 1–100 |
| `perPage` | integer | `20` | Results per page, 1–80 |

**Provider behavior**

| `provider` | `type=photo` | `type=video` |
|------------|--------------|--------------|
| `all` | Interleaved Pexels + Unsplash + Pixabay (skips providers without keys) | Interleaved Pexels + Pixabay |
| `pexels` | Pexels only | Pexels only |
| `unsplash` | Unsplash only | **400** — not supported |
| `pixabay` | Pixabay only | Pixabay only |

**Response (200)** – `data`:

```json
{
  "items": [
    {
      "provider": "pexels",
      "externalId": "12345",
      "mediaType": "photo",
      "previewUrl": "https://images.pexels.com/...",
      "width": 1920,
      "height": 1080,
      "photographer": "Jane Doe",
      "attribution": "Photo by Jane Doe on Pexels",
      "pageUrl": "https://www.pexels.com/photo/..."
    },
    {
      "provider": "pixabay",
      "externalId": "98765",
      "mediaType": "video",
      "previewUrl": "https://...thumbnail.jpg",
      "previewVideoUrl": "https://...preview-small.mp4",
      "width": 1920,
      "height": 1080,
      "durationSec": 15,
      "photographer": "Jane Doe",
      "attribution": "Video by Jane Doe on Pixabay",
      "pageUrl": "https://pixabay.com/videos/..."
    }
  ],
  "page": 1,
  "perPage": 20,
  "totalResults": 500,
  "nextPage": null
}
```

- **503** if no provider API keys are configured (or the requested provider's key is missing).
- **429** if a provider rate-limits the request.

`previewUrl` is for the library UI only (poster/thumbnail). Video items also include **`previewVideoUrl`** for hover preview. Do **not** persist provider CDN URLs in `project.data`.

---

## Import stock media into workspace

Downloads from the provider, uploads to S3, creates (or returns existing) workspace asset. Counts against the workspace owner's **storageUsed**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/stock/workspaces/:workspaceId/import` |
| **Auth** | Bearer + workspace access |

**Request body**

```json
{
  "provider": "pixabay",
  "externalId": "98765",
  "mediaType": "video",
  "name": "optional display name"
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `provider` | yes | `pexels`, `unsplash`, or `pixabay` |
| `externalId` | yes | Provider item id (string) |
| `mediaType` | yes | `photo` or `video` (`unsplash` → `photo` only) |
| `name` | no | Asset display name; defaults to provider filename |

**Unsplash import:** backend calls `GET /photos/:id/download` (download tracking) before fetching the file.

**Response (200)** – `data`: `{ "asset": { ... } }` — same envelope shape as asset upload.

**Dedupe:** Re-importing the same `(workspace, provider, externalId)` returns the existing asset without extra storage.

---

## Using imported assets in the editor

After import, reference the returned `asset.id` in project JSON:

```json
{
  "type": "image",
  "content": { "assetId": "uuid-from-import", "mediaType": "image" }
}
```

Render and playback resolve `assetId` → presigned S3 URL (no stock-specific render changes).

Show `asset.stockMetadata.attribution` in the UI where required.

---

## Related

- [Assets API](ASSETS_API.md) — list uploads + stock imports (`source=upload|stock|all`)
- [Stock frontend integration](../STOCK_FRONTEND_INTEGRATION.md)
- [Postman collection](../../postman/AthenaVI_Backend.postman_collection.json) — **Stock** folder

---

**[← API index](README.md)** · [Project root README](../../README.md)
