# Stock Media API

Base path: **`/api/stock`**

Proxied search against **Pexels** (phase 1). Import copies media into workspace **S3** and creates a normal workspace **`Asset`** row so projects reference `assetId` — same as uploads.

All routes require **`Authorization: Bearer <access_token>`**.

Import also requires **workspace access** (`checkWorkspaceAccess` — same rules as [Assets API](ASSETS_API.md)).

**Server env:** `PEXELS_API_KEY` (required for stock routes). Optional size caps: `STOCK_PHOTO_MAX_BYTES` (default 15 MB), `STOCK_VIDEO_MAX_BYTES` (default 100 MB).

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
| `page` | integer | `1` | Page number, 1–100 |
| `perPage` | integer | `20` | Results per page, 1–80 |

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
    }
  ],
  "page": 1,
  "perPage": 20,
  "totalResults": 500,
  "nextPage": "https://api.pexels.com/v1/search?..."
}
```

- **503** if `PEXELS_API_KEY` is missing.
- **429** if Pexels rate-limits the request.

`previewUrl` is for the library UI only. Do **not** persist provider CDN URLs in `project.data`.

---

## Import stock media into workspace

Downloads the best-quality file from Pexels, uploads to S3, creates (or returns existing) workspace asset. Counts against the workspace owner's **storageUsed**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/stock/workspaces/:workspaceId/import` |
| **Auth** | Bearer + workspace access |

**Request body**

```json
{
  "provider": "pexels",
  "externalId": "12345",
  "mediaType": "photo",
  "name": "optional display name"
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `provider` | yes | Phase 1: `pexels` only |
| `externalId` | yes | Provider item id (string) |
| `mediaType` | yes | `photo` or `video` |
| `name` | no | Asset display name; defaults to provider filename |

**Response (200)** – `data`: `{ "asset": { ... } }` — same envelope shape as asset upload. Asset includes:

- `source`: `"stock"`
- `stockProvider`: `"pexels"`
- `stockExternalId`: provider id
- `stockMetadata`: `{ photographer, attribution, pageUrl, width, height, ... }`

**Dedupe:** Re-importing the same `(workspace, pexels, externalId)` returns the existing asset without extra storage.

**Errors**

| Status | When |
|--------|------|
| **400** | Invalid body, unsupported provider, file too large, storage limit exceeded |
| **404** | Item removed from Pexels before import |
| **502** | Could not download from Pexels |
| **503** | Missing `PEXELS_API_KEY` |

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

Show `asset.stockMetadata.attribution` in the UI where Pexels requires credit.

---

## Related

- [Assets API](ASSETS_API.md) — list uploads + stock imports (`source=upload|stock|all`)
- [Stock frontend integration](../STOCK_FRONTEND_INTEGRATION.md)
- [Postman collection](../../postman/AthenaVI_Backend.postman_collection.json) — **Stock** folder

---

**[← API index](README.md)** · [Project root README](../../README.md)
