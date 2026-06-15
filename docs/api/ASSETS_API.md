# Assets API

Base path: **`/api/assets`**

Workspace uploads are stored in **S3**; metadata is tied to the workspace and counts against the **workspace owner’s** storage quota.

All routes require **`Authorization: Bearer <access_token>`** and **`checkWorkspaceAccess`**:

- **PRIVATE** workspace: only the **owner** may access routes for that `workspaceId`.
- **TEAM** workspace: any **member** may access.

---

## Upload asset

`multipart/form-data` with a single file field **`file`**.

Allowed MIME types: **`image/jpeg`**, **`image/png`**, **`image/webp`**, **`video/mp4`**, **`audio/mp3`**. Maximum size **50 MB**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/assets/:workspaceId/upload` |
| **Auth** | Bearer (see workspace rules above) |

**Response (201)** – `data`: `{ "asset": { ... } }` (includes URL, name, size, type, etc.).

- **400** if file type invalid or storage limit exceeded.

---

## List assets

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/assets/:workspaceId` |
| **Auth** | Bearer (see workspace rules above) |

**Query (optional)**

- `take` – page size, **1–100** (default **20** when omitted).
- `skip` – offset, default **0**.
- `source` – `upload` \| `stock` \| `all` (default **all** when omitted).

For **PRIVATE** workspaces, only assets **uploaded by the current user** are returned. For **TEAM** workspaces, assets for the whole workspace are listed.

Stock imports (`source: "stock"`) appear alongside uploads. See [Stock API](STOCK_API.md) for search/import.

**Response (200)** – `data`: `{ "assets": [ ... ] }`.

---

## Rename asset

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/assets/:workspaceId/:assetId/rename` |
| **Auth** | Bearer (see workspace rules above) |

**Request body**

```json
{
  "name": "new-name.webp"
}
```

- `name`: string, **1–255** characters (trimmed).

**Response (200)** – `data`: `{ "asset": { ... } }`.

---

## Delete asset

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/assets/:workspaceId/:assetId` |
| **Auth** | Bearer (see workspace rules above) |

Removes the object from storage (when applicable) and decrements the owner’s **storageUsed**.

**Response (200)** – `data`: `{ "asset": { ... } }`.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

