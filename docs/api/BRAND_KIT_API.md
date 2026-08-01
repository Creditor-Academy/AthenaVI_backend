# Brand Kit API

Canva-style **workspace Brand Kits**: named colors, fonts, multi-role logos, brand photos/graphics, voice, and chart colors. Kits are scoped to a single workspace.

Base path: **`/api/workspaces/:workspaceId/brand-kits`**

| | |
|---|---|
| **Auth** | `Authorization: Bearer <access_token>` |
| **Read** | Workspace **OWNER**, **ADMIN**, or **MEMBER** |
| **Write** | Workspace **OWNER** or **ADMIN** |

Envelope: [OVERVIEW.md](OVERVIEW.md).

---

## Data shape (`data`)

```json
{
  "colors": [
    { "id": "c1", "name": "Navy", "hex": "#0B1220" },
    { "id": "c2", "name": "Blue", "hex": "#3B82F6" },
    { "id": "c3", "name": "White", "hex": "#F8FAFC" }
  ],
  "colorRoles": {
    "bg": "c1",
    "text": "c3",
    "primary": "c2",
    "secondary": "c2",
    "muted": "c3"
  },
  "fonts": {
    "heading": { "fontPairingId": "inter_space", "family": "Inter" },
    "body": { "fontPairingId": "inter_space", "family": "Inter" }
  },
  "voice": {
    "tone": "Professional, confident",
    "audience": "Enterprise buyers",
    "dos": ["Use short sentences"],
    "donts": ["No slang"],
    "vocabulary": ["Athena VI"]
  },
  "chartStyles": { "colorIds": ["c2", "c3"] },
  "imageStyle": "clean product photography, brand-safe"
}
```

`colorRoles.bg` / `text` / `primary` are required and must reference color ids. Palette is contrast-checked (WCAG AA) when creating/updating.

---

## Routes

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/` | member | List kits (summary + mediaCount) |
| `POST` | `/` | OWNER/ADMIN | Create kit `{ name, data, isDefault? }` |
| `GET` | `/:brandKitId` | member | Full kit + media (presigned URLs) |
| `PATCH` | `/:brandKitId` | OWNER/ADMIN | Update name / data / isDefault |
| `DELETE` | `/:brandKitId` | OWNER/ADMIN | Delete kit + S3 media (decks keep snapshotted themeTokens) |
| `POST` | `/:brandKitId/set-default` | OWNER/ADMIN | Set as workspace default |
| `POST` | `/:brandKitId/media` | OWNER/ADMIN | Multipart upload |
| `DELETE` | `/:brandKitId/media/:mediaId` | OWNER/ADMIN | Remove media |

### Media upload

`POST .../media` — `multipart/form-data`:

| Field | Required | Notes |
|-------|----------|--------|
| `file` | yes | jpeg / png / webp / svg, max 50MB |
| `kind` | yes | `logo` \| `photo` \| `graphic` |
| `role` | logos only | `primary` \| `secondary` \| `icon` \| `light` \| `dark` |
| `name` | no | Display label |

---

## Using a kit on presentations

| Action | API |
|--------|-----|
| Create with kit | `POST .../presentations` + `brandKitId` (any `createMode`) |
| Create from deck pack + kit | `createMode: "pack"`, `packId`, `brandKitId` |
| Apply to existing deck | `POST .../presentations/:id/apply-brand-kit` `{ "brandKitId" }` |
| AI generate | `generationFlow.selections.brandKitId` (and optional `packId`) |

**Precedence:** Brand Kit theme/voice/logos/photos → pack theme → wizard `colorTheme` → catalog default.

Resolved kit becomes `deck.themeTokens` (includes `brand.logos`, `brand.photos`, `brand.voice`, `brand.chartColors`). Export resolves symbolic colors from `themeTokens.palette`.

See also: [PRESENTATION_API.md](PRESENTATION_API.md), [PRESENTATION_FRONTEND_INTEGRATION.md](../PRESENTATION_FRONTEND_INTEGRATION.md).
