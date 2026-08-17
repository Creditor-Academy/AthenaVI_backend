# Brand Kit API

Canva-style **workspace Brand Kits**: named colors, fonts, multi-role logos, brand photos/graphics, voice, chart colors, AI suggestions, and brand guideline decks. Kits are scoped to a single workspace.

Base path: **`/api/workspaces/:workspaceId/brand-kits`**

| | |
|---|---|
| **Auth** | `Authorization: Bearer <access_token>` |
| **Read** | Workspace **OWNER**, **ADMIN**, or **MEMBER** |
| **Write** | Workspace **OWNER** or **ADMIN** |
| **AI suggest / guideline generate** | OWNER/ADMIN (credits charged) |

Envelope: [OVERVIEW.md](OVERVIEW.md).

---

## Data shape (`data`)

```json
{
  "meta": {
    "tagline": "Empowering Executive Decks",
    "industry": null,
    "guidelineProjectId": "clxx…"
  },
  "colors": [
    { "id": "c1", "name": "Primary (Light)", "hex": "#D51C0B" },
    { "id": "c2", "name": "Background (Light)", "hex": "#F7F3F3" },
    { "id": "c3", "name": "Text (Light)", "hex": "#1B1110" },
    { "id": "c4", "name": "Background (Dark)", "hex": "#1B1110" },
    { "id": "c5", "name": "Primary (Dark)", "hex": "#FB6456" },
    { "id": "c6", "name": "Text (Dark)", "hex": "#F7F3F3" }
  ],
  "colorRoles": {
    "bg": "c2",
    "text": "c3",
    "primary": "c1",
    "secondary": "c1",
    "muted": "c3",
    "bgDark": "c4",
    "textDark": "c6",
    "primaryDark": "c5"
  },
  "fonts": {
    "heading": { "fontPairingId": "outfit_source", "family": "Outfit", "weight": 700, "sizePx": 40, "lineHeight": 1.2 },
    "subheading": { "fontPairingId": "outfit_source", "family": "Space Grotesk", "weight": 600, "sizePx": 20, "lineHeight": 1.4 },
    "body": { "fontPairingId": "outfit_source", "family": "Inter", "weight": 400, "sizePx": 14, "lineHeight": 1.6 }
  },
  "buttons": {
    "primary": {
      "label": "Primary",
      "backgroundColorId": "c1",
      "textColorId": null,
      "borderColorId": null,
      "borderWidthPx": 0,
      "borderRadiusPx": 10,
      "paddingXPx": 20,
      "paddingYPx": 10,
      "fontWeight": 600,
      "fontSizePx": 14
    },
    "secondary": {
      "label": "Secondary",
      "backgroundColorId": "c2",
      "textColorId": "c1",
      "borderColorId": "c1",
      "borderWidthPx": 1,
      "borderRadiusPx": 10,
      "paddingXPx": 20,
      "paddingYPx": 10,
      "fontWeight": 600,
      "fontSizePx": 14
    }
  },
  "voice": {
    "tone": "Professional, confident",
    "audience": "Enterprise buyers",
    "dos": ["Use short sentences"],
    "donts": ["No slang"],
    "vocabulary": ["Athena VI"]
  },
  "usage": {
    "logoClearSpace": "1.5x cap height",
    "logoMinSizePx": 24,
    "doNot": ["Recolor logo", "Stretch lockup"]
  },
  "chartStyles": { "colorIds": ["c1", "c5"] },
  "imageStyle": "clean product photography, studio lighting, brand-safe"
}
```

`colorRoles.bg` / `text` / `primary` are required and must reference color ids. Light and dark pairs are contrast-checked (WCAG AA) when creating/updating or when applying AI color suggestions.

When mapped to presentations, kits produce `themeTokens` with `palette`, optional `paletteDark`, font weights/sizes, `buttons` (resolved primary/secondary styles), and `brand.chartColors`.

`buttons.primary` / `buttons.secondary` are optional. Color fields reference palette `id`s (`backgroundColorId`, `textColorId`, `borderColorId`). If `textColorId` is omitted on primary, text ink is auto-contrasted against the background.

---

## CRUD routes

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/` | member | List kits (summary + mediaCount) |
| `POST` | `/` | OWNER/ADMIN | Create kit `{ name, data, isDefault? }` |
| `GET` | `/:brandKitId` | member | Full kit + media (presigned URLs) |
| `PATCH` | `/:brandKitId` | OWNER/ADMIN | Update name / data / isDefault |
| `DELETE` | `/:brandKitId` | OWNER/ADMIN | Delete kit + S3 media |
| `POST` | `/:brandKitId/set-default` | OWNER/ADMIN | Set as workspace default |
| `GET` | `/:brandKitId/health` | member | Completeness score (Overview gauge) |

### Default kit resolution

If `brandKitId` is omitted on presentation **create** or **generate**, the workspace kit with `isDefault: true` is applied when present.

---

## Media

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `POST` | `/:brandKitId/media` | OWNER/ADMIN | Multipart upload |
| `DELETE` | `/:brandKitId/media/:mediaId` | OWNER/ADMIN | Remove media |
| `GET` | `/:brandKitId/media/:mediaId/stream` | member | Stream media bytes |

`POST .../media` — `multipart/form-data`:

| Field | Required | Notes |
|-------|----------|--------|
| `file` | yes | jpeg / png / webp / svg, max 50MB |
| `kind` | yes | `logo` \| `photo` \| `graphic` \| `mockup` |
| `role` | logos / mockups | logos: `primary`, … ; mockups: catalog template id |
| `name` | no | Display label |

Re-uploading a logo or mockup with the same `role` replaces the previous asset (no duplicate role rows).

---

## AI suggestion routes (credits)

Suggest endpoints return proposals only — client confirms via `PATCH` or `POST .../media`.

| Method | Path | Body / upload | Response |
|--------|------|---------------|----------|
| `POST` | `/suggest/colors` | multipart `file` **or** `{ mediaId, brandKitId?, tone?, tagline? }` | `{ colors, colorRoles, rationale }` |
| `POST` | `/suggest/fonts` | `{ tone?, primaryHex?, brandKitId? }` | `{ fonts, rationale }` |
| `POST` | `/suggest/voice` | `{ name, tagline?, tone?, brandKitId? }` | `{ voice, rationale }` |
| `POST` | `/suggest/image-style` | `{ tone?, colors?, colorRoles?, brandKitId? }` | `{ imageStyle, chartStyles, rationale }` |
| `POST` | `/:brandKitId/suggest/logo-variants` | `{ applyRoles?: string[] }` | `{ generated, missingRoles, variants[] }` |

**Logo variants:** deterministic transforms (light/dark/black/white/lockups) from the primary mark. Wordmark lockups use **Heading** font + light/dark text colours from `data.fonts.heading.lightTextColorId` / `darkTextColorId` (fallback: `colorRoles.text` / `colorRoles.textDark`). Roles: `with-name-below`, `with-name-adjacent`, `with-name-below-dark`, `with-name-adjacent-dark`. Omit `applyRoles` for **free preview** (base64 URLs, no S3 upload, no credit charge). Pass `applyRoles` to commit selected roles to the kit in one call (charged only when variants are applied).

Credit feature keys and default AC: see [CREDITS_API.md — Brand Kit AI](CREDITS_API.md#brand-kit-ai-flat-ac). Frontend integration: [CREDITS_FRONTEND_INTEGRATION.md](../CREDITS_FRONTEND_INTEGRATION.md).

---

## Logo product mockups (Imagery)

AI product scenes with the kit logo as a reference image (OpenAI Images Edit).

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/:brandKitId/mockups/catalog` | member | 10 templates + free-quota billing |
| `GET` | `/:brandKitId/mockups` | member | Saved `kind: mockup` media + quota |
| `POST` | `/:brandKitId/mockups/generate` | OWNER/ADMIN | Generate one scene |

**Catalog templates:** `mug`, `tshirt`, `hoodie`, `tote`, `cap`, `business_card`, `laptop_lid`, `phone_case`, `packaging_box`, `storefront_sign`. Each has `category`, `preferredLogoRoles` (contrast hint only), `size`, `supportsItemColor`, `defaultLogoRole` (`primary`), and apparel flags: `supportsLogoPosition`, `logoPositions`, `defaultLogoPosition`.

**Generate body:** `{ "templateId": "mug", "itemColor?": "#1A1A1A", "logoRole?": "primary", "logoPosition?": "left_chest", "save?": false }`

- Omitting `logoRole` uses **`primary`**, then any kit logo. Do not auto-pick from `preferredLogoRoles`.
- `itemColor` (optional `#RGB` / `#RRGGBB`): product/garment colour for **all** templates. Omit = current look (brand `primaryHex` / `bgHex` hints only).
- `logoPosition` is **only** for `tshirt` and `hoodie`: `center_chest` (default), `left_chest`, `full_front`, `center_back`, `full_back`. Sending it on any other template is **400**. Aliases for back: `back_center`, `back`, `rear` → `center_back`. Unknown values are **400** (they are not silently remapped to chest).
- Response `data.mockup` includes `logoRoleUsed`, `itemColorUsed` (null if omitted), `logoPositionUsed` (null unless apparel).
- Preview always uploads to S3 (`mockup-preview/`) and returns a **presigned URL** (no base64).
- `save: true` stores `kind: mockup`, `role: templateId`, **replace-on-save** for that role.
- **First 2 successful generates per kit are free** (`data.meta.mockupFreeUsed`). Failures do not consume free slots or credits. After that, flat AC (`brand_kit_logo_mockup`, default **4**).
- Rate limit: **20 / hour** per user+workspace (429). Env: `BRAND_KIT_MOCKUP_RATE_LIMIT_MAX`, `BRAND_KIT_MOCKUP_RATE_LIMIT_WINDOW_SEC`.

Both catalog and list responses include:
`billing: { charged, freeUsed, freeLimit: 2, freeRemaining, athenaCredits, feature }`.

---

## Brand guideline deck

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `POST` | `/:brandKitId/guidelines/generate` | OWNER/ADMIN | Create 6-slide guideline presentation |
| `GET` | `/:brandKitId/guidelines` | member | Linked presentation id + status |

**Generate body:** `{ "folderId": "<uuid>" }` (required).

Creates a normal workspace **Presentation** with fixed scenes: Cover → Colors → Logos → Typography → Imagery → Governance. Stores `data.meta.guidelineProjectId` on the kit.

**Regenerate:** if `guidelineProjectId` already points to an existing presentation in the workspace, slides are replaced in place (same project/deck id). Otherwise a new presentation is created.

**Download:** use existing presentation export:

`POST /api/workspaces/:workspaceId/presentations/:presentationId/export` `{ "format": "pdf" | "pptx" }`

Scene structure reference: `src/modules/brandKit/templates/brand-guideline-pack.meta.json`.

---

## Health response

`GET .../:brandKitId/health` → `{ health: { score, label, checks[], missing[], guidelineProjectId } }`

Deterministic completeness (no LLM). Labels: `Excellent Consistency` (≥90), `Good Consistency` (≥75), etc.

---

## Using a kit on presentations

| Action | API |
|--------|-----|
| Create with kit | `POST .../presentations` + `brandKitId` (optional if default kit exists) |
| Create from deck pack + kit | `createMode: "pack"`, `packId`, `brandKitId?` |
| Apply to existing deck | `POST .../presentations/:id/apply-brand-kit` `{ "brandKitId" }` |
| AI generate | `generationFlow.selections.brandKitId` |

**Precedence:** Brand Kit → pack theme → wizard `colorTheme` → catalog default.

Resolved kit becomes `deck.themeTokens` (`brand.logos`, `brand.photos`, `brand.voice`, `brand.chartColors`, `paletteDark`). Chart export falls back to `brand.chartColors` when slide content has no colors.

See also: [PRESENTATION_API.md](PRESENTATION_API.md), [FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md](../FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md).
