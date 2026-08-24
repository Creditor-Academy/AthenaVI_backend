# Fonts API

Shared **Google Fonts catalog** for Brand Kit pickers, the video editor text panel, PPT canvas/share views, and AI font pairing.

Base path: **`/api/fonts`**

| | |
|---|---|
| **Auth** | `Authorization: Bearer <access_token>` |
| **Scope** | User-scoped (not workspace-nested) |

Envelope: [OVERVIEW.md](OVERVIEW.md).

Works **without** `GOOGLE_FONTS_API_KEY` via a vendored snapshot under `src/modules/fonts/catalog/googleFonts.snapshot.json`. When the key is set, the server merges a live Google Web Fonts directory (cached in Redis ~24h) on top of the snapshot.

---

## `GET /api/fonts/catalog`

Searchable font list + curated pairings.

### Query

| Param | Type | Notes |
|-------|------|--------|
| `q` | string | Case-insensitive substring on `family` |
| `category` | string | `sans-serif` \| `serif` \| `display` \| `handwriting` \| `monospace` |
| `subset` | string | e.g. `latin`, `latin-ext`, `cyrillic` |
| `featured` | boolean | When `true`, only featured (~80–110) families |
| `limit` | number | 1–500, default **200** |

### Response `data`

```json
{
  "fonts": [
    {
      "family": "Playfair Display",
      "category": "serif",
      "variants": ["regular", "700", "italic"],
      "subsets": ["latin", "latin-ext"],
      "featured": true,
      "cssUrl": "https://fonts.googleapis.com/css2?family=Playfair+Display:wght@300;400;500;600;700;800&display=swap"
    }
  ],
  "pairings": [
    {
      "id": "playfair_lato",
      "heading": "Playfair Display",
      "subheading": "Plus Jakarta Sans",
      "body": "Inter",
      "moods": ["luxury", "editorial", "elegant", "fashion"],
      "useCases": ["pitch", "fashion", "annual-report"]
    }
  ],
  "total": 1
}
```

**Frontend usage**

1. Brand kit / video text panel: load featured grid (`featured=true`), search with `q`.
2. On select, store the family name (`"Playfair Display"`) — not the CSS URL — on brand kit `data.fonts.*.family` or video `style.fontFamily`.
3. Inject `cssUrl` (or `GET /api/fonts/css`) for live preview.
4. Prefer applying a `pairings[]` entry so heading / subheading / body stay coherent.

---

## `GET /api/fonts/css`

Build a single Google Fonts CSS2 URL for one or more families.

### Query

| Param | Required | Notes |
|-------|----------|--------|
| `families` | yes | Comma-separated string, e.g. `Inter,Playfair Display`, or repeated query values |

### Response `data`

```json
{
  "href": "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Playfair+Display:wght@300;400;500;600;700;800&display=swap",
  "families": ["Inter", "Playfair Display"]
}
```

---

## Deck / share payloads

Authenticated presentation GET and public share view include:

| Field | Notes |
|-------|--------|
| `themeTokens.fonts` | `{ heading, subheading, body, … }` family names |
| `fontCssUrl` | Ready-to-inject stylesheet URL derived from those families (or `null`) |

Inject `fontCssUrl` as `<link rel="stylesheet">` in the PPT editor and `/p/:token` share view.

---

## AI / Brand Kit

- AI PPT (`ensureThemeFonts`) and `POST .../brand-kits/suggest/fonts` pick from the shared pairing catalog (`src/shared/fonts/fontPairings.js`).
- Brand kit fonts still win (`fontSource: 'brand_kit'`).
- Custom font file upload is **not** supported in v1.

---

## Environment

| Variable | Required | Notes |
|----------|----------|--------|
| `GOOGLE_FONTS_API_KEY` | no | Google Cloud **Web Fonts Developer API** key (not OAuth). Enables live merge + `scripts/refresh-font-catalog.js`. |

Refresh the vendored snapshot:

```bash
dotenv -e .env.development -- node scripts/refresh-font-catalog.js
```

---

## Related

- Brand Kits: [BRAND_KIT_API.md](BRAND_KIT_API.md)
- Presentations: [PRESENTATION_API.md](PRESENTATION_API.md)
- Frontend A→Z: [FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md](../FRONTEND_PPT_IMAGE_BRAND_KIT_A_TO_Z.md)
