# Presentation layout coverage

Maps each `content_type` to seed `layout_id` values from `seed-layouts.json`.

**Catalog status:** empty — previous seed layouts and deck packs were removed.
Add new entries to `seed-layouts.json` / `seed-deck-packs.json`, then run:

- `npm run seed:presentation-templates`
- `npm run seed:presentation-deck-packs`

## FE gallery categories

`GET .../presentation-templates` returns `categories[]` (picker tabs) plus `templates[]`.
Filter with `?category=simple_slides` (or `?contentType=agenda` for a single AI tag).

| category id | Label | contentTypes |
|---|---|---|
| `all` | All | *(no filter)* |
| `simple_slides` | Simple slides | `title`, `bullet_list`, `section_divider`, `image+text`, `comparison` |
| `grid` | Grid | `grid` |
| `charts_and_data` | Charts and data | `chart`, `stat` |
| `timeline_and_plans` | Timeline and project plans | `timeline` |
| `pricing` | Pricing | `pricing` |
| `agenda` | Agenda | `agenda` |
| `people_and_team` | People and team | `team` |
| `quotes_and_testimonials` | Quotes and testimonial | `quote` |
| `device_frames` | Device frames | `device_frames` |
| `closing` | Closing | `closing` |

Source of truth: [`layoutCategories.js`](../layoutCategories.js).

| content_type | layout_ids |
|---|---|
| *(none yet)* | |

**Totals:** 0 layouts.

## Deck packs (`DECK_PACK`) — schemaVersion 2

Seeded via `npm run seed:presentation-deck-packs` (requires layouts first).

| pack_id | themeId | slides | use case |
|---|---|---|---|
| `brand_guideline_v1` | *(kit theme)* | 6 | **Not seeded** — built at runtime by `brandKit.guideline.service.js` on `POST .../guidelines/generate`. Scene reference: `src/modules/brandKit/templates/brand-guideline-pack.meta.json`. |
