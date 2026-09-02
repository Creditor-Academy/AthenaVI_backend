# Presentation layout coverage

Maps each `content_type` to seed `layout_id` values from `seed-layouts.json`.

**Catalog status:** 129 layouts seeded via `npm run seed:presentation-templates`.

Source of truth for catalog modules: [`deckLayoutCatalogs.js`](../../../AthenaVI/src/utils/deckLayoutCatalogs.js) (merged into [`deckLayoutRegistry.js`](../../../AthenaVI/src/utils/deckLayoutRegistry.js) and `scripts/export-seed-layouts.mjs`).

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
| `diagrams` | Diagrams | `diagram` |
| `closing` | Closing | `closing` |

Source of truth: [`layoutCategories.js`](../layoutCategories.js).

## Layout inventory by content_type

| content_type | count | layout_ids (sample) |
|---|---:|---|
| `image+text` | 20 | section_with_image_v1, full_bg_image_overlay_v1, … |
| `chart` | 14 | chart_single_v1, chart_with_description_v1, … |
| `grid` | 14 | grid_bento_three_v1, logo_wall_v1, … |
| `team` | 12 | team_four_v1, team_featured_lead_v1, … |
| `device_frames` | 8 | device_phone_vertical_split_v1, … |
| `stat` | 7 | metric_single_v1, metric_three_v1, … |
| `timeline` | 5 | timeline_horizontal_v1, timeline_roadmap_v1, … |
| `pricing` | 13 | pricing_three_plans_v1, pricing_comparison_cards_v1, … |
| `comparison` | 4 | comparison_side_by_side_v1, comparison_table_v1, … |
| `title` | 6 | title_centered_v1, title_minimal_v1, … |
| `bullet_list` | 8 | intro_four_para_v1, bullet_list_cards_v1, … |
| `agenda` | 6 | agenda_three_columns_v1, agenda_numbered_v1, … |
| `quote` | 5 | statement_large_v1, quote_portrait_v1, … |
| `section_divider` | 4 | section_divider_centered_v1, section_divider_band_v1, … |
| `closing` | 4 | centered_text_cta_v1, closing_thank_you_v1, … |
| `diagram` | 7 | diagram_swot_v1, diagram_funnel_v1, … |

**Totals:** 129 layouts.

## Seed workflow

```bash
# 1. Export catalog JS → seed JSON
cd AthenaVI && node scripts/export-seed-layouts.mjs

# 2. Seed database (direct)
cd AthenaVI_backend && npm run seed:presentation-templates

# 3. Optional: sync via Superadmin API
cd AthenaVI && npm run seed:layouts:update
```

## Deck packs (`DECK_PACK`)

Seeded via `npm run seed:presentation-deck-packs` (requires layouts first).
