# Presentation layout coverage

Maps each `content_type` to seed `layout_id` values from `seed-layouts.json`.

All layouts are **schemaVersion 2**: slots include `role`, optional `typography`, and
decoration/background shapes where appropriate.

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
| title | `title_centered_v1`, `title_left_accent_v2`, `title_hero_image_v3` |
| agenda | `agenda_numbered_v1`, `agenda_two_column_v2`, `agenda_side_image_v3` |
| bullet_list | `bullet_list_classic_v1`, `bullet_list_dense_v2`, `bullet_list_cards_v3`, `numbered_four_up_v1`, `policy_numbered_split_v1`, `achievement_three_up_v1` |
| comparison | `comparison_side_by_side_v1`, `comparison_pros_cons_v2`, `comparison_table_v3` |
| stat | `stat_big_number_v1`, `stat_three_up_v2`, `stat_with_context_v3` |
| quote | `quote_centered_v1`, `quote_portrait_v2`, `quote_banner_v3` |
| image+text | `image_text_split_v1`, `image_text_split_v2`, `image_text_overlay_v3` |
| timeline | `timeline_horizontal_v1`, `timeline_vertical_v2`, `timeline_alternating_v3` |
| team | `team_grid_four_v1`, `team_featured_lead_v2`, `team_row_v3` |
| chart | `chart_full_width_v1`, `chart_with_callouts_v2`, `chart_compact_v3` |
| closing | `closing_centered_cta_v1`, `closing_contact_v2`, `closing_thank_you_image_v3` |
| section_divider | `section_divider_centered_v1`, `section_divider_numbered_v2`, `section_divider_band_v3` |
| grid | `grid_four_cards_v1`, `grid_three_columns_v2`, `grid_six_tiles_v3` |
| pricing | `pricing_three_tiers_v1`, `pricing_featured_middle_v2`, `pricing_table_v3` |
| device_frames | `device_frame_laptop_v1`, `device_frame_phone_v2`, `device_frame_dual_v3` |

**Totals:** 15 content types; core variants + meeting layouts = **48** layouts.

## Deck packs (`DECK_PACK`) — schemaVersion 2

Seeded via `npm run seed:presentation-deck-packs` (requires layouts first).

Each pack includes `meta`, `narrative` (`arc` + `summary`), per-slide `intent`,
`designTokens`, `generationHints`, richer `preview`, and `generationDefaults`
(`layoutWhitelist`, `slideOrder: fixed`, `contentDistribution`).

Image-capable slides get durable **`TemplateMedia`** on seed (stock-once → S3);
pack clone fills image URLs. Seed also creates `kind: preview` for picker thumbnails.

| pack_id | themeId | slides | use case |
|---|---|---|---|
| `corp_pitch_midnight` | `midnight_blue` | 5 | short pitch |
| `marketing_clean_light` | `clean_light` | 5 | campaign story |
| `portfolio_forest` | `forest_slate` | 5 | studio portfolio |
| `consulting_report_paper` | `paper_ink` | 8 | text-first consulting (`preferVisuals: false`) |
| `investor_deck_violet` | `violet_noir` | 8 | fundraising |
| `product_launch_ocean` | `ocean_mist` | 8 | product launch |
| `executive_review_charcoal` | `charcoal_gold` | 8 | QBR (`preferVisuals: false`) |
| `brand_story_sand` | `warm_sand` | 8 | brand / editorial |
| `company_meeting_clean` | `clean_light` | 10 | internal company meeting (`preferVisuals: true`, title/closing image slots) |

**Totals:** 9 packs.

### Theme tokens (catalog)

Palette now includes `accent`, `divider`, `cardBg`, `gradientStart`, `gradientEnd`, `shadow`.
`typeScale` includes `display`, `title`, `subtitle`, `body`, `caption`, `stat` plus `scaleRatio`.
