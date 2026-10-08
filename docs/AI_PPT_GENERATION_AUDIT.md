# AI PPT generation — audit report

**Date:** 2026-10-08  
**Scope:** Existing AI PPT pipeline (outline → content → layout selection → slot mapping → canvas render)  
**Catalog counted:** **246** seed layouts in `src/modules/presentation/templates/seed-layouts.json` (not 249)  
**Code changed:** none — read-only audit  

Companion to [`AI_PPT_GENERATION_COMPLETE.md`](AI_PPT_GENERATION_COMPLETE.md). HTTP contracts stay in [`docs/api/PRESENTATION_API.md`](api/PRESENTATION_API.md).

**Objective of remaining work:** given any generated slide content, select a layout that can naturally hold that content and map every piece to the correct visual slot — without forcing, overflowing, or filling holes with dummy copy.

**Do not:** rebuild the pipeline, redesign layouts, or retouch all 246 schemas.

---

## A. Current architecture (verified from code)

The live generate path is **not** “content contract → candidates → rank → select → map.” It is:

```
INPUT (outline LLM + arrangement + optional blueprint lock)
  → PRE-LAYOUT (deterministic, stub content, phase pre_content)
  → CONTENT (slide LLM, constrained by that early layout)
  → CLASSIFY + visual policy
  → CANDIDATES (DB/seed filtered by catalog content_type)
  → RANK (hardReject, then scoreLayout)
  → SELECT (AI only on phase final; else ranked[0])
  → PRE-SHAPE / QA truncate
  → IMAGES
  → COMPILE (deriveContentContract → textForSlot → layoutSlotsToElements
             or rebind → finalizeElementsDoc)
  → persist slide.elements
```

There is **no stored content-contract artifact**. `deriveContentContract(layoutSchema)` is computed whenever a schema is known.

| Stage | File · function |
|---|---|
| Outline + purpose | `deckGeneration.service.js` `generateOutline` · `prompts/outline.prompt.js` · `slideArrangementPlan.service.js` `enrichOutlineWithArrangement` |
| Intention on each slide | Outline fields `purpose`, `contentIntent`, `narrativeRole`, `beats`, `suggestedContentType` |
| Slide content | `processSlide` → `prompts/slideContent.prompt.js` |
| Pre-layout | `resolvePreGenerationLayout` with stub `{ title, summary, body, beats, bullets: [] }` |
| Candidates | `resolveLayoutTemplates(contentType)` |
| Filter | Slide-order, gallery/closing, pricing/problem, `evaluateLayoutCompatibility` hardReject |
| Rank | `deckLayout/rankLayouts.js` → `scoreLayout.js` |
| Select | `pickLayoutForGeneratedSlide` → `selectBestLayoutWithAI` |
| Contract | `packages/athena-contracts/contentContract.js` `deriveContentContract` |
| Map | `packages/athena-contracts/slotText.js` `textForSlot` → `layoutToElements.js` |
| Validate | `layoutQa.validateSlide` (generate path **omits** `includeContract`) |
| Render | `slideCompiler.compileSlide` → canvas JSON (`slide.elements`), not PPTX |

`layoutSelector.selectLayout` is **deprecated** and is not the generate path.

Docs are behind the code: `AI_PPT_GENERATION_COMPLETE.md` still says prompt bundle v1.8; `prompts/index.js` exports **`PROMPT_BUNDLE_VERSION = 'v2.1'`**.

### Catalog snapshot

| content_type | Count |
|---|---|
| image+text | 34 |
| chart (includes tables + some process layouts) | 33 |
| grid | 27 |
| diagram | 21 |
| title | 15 |
| closing | 15 |
| stat | 14 |
| agenda | 13 |
| bullet_list | 13 |
| timeline | 12 |
| pricing | 10 |
| team | 9 |
| section_divider | 8 |
| device_frames | 8 |
| comparison | 8 |
| quote | 6 |
| **Total** | **246** |

All seed layouts are `schemaVersion: 2`. **0** missing roles, **0** missing regions, **0** duplicate slot IDs. **0** slots have a `required` flag. Only **6** layout IDs have hand-tuned selector metadata in `layoutMetadataOverrides.js`.

---

## B. Top 10 problems (by severity)

1. **Candidate pool is a single catalog `content_type`.** A comparison slide typed `bullet_list` never sees comparison layouts. (`resolveLayoutTemplates`)
2. **Soft compatibility does not change rank.** Overflow, timeline mismatch, and density mismatch are warnings only. (`scoreLayout` copies `compat.penalties` into `warnings`)
3. **If every layout hard-rejects, the system ranks the full pool anyway.** (`rankLayouts` unconstrained fallback)
4. **Content is written for a pre-layout chosen from a stub.** Final layout can need a different slot count. (`resolvePreGenerationLayout`)
5. **Empty extra chart slots get fabricated Q1–Q4 data.** (`layoutToElements.js` `sampleChartDataset`)
6. **Generate QA never runs the content contract.** `validateSlide({ content, layoutSchema })` defaults `includeContract: false`. Repair-at-compile does run it, but after selection.
7. **Many real slot families are invisible to `textForSlot` and `deriveContentContract`.** `POINT_*`, `CELL_*`, `ROW_n_LEFT_*`, `step_n_desc`, `METRIC_A_*`. Specialized `finalizeElementsDoc` then paints **catalog dummy copy**.
8. **Purpose collapse.** `quote` → `benefits`, `diagram` → `process`, `section_divider` → `introduction`, `timeline` ↔ `process` related. Selector cannot tell cousins apart.
9. **Repair/pre-shape invents content** (`Focus area N`, `Morning`/`Afternoon`, years `2010+n`) instead of failing or regenerating.
10. **AI selector prompt omits** `narrativeRole`, `suggestedContentType`, `hasTimeline`, `hasPricing`, `contentStructure`. It mostly sees truncated title/body + scores.

---

## C. Layout issues (only layouts that need attention)

Do **not** retouch all 246. Geometry, roles, and regions are complete. The remaining gaps are mapping, catalog typing, and selector metadata.

### P0 — mapping or catalog-type lies

| Layouts | Problem |
|---|---|
| `eight_short_texts_image_v1`, `eight_short_texts_image_right_v1` | `POINT_n_TITLE/DESC` not in `textForSlot`. `layoutEightShortTextsImage` falls back to “Strategic Vision / Scalable Engine …” |
| `table_single_v1`, `table_with_description_v1`, `table_with_description_side_v1`, `table_two_desc_v1`, `table_two_same_header_v1`, `table_*_cards_v1` | `CELL_*` / headers / row labels unmapped. Table layouts ship Lorem / `—` defaults. Catalog type is **`chart`**. |
| `comparison_table_v1`, `comparison_table_grid_v1`, `comparison_before_after_v1` | `ROW_n_LEFT_TITLE/BODY` and `ROW_n_RIGHT_*` have no mapper. Comparison JSON never reaches those slots. |
| `process_linear_business_v1`, `process_linner_horti_v1`, `process_linner_horti_four_v1`, `process_linner_numeric_v1`, `process_linear_four_cards_v1`, `process_linear_horizontal_v2`, `process_linear_numeric_cards_v1` | Catalog type **`chart`**, `supported.chart === true`, **no CHART slot**. Process slides compete with real charts. |

### P1 — selector confusion or half-mapped families

| Layouts | Problem |
|---|---|
| `timeline_process_steps_v1`, `timeline_process_horizontal_v1` | Slot IDs are `step_n_desc/year/detail`; mapper only knows `STEP_n_TITLE/BODY`. Both share `TIMELINE_PROCESS_OVERRIDE` (`process` + `roadmap`). |
| `chart_three_context_v1`, `chart_three_context_cards_v1` | `CARD_n_QUARTER`, `CARD_n_INSIGHT_*` unmapped |
| `chart_two_cards_split_v1` | `METRIC_A_*` / `METRIC_B_*` not in contract groups |
| `quote_grid_v1` + quote family | Purpose tagged `benefits`. Grid needs `quotes[1..3]`; content LLM usually emits one `quote`. |
| `wide_image_statement_*` | `SUBHEADLINE` does not match `id.includes('subtitle')` |
| `intro_four_para_v1` | `INTRO` unmapped |
| `grid_text_image_cards_v1`, `grid_text_image_mosaic_v1`, `grid_insights_chart_*` | `POINT_TITLE/BODY`, `FEATURE_TITLE/BODY`, `INSIGHT_LABEL_n` unmapped |
| `grid_three_images_text_v1`, `_asymmetric_v1` | `HEADING_1` / `HEADING_3` unmapped (`HEADING` works; these do not) |

### P2 — metadata too similar for the selector

- All **13** `bullet_list_*` → purposes `features, solution`
- All **8** `section_divider_*` → `introduction` (same as agenda)
- All **14** `stat` → `statistics, traction` (no density/count distinction in purpose)
- All **21** `diagram_*` → `process` (architecture / SWOT / funnel / cycle look the same to the scorer)
- **63** pairs/groups share identical slot-ID sets (mirror variants). Fine visually; the AI only gets density + structure, so it cannot tell them apart except by previous-layout variety.

### Healthy majority (do not rewrite)

Title, standard `image+text` (`BODY` / `HEADING` / `HERO_IMAGE`), `CARD_n_*` / `COL_n_*` grids, agenda, pricing `PLAN_n_*`, team `MEMBER_n_*`, most timelines with `milestone_n_label/detail`, most closings.

---

## D. Content contract issues

`deriveContentContract` only counts:

`CARD|COL|ROW|FEATURE_*`, `STAT_*`, `MEMBER_*`, `MILESTONE_*`, `STEP_*`, `Q\d_`, `FUNNEL_*`, `BULLET_*`, `QUOTE_*`, `ITEM_*`, `IMAGE_*`, `PLAN_*`.

**Missing groups:** `AGENDA_COL_*`, `PROS_n_*` / `CONS_n_*`, `POINT_*`, `CELL_*`, `METRIC_A/B`, `ROW_n_LEFT/RIGHT`, `HEADING_n`, `INSIGHT_*`.

Joi (`contentContract.schema.js`) only caps array **length**. It does not require “slot X must be bound to field Y.”

The contract is strong enough for **title / body / columns / stats / plans**. It is **not** strong enough to guarantee mapping for tables, 8-point grids, comparison matrices, agenda, or diagram extras.

Content the LLM is asked to produce (`slideContent.prompt.js`) is mostly:

`title`, `subtitle`, `body`, `bullets`, `columns[]`, `chart`, `plans[]`, `timeline[]`, `diagram.cells[]`, `pros`/`cons`, `imagePrompts`.

It does **not** emit `POINT_*`, `CELL_*`, `quotes[]` (plural), `agenda.columns`, or `CARD_n_INSIGHT`. Pre-shape is supposed to bridge that — and often invents filler instead.

---

## E. Layout selection issues

### Scoring weights (`layoutScoring.weights.js`)

| Dimension | Weight |
|---|---|
| purposeMatch | 25 |
| contentTypeMatch | 25 |
| capacityMatch | 15 |
| compositionMatch | 10 |
| styleMatch | 10 |
| industryMatch | 5 |

**Unused in score:** `contentStructure`, `visualWeight`, `narrativeRole`, `suggestedContentType` (except problem/pricing filters), `hasTimeline` from type alone, per-slot `max_words`, soft compatibility penalties, aspect ratio.

**Repetition:** −5 / −12 / −20 by reuse count; adjacent same layout −35.

### Purpose collapse (`toSlideContentProfile.js`)

| Catalog type | Mapped purpose |
|---|---|
| title | cover |
| section_divider | introduction |
| quote | benefits |
| diagram | process |
| timeline | roadmap |
| comparison | competition |
| bullet_list / image+text / grid | features |
| chart / stat | statistics |

`RELATED_PURPOSES` also links **process ↔ roadmap** at 72% of purpose points.

### Why a comparison brief can miss comparison layouts

**Example:** “Compare React and Vue across performance, ecosystem, learning curve, and community.”

| If outline types it as | Pool | Likely pick | Suitable? |
|---|---|---|---|
| `comparison` | 8 comparison layouts | side-by-side / cards | Yes |
| `bullet_list` (common) | 13 bullet layouts, all `features+solution` | numbered or two-column bullets | No |
| `quote` | 6 quote layouts, purpose `benefits` | statement + portrait | No |
| `timeline` | 12 timelines | milestones | No |

There is **no `hasComparison` flag** and **no hard reject** for 2-sided compare content on a single-column layout.

Other unreliable distinctions:

- Process vs timeline — related purposes; two layouts share one override
- Metrics vs feature cards — stats infer both `statistic` and `metrics`
- Section divider vs intro — same purpose
- Architecture vs funnel — both `diagram` → `process`
- Quote vs benefits feature list — same purpose bucket
- Tables vs charts — tables are `content_type: chart`

### Fallback strategy (always picks something)

| Condition | Behavior |
|---|---|
| Empty pool | `list[0]` |
| AI error / unknown ID / confidence &lt; 70 | ranked[0] |
| Exclusions empty the pool | **Ignore exclusions** |
| All hard-reject | Rank unconstrained |
| `promotePreferred` | Unshifts heuristic ID to rank 1 without rescoring |
| Pre-content phase | Never uses AI |

The system almost never refuses a bad fit.

---

## F. Content alignment issues

Canonical path:

`content.field` → `textForSlot(slotId)` → `clampSlotText` → element.

Specialized `finalizeElementsDoc` then **rebuilds** many families from previous element text or **hardcoded defaults**.

| Break | Example |
|---|---|
| Slot ID not in `textForSlot` | `POINT_1_TITLE`, `CELL_2_3`, `ROW_1_LEFT_BODY`, `INTRO`, `SUBHEADLINE` |
| Generic `id.includes('title')` / `subtitle` fallbacks | Flood some slots; miss `HEADLINE` in `textForSlot` (compile has a `isMainTitleSlot` backup) |
| Quote slot | `id.includes('quote')` → `content.quote \|\| content.body` |
| CTA | defaults to `"Learn more"` or `Explore {title}` |
| Image label | empty → `"Gallery N"` |
| Extra chart | `sampleChartDataset` Q1–Q4 |
| Pre-shape pad | agenda Morning/Afternoon; timeline years 2010+n; repair `Focus area N` |
| Rebind (pack) | skips `clampSlotText`; keeps pack demo text unless `forceTextReplace` |
| `slotFieldMap` in QA | only generic keys (`title`, `body`, `bullets`). Does not truncate `CARD_2_BODY` / `PLAN_2_ITEM_3` |
| Density | prompt caps ≠ `inferDensity` ≠ contract defaults ≠ slot `max_lines` |

Empty slots are often **not empty** — they show **template lorem**. That is the “unused / incorrectly populated slot” symptom.

Scripted check against a fully populated sample payload: **104 / 246** layouts still had at least one text slot that `textForSlot` left empty (some of those are optional extras; the P0/P1 IDs above are the ones that then get dummy copy).

---

## G. Validation gaps

| Layer | Exists? | When |
|---|---|---|
| Prompt density / layout rules | Soft | Content LLM |
| Pre-shape | Yes, mutates | After LLM and after final layout |
| Structured QA (agenda, chart, comparison, timeline) | Yes | `validateSlide` |
| Per-slot truncate via `slotFieldMap` | Partial | Same |
| Content contract + Joi | Yes, but | **Compile repair only**, not generate QA |
| Required slot populated | **No** | — |
| Invalid content→slot type | **No** | — |
| Post-render overflow / overlap / empty area | Font shrink only (`fitTextElementsToBoxes`) | After compile |
| Catalog metadata vs visual truth | `validateDeckLayout` | Admin/catalog, not generate |
| Final layout vs content structure used at LLM time | **No** | — |

Validation is **repair-oriented**, not fail-closed. Bad slides still go `READY`.

---

## H. Recommended fix order

Small, targeted changes only.

1. **Score soft compatibility** (subtract per penalty) and **stop unconstrained ranking** when hard-reject empties the pool — pick least-bad by capacity or widen the pool.
2. **Widen candidates** when purpose/structure says comparison / timeline / quote / table, even if `suggestedContentType` is `bullet_list`.
3. **Disable `sampleChartDataset`** unless `chart.isIllustrative` or a dedicated empty-state.
4. **`validateSlide({ includeContract: true })` on the generate path.** Fail or regen when a required text slot maps to `''`.
5. **Add mappers + contract groups** for `POINT_*`, `CELL_*`, `ROW_n_LEFT/RIGHT`, `step_n_desc`, `METRIC_A/B`. Stop specialized layouts from using catalog dummy copy when content exists in `columns[]` / `table`.
6. **Treat pre-layout as a hint, not a lock.** If final layout slot count ≠ generated groups, run a short content repair pass (`repairSlideContentFromQa`) instead of padding.
7. **Stop inventing** `Focus area N` / fake years / Morning–Afternoon. Pad empty and trigger QA/regen.
8. **Add to AI prompt + `scoreLayout`:** `narrativeRole`, `suggestedContentType`, `hasTimeline`, `hasComparison`, `contentStructure`.
9. **Metadata only for the P0/P1 IDs above:** split process vs timeline override; retag table/process layouts out of `chart`; give section_divider purpose `section`; give quote purpose `benefits` **and** `quote`.
10. **Run the regression matrix below.** Only then touch remaining similar-looking variants.

Avoid: new layout system, replacing `rankLayouts`, rewriting all 246 schemas.

---

## I. Regression test matrix

For each case: **INPUT → expected content structure → expected layout type → expected slot mapping → validation**.

| Case | INPUT (slide brief) | Expected content | Expected layout type | Expected slot mapping | Validation |
|---|---|---|---|---|---|
| Title-only | Cover: product name | `title` + optional `subtitle` | `title` / hero | `MAIN_TITLE`/`HEADLINE` ← title; no body forced | No dummy body; no extra image required unless hero |
| Title + paragraph | One insight | `title` + `body` | `image+text` or text-only, **not** 4-card | `HEADING`+`BODY` | Body ≤ slot `max_lines`; no empty card slots |
| Title + bullets | 3–5 features | `title` + `bullets` or `columns` | `bullet_list`, capacity ≥ N | `BULLET_n` / `ITEM_n` | No 8-point layout for 3 bullets |
| 2-column comparison | React vs Vue, 4 axes | `left`/`right` or `columns[2]` | `comparison_*`, **not** quote/timeline/single para | `LEFT_*`/`RIGHT_*` or `ROW_n_LEFT/RIGHT` | Hard-fail if quote/timeline selected |
| 3/4-card | 3 benefits | `columns[3]` | 3-card / 4-card grid matching count | `CARD_n_TITLE/BODY` | Do not pad 4th with “Focus area 4” |
| Timeline | 4 dated milestones | `timeline[]` with label+detail | `timeline_*`, **not** process linear | `milestone_n_label/detail` | No invented years |
| Process | 4 how-to steps | `diagram.cells` or `steps` | `diagram_process_*` or process linear, **not** roadmap | `STEP_n_TITLE/BODY` | Process layouts must not sit in chart pool |
| Metrics | 4 KPIs | `stats[4]` | `metric_four_*`, **not** feature cards | `STAT_n_VALUE/LABEL` | `metricsRequired` hard-reject non-stat |
| Chart/data | One series | `chart.labels` + `series` | `chart_*` with **one** CHART slot | `CHART_1` only | **No** sample data on `CHART_2` |
| Table | 5×4 grid | `table.headers/rows` | table layouts (should not be typed `chart`) | `CELL_r_c` + headers | No Lorem cells if table payload exists |
| Image + text | One visual + para | `title`+`body`+image | `image+text` split | `HERO_IMAGE`+`BODY` | Empty image only if optional |
| Quote | One testimonial | `quote` + attribution | `quote` / statement, **not** benefits bullets | `STATEMENT`/`QUOTE` + `NAME`/`ROLE` | Body must not fill quote |
| Architecture | System boxes | `diagram` or `pathBSpec` | diagram / pathB, **not** bullet list | cells or pathB panels | No funnel unless type=funnel |
| Dense | 8 points | `columns[8]` or `points` | `eight_short_texts_*` or dense grid | `POINT_n_*` ← columns, **not** Strategic Vision | Fail if defaults remain |
| Minimal | Title + 1 line | short `body` | low-density title/statement | one heading + one support | No 8 empty cards |
| Unexpected / missing | Title only on 4-card layout | incomplete | either switch layout **or** leave optional slots empty | no filler titles | QA issue, not READY-with-dummy |

---

## Finding register

| Pri | File · function | Problem | Why | Example | Fix | Risk |
|---|---|---|---|---|---|---|
| P0 | `deckGeneration.service.js` `resolveLayoutTemplates` | Pool = one catalog type | DAO/seed filter | Compare brief typed `bullet_list` | Add purpose/structure widen | Low — additive candidates |
| P0 | `scoreLayout.js` `scoreLayout` | Soft penalties unused | Warnings only | 8 bullets on max 4 still ranks high | Subtract N per soft hit | Low |
| P0 | `rankLayouts.js` | Unconstrained if all reject | Fail-open | Dense content on tiny layouts | Least-bad or widen | Low |
| P0 | `resolvePreGenerationLayout` | Stub has `bullets: []` | No structure yet | Metrics planned as paragraph | Hint only; final pick after content | Medium — content prompt uses early slots |
| P0 | `layoutToElements.js` ~2172 | Sample extra charts | Always fill CHART_n | Dual-chart layout, one dataset | Sample only if illustrative | Low |
| P0 | `deckGeneration.service.js` ~3727 | No contract on generate QA | `includeContract` default false | Overflow columns silent | Pass `true` | Low |
| P0 | `slotText.js` + eight-short / table / comparison-table layouts | Slot IDs unmapped | Regex vocabulary incomplete | POINT/CELL/ROW_LEFT empty → dummy | Add mappers; bind `columns`/`table` | Medium — test those families |
| P1 | `toSlideContentProfile.js` `CONTENT_TYPE_FROM_CATALOG` | Purpose collapse | quote→benefits, diagram→process | Quote vs feature list | Dedicated purposes + flags | Low |
| P1 | `layoutScoring.weights.js` `RELATED_PURPOSES` | process ↔ roadmap | Bidirectional 72% | Process on timeline | Split; require `suggestedContentType` | Low |
| P1 | `contentRepair.js` / `contentPreShape.util.js` | Invented filler | Prefer full slots | “Focus area 3”, year 2019 | Empty + regen | Medium — more empty slots until regen |
| P1 | `layoutAiSelection.prompt.js` | Thin AI context | Omits role/type/flags | Case study → generic grid | Add those fields | Low |
| P1 | `layoutMetadataOverrides.js` | 6 overrides only; process+timeline shared | Heuristic `toDeckLayout` | All diagrams look like process | Overrides for P0/P1 IDs only | Low |
| P2 | `pickLayoutForGeneratedSlide.js` `promotePreferred` | Heuristic becomes #1 | Unshift | Preferred process beats better fit | Score boost, not reorder | Low |
| P2 | `slotText.js` `cta` / quote / subtitle | Fallbacks | Convenience | “Learn more”; body in quote | Empty + QA | Low |
| P2 | `rebindContentToElements` | Stale pack text | No clamp / no force replace | Demo copy after regen | Force replace on generate | Medium for packs |
| P2 | `textFit.util.js` | Shrink hides overflow | No QA feedback | 8px body | Fail if below min size | Low |
| P3 | `validateDeckLayout.js` | No slot-vocabulary check | Catalog-only | New POINT_ slots pass | Registry test of slot IDs vs `textForSlot` | Low |

---

## Fallbacks (current behavior)

| Scenario | Behavior |
|---|---|
| No suitable layout | `rankLayouts` ranks all if hard-reject empties pool; picker returns `list[0]` if ranked empty |
| AI invalid layout | Unknown id / low confidence / timeout → top heuristic candidate |
| Unexpected content structure | `runContentPreShape`, `repairContentForLayoutDetailed`, QA repair LLM |
| Required slot empty / weak copy | Truncate; QA repair; `blueprintSeed` + recompile |
| Too much / too little content | QA caps; contract repair; density caps in **prompt only** |
| Layout metadata incomplete | Seed/DB fallbacks; compile with `{ slots: [] }` if no schema |
| Compile fails | Minimal empty-schema compile; slide `FAILED` with partial elements |
| Image failure | Slide still `READY`; `imageRef.status: failed` |

---

## Summary

The pipeline already generates content before the **final** layout pick and already has capacity scoring. It still **selects inside the wrong family**, **does not punish unfit layouts**, and **fills holes with dummy copy** instead of remapping or refusing.

Start with ranking + contract-on-QA + the P0 mappers (`POINT_`, `CELL_`, comparison rows, no sample charts). Do not touch the other ~200 layouts until those land and the regression matrix is green.