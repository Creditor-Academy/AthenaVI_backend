# Engine policy — AI presentation generation

**Lead:** Komal Giri  
**Backups (pair):** Ankit Kumar (editor / content contract), Sahil (APIs / credits)  
**Status:** Policy written 19 October 2026. Tests are the contract. Ankit's editor-contract and Image Studio boundary tests are in the frontend tree. A live scoring walkthrough with Komal is still useful; backups can already point at the tests below.

This is the **policy** note: *why* a layout wins, *when* repair runs, *when* Path A vs Path B is chosen, and *what is billed*. It is not the HTTP spec and not a dump of `deckGeneration.service.js`.

| Need | Doc |
|------|-----|
| HTTP, jobs, polling | [`api/PRESENTATION_API.md`](api/PRESENTATION_API.md) |
| Full pipeline / data model | [`AI_PPT_GENERATION_COMPLETE.md`](AI_PPT_GENERATION_COMPLETE.md) |
| Prompt files / bundle version | [`PRESENTATION_PROMPTS.md`](PRESENTATION_PROMPTS.md) |
| Frontend wiring | [`PRESENTATION_FRONTEND_INTEGRATION.md`](PRESENTATION_FRONTEND_INTEGRATION.md) |
| Credit numbers and estimate API | [`PRESENTATION_CREDITS_FRONTEND.md`](PRESENTATION_CREDITS_FRONTEND.md) |
| Layout/content gap analysis | [`AI_PPT_GENERATION_AUDIT.md`](AI_PPT_GENERATION_AUDIT.md) |

---

## 1. Purpose and non-goals

**Purpose.** Generation is **not** a single LLM dump. The engine:

1. Classifies the slide.
2. **Scores** catalog layouts and rejects impossible fits.
3. Fills slots (LLM copy + Path A or Path B image).
4. **QA / repair** so content fits the chosen layout.
5. Compiles `slide.elements` for the editor.

**Non-goals.** This note does not define REST envelopes, wizard UX, Brand Kit tokens, or Image Studio (separate product; infographic prompts must stay independent of Path B).

**How to read a rule.** Each rule below names the **code** and the **test** that fails if you break it. If the test and this note disagree, **fix this note or the test first**, then the scorer.

---

## 2. Pipeline order

Implemented in `src/modules/presentation/deckGeneration.service.js` (per-slide work). Do not skip steps.

```
Outline (LLM, token-reconcile AC)
    → classify slide (content type, visual_need, beats)
    → diagram / gallery / chart-density policy (may change visual_need + type)
    → layout scoring + compatibility (hard-reject / rank)
    → ensureCompatibleLayout (widen pool; last resort = universal text)
    → optional AI layout pick among the scored shortlist
    → slide content LLM (flat 2 AC on success)
    → Path A image (4 AC) or Path B image (9 AC) or cache hit (0 AC)
    → QA + repair (truncate, integrity, layout retry on non-repairable overflow)
    → compile to slide.elements
    → READY or FAILED
    → editor / export (export 3 AC on success)
```

A failed outline, slide, or image **is not billed** for that piece (charge-on-success). See §7.

---

## 3. Scoring — how a layout wins

### 3.1 Inputs

The scorer sees a **slide content profile** (`toSlideContentProfile`) plus a **DeckLayout** (`toDeckLayout` from seed/`Template`):

- Slide intent: `purpose`, `narrativeRole`, `suggestedContentType`, title/summary/beats
- Shape: bullet/card/metric/image counts, `hasChart`, `hasTable`, `hasQuote`, `hasComparison`, density
- Layout offer: `slidePurposes`, `contentTypes`, `supportedElements`, `contentCapacity`, category, keywords, topics

### 3.2 Score (0–100, then bonuses/penalties)

Weights (`deckLayout/layoutScoring.weights.js`):

| Signal | Weight |
|--------|--------|
| Purpose match | 25 |
| Content-type match | 25 |
| Capacity (will the copy fit) | 15 |
| Composition | 10 |
| Style | 10 |
| Industry | 5 |

Then:

- **Keyword / topic** bonus (capped).
- **Repetition:** −5 / −12 / −20 if the same `layoutId` was already used 1 / 2 / 3+ times in the deck.
- **Adjacent:** −35 if the candidate is the **immediately previous** slide’s layout (variety).
- Domain / closing / problem-layout boosts (problem slides demote charts).

Confidence bands: ≥90 excellent, ≥80 strong, ≥70 good, ≥60 acceptable, else weak.

**Contract:** `src/modules/presentation/deckLayout/scoreLayout.js`  
**Tests:** `src/modules/presentation/test/layoutRules.test.js`, `scripts/test-layout-scoring.js` (`npm run test:layout-scoring`)

### 3.3 Hard-reject vs soft penalty (`layoutBadFit`)

`evaluateLayoutCompatibility` returns `hardReject` or penalties.

**Hard-reject (layout must not win), examples:**

- Comparison / versus / competition slide vs a quote-only layout.
- Chart content vs a layout that cannot host a chart.
- Required cards/metrics/images the layout does not support.

Hard-reject **removes** the layout from ranking. If the primary pool and the widened pool all hard-reject, ranking is empty and `ensureCompatibleLayout` takes over.

**Soft penalty:** still allowed, but score drops (overflow of bullets/cards is extra-expensive). Heavy bullet copy on a dense list scores worse than light copy on the same layout.

**Contract:** `deckLayout/layoutCompatibility.js`  
**Tests:** `test/layoutBadFit.test.js`

### 3.4 `ensureCompatibleLayout` — a slide always gets a layout

Product rule: **generation must not fail only because the first pool was empty.**

1. Score the requested / classified pool.
2. If everything hard-rejects, **widen to the full catalog**.
3. If a pack **whitelist** has no compatible layout, **bypass the whitelist** and log `presentation_layout_whitelist_bypassed`.
4. If still nothing, use a **universal text** layout: `bullet_list_dense_v1`, `text_only_centered_v1`, or `bullet_list_two_column_v1`. Content normalizers reshape cards/columns into bullets.

**Contract:** `deckLayout/ensureLayoutPick.js`  
**Tests:** `test/ensureLayoutPick.test.js`

### 3.5 Chart density (deck-level, before per-slide pick)

Do not fill a deck with charts.

| Deck length | Max chart slides |
|-------------|------------------|
| 8 | 2 |
| 10 | 2 |
| 12–16 | 3 |
| 20 | 4 |

Surplus charts are demoted to `image+text` (with a budget note). **Title and closing slides are never demoted.** `layoutLocked` charts are kept. Prefer keeping quantitative titles (revenue, share, growth).

**Contract:** `layoutCatalogPolicy.js` (`maxChartSlidesForDeck`, `enforceChartDensityCap`)  
**Tests:** `scripts/test-chart-density-cap.js` (also `npm run test:presentation-scripts`)

### 3.6 Gallery grids

Image-led “spaces / rooms / four photos” slides are **pure gallery**, even if the outline said `image+text`. Use gallery layouts (`grid_bento_*`, etc.), not a single hero + caption.

**Contract:** `galleryGridPolicy.util.js`  
**Tests:** `scripts/test-gallery-grid-policy.js`, `test/gridGalleryImageCoherence.test.js`

### 3.7 AI selection

After scoring, an optional LLM may pick among the **already ranked** shortlist (`deckLayout/layoutAiSelection.*`). It must not resurrect a hard-reject. Tests: `scripts/test-layout-ai-selection.js`.

---

## 4. Repair / QA

Repair exists so generated copy **fits the chosen layout**. It is not permission to invent missing product facts.

### 4.1 What is auto-fixed (repairable)

`layoutQa.service.js` truncates to slot `max_words` / `max_lines` / `max_items`. Safety cap: more than **8 bullets** is truncated.

Also:

- Theme fonts / readable sizes (`test/readableText.test.js`, `test/contrastTypographyPlaceholders.test.js`).
- Slot image QA: drop or replace a bad/duplicate slot image (`repairSlotImagesFromQa` in `deckGeneration.service.js`).
- LLM content repair for repairable QA issues (`repairSlideContentFromQa`). If that call fails, log `presentation_slide_qa_repair_failed` and continue with what you have — do not charge extra.
- Placeholders and weak catalog copy: strip or flag (`test/cleanPlaceholders.test.js`).

The **editor** still owns: tone, brand wording, regrouping, swapping layouts by hand, and anything the user types after `READY`.

### 4.2 What must NOT be silently repaired

| Rule | Behaviour | Test |
|------|-----------|------|
| **ARRAY_OVERFLOW** (e.g. 5 columns into a 2-card layout) | `repairable: false`, `requiresLayoutRetry: true`. Do **not** slice extra cards and pretend it fit. Retry another layout or fail the slide. | `test/layoutSelectionRegression.test.js`, `test/contentIntegrityRegression.test.js` |
| Missing real chart data on a dual-chart layout | Do **not** inject sample “Q1” series unless `isIllustrative`. | `test/contentIntegrityRegression.test.js` |
| Underfilled cards | Do **not** invent “Focus area” titles. | same |
| Export | Must not contain synthetic repair fingerprints. | same |

`qaHasUnresolvedOverflow` → controlled failure / layout retry, not a quiet trim.

### 4.3 READY vs FAILED

- **READY:** compiled `slide.elements`, repairable issues handled or accepted, no unresolved overflow.
- **FAILED:** LLM/image/hard overflow after retry. Deck may be `partial: true` if some slides READY and some FAILED (`AI_PPT_GENERATION_COMPLETE.md` status machines).
- Failed **piece** is not billed (§7). Other successful slides in the same generate still charge.

---

## 5. Path A vs Path B

**Owner of the rules:** `diagramPathPolicy.util.js` (`resolveDiagramVisualPolicy`).  
**Regression:** `scripts/test-path-b-vs-layouts.js` (`npm run test:path-b-vs-layouts`).

### 5.1 Definitions

| Path | What it is | Default AC (success) |
|------|------------|----------------------|
| **Path A** | Stock and/or an image **brief** (`imageBrief.prompt.js`) → `ppt_image_path_a` | **4** |
| **Path B** | Richer composite diagram from a usable `pathBSpec` (`pathB.prompt.js`) → `ppt_image_path_b` | **9** |
| **diagram_template** | Templated process/diagram **layout** (SVG/slots), not a Path B image | no Path B charge |
| **Cache hit** | Same brief already on S3 | **0** (`ppt_image_cache_hit`) |

Path B is **one image slot** in the export contract (no requirement for editable text overlay on that raster).

Image Studio infographics are a **different product**. Copy Path B prompt *patterns* if useful; do not share one module (`docs/IMAGE_GEN_COMPLETE.md`).

### 5.2 When Path B is allowed

`looksLikePathBTopology` is true when title/summary/beats/visual/intent match:

architecture, ERD / entity-relation, system map/diagram, branching, cross-link, schema map, multi-panel diagram/infographic, untemplatable / bespoke diagram.

**And** `hasUsablePathBSpec`: `pathBSpec.panels[]` with at least one panel that has title, content, steps, or boxes.

If `visualNeed === 'path_b'` **but** the spec is empty/`panels: []` → **downgrade to `diagram_template`**. Do **not** charge Path B.

### 5.3 When Path B is forbidden

Linear how-it-works / workflow with **2–6 real steps** (`looksLikeLinearProcessSlide`) is **not** Path B.

Example locked by test: “How NovaFlow Works” / Upload → Extract → Validate → Post → `diagram_template` + process layout (`diagram_process_steps_v1` for 4 steps). Vague “workflow” words **without** steps are not enough to force a process layout.

Step-count → preferred process layout:

| Steps | Prefer |
|-------|--------|
| 2–3 | `process_linner_horti_v1` family |
| 4 | `diagram_process_steps_v1` family |
| 5+ | timeline vertical (5 milestones), then 4-step family |

### 5.4 Device / product UI

App mockups, device frames, screenshots → `contentType: device_frames`. **Never** overwrite those with Path B or process diagrams. If `visualNeed` was `path_b`, coerce to `photo`.

### 5.5 Outline must not pre-commit Path B

Outline prompt: do **not** emit `path_b` in the outline; Path B is decided later, only for architecture/ERD-style slides (`prompts/outline.prompt.js`).

---

## 6. Caps (policy, not just constants)

Canonical table lives in [`AI_PPT_GENERATION_COMPLETE.md`](AI_PPT_GENERATION_COMPLETE.md) § Caps. Do not fork numbers here.

| Limit | Value | Policy meaning |
|-------|-------|----------------|
| AI outline / generate | 5–20 slides | `AI_SLIDE_MAX` |
| Manual add / duplicate | 40 slides | after AI, user may grow the deck |
| Elements per slide | 60 | `MAX_ELEMENTS_PER_SLIDE` |
| 16:9 / 4:3 | 1920×1080 / 1600×1200 | native PPT canvases |
| 9:16 | **rejected 400** | PPT only — use Canvas Editor for custom sizes |

Chart density caps are in §3.5 (they *are* policy).

---

## 7. Credits policy

**Source of numbers:** `src/shared/config/presentationCreditPricing.js`  
**Frontend/estimate behaviour:** [`PRESENTATION_CREDITS_FRONTEND.md`](PRESENTATION_CREDITS_FRONTEND.md)

| Feature | Mode | Default |
|---------|------|---------|
| `ppt_outline` | Token reconcile after success | ~286 AC on the 800 in / 1200 out estimate, 40% margin, 10 000 AC/USD |
| `ppt_slide_content` | Flat | 2 AC |
| `ppt_image_path_a` | Flat | 4 AC |
| `ppt_image_path_b` | Flat | 9 AC |
| `ppt_export` | Flat | 3 AC |
| `ppt_image_cache_hit` | Flat | **0 AC** |

**Charge-on-success**

- Affordability is checked **before** the call (402 if the estimate cannot be paid).
- Deduct **after** that piece succeeds (outline LLM, one slide’s copy, one image, one export).
- Failed outline / slide / image: **no charge for that piece**.
- Empty Path B spec that fell back to `diagram_template`: **not** Path B AC.
- Cache hit: 0 AC (main PPT cost control).
- Partial decks: successful slides may have charged; failed slides have not.

Do not hard-code AC in the SPA; use the estimate endpoint. Env may override flats (`PPT_IMAGE_PATH_A_AC`, etc.).

---

## 8. How to change a rule

1. **Edit this note** so the new rule is explicit (who it applies to, exception, test).
2. **Add or adjust a test** in `src/modules/presentation/test/` and/or `scripts/test-*.js`. The test is the contract.
3. Run:
   - targeted: `node --test src/modules/presentation/test/<file>.js`
   - Path B: `npm run test:path-b-vs-layouts`
   - scoring: `npm run test:layout-scoring`
   - bundle: `npm run test:presentation-scripts`
   - eval: `npm run eval:presentation` (offline; `PPT_EVAL_LIVE=1` only when you mean to hit vendors)
4. **Then** change `scoreLayout` / `layoutQa` / `diagramPathPolicy` / `layoutCatalogPolicy`.
5. If prompts change, bump `PROMPT_BUNDLE_VERSION` and update [`PRESENTATION_PROMPTS.md`](PRESENTATION_PROMPTS.md).

Do not “just tweak the scorer” because a single deck looked wrong. If the catalog seed is the problem, say so in the test (seed id), do not hide it in a one-off penalty.

---

## 9. Test index (policy → contract)

| Policy | Break this test |
|--------|-----------------|
| Scoring weights / rank | `test/layoutRules.test.js`, `scripts/test-layout-scoring.js` |
| Hard-reject comparison vs quote | `test/layoutBadFit.test.js` |
| Empty pool → widen / universal text | `test/ensureLayoutPick.test.js` |
| ARRAY_OVERFLOW not silently sliced | `test/layoutSelectionRegression.test.js`, `test/contentIntegrityRegression.test.js`, frontend `src/utils/engineEditorContract.test.mjs` |
| Chart density | `scripts/test-chart-density-cap.js` |
| Gallery vs hero | `scripts/test-gallery-grid-policy.js`, `test/gridGalleryImageCoherence.test.js` |
| Path B vs process vs empty spec | `scripts/test-path-b-vs-layouts.js` |
| Readable type / contrast | `test/readableText.test.js`, `test/contrastTypographyPlaceholders.test.js` |
| Placeholders | `test/cleanPlaceholders.test.js` |
| Problem slide ≠ chart | `test/problemSlideChartGate.test.js` |
| Closing layout | `test/closingLayoutPrefer.test.js` |
| Editor canvas vs compile | `test/editorCanvasParity.test.js` |
| Export fidelity / Path B single image | `test/pptxExportFidelity.test.js`, `eval:presentation-export` |

---

## 10. Owners and pairing

| Role | Person | Must be able to |
|------|--------|-----------------|
| Lead | **Komal Giri** | Change scoring, repair, Path A/B, catalog policy |
| Backup — editor contract | **Ankit Kumar** | Point at `ARRAY_OVERFLOW` / canvas compile tests before changing slot repair |
| Backup — API / credits | **Sahil** | Point at charge-on-success + Path A/B feature keys before changing billing |
| Pair — Image Studio | **Ankit Kumar** (Tanu lead) | Keep studio infographics off PPT Path B (`imageStudioEngineBoundary.test.mjs`) |

**Backup tests Ankit can name (run these before touching slot repair or Path B):**

| Rule | Command |
|------|---------|
| ARRAY_OVERFLOW not silently sliced | Frontend: `node --import ./scripts/test-resolve-hook.mjs --test src/utils/engineEditorContract.test.mjs` · Backend: `node --test src/modules/presentation/test/layoutSelectionRegression.test.js` |
| Editor slot map vs compile | Backend: `node --test src/modules/presentation/test/editorCanvasParity.test.js` |
| PPT caps / 9:16 → 16:9 | `engineEditorContract.test.mjs` (same command as overflow) |
| Image Studio ≠ Path B | `node --import ./scripts/test-resolve-hook.mjs --test src/pages/Slides/AIStudio/imageStudioEngineBoundary.test.mjs` |
| Path B vs process layout | `npm run test:path-b-vs-layouts` (backend) |

**Pair walkthrough:** Komal should still walk scoring (§3) live once. Overflow (§4) and Path B vs Image Studio (§5.1) now have named tests a second engineer can run without Komal. Until the scoring walk happens, bus-factor is reduced but scoring remains Komal-led.

---

## 11. What this note does not change

- Canvas Editor persistence / thumbnails (separate gap).
- Frontend UI test bar / Jenkins.
- Gemini Image Studio pricing placeholders.
- Hostname lock, `@athena/contracts` ESM, seed-JSON in git.
