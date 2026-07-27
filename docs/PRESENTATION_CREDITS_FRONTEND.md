# Presentation credits — frontend guide

How Athena Credits (AC) work for the **AI PPT / presentation** module. Canonical HTTP: [`docs/api/PRESENTATION_API.md`](api/PRESENTATION_API.md). Shared credit pools/history: [`CREDITS_FRONTEND_INTEGRATION.md`](./CREDITS_FRONTEND_INTEGRATION.md).

Pricing source: `src/shared/config/presentationCreditPricing.js` (isolated from HeyGen/Remotion tables).

---

## Feature keys (`ppt_*`)

| Feature | Key | Pricing mode | Typical default |
|---------|-----|--------------|-----------------|
| Outline generation | `ppt_outline` | Token-based (estimate → reconcile) | Derived from token rates + margin |
| Slide body copy | `ppt_slide_content` | Flat AC | **2** |
| Image Path A (stock/AI brief) | `ppt_image_path_a` | Flat AC | **4** |
| Image Path B (richer gen) | `ppt_image_path_b` | Flat AC | **9** |
| Export PPTX/PDF | `ppt_export` | Flat AC | **3** |
| Image cache hit | `ppt_image_cache_hit` | Flat AC | **0** |

Env overrides for flat costs: `PPT_SLIDE_CONTENT_AC`, `PPT_IMAGE_PATH_A_AC`, `PPT_IMAGE_PATH_B_AC`, `PPT_EXPORT_AC`, `PPT_IMAGE_CACHE_HIT_AC`.

Margin / FX for outline USD→AC: `PPT_MARGIN_PERCENT` / `PPT_AC_PER_USD` (fallback `ATHENA_MARGIN_PERCENT` / `ATHENA_AC_PER_USD`).

---

## Flat vs reconcile (outline)

1. **Pre-check / UI estimate** — `estimateOutlineAc()` uses configured estimate token counts (`PPT_OUTLINE_ESTIMATE_INPUT_TOKENS` / `PPT_OUTLINE_ESTIMATE_OUTPUT_TOKENS`) and per-token USD rates.
2. **Charge on success** — after the outline LLM returns, server calls **`reconcileOutlineAc(usage)`** with actual prompt/completion tokens and charges that AC amount (idempotent key per deck/job).
3. Flat features never reconcile tokens; they always use `getFlatAc(feature)`.

Frontend should treat outline cost as **approximate** until the outline response completes; show the estimate from **`GET …/credit-estimate`**, then refresh balances from credits APIs after success.

---

## Charge-on-success

| Action | When charged |
|--------|----------------|
| Outline | After successful LLM outline |
| Slide content / images | Per slide piece after that piece succeeds (partial decks may have partial charges) |
| Cache hit | **0** AC (`ppt_image_cache_hit`) |
| Export | After successful PPTX/PDF write |
| Failed jobs | No charge for that failed piece (pre-check may still **402** if estimate cannot be afforded) |

Same pattern as Remotion/HeyGen scene: assert affordability up front, deduct after success. Workspace pool (`SCOPE.WORKSPACE`).

---

## Estimate endpoint

`GET /api/workspaces/:workspaceId/presentations/:presentationId/credit-estimate?slideCount=`

Returns:

- `outline` — estimate-mode AC for one outline call  
- `generate` — `slideCount × (ppt_slide_content + ppt_image_path_a)` (Path A assumption; Path B may cost more if used)  
- `export` — flat `ppt_export`  
- `totalEstimatedCredits` — sum of the three  

Use this for confirm dialogs before outline / generate / export. Regenerate should estimate 1× content and/or 1× image depending on `target`.

---

## UX checklist

- Show AC estimate before outline and full generate.
- Poll status; surface `creditsChargedSoFar` and partial failures.
- On **402**, deep-link to credits / request more (same as video editor).
- Do not hard-code flat AC in the client — prefer estimate endpoint or documented env defaults as display fallback only.
- History: presentation charges appear in workspace credit history with `feature` metadata `ppt_*`.

---

**Related:** [PRESENTATION_API.md](api/PRESENTATION_API.md) · [PRESENTATION_PROMPTS.md](./PRESENTATION_PROMPTS.md) · [CREDITS_API.md](api/CREDITS_API.md)
