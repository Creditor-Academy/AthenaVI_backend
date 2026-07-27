# Presentation prompt bundle

**Current version:** `PROMPT_BUNDLE_VERSION = "v1"`  
Defined in `src/modules/presentation/prompts/index.js` and stored on decks as `promptBundleVersion` when generation runs.

Each prompt module exports **`buildSystem()`** and **`buildUser(vars)`**.

---

## Prompt files

| Module | File | Role |
|--------|------|------|
| Outline | `outline.prompt.js` | Narrative outline JSON (no full body copy) |
| Slide content | `slideContent.prompt.js` | Per-slide copy into layout slots |
| Classify | `classify.prompt.js` | Content-type / layout classification |
| Image brief | `imageBrief.prompt.js` | Path A image brief |
| Path B | `pathB.prompt.js` | Richer image / Path B spec |
| Vision relevance | `visionRelevance.prompt.js` | Vision check that an image fits the slide |

Access via getters on `prompts/index.js` (`getOutlinePrompt()`, …) or the named exports above.

---

## When to bump `PROMPT_BUNDLE_VERSION`

Bump (e.g. `v1` → `v2`) when any of the following change in a way that should be distinguishable in metrics, caches, or support:

- System or user prompt wording that materially changes model behavior or output schema
- Density caps / output JSON schema contracts expected by parsers
- Adding/removing a prompt module that participates in generation
- Intentional A/B or rollback of generation quality

Do **not** bump for typos that do not change behavior, or for non-prompt code (pricing, rate limits, layout seed JSON) unless you also need a new bundle label for ops.

After bumping, update this doc and re-run `npm run eval:presentation` (offline check asserts exports + reports `promptBundleVersion`).

---

**Related:** [PRESENTATION_API.md](api/PRESENTATION_API.md) · [PRESENTATION_CREDITS_FRONTEND.md](./PRESENTATION_CREDITS_FRONTEND.md)
