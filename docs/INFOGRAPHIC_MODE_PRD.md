# PRD — Infographics mode (Image Gen)

Status: Implemented (v1 code path) — product decisions locked 2026-08-25; credits margin pass still deferred
Owner: TBD
Related docs: `IMAGE_GEN_COMPLETE.md` (Part 11 is the research this PRD formalizes), `docs/api/IMAGE_GEN_API.md`, `IMAGE_GEN_FRONTEND_INTEGRATION.md`, `INFOGRAPHIC_EVAL_SET.md`

---

## 1. Problem

Image Gen's `image` mode is live and good at general images, but it cannot
reliably produce infographics: it garbles text, invents numbers, and has no
concept of layout structure (timeline vs comparison vs funnel). Users who
want a readable, information-dense visual — not a scene — have no path
today. The API already rejects `mode: "infographic"` with a 400.

## 2. Goal

Ship a second Image Gen mode, `infographic`, that takes a topic, brief, or
data (optionally with attached context docs) and produces a downloadable,
readable, well-structured infographic — reusing the existing thread /
credit / library UX from `image` mode.

**Both the content and the visual design of the output are fully driven by
the user's request. Nothing is a fixed house style** — the system adapts
structure (process vs comparison vs stats, etc.) and look (color, icon
style, density, tone) to whatever was asked, the same way `image` mode
today adapts to any prompt. What's fixed is not a look — it's a content
fidelity guarantee: exact text, no invented numbers, structure that matches
the content.

## 3. Non-goals (v1)

- Editable vector canvas with movable text boxes (that's a PPT-editor problem, not this one)
- Multi-page PDF reports
- Live chart engines embedded in the output
- A fixed "brand" visual identity — see design philosophy above; explicitly out of scope until Brand Kit is revisited (§13, decision 8)

## 4. Success criteria

1. Content (section labels, numbers, body text) is still AI-generated from the user's prompt/context — that doesn't change. What changes is fidelity at the point of turning that content into pixels: whatever the spec says must come out correctly spelled and exactly as written, with no numbers, facts, or words invented or altered during rendering. Today's `image` mode fails here — a model asked to "make an infographic" will misspell words and fabricate numbers not present in the prompt, even when the surrounding content is accurate. The success bar is a materially lower rate of that specific failure, not a claim that every generated fact is true — factual accuracy of AI-generated content is bounded by what the user/context supplied (see `doNotInventNumbers`, §6.1), not verified independently.
2. Output structure matches what the content actually is (a 4-step process doesn't get rendered as a comparison table) without the user having to describe layout mechanics.
3. Visual design responds to what the user asked for or implied — a request with no style signal produces a reasonable default; a request with explicit style language (minimal, playful, hand-drawn, corporate) is visibly reflected in the output.
4. Same thread / regenerate / tweak / download UX as `image` mode — no new mental model for the user.
5. Credits charged transparently, on success only, consistent with existing pricing patterns.
6. Context and user-entered numbers drive factual content when present (used verbatim). When the brief needs a fact that was not supplied but is a reasonable public/knowledge fill (e.g. country population), the spec LLM may supply it from model knowledge — see §13.4. Private/company metrics that were not supplied must not be invented.

## 5. Architecture

**Spec-first, two-step pipeline**, per `IMAGE_GEN_COMPLETE.md` §11.3 Option B.
This extends the existing `generate` pipeline (§6.1 of `IMAGE_GEN_COMPLETE.md`)
with a spec-generation step inserted before the image call — every other
step (folder check, rate limit, afford check, asset persistence, thread
creation) stays the same as `image` mode:

```
validate (mode=infographic, folderId, prompt, …)
  → assert folder in workspace
  → rate limit (generate bucket — same bucket as image mode, no new bucket)
  → resolve context (optional)
  → assertAfford (covers spec + render cost — see §9)
  → LLM call → InfographicSpec (structured content, JSON)
      → Joi-validate the spec; on failure, one retry with a corrective
        system message, then fail the request (400) rather than
        rendering a spec that didn't pass validation
  → buildInfographicPrompt(spec) → strong typesetting prompt
  → generateImage (prefer HD)
  → crop (contain, not cover — see §7.3)
  → persistWorkspaceAsset (source: ai_gen)
  → create ImageGeneration (request.infographicSpec = spec)
  → pin context if used
  → chargeFlat (feature = infographic feature key, §9)
  → create ImageGenThread + seed messages
  → return { generation, asset, creditsCharged, thread, actions }
```

Charging happens once, on success, after both the spec call and the render
call complete — consistent with the existing charge-on-success rule. A
spec-generation failure never charges credits.

### 5.1 The core design decision: content and design are separate layers

| Layer | Typed? | Carries |
|---|---|---|
| **Content** — `InfographicSpec.sections`/`flows`, `label`, `body`, `metric`, `archetype` | Yes (Joi-validated) | Exact text and numbers. This is the fidelity guarantee — regardless of how the output looks, these fields render verbatim. |
| **Design** — `InfographicSpec.visualStyle`, per-section `color`, `iconHint`, `palette` | No — free text, fully optional | How it looks. Derived fresh from the user's request each time, the same way the `styles` catalog in `image` mode appends a prompt suffix without constraining layout. An empty `visualStyle` is a valid, common case — the model makes reasonable design choices rather than the system imposing a default look. |

This mirrors two existing patterns in the codebase: `formats` control
dimensions without touching content, and `styles` control mood without
touching layout. Infographics needs one additional axis (content
*structure* — is this a sequence? a comparison?) to be typed, because
that's the only lever that prevents garbled text; everything about
*appearance* stays exactly as open as it already is in `image` mode.

### 5.2 Archetype is a content-shape hint, not a template

`archetype` (`process | timeline | comparison | stats | hierarchy | list |
cycle`) describes what kind of content this is, not what it looks like.
Two `process` infographics can be visually unrecognizable from each other
depending on `visualStyle` — one minimal and monochrome, one illustrated
and colorful. This is why the system does **not** build fixed SVG/HTML
templates per archetype (that would re-couple structure to a fixed look);
archetype instead becomes typesetting guidance inside the render prompt
(e.g. "lay this out as a left-to-right numbered sequence" vs "lay this out
as side-by-side comparison columns"), executed by the image model itself.

## 6. Data model changes

### 6.1 `InfographicSpec` (new)

See `validations/infographicSpec.validations.js` (drafted this session).
Top-level shape:

```json
{
  "title": "string, required",
  "titleAccent": "optional substring to accent",
  "subtitle": "optional",
  "sections": "[ ...steps ] — XOR with flows",
  "flows": "[ ...named sub-flows ] — XOR with sections",
  "sidebar": "optional reference panel",
  "notes": "optional callout boxes",
  "footerFlow": "optional closing icon+label chain",
  "archetype": "process | timeline | comparison | stats | hierarchy | list | cycle",
  "orientation": "horizontal | vertical, optional",
  "visualStyle": "free text, optional, drives all appearance",
  "palette": "optional hex array, hard color constraint if the user wants one",
  "constraints": { "doNotInventNumbers": true, "language": "en", "tone": "free text" }
}
```

Each `section`: `id`, optional `number`, `label`, `body`, `metric`, optional
`color`, `iconHint`, `chips[]`, `emphasize`. All presentation fields
optional — a spec can be pure content with zero styling hints.

### 6.2 `ImageGeneration.request`

Add `infographicSpec` alongside the existing `prompt`, `style`, `palette`,
`contextId`, `contextSnapshot`, `tweak instruction` fields (per Part 4.5).
This is what makes regenerate/tweak stable: an omitted regenerate body
reuses the parent's stored spec rather than re-deriving it, so re-renders
don't drift.

### 6.3 `Asset.stockMetadata`

No change needed beyond what already exists (`mode`, `model`, `format`,
`action`, `threadId`) — `mode: "infographic"` distinguishes these from
`image` assets in the folder library today's schema already supports.

## 7. API changes

### 7.1 Joi (`validations/imageGen.validations.js`)

- `mode` accepts `image | infographic`
- Client body for infographic is the **flat** shape in §7.2 (no nested
  `infographic` object in v1 — that earlier research idea is dropped)
- Keep `headline`, `subheadline`, `textMode`, and nested `infographic`
  **forbidden** so old clients fail loudly
- New file: `validations/infographicSpec.validations.js` validates the
  **server-generated** spec (not the client body)
- Invalid client body → **400** (same as rest of Image Gen). Invalid LLM
  spec after one corrective retry → **400** with a clear message (do **not**
  introduce 422 — FE error map stays consistent)

### 7.2 New/changed endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/image-gen/archetypes` | New catalog, mirrors `/models` `/formats` `/styles` |
| POST | `/workspaces/:id/generate` | Branches on `mode`; `infographic` path runs the two-step pipeline |
| POST | `/generations/:id/regenerate` | Reuses parent `request.infographicSpec` unless `prompt` / hints change enough to re-run spec LLM (see below) |
| POST | `/generations/:id/tweak` | Routes per §13.5 (spec mutate **or** pixel edit) |
| POST | `/threads/:id/messages` | Same routing as tweak (§13.5) |

**`GET /api/image-gen/archetypes` response** — flat catalog, no dependency
on format/model:
```json
[
  { "id": "process", "label": "Process", "description": "Ordered steps or stages toward an outcome" },
  { "id": "timeline", "label": "Timeline", "description": "Dated or chronological milestones" },
  { "id": "comparison", "label": "Comparison", "description": "Two or more options on shared criteria" },
  { "id": "stats", "label": "Stats", "description": "KPI-style figures, minimal narrative" },
  { "id": "hierarchy", "label": "Hierarchy", "description": "Org, tree, or pyramid relationships" },
  { "id": "list", "label": "List", "description": "An unordered or lightly-ordered set of items" },
  { "id": "cycle", "label": "Cycle", "description": "A process that loops back to its start" }
]
```

#### Locked generate request (`mode: "infographic"`)

Client never sends `InfographicSpec`. Server builds it.

```json
{
  "mode": "infographic",
  "folderId": "uuid",
  "modelId": "gpt-image-1-hd",
  "formatId": "landscape",
  "prompt": "the user's raw request — required, this is the only mandatory content input",
  "archetypeHint": "process",
  "styleHint": "minimal, black and white, no icons",
  "contextId": "optional-uuid",
  "brandPalette": ["#0B1F3A", "#3DDC97"]
}
```

| Field | Required | Notes |
|-------|----------|--------|
| `mode` | yes (or default only for image) | Must be `"infographic"` for this path |
| `folderId` | **yes** | Same as image mode |
| `prompt` | **yes** | Only mandatory content input |
| `modelId` | no | Default `gpt-image-1-hd` |
| `formatId` | no | Default `landscape` for infographic (better for reading); `square` / `portrait` allowed |
| `archetypeHint` | no | If set → hard instruction to spec LLM; if omitted → auto-pick |
| `styleHint` | no | Seeds `visualStyle`; free text or existing style id string |
| `contextId` | no | Existing context bundle |
| `brandPalette` | no | Maps to `InfographicSpec.palette` |

#### Locked generate response

Same envelope as image mode. Spec is stored on the hop and exposed both
ways for FE convenience:

```json
{
  "generation": {
    "id": "uuid",
    "mode": "infographic",
    "modelId": "gpt-image-1-hd",
    "formatId": "landscape",
    "prompt": "...",
    "request": {
      "mode": "infographic",
      "modelId": "gpt-image-1-hd",
      "formatId": "landscape",
      "prompt": "...",
      "archetypeHint": "process",
      "styleHint": "...",
      "brandPalette": ["#0B1F3A", "#3DDC97"],
      "contextId": null,
      "contextSnapshot": null,
      "infographicSpec": { "title": "...", "archetype": "process", "sections": [] }
    },
    "infographicSpec": { "title": "...", "archetype": "process", "sections": [] },
    "url": "https://...",
    "threadId": "uuid",
    "creditsCharged": 0,
    "downloadFormats": ["png", "jpg", "jpeg", "pdf"]
  },
  "asset": { "id": "uuid", "url": "https://...", "name": "..." },
  "creditsCharged": 0,
  "thread": { "id": "uuid", "threadId": "uuid", "title": "...", "head": {} },
  "actions": {
    "viewUrl": "https://...",
    "downloadPath": "/api/image-gen/workspaces/.../generations/.../download",
    "threadId": "uuid"
  }
}
```

- **`generation.request.infographicSpec`** — source of truth for regenerate /
  chat (always persisted).
- **`generation.infographicSpec`** — same object, duplicated at top level by
  the serializer so FE does not dig into `request` (optional panel / debug).
- **`creditsCharged`** — may be `0` or a temporary placeholder until the
  margin pricing pass (§9). Envelope shape does not change later.

#### Regenerate body (locked)

Omitted fields reuse parent `request`. Rules:

- **No new `prompt` / hints** → re-render from stored `infographicSpec` only
  (no second spec LLM unless product later wants “fresh invent”).
- **New `prompt` and/or `archetypeHint` / `styleHint` / `contextId`** →
  re-run spec LLM, then render (content intentionally changed).

### 7.3 Formats

Reuse `square | landscape | portrait`. Add `compose`/`safeZone` rules that
permit **margins, cards, legends** for infographic mode — the opposite of
`image` mode's full-bleed rules, which fight chart-like layouts. Crop
policy: `contain`, not `cover` — labels must never be clipped.

## 8. Prompts (new files)

- `prompts/infographicSpec.prompt.js` — **drafted this session.** LLM call that turns `{ userPrompt, contextText, archetypeHint, tone }` into a validated `InfographicSpec`. Explicitly topic-agnostic and design-agnostic; enforces structure and the no-invented-numbers rule only.
- `prompts/infographicRender.prompt.js` — **next to build.** Takes a spec (with or without `visualStyle` filled in) and produces the actual `generateImage` prompt: instructs verbatim reproduction of every label/body/metric, applies archetype as layout guidance, applies `visualStyle` as appearance guidance if present, and falls back to sensible unguided defaults if not.
- `prompts/infographicChat.prompt.js` — patches an existing spec from a chat message ("swap step 2 and 3", "add a fourth stage for QA") before re-render.

## 9. Credits (**deferred** — after features)

**Product rule (locked):** final Athena Credits will be priced for about a
**20% profit margin** on top of measured OpenAI cost (spec LLM + image
generate/edit usage), as a **single flat AC** per successful action (§13.3).
Exact AC numbers are **out of scope until the feature pipeline works**.

**While building features:**

- Wire `estimate` / `chargeFlat` hooks so the shape stays correct
- Use a **temporary placeholder** charge (e.g. reuse current image-mode
  model AC for the selected `modelId`, or charge `0` behind an env flag
  for internal dogfood) — pick one in implementation and document it
- Do **not** block P0–P3 on margin math
- After features + eval pass: measure real OpenAI $ per successful
  generate / chat-spec-rerender / pixel-tweak → set
  `IMAGE_GEN_INFOGRAPHIC_AC` (and drop any separate spec AC) so
  `price ≈ cost × 1.20` in AC terms

Charge-on-success stays. Rate limiting reuses existing `generate` /
`regenerate` Redis buckets — no new bucket.

## 10. Context pipeline

Reuse existing `ImageGenContext` unchanged. Additions:
- Spec-generation prompt treats **user prompt numbers + attached context** as the first source of truth; never contradict or overwrite them
- When a needed public/general fact is missing, the spec LLM may fill from **model knowledge** (not a live web API in v1 unless we add a search tool later) — see §13.4
- Private or company-specific figures that were never supplied must not be fabricated
- Number/fidelity rules are enforced at the **spec-generation** step, not at render time (render must typeset the spec verbatim)
- Later: consider CSV in the accepted MIME list, since tabular data is a natural infographic source

## 11. Rollout plan

| Phase | Deliverable | Exit criteria |
|---|---|---|
| P0 — Research spike (3–5 days) | Hand-built spec → throwaway `infographicRender.prompt.js` v0, tested against 10 varied briefs (different topics AND different style asks) | Text fidelity and design responsiveness both hold up without hand-tuning per brief |
| P1 — API unlock | `mode=infographic`, archetype catalog, `contain` crop, Joi changes, request/response contract (§7.2), docs | FE can wire a mode toggle end to end |
| P2 — Spec pipeline | `infographicSpec.prompt.js` (done) + `infographicRender.prompt.js` hardened from the P0 spike into the real module; store snapshot; regenerate from spec | Quality bar for v1 met on eval set (§12) |
| P3 — Chat-on-spec | Thread messages patch spec, then re-render | Iteration feels intentional, no drift across edits |
| P4 — Brand Kit (optional) | `brandKitId` → palette/logo become one more design input, not a forced default | Consistency with PPT Path B when requested |

## 12. Eval set + pass threshold (**locked recommendation**)

**Set size:** 20 fixed briefs spanning both axes: different subject matter
(business, science, personal, historical, …) **and** different style asks
(explicit style vs none; mix of all 7 archetypes).

**Scoring (human, pass/fail per axis per brief):**

| Axis | Pass means |
|------|------------|
| **Fidelity** | Labels / numbers / titles in the PNG match the stored `infographicSpec` (no garbled or altered copy) |
| **Structure** | Layout matches the content shape / archetype (e.g. 4-step process is not a 2-column comparison) |
| **Style** | If the brief asked for a look, output visibly reflects it; if no style ask, output is readable and not stuck in one house look across the set |

**Pass threshold to exit P2 (recommended lock):**

| Gate | Threshold |
|------|-----------|
| Fidelity | **≥ 80%** of briefs pass (16/20) |
| Structure | **≥ 75%** (15/20) |
| Style (only briefs that asked for style; min 8 such briefs) | **≥ 70%** of those pass |
| Dense briefs (8+ sections) | At least **3** in the set; **≥ 2/3** pass fidelity |

Owner of running/scoring the set: **TBD** (assign before P2 exit).  
Fail → fix prompts / crop / model default; do not ship P2 as “done.”

## 13. Product decisions (locked 2026-08-25)

| # | Topic | Decision |
|---|--------|----------|
| 1 | **Archetype scope** | Ship **all 7** (`process`, `timeline`, `comparison`, `stats`, `hierarchy`, `list`, `cycle`). FE archetype picker optional; “auto” = omit `archetypeHint`. |
| 2 | **Default model** | **User may pick** any catalog model that lists `infographic`. If omitted, default to **`gpt-image-1-hd`** (best text density). Estimate/charge follow the chosen model’s flat infographic AC (see #3). |
| 3 | **Credits** | **Single flat AC** per successful action. **Pricing deferred** until after features: target **~20% margin** over measured OpenAI cost (spec + image). Placeholder charge OK while building (§9). |
| 4 | **Data / numbers** | **Prefer user + context, then knowledge fill when needed** — see §13.4 below. |
| 5 | **Tweak / chat** | **Both paths** — see §13.5 below. |
| 6 | **PPT Path B** | Keep Image Gen infographic prompts **independent** of Path B (copy patterns only; do not share one module). |
| 7 | **Social mode** | **Blocked / parked** for now — out of v1 scope. |
| 8 | **Brand Kit** | **v1.1** — not in v1. Optional `brandKitId` later; do not force brand identity before open-design core is proven. |

### 13.4 Data / numbers (detail)

Priority when building `InfographicSpec`:

1. **User-entered numbers and facts in the prompt** — use **verbatim**.
2. **Attached context** (PDF, brief, pasted text, tables) — use **verbatim**; never contradict or “improve” them.
3. **If the brief needs a value that was not supplied**, and it is a **public / general knowledge** fact the model can reasonably supply from what the user asked (e.g. country **population**, well-known historical dates, widely cited public stats) — the **spec LLM may fill it** from **model knowledge**.
4. **Do not invent private or company-specific metrics** that were never given (e.g. “our Q3 conversion rate” with no figure in prompt/context). For those, omit the metric or use a clear placeholder such as `"—"` — do not fabricate.

**v1 note:** “Fetch” here means **LLM world knowledge**, not a live web-search API. Adding a real search/tool call is a later enhancement if accuracy of public stats becomes a complaint.

`constraints.doNotInventNumbers` in the spec should mean: **do not invent private/unsupplied business data**; public knowledge fills under rule 3 are allowed and should be treated as normal spec content for verbatim render.

### 13.5 Tweak / chat — both paths (detail)

Support **both**:

| Path | When | Behavior |
|------|------|----------|
| **Spec mutate + re-render** | Content / structure changes (“swap step 2 and 3”, “add a QA stage”, “change the title”) | LLM patches `infographicSpec` → `buildInfographicPrompt` → `generateImage` (or HD regenerate). Preserve prior `visualStyle` / palette unless the user asks to change look. |
| **Pixel `editImage`** | Pure visual tweaks (“make the background darker”, “increase contrast”) | `editImage` on the current head PNG; do **not** rewrite the stored content spec. |

**Routing (v1):** Server-side classifier (heuristics and/or a tiny LLM router) chooses the path from the user message. Prefer **spec path** when unsure if the ask touches labels, order, numbers, or sections. Optional later: FE sends `editMode: "spec" | "pixel"` to override.

Both paths use the **same flat infographic charge hook** (#3 / §9). Rate limit: existing regenerate bucket. Exact AC set in the later margin pass.

## 14. Risks

- **Spec-generation LLM under-specifies design**, causing every output to converge on one look despite `visualStyle` being free — needs explicit eval coverage (§12) since this is a regression path, not just an edge case.
- **Iteration cost**: chat edits that mutate the spec and re-render lose whatever the image model chose stylistically last time, unless the render prompt is told to preserve unstated style choices from the prior spec snapshot — worth a spike experiment in P0.
- **Text fidelity at high content density** (14-section specs) is unproven at this scope — cap `sections` at a sane max (already 14 in the schema) and validate against dense briefs in the eval set specifically.

## 15. Frontend requirements

Minimal surface change, per the "same UX as `image` mode" success
criterion (§4.4) — this is additive to `IMAGE_GEN_FRONTEND_INTEGRATION.md`,
not a new flow:

- **Mode toggle** on the existing Image Gen composer (`image` /
  `infographic`), same location as model/format pickers.
- **Archetype selector**: optional, defaults to "auto" (no `archetypeHint`
  sent — see §7.2). Show all **7** archetypes (§13.1).
- **Model picker**: shown in infographic mode; default selection **`gpt-image-1-hd`** when user does not change it (§13.2).
- **Style input**: a free-text field or the existing `styles` chip picker
  reused as `styleHint` — do not build a new, separate style catalog
  specific to infographics, since visual design is meant to be as open as
  `image` mode's (§5.1).
- **Spec preview** (optional, nice-to-have for P2): since the response now
  includes `generation.infographicSpec`, the client could show a
  collapsible "what we generated" panel before/after render — useful for
  trust, not required for v1.
- **Chat/tweak UI**: same composer as `image` mode for v1; **routing** between
  spec-mutate and pixel-edit is **server-side** (§13.5). Optional FE
  `editMode` override is a later nicety, not required for v1.
- **Download/library**: unchanged — infographic assets flow through the
  same folder library and export pipeline as `image` assets (§6.3).

## 16. Definition of done (v1)

- [x] §13 product decisions locked (2026-08-25)
- [x] Generate request/response contract locked (§7.2)
- [x] Eval threshold locked (§12)
- [x] Credits: margin rule locked; **exact AC deferred** until after features (§9)
- [ ] §13 + §7.2 reflected in code and API docs
- [ ] `infographicSpec.validations.js`, `infographicSpec.prompt.js`, `infographicRender.prompt.js`, `infographicChat.prompt.js` merged
- [ ] `mode=infographic` Joi-unlocked; list/get/library accept infographic; `image` mode unchanged
- [ ] Eval set (§12) scored by named owner and meeting thresholds
- [ ] FE: mode toggle, archetype selector, model picker, style input (§15)
- [ ] Client timeout guidance documented (recommend **≥ 120s** for sync generate)
- [ ] Postman + `ENVIRONMENT.md` / `IMAGE_GEN_API.md` updated
- [ ] **Post-v1 pricing pass:** measure OpenAI cost → set flat AC at ~20% margin
- [ ] PRD status → Approved; owner assigned

