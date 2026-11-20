# HeyGen API v3 migration assessment (Athena VI backend)

**Status:** Phases 1–4 implemented on branch `heygenReveamp` — scene video and avatar list recovery are **v3-only** in `src/`. Use this doc for history, test matrix, and remaining product gaps (webhooks, voice catalog).

**Audience:** Backend, frontend/editor, DevOps.

**Official references**

| Resource | URL |
|----------|-----|
| Quick Start | https://developers.heygen.com/docs/quick-start |
| Full doc index (for agents) | https://developers.heygen.com/llms.txt |
| **v1/v2 → v3 endpoint map** | https://developers.heygen.com/endpoint-version-comparison |
| OpenAPI (v3) | https://developers.heygen.com/openapi/external-api.json |
| Webhooks | https://developers.heygen.com/docs/webhooks |
| Voice on `POST /v3/videos` | https://developers.heygen.com/voice-in-avatar-videos |
| Avatar III engine (v3) | https://developers.heygen.com/avatar-iii |
| Our HeyGen user API | [api/HEYGEN_API.md](api/HEYGEN_API.md) |
| Our project videos API | [api/HEYGEN_PROJECT_VIDEOS_API.md](api/HEYGEN_PROJECT_VIDEOS_API.md) |
| Webhook design (not built yet) | [CLIENT_RENDERING_RECOMMENDATIONS.md](CLIENT_RENDERING_RECOMMENDATIONS.md) §3 |

---

## 1. Executive summary

HeyGen **ended support for v1/v2 on 31 October 2026** and is **removing those routes**; calls may **fail intermittently** until removal is complete. Production integrations must use **v3 only** (`https://api.heygen.com`, header `X-Api-Key`).

Athena VI **scene avatar video** and **avatar look list recovery** use **`/v3/*` only** (`POST /v3/videos` with `avatar_iv` / `avatar_v` / `avatar_iii`; no `POST /v2/video/generate` or `GET /v2/avatars` in application code). Expressive and III-only looks route via **`avatar_iii`** on v3.

**Staging validation:** confirm expressive public and III-only looks complete end-to-end; monitor `POST .../heygen/videos` errors after deploy.

**Secondary gaps (platform alignment, not v2 sunset):**

- **No inbound HeyGen webhooks** yet — we still **poll** `GET /v3/videos/{id}` (see `pollLatestStatus` in `src/modules/video/services/heygen.service.js`). Webhooks are the documented replacement for polling.
- **Video voice pipeline** — latest HeyGen guidance expects explicit `voice_settings.engine_settings` (`engine_type`, `model`) on `POST /v3/videos`; we often omit it and rely on HeyGen defaults (can fail or pick an unexpected TTS engine).
- **Dual voice APIs** — we use **`/v3/voices/*`** (list, design, clone, Starfish preview speech). HeyGen’s newer **HeyGen Voice 1** catalog and TTS live under **`/v3/models/audio/*`**. Both can coexist; product should decide whether to migrate clone/TTS/preview to the model API long term.

---

## 2. Deprecation timeline (vendor)

| Phase | Date | Expectation |
|-------|------|-------------|
| Sunset | **2026-10-31** | v1/v2 end of support; v3 is the supported API |
| Removal | **In progress** | Legacy endpoints dropped; **intermittent failures** until traffic is on v3 |

Legacy responses (while still up) may include JSON:

```json
{
  "warning": {
    "message": "… migrate to POST /v3/videos …",
    "v3_endpoint": "POST /v3/videos",
    "sunset_date": "2026-10-31"
  }
}
```

**Inventory tip:** log `warning.v3_endpoint` from any remaining v2 responses in staging to confirm the migration list is complete.

---

## 3. What we call today (code inventory)

Central HTTP client: `src/shared/services/heygenV3.client.js` (default base `https://api.heygen.com`, `x-api-key`).

| HeyGen path | Used for | Athena module(s) |
|-------------|----------|------------------|
| `GET /v3/users/me` | Billing / quota for superadmin alerts | `heygenV3.service.js` |
| `GET /v3/avatars` | List avatar groups | `heygenV3.service.js` |
| `GET /v3/avatars/{group_id}` | Group detail, delete safeguards | `heygenV3.service.js` |
| `GET /v3/avatars/looks` | List looks | `heygenV3.service.js` |
| `GET /v3/avatars/looks/{id}` | Look detail, engine resolution | `heygenV3.service.js`, `heygenAccess.service.js` |
| `POST /v3/avatars` | Create photo / digital_twin / prompt | `heygenV3.service.js` |
| `POST /v3/avatars/{group_id}/consent` | Digital twin consent | `heygenV3.service.js` |
| `DELETE /v3/avatars/{group_id}` | Delete group | `heygenV3.service.js` |
| `DELETE /v3/avatars/looks/{id}` | Delete look | `heygenV3.service.js` |
| `GET /v3/voices` | List voices | `heygenV3.service.js` |
| `POST /v3/voices` | Voice design | `heygenV3.service.js` |
| `POST /v3/voices/clone` | Voice clone | `heygenV3.service.js` |
| `GET /v3/voices/{id}` | Voice detail, select flow | `heygenV3.service.js` |
| `DELETE /v3/voices/{id}` | Delete clone | `heygenV3.service.js` |
| `POST /v3/voices/speech` | TTS preview + project speech | `heygenV3.service.js`, `speech.service.js` |
| `POST /v3/assets/direct-uploads` + `POST /v3/assets/{id}/complete` | Large uploads for avatar/voice create | `heygenAssets.service.js` |
| `POST /v3/videos` | **Primary** avatar scene videos | `heygenV3.service.js` → `heygen.service.js` |
| `GET /v3/videos/{id}` | Status, URL, failure info | `heygenV3.service.js` → polling / sync |
| **`POST /v2/video/generate`** | **Legacy** scene videos | `heygenV3.service.js` → `heygen.service.js` |
| **`GET /v2/avatars`** | **Legacy** look-id recovery | `heygenV3.service.js` (`collectV2AvatarLookCandidates`) |

**Not used (HeyGen v3 capabilities we do not integrate):** Video Agent, studio multi-scene `type: "studio"`, templates, translation, lipsync, batches, HyperFrames, brand kits/glossaries on HeyGen, managed webhooks (`/v3/webhooks/endpoints`), `GET /v3/videos/voice-capabilities`, `POST /v3/models/audio/tts`, realtime LiveAvatar, etc.

---

## 4. Legacy v2 usage — impact and v3 replacement

### 4.1 `POST /v2/video/generate` (critical)

| | |
|--|--|
| **Vendor replacement** | `POST /v3/videos` (`type: "avatar"`, discriminated union body) |
| **Our entry points** | `createVideoV2` in `heygenV3.service.js`; `buildHeyGenV2VideoPayload` + `createHeygenVideoJob({ useLegacyV2: true })` in `src/modules/video/services/heygen.service.js` |
| **When we choose v2** | `resolveVideoPlanForLook` / `usesHeygenLegacyV2VideoLook` in `src/shared/constants/heygen.js`: expressive public look ids (`*_expressive*_public`), looks with **only** `avatar_iii` in `supported_api_engines`, empty engine list; plus **runtime fallback** from v3 → v2 on certain 400 errors |
| **Billing note** | `billingContext.heygenApiVersion` can be `v2`; credits use `legacy_v2` / `avatar_iii` rates in `creditPricing.js` |

**HeyGen v3 note (important):** Avatar III is **not** v2-only anymore. Official v3 docs: use `POST /v3/videos` with `"engine": { "type": "avatar_iii" }` for digital twins, studio avatars, and photo avatars ([Avatar III](https://developers.heygen.com/avatar-iii)). Today we **never** send `avatar_iii` on v3 — we send `avatar_iv` / `avatar_v` or fall back to v2.

**Recommended investigation (before coding):**

1. Sample failing / v2-routed look ids from production logs (`billingContext.heygenApiVersion = v2`).
2. For each, `GET /v3/avatars/looks/{id}` and read `supported_api_engines`.
3. Try **v3** create with `engine.type = avatar_iii` (and existing IV/V attempts) in a **staging** key; compare output and HeyGen errors.
4. Confirm **webhook** `avatar_video.success` fires for v3 `avatar_iii` jobs (when webhooks are implemented).

### 4.2 `GET /v2/avatars` (degraded picker)

| | |
|--|--|
| **Vendor replacement** | `GET /v3/avatars`, `GET /v3/avatars/looks`, per-look `GET /v3/avatars/looks/{id}` |
| **Our use** | Fallback in `fetchLooksListFallbackForGroup` when v3 list returns empty/400 |
| **Risk** | Intermittent **empty private/shared look lists** for affected groups if v2 list disappears |
| **Mitigation** | Rely on v3 single-look GET + group metadata; escalate HeyGen support on bad `created_at` rows; remove v2 catalog scrape |

---

## 5. v3 alignment gaps (not strict v2 sunset, but latest API behavior)

### 5.1 Voice on video create

[Voice in avatar videos](https://developers.heygen.com/voice-in-avatar-videos) documents:

- Public/private voices via `GET /v3/models/audio/voices` (we expose voices via our proxy of `GET /v3/voices`).
- **`voice_settings.engine_settings`** with `engine_type` + `model` (e.g. `heygen_voice` + `heygen-voice-1`) — **recommended on every script-based video**.
- `GET /v3/videos/voice-capabilities` to validate language/locale/engine combinations.

Our `buildHeyGenVideoPayload` (`heygen.service.js`) sends `voice_settings.speed`, `pitch`, `volume`, `locale`, and optional passthrough `engine_settings`, but **does not set a default** `engine_type` / `model`. HeyGen warns omitting `engine_settings` can cause **late failures** after job creation.

**Action (later):** define product defaults (likely `heygen_voice` / `heygen-voice-1` for English editor scripts), optionally call voice-capabilities when locale/engine matters, and extend validation on `POST .../heygen/videos`.

### 5.2 Starfish TTS vs HeyGen Voice 1

| Surface | Our usage | HeyGen “latest” catalog |
|---------|-----------|-------------------------|
| `POST /v3/voices/speech` | Speech preview (`/api/heygen/...`), project `speech.service.js` | Starfish-oriented preview path |
| `POST /v3/models/audio/tts` | Not used | HeyGen Voice 1 TTS (turbo-free promo until 2026-11-30 per docs) |
| `POST /v3/voices/clone` | User voice clone | v3 map lists `POST /v3/models/audio/voices` `mode: instant` |

**Action (later):** product decision — keep Starfish preview for compatibility or migrate preview/project speech to `/v3/models/audio/tts` and align clone/list with `/v3/models/audio/voices`. Until then, **`/v3/voices/*` is still v3**, not the sunset v2 list API.

### 5.3 Webhooks and polling

| Current | HeyGen recommendation |
|---------|-------------------------|
| `pollLatestStatus`: up to 24 × 1.5s `GET /v3/videos/{id}` on sync/download paths | `POST /v3/webhooks/endpoints` + HMAC `signature` on raw body |
| In-process S3 copy queue | Durable queue (already described in `CLIENT_RENDERING_RECOMMENDATIONS.md`) |

**v2 webhook note:** When expressive looks still use v2 generate, confirm whether `avatar_video.success` applies to v2-created ids before removing polling entirely (documented as open question in CLIENT_RENDERING_RECOMMENDATIONS §3 item 7).

### 5.4 Pagination

v3 lists use **cursor** `token` parameters. Our proxies forward HeyGen query params; verify frontend passes `token` on avatar/voice lists after any migration (no offset assumptions).

### 5.5 Rate limits and errors

Documented behaviors we should respect in implementation work:

- **429** — honor `Retry-After`, backoff (client today surfaces `AppError` 429).
- **401** — key rotation; we already use `GET /v3/users/me` for superadmin billing checks.
- Failed videos — read `failure_code` / `failure_message` on `GET /v3/videos/{id}` (we normalize in `normalizeVideoStatusResponse`).

---

## 6. Features we do not need for sunset (optional roadmap)

These are **v3-only** and **not required** to leave v2, unless product expands scope:

| Feature | Endpoint | Notes |
|---------|----------|--------|
| Batch scene renders | `POST /v3/videos/batches` | Up to 100 jobs; may help editor bulk export |
| Studio composition | `POST /v3/videos` `type: "studio"` | Replaces **multi-input** v2 `video_inputs` pattern for complex timelines — different from our per-scene MP4 model |
| Video Agent | `POST /v3/video-agents` | Prompt-to-finished-video; separate product surface |
| Translation / lipsync | `/v3/video-translations`, `/v3/lipsyncs` | Not in Athena VI today |
| HeyGen Brand Kit / Glossary | `/v3/brand-kits`, `/v3/brand-glossaries` | We have **workspace Brand Kits** in our DB, not HeyGen’s brand APIs |

---

## 7. Recommended phased work (when you approve code changes)

### Phase 0 — Observe (no behavior change)

- [ ] Enable temporary logging of HeyGen `warning` objects on any response in staging.
- [ ] Metric: % of scene creates with `heygenApiVersion: v2` vs `v3` (from `heygen_responses` / billing context).
- [ ] Export list of distinct `avatarId` values that used v2 in the last 30 days.

### Phase 1 — Remove v2 **video** dependency (P0)

- [ ] Implement `avatar_iii` in `heygen.js` engine map and `buildHeyGenVideoPayload` (`engine: { type: "avatar_iii" }`).
- [ ] Change `resolveVideoPlanForLook` to prefer v3 `avatar_iii` over `videoApi: 'v2'` when look metadata allows.
- [ ] Retest expressive public looks on **v3** only (HeyGen may have enabled IV/V or dedicated handling — confirm per look).
- [ ] Remove or gate `createVideoV2` / `buildHeyGenV2VideoPayload` behind a feature flag until production validation passes.
- [ ] Update credit labeling (`legacy_v2` → `avatar_iii` on v3) where needed.

**Files likely touched:** `src/shared/constants/heygen.js`, `src/modules/video/services/heygen.service.js`, `src/modules/heygen/heygenV3.service.js`, `src/shared/config/creditPricing.js`, tests, `docs/api/HEYGEN_PROJECT_VIDEOS_API.md`.

### Phase 2 — Remove v2 **avatar list** fallback (P1)

- [ ] Delete `collectV2AvatarLookCandidates` or replace with v3-only recovery.
- [ ] Add monitoring when `listDegraded` / `heygenListUnavailable` appears in API responses to avatar looks endpoints.

**Files:** `src/modules/heygen/heygenV3.service.js`, `docs/api/HEYGEN_API.md`.

### Phase 3 — Webhooks + queue (P1, parallel-friendly)

- [ ] Implement `POST /api/heygen/webhook` per `CLIENT_RENDERING_RECOMMENDATIONS.md`.
- [ ] Register `POST /v3/webhooks/endpoints` per environment; store `HEYGEN_WEBHOOK_SECRET`.
- [ ] Reduce hot-path polling; keep status GET as backstop / sweeper only.

### Phase 4 — Voice pipeline hardening (P2)

- [ ] Default `voice_settings.engine_settings` on video create.
- [ ] Optional: integrate `GET /v3/videos/voice-capabilities`.
- [ ] Evaluate migration of preview/speech from `/v3/voices/speech` to `/v3/models/audio/tts`.

### Phase 5 — Docs and Postman

- [ ] Update `docs/api/HEYGEN_API.md` / `HEYGEN_PROJECT_VIDEOS_API.md` with engine and webhook behavior.
- [ ] Postman collection env vars if new routes or fields are exposed.

---

## 8. Test matrix (staging / production cutover)

| # | Scenario | Pass criteria |
|---|----------|----------------|
| 1 | Public catalog look, `avatar_iv` | `POST /v3/videos` completes; S3 copy; credits charged |
| 2 | Studio / digital twin, `avatar_v` | Same; no erroneous IV fallback |
| 3 | Look previously on **v2 only** (expressive or `avatar_iii`) | Completes on **v3** without calling `/v2/video/generate` |
| 4 | Photo avatar + expressiveness | IV + expressiveness only when HeyGen allows |
| 5 | WebM transparent export | `output_format` + no invalid `background` on webm |
| 6 | Voice clone + scene video | Clone voice works with chosen `engine_settings` |
| 7 | `POST /v3/voices/speech` project speech | Audio in S3; billing |
| 8 | Avatar looks list for group with known HeyGen list bug | Looks still returned without `GET /v2/avatars` |
| 9 | Webhook | `avatar_video.success` updates DB and enqueues S3 job ≤10s response to HeyGen |
| 10 | Idempotent recreate same scene hash | No duplicate HeyGen jobs |

---

## 9. Environment and operations

| Variable | Role today | Add when implementing webhooks |
|----------|------------|--------------------------------|
| `HEYGEN_API_KEY` | Required | Same |
| `HEYGEN_BASE_URL` | Optional override | Same |
| `HEYGEN_WEBHOOK_SECRET` | Not in code yet | Per-endpoint secret from HeyGen create/rotate |
| Public API URL | — | HTTPS URL HeyGen can reach for webhook registration |

Billing visibility already uses `GET /v3/users/me` (wallet vs subscription). No v1/v2 quota endpoints in our code.

---

## 10. Mapping table (vendor legacy → our code → v3 target)

| Legacy (sunset) | Our code reference | v3 target |
|-----------------|-------------------|-----------|
| `POST /v2/video/generate` | `createVideoV2`, `buildHeyGenV2VideoPayload` | `POST /v3/videos` (+ `engine.type` including `avatar_iii`) |
| `GET /v2/avatars` | `collectV2AvatarLookCandidates` | `GET /v3/avatars/looks/{id}` + group detail |
| `GET /v2/videos/{id}` | Not used (we use v3 GET) | — |
| `POST /v2/voices/clone` | Not used (we use `/v3/voices/clone`) | Optional: `/v3/models/audio/voices` |
| `POST /v1/audio/text_to_speech` | Not used | We use `/v3/voices/speech`; optional `/v3/models/audio/tts` |

---

## 11. Decision log (fill as you implement)

| Date | Decision | Owner |
|------|----------|-------|
| | | |

---

## 12. Summary for stakeholders

- **We are not starting from zero:** the majority of HeyGen traffic is already **v3**.
- **We must eliminate v2 video generate** for affected avatars; HeyGen documents **Avatar III on v3**, which our routing logic currently does not use.
- **Webhooks** are the largest operational improvement adjacent to the sunset (polling is still in production paths).
- **No code was changed** to produce this assessment; implementation should follow your go-ahead on Phase 1+.

When you want implementation, follow the phased **4-commit** plan (no webhooks; polling unchanged): **[HEYGEN_V2_MIGRATION_IMPLEMENTATION_PLAN.md](HEYGEN_V2_MIGRATION_IMPLEMENTATION_PLAN.md)**.