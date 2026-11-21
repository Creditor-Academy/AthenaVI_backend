# Task log — HeyGen v2 → v3 migration

**Date:** 2026-11-20 (session work)  
**Branch:** `heygenReveamp`  
**Merged to `main`:** PR [#29](https://github.com/Creditor-Academy/AthenaVI_backend/pull/29) — merge commit `f77f240`  
**Prisma / DB:** No schema or migration changes.

---

## Objective

Remove dependence on HeyGen v2 (`POST /v2/video/generate`, `GET /v2/avatars`); route all scene avatar video and look-list recovery through v3. Keep editor HTTP contracts; polling unchanged; no webhooks.

---

## Commits (migration phases)

| Phase | Commit (short) | Full SHA | Message |
|-------|----------------|----------|---------|
| 1 | `0df6c3d` | `0df6c3dabae91b84302023e20adf624cb42437a6` | Implement HeyGen v2 to v3 migration plan and add related tests |
| 2 | `3b08ba6` | `3b08ba6261dfd60b61fa2e4d18728eca77fa132b` | Refactor HeyGen video engine handling and update tests |
| 3 + 4 | `4d83016` | `4d83016eb39448d70cfb464bd79e94485eb84e13` | Refactor HeyGen video handling and finalize v2 to v3 migration |
| Docs | `61d79ab` | `61d79ab61c1937b8bc27a0a7d4f6c1d2d44fe31a` | Enhance HeyGen API documentation and finalize v2 sunset |

**Merge / integration on branch**

| Commit | Message |
|--------|---------|
| `daf9651` | Merge branch `development` into `heygenReveamp` |
| `4d650d9` | Merge branch `development` into `heygenReveamp` (incl. media proxy) |
| `5b0ae3a` | Add image proxy for canvas exports (on branch, not HeyGen core) |
| `887743e` | Merge branch `main` into `heygenReveamp` |
| `f77f240` | Merge pull request #29 from Creditor-Academy/heygenReveamp |

---

## Deliverables by phase

### Phase 1 (`0df6c3d`)

- `avatar_iii`, `resolveVideoPlanForLook`, `heygenVideoMigration.js`, `heygen.test.js`
- `HEYGEN_API_V3_MIGRATION_ASSESSMENT.md`, `HEYGEN_V2_MIGRATION_IMPLEMENTATION_PLAN.md`
- `docs/api/ENVIRONMENT.md`, `docs/api/README.md`, `package.json` test script

### Phase 2 (`3b08ba6`)

- v3-first `generateAvatarVideo`, billing/hash, default `voice_settings.engine_settings`
- IV ↔ V and `avatar_iii` retries (v2 fallback still present until phase 4)
- `creditPricing.js` + `creditPricing.heygen.test.js`, `engineBuckets.avatar_iii`

### Phase 3 + 4 (`4d83016`)

- Removed `GET /v2/avatars` / `collectV2AvatarLookCandidates`
- Removed `createVideoV2` and v2 create fallback; v3-only routing
- `HEYGEN_PREFER_V3_VIDEO` default on; removed `HEYGEN_ALLOW_V2_VIDEO_FALLBACK`
- Degraded looks list: `warn` logging

### Docs (`61d79ab` + follow-up)

- `HEYGEN_PROJECT_VIDEOS_API.md`, assessment §4/§7, editor integration, API index

---

## Session activities (not necessarily separate commits)

- Resolved `package.json` merge conflict with `development` (HeyGen tests + `mediaProxy` test)
- Removed migration env vars from `.env.development` (`HEYGEN_PREFER_V3_VIDEO`, `HEYGEN_ALLOW_V2_VIDEO_FALLBACK`)
- PR description for `heygenReveamp` → `main`; **no staging** — production post-deploy smoke
- QA notes: no Prisma changes; optional frontend cleanup for `usesLegacyV2Video`

---

## Production verification (no staging)

Post-deploy smoke: photo IV, studio V, III/expressive, looks list, idempotent re-POST, sync/download; 48h monitoring on `POST .../heygen/videos`.

---

## References

- Plan: [`HEYGEN_V2_MIGRATION_IMPLEMENTATION_PLAN.md`](HEYGEN_V2_MIGRATION_IMPLEMENTATION_PLAN.md)
- Assessment: [`HEYGEN_API_V3_MIGRATION_ASSESSMENT.md`](HEYGEN_API_V3_MIGRATION_ASSESSMENT.md)