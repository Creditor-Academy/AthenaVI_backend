/** HeyGen POST /v3/videos engine discriminators (see supported_api_engines on looks). */
const HEYGEN_AVATAR_ENGINES = Object.freeze({
  IV: 'avatar_iv',
  V: 'avatar_v',
});

const DEFAULT_HEYGEN_AVATAR_ENGINE = HEYGEN_AVATAR_ENGINES.IV;

const HEYGEN_AVATAR_ENGINE_VALUES = Object.freeze([
  HEYGEN_AVATAR_ENGINES.IV,
  HEYGEN_AVATAR_ENGINES.V,
]);

/**
 * @param {string|undefined|null} value
 * @returns {'avatar_iv'|'avatar_v'}
 */
function normalizeHeygenAvatarEngine(value) {
  if (value == null || String(value).trim() === '') {
    return DEFAULT_HEYGEN_AVATAR_ENGINE;
  }
  const normalized = String(value).trim().toLowerCase();
  if (normalized === HEYGEN_AVATAR_ENGINES.IV || normalized === 'iv') {
    return HEYGEN_AVATAR_ENGINES.IV;
  }
  if (normalized === HEYGEN_AVATAR_ENGINES.V || normalized === 'v') {
    return HEYGEN_AVATAR_ENGINES.V;
  }
  return normalized;
}

function isExpressivePublicLookId(avatarId) {
  if (avatarId == null || String(avatarId).trim() === '') return false;
  return /_expressive\d*_public$/i.test(String(avatarId).trim());
}

/**
 * HeyGen public "expressive" studio looks use the legacy v2 video API on HeyGen's
 * side (same as the web app). POST /v3/videos rejects them for avatar_iv and avatar_v.
 */
function usesHeygenLegacyV2VideoApi(avatarId) {
  return isExpressivePublicLookId(avatarId);
}

/** @deprecated use usesHeygenLegacyV2VideoApi */
const isNonGeneratableExpressiveLookId = usesHeygenLegacyV2VideoApi;

/**
 * @param {unknown} lookBody
 * @returns {string|null}
 */
function extractLookIdFromLookBody(lookBody) {
  if (!lookBody || typeof lookBody !== 'object') return null;
  if (typeof lookBody.id === 'string' && lookBody.id.trim()) return lookBody.id.trim();
  const data = lookBody.data;
  if (data && typeof data === 'object' && typeof data.id === 'string' && data.id.trim()) {
    return data.id.trim();
  }
  return null;
}

/**
 * Looks that must be rendered via HeyGen legacy POST /v2/video/generate.
 * Includes expressive public looks and Avatar III-only studio looks (e.g. Diora_public_3).
 * @param {unknown} lookBody
 * @returns {boolean}
 */
function usesHeygenLegacyV2VideoLook(lookBody) {
  const rawEngines = extractRawSupportedApiEnginesFromLook(lookBody);
  if (Array.isArray(rawEngines) && rawEngines.length === 0) {
    return true;
  }

  const v3Engines = extractSupportedApiEnginesFromLook(lookBody);
  if (Array.isArray(rawEngines) && rawEngines.length > 0 && (!v3Engines || v3Engines.length === 0)) {
    // e.g. supported_api_engines: ['avatar_iii'] — no IV/V → must use v2.
    return true;
  }

  const lookId = extractLookIdFromLookBody(lookBody);
  if (!usesHeygenLegacyV2VideoApi(lookId)) return false;
  return v3Engines == null || v3Engines.length === 0;
}

/** @deprecated use usesHeygenLegacyV2VideoLook */
const isNonGeneratableLook = usesHeygenLegacyV2VideoLook;

/**
 * @param {'avatar_iv'|'avatar_v'} avatarEngine
 * @returns {{ type: 'avatar_iv'|'avatar_v' }}
 */
function buildHeygenVideoEnginePayload(avatarEngine) {
  const type = normalizeHeygenAvatarEngine(avatarEngine);
  return { type };
}

/** HeyGen v3 rejects Avatar IV for studio / digital-twin video avatars. */
function isStudioOrDigitalTwinAvatarType(avatarType) {
  const type = avatarType != null ? String(avatarType).trim() : '';
  return type === 'studio_avatar' || type === 'digital_twin';
}

/**
 * Map Avatar IV → V for studio/video avatars (HeyGen v3 rejects IV for those types).
 * @param {'avatar_iv'|'avatar_v'} engine
 * @param {string|undefined|null} avatarType
 * @returns {'avatar_iv'|'avatar_v'}
 */
function coerceEngineForAvatarType(engine, avatarType) {
  if (!isStudioOrDigitalTwinAvatarType(avatarType)) return engine;
  if (engine === HEYGEN_AVATAR_ENGINES.IV) return HEYGEN_AVATAR_ENGINES.V;
  return engine;
}

/**
 * Raw engine strings from look metadata (avatar_iii, avatar_iv, avatar_v, …).
 * @param {unknown} lookBody
 * @returns {string[]|null} null if field missing; [] if explicitly empty
 */
function extractRawSupportedApiEnginesFromLook(lookBody) {
  const MAX_DEPTH = 8;
  const MAX_NODES = 2000;
  const visited = new Set();
  const found = [];
  const seen = new Set();
  let nodesVisited = 0;
  let sawExplicitEmpty = false;
  let sawArray = false;

  function scan(node, depth) {
    if (nodesVisited++ > MAX_NODES || depth > MAX_DEPTH) return;
    if (!node || typeof node !== 'object') return;

    if (!Array.isArray(node)) {
      if (visited.has(node)) return;
      visited.add(node);
    }

    if (Array.isArray(node)) {
      for (const item of node) scan(item, depth + 1);
      return;
    }

    const direct = node.supported_api_engines ?? node.supportedApiEngines;
    if (Array.isArray(direct)) {
      sawArray = true;
      if (direct.length === 0) sawExplicitEmpty = true;
      for (const e of direct) {
        if (e == null) continue;
        const value = String(e).trim().toLowerCase();
        if (!value || seen.has(value)) continue;
        seen.add(value);
        found.push(value);
      }
    }

    for (const v of Object.values(node)) {
      scan(v, depth + 1);
    }
  }

  scan(lookBody, 0);
  if (!sawArray) return null;
  if (found.length === 0) return sawExplicitEmpty ? [] : null;
  return found;
}

/**
 * @param {unknown} lookBody HeyGen GET look response
 * @returns {string[]|null}
 */
function extractSupportedApiEnginesFromLook(lookBody) {
  /**
   * HeyGen look responses are inconsistently wrapped:
   * - `{ data: ... }` / `{ data: { data: ... } }`
   * - `supported_api_engines` may be nested under `avatar_item`, `look`, or deeper.
   *
   * Returns only v3 engines: `['avatar_iv', 'avatar_v']` (subset), or `null` if none.
   * Explicit empty `[]` is returned as `[]`. Avatar III-only looks return `[]`-equivalent
   * via usesHeygenLegacyV2VideoLook (raw engines without IV/V).
   */
  const raw = extractRawSupportedApiEnginesFromLook(lookBody);
  if (raw == null) return null;
  if (raw.length === 0) return [];

  const found = new Set();
  for (const e of raw) {
    const normalized = normalizeHeygenAvatarEngine(e);
    if (normalized === HEYGEN_AVATAR_ENGINES.IV || normalized === HEYGEN_AVATAR_ENGINES.V) {
      found.add(normalized);
    }
  }
  return [...found];
}

/**
 * Engines to use for filtering / UI buckets when HeyGen omits or returns [].
 * Matches video create default (`avatar_iv`) and service retry to `avatar_v`.
 *
 * @param {unknown} lookBody
 * @returns {string[]}
 */
function getEffectiveSupportedApiEnginesFromLook(lookBody) {
  if (usesHeygenLegacyV2VideoLook(lookBody)) {
    return ['legacy_v2'];
  }

  const supported = extractSupportedApiEnginesFromLook(lookBody);
  if (supported && supported.length > 0) {
    return supported;
  }
  return [DEFAULT_HEYGEN_AVATAR_ENGINE];
}

function getLookSupportedVideoEngines(lookBody) {
  const plan = resolveVideoPlanForLook(lookBody, null);
  return plan.supportedApiEngines;
}

/**
 * Single source of truth for how to render a look.
 * @returns {{
 *   videoApi: 'v2'|'v3',
 *   engine: 'avatar_iv'|'avatar_v'|null,
 *   supportedApiEngines: string[],
 *   defaultAvatarEngine: string,
 *   engineCoerced: boolean,
 * }}
 */
function resolveVideoPlanForLook(lookBody, requestedEngine, avatarType = null) {
  if (usesHeygenLegacyV2VideoLook(lookBody)) {
    return {
      videoApi: 'v2',
      engine: null,
      supportedApiEngines: ['legacy_v2'],
      defaultAvatarEngine: 'legacy_v2',
      engineCoerced: false,
    };
  }

  const raw = extractSupportedApiEnginesFromLook(lookBody);
  const v3Engines = (raw && raw.length > 0 ? raw : [DEFAULT_HEYGEN_AVATAR_ENGINE]).filter(
    (engine) => engine === HEYGEN_AVATAR_ENGINES.IV || engine === HEYGEN_AVATAR_ENGINES.V
  );

  const requested = normalizeHeygenAvatarEngine(requestedEngine);
  let engine = requested;
  let engineCoerced = false;

  if (!v3Engines.includes(requested)) {
    if (v3Engines.includes(HEYGEN_AVATAR_ENGINES.IV)) {
      engine = HEYGEN_AVATAR_ENGINES.IV;
      engineCoerced = true;
    } else if (v3Engines.includes(HEYGEN_AVATAR_ENGINES.V)) {
      engine = HEYGEN_AVATAR_ENGINES.V;
      engineCoerced = true;
    } else {
      return {
        videoApi: 'v3',
        engine: null,
        supportedApiEngines: v3Engines,
        defaultAvatarEngine: DEFAULT_HEYGEN_AVATAR_ENGINE,
        engineCoerced: false,
      };
    }
  }

  const coercedEngine = coerceEngineForAvatarType(engine, avatarType);
  const typeCoerced = coercedEngine !== engine;

  const defaultAvatarEngine = isStudioOrDigitalTwinAvatarType(avatarType)
    ? HEYGEN_AVATAR_ENGINES.V
    : v3Engines.includes(HEYGEN_AVATAR_ENGINES.IV)
      ? HEYGEN_AVATAR_ENGINES.IV
      : v3Engines[0] || DEFAULT_HEYGEN_AVATAR_ENGINE;

  return {
    videoApi: 'v3',
    engine: coercedEngine,
    supportedApiEngines: v3Engines,
    defaultAvatarEngine,
    engineCoerced: engineCoerced || typeCoerced,
  };
}

/**
 * Choose a HeyGen video engine compatible with the look.
 * @deprecated prefer resolveVideoPlanForLook
 */
function resolveAvatarEngineForLook(lookBody, requestedEngine) {
  const plan = resolveVideoPlanForLook(lookBody, requestedEngine);
  if (plan.videoApi === 'v2') {
    return { useLegacyV2: true, engine: DEFAULT_HEYGEN_AVATAR_ENGINE };
  }
  if (plan.engine == null) {
    return { useLegacyV2: false, engine: null, supported: plan.supportedApiEngines };
  }
  return {
    useLegacyV2: false,
    engine: plan.engine,
    ...(plan.engineCoerced ? { engineCoerced: true } : {}),
  };
}

function enrichLookWithEngineHints(look) {
  if (!look || typeof look !== 'object' || Array.isArray(look)) return look;
  const avatarType = look.avatar_type ?? look.avatarType ?? null;
  const plan = resolveVideoPlanForLook(look, null, avatarType);
  return {
    ...look,
    supportedApiEngines: plan.supportedApiEngines,
    defaultAvatarEngine: plan.defaultAvatarEngine,
    videoApi: plan.videoApi,
    usesLegacyV2Video: plan.videoApi === 'v2',
  };
}

module.exports = {
  HEYGEN_AVATAR_ENGINES,
  DEFAULT_HEYGEN_AVATAR_ENGINE,
  HEYGEN_AVATAR_ENGINE_VALUES,
  normalizeHeygenAvatarEngine,
  usesHeygenLegacyV2VideoApi,
  usesHeygenLegacyV2VideoLook,
  isNonGeneratableExpressiveLookId,
  isNonGeneratableLook,
  extractLookIdFromLookBody,
  buildHeygenVideoEnginePayload,
  isStudioOrDigitalTwinAvatarType,
  coerceEngineForAvatarType,
  extractRawSupportedApiEnginesFromLook,
  extractSupportedApiEnginesFromLook,
  getEffectiveSupportedApiEnginesFromLook,
  getLookSupportedVideoEngines,
  resolveVideoPlanForLook,
  resolveAvatarEngineForLook,
  enrichLookWithEngineHints,
};
