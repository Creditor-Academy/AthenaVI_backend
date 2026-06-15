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
 * @param {unknown} lookBody
 * @returns {boolean}
 */
function usesHeygenLegacyV2VideoLook(lookBody) {
  const lookId = extractLookIdFromLookBody(lookBody);
  if (!usesHeygenLegacyV2VideoApi(lookId)) return false;
  const supported = extractSupportedApiEnginesFromLook(lookBody);
  return !supported || supported.length === 0;
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
   * This function scans the payload (bounded) and returns a normalized list of:
   * `['avatar_iv', 'avatar_v']` (subset), or `null` if we can't find any.
   */
  const MAX_DEPTH = 8;
  const MAX_NODES = 2000;
  const visited = new Set();
  const found = new Set();
  let nodesVisited = 0;

  function tryCollectEngineValue(v) {
    const normalized = normalizeHeygenAvatarEngine(v);
    if (normalized === HEYGEN_AVATAR_ENGINES.IV || normalized === HEYGEN_AVATAR_ENGINES.V) {
      found.add(normalized);
    }
  }

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
      for (const e of direct) {
        if (e == null) continue;
        tryCollectEngineValue(e);
      }
      if (found.size >= 2) return;
    }

    // Generic scan with depth+node limits to find `supported_api_engines` anywhere.
    for (const v of Object.values(node)) {
      scan(v, depth + 1);
      if (found.size >= 2) return;
    }
  }

  scan(lookBody, 0);
  if (found.size === 0) return null;
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
  extractSupportedApiEnginesFromLook,
  getEffectiveSupportedApiEnginesFromLook,
};
