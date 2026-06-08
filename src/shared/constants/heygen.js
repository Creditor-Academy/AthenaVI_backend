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

module.exports = {
  HEYGEN_AVATAR_ENGINES,
  DEFAULT_HEYGEN_AVATAR_ENGINE,
  HEYGEN_AVATAR_ENGINE_VALUES,
  normalizeHeygenAvatarEngine,
  buildHeygenVideoEnginePayload,
  extractSupportedApiEnginesFromLook,
};
