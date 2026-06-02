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
  if (!lookBody || typeof lookBody !== 'object') return null;
  const data = 'data' in lookBody && lookBody.data != null ? lookBody.data : lookBody;
  if (!data || typeof data !== 'object') return null;
  const item =
    data.avatar_item ??
    data.look ??
    (data.id || data.avatar_id ? data : null);
  const engines =
    (item && item.supported_api_engines) ??
    data.supported_api_engines ??
    null;
  if (!Array.isArray(engines)) return null;
  return engines.map((e) => String(e).trim()).filter(Boolean);
}

module.exports = {
  HEYGEN_AVATAR_ENGINES,
  DEFAULT_HEYGEN_AVATAR_ENGINE,
  HEYGEN_AVATAR_ENGINE_VALUES,
  normalizeHeygenAvatarEngine,
  buildHeygenVideoEnginePayload,
  extractSupportedApiEnginesFromLook,
};
