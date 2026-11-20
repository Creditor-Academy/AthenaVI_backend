'use strict';

function envFlagTrue(name) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return false;
  return String(raw).trim().toLowerCase() === 'true';
}

/** When true, III-only looks use POST /v3/videos with engine avatar_iii instead of v2. */
function isHeygenPreferV3VideoEnabled() {
  return envFlagTrue('HEYGEN_PREFER_V3_VIDEO');
}

/** When true, failed v3 create may still retry POST /v2/video/generate (until commit 4). */
function isHeygenAllowV2VideoFallbackEnabled() {
  const raw = process.env.HEYGEN_ALLOW_V2_VIDEO_FALLBACK;
  if (raw == null || String(raw).trim() === '') return true;
  return String(raw).trim().toLowerCase() === 'true';
}

module.exports = {
  isHeygenPreferV3VideoEnabled,
  isHeygenAllowV2VideoFallbackEnabled,
};