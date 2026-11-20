'use strict';

function envFlagFalse(name) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return false;
  return String(raw).trim().toLowerCase() === 'false';
}

/**
 * When true (default), III-only and other legacy-metadata looks use POST /v3/videos
 * (e.g. engine.type avatar_iii). Set HEYGEN_PREFER_V3_VIDEO=false only for emergency rollback
 * of III routing (v2 video API removed — all creates use v3).
 */
function isHeygenPreferV3VideoEnabled() {
  return !envFlagFalse('HEYGEN_PREFER_V3_VIDEO');
}

module.exports = {
  isHeygenPreferV3VideoEnabled,
};