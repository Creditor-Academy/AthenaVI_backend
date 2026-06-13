const { HEYGEN_AVATAR_ENGINES } = require('../constants/heygen');

const FEATURE = Object.freeze({
  HEYGEN_VIDEO: 'heygen_video',
  VOICE_CLONE: 'voice_clone',
  VOICE_DESIGN: 'voice_design',
  VOICE_PREVIEW: 'voice_preview',
  AVATAR_CREATE: 'avatar_create',
  REMOTION_EXPORT: 'remotion_export',
});

const SCOPE = Object.freeze({
  USER: 'user',
  WORKSPACE: 'workspace',
});

/** HeyGen avatar look types (POST /v3/videos). */
const HEYGEN_AVATAR_TYPES = Object.freeze({
  PHOTO: 'photo_avatar',
  STUDIO: 'studio_avatar',
  DIGITAL_TWIN: 'digital_twin',
});

/** Legacy Avatar III engine — existing customers only. */
const HEYGEN_AVATAR_ENGINE_III = 'avatar_iii';

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function getBillingMode() {
  const mode = String(process.env.HEYGEN_BILLING_MODE || 'payg').trim().toLowerCase();
  return mode === 'enterprise' ? 'enterprise' : 'payg';
}

function getMarginMultiplier() {
  const pct = envNumber('ATHENA_MARGIN_PERCENT', 40);
  return 1 + Math.max(0, pct) / 100;
}

function getAcPerUsd() {
  return Math.max(1, Math.floor(envNumber('ATHENA_AC_PER_USD', 10000)));
}

function getEnterpriseUsdPerCredit() {
  return Math.max(0.000001, envNumber('HEYGEN_ENTERPRISE_USD_PER_CREDIT', 0.5));
}

function getRemotionUsdPerSec() {
  return Math.max(0, envNumber('REMOTION_USD_PER_OUTPUT_SEC', 0.01));
}

function getWordsPerMinute() {
  return Math.max(1, envNumber('CREDIT_ESTIMATE_WORDS_PER_MINUTE', 150));
}

/**
 * @param {string|undefined|null} avatarType
 * @returns {'photo_avatar'|'studio_avatar'|'digital_twin'|null}
 */
function normalizeAvatarType(avatarType) {
  if (avatarType == null || String(avatarType).trim() === '') return null;
  const normalized = String(avatarType).trim().toLowerCase();
  if (
    normalized === HEYGEN_AVATAR_TYPES.PHOTO ||
    normalized === HEYGEN_AVATAR_TYPES.STUDIO ||
    normalized === HEYGEN_AVATAR_TYPES.DIGITAL_TWIN
  ) {
    return normalized;
  }
  return null;
}

/**
 * PAYG USD/sec for Avatar IV & V at 720p/1080p (HeyGen self-serve pricing).
 * 4K rates exist in HeyGen docs but are not accepted by our API yet.
 */
function paygAvatarUsdPerSec(avatarType) {
  const type = normalizeAvatarType(avatarType);
  if (type === HEYGEN_AVATAR_TYPES.PHOTO) return 0.05;
  return 0.0667;
}

/**
 * Enterprise HeyGen credits/sec for Avatar IV & V (all avatar types same rate).
 * Avatar III legacy: 0.0033 credits/sec.
 */
function enterpriseHeygenCreditsPerSec(engine) {
  const normalized = String(engine || HEYGEN_AVATAR_ENGINES.IV).trim().toLowerCase();
  if (normalized === HEYGEN_AVATAR_ENGINE_III || normalized === 'avatar_3' || normalized === 'iii') {
    return 0.0033;
  }
  return 0.1;
}

function enterpriseVideoUsdPerSec(engine) {
  return enterpriseHeygenCreditsPerSec(engine) * getEnterpriseUsdPerCredit();
}

/**
 * @param {object} opts
 * @param {string} [opts.avatarEngine]
 * @param {string} [opts.avatarType]
 * @param {string} [opts.resolution]
 * @returns {{ usdPerSec: number, heygenCreditsPerSec: number|null, rateSource: string }}
 */
function heygenVideoRate({ avatarEngine, avatarType, resolution }) {
  const engine = avatarEngine || HEYGEN_AVATAR_ENGINES.IV;
  const type = normalizeAvatarType(avatarType);
  const res = resolution ? String(resolution).trim().toLowerCase() : null;

  if (getBillingMode() === 'enterprise') {
    const heygenCreditsPerSec = enterpriseHeygenCreditsPerSec(engine);
    return {
      usdPerSec: heygenCreditsPerSec * getEnterpriseUsdPerCredit(),
      heygenCreditsPerSec,
      rateSource: 'enterprise_credits',
    };
  }

  void res;
  return {
    usdPerSec: paygAvatarUsdPerSec(type),
    heygenCreditsPerSec: null,
    rateSource: 'payg_usd',
  };
}

function flatUsdForFeature(feature) {
  if (getBillingMode() === 'enterprise') {
    if (feature === FEATURE.AVATAR_CREATE || feature === FEATURE.VOICE_CLONE) {
      return 1 * getEnterpriseUsdPerCredit();
    }
    if (feature === FEATURE.VOICE_DESIGN) {
      return 0.5 * getEnterpriseUsdPerCredit();
    }
    return 0;
  }
  if (feature === FEATURE.AVATAR_CREATE) return 1;
  if (feature === FEATURE.VOICE_CLONE) return 2;
  if (feature === FEATURE.VOICE_DESIGN) return 1;
  return 0;
}

/** TTS Starfish — PAYG $0.000667/s; Enterprise 0.000333 credits/s. */
function voicePreviewUsdPerSec() {
  if (getBillingMode() === 'enterprise') {
    return 0.000333 * getEnterpriseUsdPerCredit();
  }
  return 0.000667;
}

function usdCostToAthenaCredits(usdCost) {
  if (usdCost <= 0) return 0;
  return Math.ceil(usdCost * getMarginMultiplier() * getAcPerUsd());
}

/**
 * @param {object} input
 * @param {string} input.feature
 * @param {number} [input.durationSeconds]
 * @param {string} [input.avatarEngine]
 * @param {string} [input.avatarType]
 * @param {string} [input.resolution]
 */
function calculateUsageCredits(input) {
  const feature = input?.feature;
  const durationSeconds = Math.max(0, Number(input?.durationSeconds) || 0);
  const avatarEngine = input?.avatarEngine || HEYGEN_AVATAR_ENGINES.IV;
  const avatarType = normalizeAvatarType(input?.avatarType);
  const resolution = input?.resolution ? String(input.resolution).trim() : null;

  let heygenUsdCost = 0;
  let heygenRatePerSec = null;
  let heygenCreditsPerSec = null;
  let rateSource = null;

  switch (feature) {
    case FEATURE.HEYGEN_VIDEO: {
      const rate = heygenVideoRate({ avatarEngine, avatarType, resolution });
      heygenRatePerSec = rate.usdPerSec;
      heygenCreditsPerSec = rate.heygenCreditsPerSec;
      rateSource = rate.rateSource;
      heygenUsdCost = durationSeconds * rate.usdPerSec;
      break;
    }
    case FEATURE.VOICE_PREVIEW:
      heygenRatePerSec = voicePreviewUsdPerSec();
      rateSource = getBillingMode() === 'enterprise' ? 'enterprise_credits' : 'payg_usd';
      heygenUsdCost = durationSeconds * heygenRatePerSec;
      break;
    case FEATURE.REMOTION_EXPORT:
      heygenRatePerSec = getRemotionUsdPerSec();
      rateSource = 'platform';
      heygenUsdCost = durationSeconds * heygenRatePerSec;
      break;
    case FEATURE.VOICE_CLONE:
    case FEATURE.VOICE_DESIGN:
    case FEATURE.AVATAR_CREATE:
      heygenUsdCost = flatUsdForFeature(feature);
      rateSource = 'flat_fee';
      break;
    default:
      heygenUsdCost = 0;
  }

  const athenaCredits = usdCostToAthenaCredits(heygenUsdCost);

  return {
    athenaCredits,
    heygenUsdCost,
    breakdown: {
      feature,
      durationSeconds,
      avatarEngine,
      avatarType,
      resolution,
      heygenRatePerSec,
      heygenCreditsPerSec,
      rateSource,
      billingMode: getBillingMode(),
      marginPercent: envNumber('ATHENA_MARGIN_PERCENT', 40),
      acPerUsd: getAcPerUsd(),
    },
  };
}

function estimateDurationFromScript(script) {
  const text = String(script || '').trim();
  if (!text) return 5;
  const words = text.split(/\s+/).filter(Boolean).length;
  const minutes = words / getWordsPerMinute();
  return Math.max(5, Math.ceil(minutes * 60));
}

function estimateDurationFromText(text) {
  return estimateDurationFromScript(text);
}

function estimateDurationFromFrames(durationInFrames, fps = 30) {
  const frames = Math.max(1, Number(durationInFrames) || 1);
  const rate = Math.max(1, Number(fps) || 30);
  return Math.max(1, Math.ceil(frames / rate));
}

module.exports = {
  FEATURE,
  SCOPE,
  HEYGEN_AVATAR_TYPES,
  getBillingMode,
  getMarginMultiplier,
  getAcPerUsd,
  normalizeAvatarType,
  heygenVideoRate,
  calculateUsageCredits,
  estimateDurationFromScript,
  estimateDurationFromText,
  estimateDurationFromFrames,
  usdCostToAthenaCredits,
};
