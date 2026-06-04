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

/** PAYG USD per second of output (avatar video) */
function paygAvatarUsdPerSec(engine) {
  if (engine === HEYGEN_AVATAR_ENGINES.V) return 1 / 60;
  return 4 / 60;
}

/** Enterprise: HeyGen credits per sec → USD via contract rate */
function enterpriseVideoUsdPerSec(engine) {
  const heygenCreditsPerSec =
    engine === HEYGEN_AVATAR_ENGINES.V ? 0.0033 : 0.1;
  return heygenCreditsPerSec * getEnterpriseUsdPerCredit();
}

function heygenVideoUsdPerSec(engine) {
  const normalized =
    engine === HEYGEN_AVATAR_ENGINES.V
      ? HEYGEN_AVATAR_ENGINES.V
      : HEYGEN_AVATAR_ENGINES.IV;
  if (getBillingMode() === 'enterprise') {
    return enterpriseVideoUsdPerSec(normalized);
  }
  return paygAvatarUsdPerSec(normalized);
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

function voicePreviewUsdPerSec() {
  return 0.000333 * getEnterpriseUsdPerCredit();
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
 */
function calculateUsageCredits(input) {
  const feature = input?.feature;
  const durationSeconds = Math.max(0, Number(input?.durationSeconds) || 0);
  const engine = input?.avatarEngine || HEYGEN_AVATAR_ENGINES.IV;

  let heygenUsdCost = 0;

  switch (feature) {
    case FEATURE.HEYGEN_VIDEO:
      heygenUsdCost = durationSeconds * heygenVideoUsdPerSec(engine);
      break;
    case FEATURE.VOICE_PREVIEW:
      heygenUsdCost = durationSeconds * voicePreviewUsdPerSec();
      break;
    case FEATURE.REMOTION_EXPORT:
      heygenUsdCost = durationSeconds * getRemotionUsdPerSec();
      break;
    case FEATURE.VOICE_CLONE:
    case FEATURE.VOICE_DESIGN:
    case FEATURE.AVATAR_CREATE:
      heygenUsdCost = flatUsdForFeature(feature);
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
  getBillingMode,
  getMarginMultiplier,
  getAcPerUsd,
  calculateUsageCredits,
  estimateDurationFromScript,
  estimateDurationFromText,
  estimateDurationFromFrames,
  usdCostToAthenaCredits,
};
