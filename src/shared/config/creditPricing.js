const {
  HEYGEN_AVATAR_ENGINES,
  isAvatar6Engine,
  normalizeHeygenAvatarEngine,
} = require('../constants/heygen');

const FEATURE = Object.freeze({
  HEYGEN_VIDEO: 'heygen_video',
  SPEECH_GENERATION: 'speech_generation',
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
 * PAYG USD/sec per engine and avatar type, from the HeyGen API pricing page
 * (pay-as-you-go, USD). Avatar III / IV / V rates apply to 720p and 1080p.
 * The page lists no separate Avatar 5 rate for photo/studio, so the Custom
 * Video Avatar rate is applied to all Avatar 5 types. Unknown avatar type
 * falls back to the `default` key (the Studio/Custom rate, the higher one).
 */
const PAYG_AVATAR_USD_PER_SEC = Object.freeze({
  [HEYGEN_AVATAR_ENGINES.III]: Object.freeze({
    photo_avatar: 0.0165,
    studio_avatar: 0.0165,
    digital_twin: 0.01,
    default: 0.0165,
  }),
  [HEYGEN_AVATAR_ENGINES.IV]: Object.freeze({
    photo_avatar: 0.0385,
    studio_avatar: 0.0805,
    digital_twin: 0.0805,
    default: 0.0805,
  }),
  [HEYGEN_AVATAR_ENGINES.V]: Object.freeze({
    photo_avatar: 0.12,
    studio_avatar: 0.12,
    digital_twin: 0.12,
    default: 0.12,
  }),
});

/**
 * PAYG USD/sec for Avatar III / IV / V. Engine must already be normalized
 * (see normalizeHeygenVideoBillingEngine). 4K is not accepted by our API.
 */
function paygAvatarUsdPerSec(engine, avatarType) {
  const rates = PAYG_AVATAR_USD_PER_SEC[engine] || PAYG_AVATAR_USD_PER_SEC[HEYGEN_AVATAR_ENGINES.IV];
  const type = normalizeAvatarType(avatarType);
  return (type && rates[type]) ?? rates.default;
}

/**
 * PAYG USD/sec for Avatar 6 (Pro / Turbo), same for every avatar type.
 * Published rates: 1080p and 2K. We send 1080p unless resolution is "2k".
 * 720p is mapped to 1080p by the service layer, so it bills at 1080p.
 */
function paygAvatar6UsdPerSec(engine, resolution) {
  const is2k = String(resolution || '').trim().toLowerCase() === '2k';
  if (engine === HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO) {
    return is2k
      ? envNumber('HEYGEN_AVATAR_6_TURBO_2K_USD_PER_SEC', 0.0875)
      : envNumber('HEYGEN_AVATAR_6_TURBO_USD_PER_SEC', 0.05);
  }
  return is2k
    ? envNumber('HEYGEN_AVATAR_6_2K_USD_PER_SEC', 0.145)
    : envNumber('HEYGEN_AVATAR_6_USD_PER_SEC', 0.1);
}

/**
 * Enterprise HeyGen credits/sec for Avatar IV & V (all avatar types same rate).
 * Avatar III legacy: 0.0033 credits/sec.
 */
/** Map billing labels (legacy_v2, aliases) to a rate key for HeyGen video. */
function normalizeHeygenVideoBillingEngine(engine) {
  const normalized = String(engine || HEYGEN_AVATAR_ENGINES.IV).trim().toLowerCase();
  if (normalized === 'legacy_v2' || normalized === 'legacy-v2') {
    return HEYGEN_AVATAR_ENGINE_III;
  }
  if (normalized === HEYGEN_AVATAR_ENGINE_III || normalized === 'avatar_3' || normalized === 'iii') {
    return HEYGEN_AVATAR_ENGINE_III;
  }
  return normalizeHeygenAvatarEngine(normalized);
}

/** Avatar 6 enterprise rates are not published per engine; override via env once contracted. */
function enterpriseHeygenCreditsPerSec(engine) {
  const normalized = normalizeHeygenVideoBillingEngine(engine);
  if (normalized === HEYGEN_AVATAR_ENGINE_III) {
    return 0.0033;
  }
  if (normalized === HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO) {
    return envNumber('HEYGEN_ENTERPRISE_AVATAR_6_TURBO_CREDITS_PER_SEC', 0.1);
  }
  if (normalized === HEYGEN_AVATAR_ENGINES.AVATAR_6) {
    return envNumber('HEYGEN_ENTERPRISE_AVATAR_6_CREDITS_PER_SEC', 0.2);
  }
  return 0.1;
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

  const billingEngine = normalizeHeygenVideoBillingEngine(engine);
  if (isAvatar6Engine(billingEngine)) {
    return {
      usdPerSec: paygAvatar6UsdPerSec(billingEngine, res),
      heygenCreditsPerSec: null,
      rateSource: 'payg_usd',
    };
  }
  return {
    usdPerSec: paygAvatarUsdPerSec(billingEngine, type),
    heygenCreditsPerSec: null,
    rateSource: 'payg_usd',
  };
}

/**
 * PAYG per-call USD for avatar creation (HeyGen API pricing page).
 * Photo avatar $1.32; Custom (digital twin) $2.13. `prompt` has no published
 * price, so it uses the higher Custom rate.
 */
function avatarCreateUsdPerCall(createType) {
  const normalized = String(createType || '').trim().toLowerCase();
  return normalized === 'photo' || normalized === 'photo_avatar' ? 1.32 : 2.13;
}

function flatUsdForFeature(feature, { avatarType } = {}) {
  if (getBillingMode() === 'enterprise') {
    if (feature === FEATURE.AVATAR_CREATE || feature === FEATURE.VOICE_CLONE) {
      return 1 * getEnterpriseUsdPerCredit();
    }
    if (feature === FEATURE.VOICE_DESIGN) {
      return 0.5 * getEnterpriseUsdPerCredit();
    }
    return 0;
  }
  if (feature === FEATURE.AVATAR_CREATE) return avatarCreateUsdPerCall(avatarType);
  if (feature === FEATURE.VOICE_CLONE) return 2;
  if (feature === FEATURE.VOICE_DESIGN) return 1;
  return 0;
}

/**
 * HeyGen catalog speech (POST /v3/voices/speech) is billed per second of audio on PAYG.
 * Measured on the dev workspace (wallet deltas, cent-rounded): 43.4s -> $0.10, 25.8s -> $0.07,
 * i.e. about $0.0024/s, plus a ~$0.01 minimum per call (sub-second calls still cost $0.01-0.02).
 * A per-character estimate ($15 / 1M chars) under-billed narration by roughly 10x.
 * Override with HEYGEN_SPEECH_USD_PER_SEC / HEYGEN_SPEECH_USD_PER_CALL_MIN once confirmed.
 */
const DEFAULT_PAYG_SPEECH_USD_PER_SEC = 0.0024;
const DEFAULT_PAYG_SPEECH_USD_MIN_PER_CALL = 0.01;
function paygSpeechUsdPerSec() {
  return envNumber('HEYGEN_SPEECH_USD_PER_SEC', DEFAULT_PAYG_SPEECH_USD_PER_SEC);
}
function paygSpeechUsdMinPerCall() {
  return envNumber('HEYGEN_SPEECH_USD_PER_CALL_MIN', DEFAULT_PAYG_SPEECH_USD_MIN_PER_CALL);
}

/** Enterprise speech per second (contract pricing is not published). */
function enterpriseSpeechUsdPerSec() {
  return 0.000333 * getEnterpriseUsdPerCredit();
}

/**
 * Speech USD cost. PAYG and Enterprise are both priced per second of generated audio.
 * `characters` is accepted for callers but no longer changes the PAYG price.
 */
function speechUsdCost({ durationSeconds }) {
  const seconds = Math.max(0, Number(durationSeconds) || 0);
  if (getBillingMode() === 'enterprise') {
    return seconds * enterpriseSpeechUsdPerSec();
  }
  if (seconds <= 0) return 0;
  return Math.max(paygSpeechUsdMinPerCall(), seconds * paygSpeechUsdPerSec());
}

/**
 * HeyGen video length that is billed. On PAYG, HeyGen's wallet moves in whole seconds rounded down
 * with a 1 second minimum (measured on Avatar 6 Turbo), so the ledger mirrors that to stay reconciled
 * with the wallet. Enterprise contract billing is unverified and keeps exact seconds.
 */
function heygenVideoBilledSeconds(durationSeconds) {
  const seconds = Math.max(0, Number(durationSeconds) || 0);
  if (getBillingMode() === 'enterprise') return seconds;
  if (seconds <= 0) return 0;
  return Math.max(1, Math.floor(seconds));
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
 * @param {number} [input.characters] speech input length (informational; PAYG speech is per second)
 */
function calculateUsageCredits(input) {
  const feature = input?.feature;
  const durationSeconds = Math.max(0, Number(input?.durationSeconds) || 0);
  const avatarEngine = input?.avatarEngine || HEYGEN_AVATAR_ENGINES.IV;
  const avatarType = normalizeAvatarType(input?.avatarType);
  const resolution = input?.resolution ? String(input.resolution).trim() : null;
  const characters = input?.characters ?? null;

  let heygenUsdCost = 0;
  let heygenRatePerSec = null;
  let heygenCreditsPerSec = null;
  let rateSource = null;
  let billedSeconds = null;

  switch (feature) {
    case FEATURE.HEYGEN_VIDEO: {
      const rate = heygenVideoRate({ avatarEngine, avatarType, resolution });
      heygenRatePerSec = rate.usdPerSec;
      heygenCreditsPerSec = rate.heygenCreditsPerSec;
      rateSource = rate.rateSource;
      billedSeconds = heygenVideoBilledSeconds(durationSeconds);
      heygenUsdCost = billedSeconds * rate.usdPerSec;
      break;
    }
    case FEATURE.VOICE_PREVIEW:
    case FEATURE.SPEECH_GENERATION:
      heygenUsdCost = speechUsdCost({ durationSeconds, characters });
      if (getBillingMode() === 'enterprise') {
        heygenRatePerSec = enterpriseSpeechUsdPerSec();
        rateSource = 'enterprise_credits';
      } else {
        heygenRatePerSec = paygSpeechUsdPerSec();
        rateSource = 'payg_usd_per_sec';
      }
      break;
    case FEATURE.REMOTION_EXPORT:
      heygenRatePerSec = getRemotionUsdPerSec();
      rateSource = 'platform';
      heygenUsdCost = durationSeconds * heygenRatePerSec;
      break;
    case FEATURE.VOICE_CLONE:
    case FEATURE.VOICE_DESIGN:
    case FEATURE.AVATAR_CREATE:
      heygenUsdCost = flatUsdForFeature(feature, { avatarType: input?.avatarType });
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
      ...(billedSeconds !== null ? { billedSeconds } : {}),
      avatarEngine,
      avatarType,
      resolution,
      characters,
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
  normalizeHeygenVideoBillingEngine,
};
