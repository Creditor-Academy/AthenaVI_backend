/**
 * Presentation (AI PPT) credit pricing — isolated from HeyGen/Remotion rates.
 * Uses shared ATHENA_MARGIN_PERCENT / ATHENA_AC_PER_USD with optional PPT_* overrides.
 */

const PPT_FEATURE = Object.freeze({
  OUTLINE: 'ppt_outline',
  SLIDE_CONTENT: 'ppt_slide_content',
  IMAGE_PATH_A: 'ppt_image_path_a',
  IMAGE_PATH_B: 'ppt_image_path_b',
  EXPORT: 'ppt_export',
  IMAGE_CACHE_HIT: 'ppt_image_cache_hit',
});

const DEFAULT_OUTLINE = Object.freeze({
  inputTokenRateUsd: 0.000003,
  outputTokenRateUsd: 0.000015,
  estimateInputTokens: 800,
  estimateOutputTokens: 1200,
});

const FLAT_AC = Object.freeze({
  [PPT_FEATURE.SLIDE_CONTENT]: 2,
  [PPT_FEATURE.IMAGE_PATH_A]: 4,
  [PPT_FEATURE.IMAGE_PATH_B]: 9,
  [PPT_FEATURE.EXPORT]: 3,
  [PPT_FEATURE.IMAGE_CACHE_HIT]: 0,
});

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function getMarginMultiplier() {
  const pct = envNumber('PPT_MARGIN_PERCENT', envNumber('ATHENA_MARGIN_PERCENT', 40));
  return 1 + Math.max(0, pct) / 100;
}

function getAcPerUsd() {
  return Math.max(1, Math.floor(envNumber('PPT_AC_PER_USD', envNumber('ATHENA_AC_PER_USD', 10000))));
}

/**
 * Convert USD cost to Athena Credits (ceil after margin).
 * @param {number} usd
 * @returns {number}
 */
function toAcCost(usd) {
  const cost = Number(usd) || 0;
  if (cost <= 0) return 0;
  return Math.ceil(cost * getMarginMultiplier() * getAcPerUsd());
}

function getOutlineRates() {
  return {
    inputTokenRateUsd: Math.max(
      0,
      envNumber('PPT_OUTLINE_INPUT_TOKEN_RATE_USD', DEFAULT_OUTLINE.inputTokenRateUsd)
    ),
    outputTokenRateUsd: Math.max(
      0,
      envNumber('PPT_OUTLINE_OUTPUT_TOKEN_RATE_USD', DEFAULT_OUTLINE.outputTokenRateUsd)
    ),
    estimateInputTokens: Math.max(
      1,
      Math.floor(envNumber('PPT_OUTLINE_ESTIMATE_INPUT_TOKENS', DEFAULT_OUTLINE.estimateInputTokens))
    ),
    estimateOutputTokens: Math.max(
      1,
      Math.floor(envNumber('PPT_OUTLINE_ESTIMATE_OUTPUT_TOKENS', DEFAULT_OUTLINE.estimateOutputTokens))
    ),
  };
}

function outlineUsdFromTokens(inputTokens, outputTokens) {
  const rates = getOutlineRates();
  const input = Math.max(0, Number(inputTokens) || 0);
  const output = Math.max(0, Number(outputTokens) || 0);
  return input * rates.inputTokenRateUsd + output * rates.outputTokenRateUsd;
}

/**
 * Pre-charge estimate for outline generation (fixed token assumptions).
 * @returns {{ athenaCredits: number, usdCost: number, breakdown: object }}
 */
function estimateOutlineAc() {
  const rates = getOutlineRates();
  const usdCost = outlineUsdFromTokens(rates.estimateInputTokens, rates.estimateOutputTokens);
  return {
    athenaCredits: toAcCost(usdCost),
    usdCost,
    breakdown: {
      feature: PPT_FEATURE.OUTLINE,
      inputTokens: rates.estimateInputTokens,
      outputTokens: rates.estimateOutputTokens,
      inputTokenRateUsd: rates.inputTokenRateUsd,
      outputTokenRateUsd: rates.outputTokenRateUsd,
      marginMultiplier: getMarginMultiplier(),
      acPerUsd: getAcPerUsd(),
      mode: 'estimate',
    },
  };
}

/**
 * Reconcile outline AC from actual LLM usage.
 * @param {{ prompt_tokens?: number, completion_tokens?: number, input_tokens?: number, output_tokens?: number }} usage
 * @returns {{ athenaCredits: number, usdCost: number, breakdown: object }}
 */
function reconcileOutlineAc(usage) {
  const inputTokens =
    Number(usage?.prompt_tokens ?? usage?.input_tokens) || 0;
  const outputTokens =
    Number(usage?.completion_tokens ?? usage?.output_tokens) || 0;
  const rates = getOutlineRates();
  const usdCost = outlineUsdFromTokens(inputTokens, outputTokens);
  return {
    athenaCredits: toAcCost(usdCost),
    usdCost,
    breakdown: {
      feature: PPT_FEATURE.OUTLINE,
      inputTokens,
      outputTokens,
      inputTokenRateUsd: rates.inputTokenRateUsd,
      outputTokenRateUsd: rates.outputTokenRateUsd,
      marginMultiplier: getMarginMultiplier(),
      acPerUsd: getAcPerUsd(),
      mode: 'reconcile',
    },
  };
}

const FLAT_ENV_KEYS = Object.freeze({
  [PPT_FEATURE.SLIDE_CONTENT]: 'PPT_SLIDE_CONTENT_AC',
  [PPT_FEATURE.IMAGE_PATH_A]: 'PPT_IMAGE_PATH_A_AC',
  [PPT_FEATURE.IMAGE_PATH_B]: 'PPT_IMAGE_PATH_B_AC',
  [PPT_FEATURE.EXPORT]: 'PPT_EXPORT_AC',
  [PPT_FEATURE.IMAGE_CACHE_HIT]: 'PPT_IMAGE_CACHE_HIT_AC',
});

/**
 * Flat Athena Credit cost for non-outline presentation features.
 * @param {string} feature
 * @returns {number}
 */
function getFlatAc(feature) {
  if (feature === PPT_FEATURE.OUTLINE) {
    return estimateOutlineAc().athenaCredits;
  }
  if (!(feature in FLAT_AC)) {
    return 0;
  }
  const envKey = FLAT_ENV_KEYS[feature];
  return Math.max(0, Math.floor(envNumber(envKey, FLAT_AC[feature])));
}

module.exports = {
  PPT_FEATURE,
  estimateOutlineAc,
  reconcileOutlineAc,
  getFlatAc,
  toAcCost,
};
