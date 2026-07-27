const creditLedger = require('../credit/creditLedger.service');
const { SCOPE } = require('../../shared/config/creditPricing');
const {
  PPT_FEATURE,
  estimateOutlineAc,
  reconcileOutlineAc,
  getFlatAc,
} = require('../../shared/config/presentationCreditPricing');
const logger = require('../../shared/utils/logger');

async function assertAfford(workspaceId, userId, estimatedAc) {
  return creditLedger.assertCanAfford({
    scope: SCOPE.WORKSPACE,
    workspaceId,
    userId,
    estimatedAc,
  });
}

async function charge({ workspaceId, userId, amountAc, idempotencyKey, feature, metadata }) {
  return creditLedger.chargeUsage({
    scope: SCOPE.WORKSPACE,
    workspaceId,
    userId,
    amountAc,
    idempotencyKey,
    metadata: {
      feature: feature || null,
      scope: SCOPE.WORKSPACE,
      ...(metadata || {}),
    },
    reference: metadata?.deckId || metadata?.slideId || metadata?.exportId || null,
  });
}

/**
 * Approximate full-deck generate cost: content + Path A image per slide.
 * @param {number} slideCount
 * @returns {{ athenaCredits: number, breakdown: object }}
 */
function estimateGenerateCost(slideCount) {
  const n = Math.max(0, Math.floor(Number(slideCount) || 0));
  const slideContentAc = getFlatAc(PPT_FEATURE.SLIDE_CONTENT);
  const imagePathAAc = getFlatAc(PPT_FEATURE.IMAGE_PATH_A);
  const athenaCredits = n * (slideContentAc + imagePathAAc);

  return {
    athenaCredits,
    breakdown: {
      slideCount: n,
      slideContentAc,
      imagePathAAc,
      perSlideAc: slideContentAc + imagePathAAc,
      features: [PPT_FEATURE.SLIDE_CONTENT, PPT_FEATURE.IMAGE_PATH_A],
      mode: 'estimate',
    },
  };
}

function logOpenAiVsAc({ feature, openaiUsd, athenaCredits, extra }) {
  const payload = {
    feature,
    openaiUsd: Number(openaiUsd) || 0,
    athenaCredits: Math.max(0, Math.floor(Number(athenaCredits) || 0)),
    ...(extra || {}),
  };
  try {
    logger.info('presentation_credit_openai_vs_ac', payload);
  } catch {
    console.log('[presentation_credit] openai vs AC', payload);
  }
}

/**
 * Charge outline after LLM success using reconciled token usage.
 * Prefers reconcile over estimate; still idempotent via key.
 */
async function chargeOutlineReconcile({
  workspaceId,
  userId,
  deckId,
  usage,
  idempotencyKey,
  metadata,
}) {
  const reconciled = reconcileOutlineAc(usage || {});
  const estimated = estimateOutlineAc();

  logOpenAiVsAc({
    feature: PPT_FEATURE.OUTLINE,
    openaiUsd: reconciled.usdCost,
    athenaCredits: reconciled.athenaCredits,
    extra: {
      deckId,
      mode: 'reconcile',
      estimateAc: estimated.athenaCredits,
      inputTokens: reconciled.breakdown.inputTokens,
      outputTokens: reconciled.breakdown.outputTokens,
    },
  });

  const result = await charge({
    workspaceId,
    userId,
    amountAc: reconciled.athenaCredits,
    idempotencyKey,
    feature: PPT_FEATURE.OUTLINE,
    metadata: {
      deckId,
      openaiUsd: reconciled.usdCost,
      breakdown: reconciled.breakdown,
      ...(metadata || {}),
    },
  });

  return { ...result, pricing: reconciled };
}

/**
 * Flat AC charge for slide content / image / export features.
 */
async function chargeFlat({
  workspaceId,
  userId,
  feature,
  idempotencyKey,
  metadata,
  amountAc,
}) {
  const ac =
    amountAc != null ? Math.max(0, Math.floor(Number(amountAc) || 0)) : getFlatAc(feature);

  logOpenAiVsAc({
    feature,
    openaiUsd: metadata?.openaiUsd || 0,
    athenaCredits: ac,
    extra: {
      deckId: metadata?.deckId,
      slideId: metadata?.slideId,
      mode: 'flat',
    },
  });

  const result = await charge({
    workspaceId,
    userId,
    amountAc: ac,
    idempotencyKey,
    feature,
    metadata: {
      ...(metadata || {}),
    },
  });

  return { ...result, pricing: { athenaCredits: ac, feature } };
}

module.exports = {
  PPT_FEATURE,
  assertAfford,
  charge,
  estimateGenerateCost,
  estimateOutlineAc,
  reconcileOutlineAc,
  getFlatAc,
  chargeOutlineReconcile,
  chargeFlat,
  logOpenAiVsAc,
};
