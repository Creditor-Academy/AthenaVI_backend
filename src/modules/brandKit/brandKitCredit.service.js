const creditLedger = require('../credit/creditLedger.service');
const { SCOPE } = require('../../shared/config/creditPricing');
const {
  BRAND_KIT_FEATURE,
  getFlatAc,
} = require('../../shared/config/brandKitCreditPricing');

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
    reference: metadata?.brandKitId || null,
  });
}

async function chargeFlat({ workspaceId, userId, feature, idempotencyKey, metadata, amountAc }) {
  const ac =
    amountAc != null ? Math.max(0, Math.floor(Number(amountAc) || 0)) : getFlatAc(feature);

  const result = await charge({
    workspaceId,
    userId,
    amountAc: ac,
    idempotencyKey,
    feature,
    metadata: metadata || {},
  });

  return { ...result, pricing: { athenaCredits: ac, feature } };
}

module.exports = {
  BRAND_KIT_FEATURE,
  assertAfford,
  chargeFlat,
  getFlatAc,
};
