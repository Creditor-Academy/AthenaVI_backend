const creditLedger = require('./creditLedger.service');
const {
  FEATURE,
  SCOPE,
  calculateUsageCredits,
  estimateDurationFromText,
} = require('../../shared/config/creditPricing');

async function assertUserCanAffordFeature(userId, feature, options = {}) {
  const durationSeconds =
    options.durationSeconds ??
    (feature === FEATURE.VOICE_PREVIEW
      ? estimateDurationFromText(options.text)
      : 0);
  const pricing = calculateUsageCredits({
    feature,
    durationSeconds,
    avatarEngine: options.avatarEngine,
  });
  await creditLedger.assertCanAfford({
    scope: SCOPE.USER,
    userId,
    estimatedAc: pricing.athenaCredits,
  });
  return pricing;
}

async function chargeUserFeature({
  userId,
  feature,
  idempotencyKey,
  durationSeconds = 0,
  reference,
  extraMetadata = {},
}) {
  const pricing = calculateUsageCredits({ feature, durationSeconds });
  return creditLedger.chargeUsage({
    scope: SCOPE.USER,
    workspaceId: null,
    userId,
    amountAc: pricing.athenaCredits,
    idempotencyKey,
    reference,
    metadata: {
      feature,
      scope: SCOPE.USER,
      heygenUsdCost: pricing.heygenUsdCost,
      durationSeconds,
      ...extraMetadata,
    },
  });
}

module.exports = {
  assertUserCanAffordFeature,
  chargeUserFeature,
  FEATURE,
};
