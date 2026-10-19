'use strict';

const AI_PREFERRED_PRICING_RE =
  /^pricing_(three_plans(_featured)?|comparison_(table|cards)|four_plans(_featured)?)_v1$/i;
const AI_DEMOTED_PRICING_RE =
  /pricing_(three_highlight(_split)?|four_para(_cards)?)_v1$/i;

function layoutIdFromTemplate(template) {
  return String(template?.schema?.layout_id || template?.variant || template?.id || '').trim();
}

function isDemotedAiPricingLayoutId(layoutId) {
  return AI_DEMOTED_PRICING_RE.test(String(layoutId || ''));
}

function isPreferredAiPricingLayoutId(layoutId) {
  return AI_PREFERRED_PRICING_RE.test(String(layoutId || ''));
}

/**
 * Narrow AI auto-pick pool to tier-card / comparison pricing layouts when possible.
 */
function filterTemplatesForAiPricingIntent(templates, { layoutLocked = false } = {}) {
  const list = Array.isArray(templates) ? templates.filter(Boolean) : [];
  if (layoutLocked || !list.length) return list;

  const preferred = list.filter((t) => isPreferredAiPricingLayoutId(layoutIdFromTemplate(t)));
  if (preferred.length) return preferred;

  const withoutDemoted = list.filter((t) => !isDemotedAiPricingLayoutId(layoutIdFromTemplate(t)));
  return withoutDemoted.length ? withoutDemoted : list;
}

function scoreAiPricingLayoutPreference(layoutId) {
  const id = String(layoutId || '');
  if (isPreferredAiPricingLayoutId(id)) return 6;
  if (isDemotedAiPricingLayoutId(id)) return -10;
  return 0;
}

module.exports = {
  AI_PREFERRED_PRICING_RE,
  AI_DEMOTED_PRICING_RE,
  filterTemplatesForAiPricingIntent,
  scoreAiPricingLayoutPreference,
  isDemotedAiPricingLayoutId,
  isPreferredAiPricingLayoutId,
};
