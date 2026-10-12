const { visualRoleFromDeckRhythmEntry } = require('./visualRoles');
const { designTokensForVisualRole } = require('./visualTreatment');
const { coverDesignTokens } = require('./coverArtDirection');
const { resolveStickyBrandColors } = require('./semanticTheme');

function buildSlideDesignPlan({ ctx, slide, outlineSlide } = {}) {
  const entry = ctx?.visualRhythm?.[Number(slide?.order) - 1];
  const visualRole = visualRoleFromDeckRhythmEntry(entry);
  const brand = ctx?.stickyBrandColors || resolveStickyBrandColors(ctx?.themeTokens || {});
  const appearance = brand.appearance || 'light';

  // Special treatment for cover regardless of rhythm role, if we can infer it.
  const isCover = Number(slide?.order) === 1 || String(slide?.order) === '1';
  const outlineType = String(
    outlineSlide?.suggestedContentType || slide?.suggestedContentType || ''
  ).toLowerCase();
  const isTitleSlide = outlineType === 'title' || isCover;

  const designTokens =
    isTitleSlide
      ? coverDesignTokens(ctx?.themeTokens || {})
      : designTokensForVisualRole({ visualRole, appearance });

  return {
    slideNumber: Number(slide?.order) || null,
    visualRole,
    designTokens,
    appearance,
  };
}

module.exports = {
  buildSlideDesignPlan,
};
