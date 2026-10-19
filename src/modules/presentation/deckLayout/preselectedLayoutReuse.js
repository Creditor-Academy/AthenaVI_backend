'use strict';

const { toDeckLayout } = require('./toDeckLayout');
const { toSlideContentProfile } = require('./toSlideContentProfile');
const { evaluateLayoutCompatibility } = require('./layoutCompatibility');
const { contentFitsLayoutGroups } = require('@athena/contracts/contentContract.js');

/**
 * Profile from post-classify generated content (same signals as final layout pick).
 */
function buildPostClassifyProfile({
  content,
  outlineSlide,
  policy,
  slideOrder,
  wizardDensity,
}) {
  return toSlideContentProfile({
    ...(content && typeof content === 'object' ? content : {}),
    title: content?.title || outlineSlide?.title || '',
    summary: outlineSlide?.summary || content?.summary || '',
    purpose: outlineSlide?.purpose || outlineSlide?.intent || null,
    suggestedContentType: outlineSlide?.suggestedContentType || policy?.layoutContentType,
    narrativeRole: outlineSlide?.narrativeRole || outlineSlide?.narrative_role || null,
    slideNumber: slideOrder,
    wizardDensity: wizardDensity || null,
  });
}

/**
 * True when generated arrays fit layout group caps (raw counts, before repair/normalize).
 */
function contentFitsLayoutContract(content, layoutSchema) {
  if (!layoutSchema?.slots?.length) return true;
  return contentFitsLayoutGroups(content, layoutSchema);
}

/**
 * Reuse preselected/planned layout only when compatibility and slot-group counts match actual content.
 */
function shouldReusePreselectedLayout({
  content,
  outlineSlide,
  template,
  policy,
  slideOrder,
  wizardDensity,
  galleryBlocksReuse,
}) {
  if (galleryBlocksReuse) return false;
  if (!template?.schema?.slots?.length) return false;

  const profile = buildPostClassifyProfile({
    content,
    outlineSlide,
    policy,
    slideOrder,
    wizardDensity,
  });
  const deckLayout = toDeckLayout(template);
  const compat = evaluateLayoutCompatibility(profile, deckLayout);
  if (compat.status === 'hardReject') return false;
  if (!contentFitsLayoutContract(content, template.schema)) return false;
  return true;
}

module.exports = {
  buildPostClassifyProfile,
  contentFitsLayoutContract,
  shouldReusePreselectedLayout,
};
