'use strict';

/**
 * Extra catalog content_type values to merge into the layout candidate pool.
 */
function candidateContentTypes(profile = {}, outlineSlide = {}, primaryLayoutContentType = '') {
  const types = new Set();
  const primary = String(primaryLayoutContentType || '').trim().toLowerCase();
  if (primary) types.add(primary);

  const suggested = String(
    outlineSlide?.suggestedContentType ||
      outlineSlide?.contentType ||
      profile?.suggestedContentType ||
      ''
  )
    .trim()
    .toLowerCase();

  const structural = new Set([
    'comparison',
    'timeline',
    'diagram',
    'chart',
    'stat',
    'pricing',
    'team',
    'quote',
    'grid',
    'agenda',
    'device_frames',
    'closing',
    'title',
    'section_divider',
  ]);

  if (structural.has(suggested)) types.add(suggested);

  if (profile.hasComparison || suggested === 'comparison' || profile.contentStructure === 'comparison') {
    types.add('comparison');
    if (primary !== 'comparison') types.add('image+text');
  }
  if (profile.hasTimeline || suggested === 'timeline') {
    types.add('timeline');
    types.add('diagram');
  }
  if (profile.hasPricing || suggested === 'pricing') {
    types.add('pricing');
  }
  if (profile.hasTeam || suggested === 'team') {
    types.add('team');
  }
  if (profile.hasQuote || suggested === 'quote') {
    types.add('quote');
  }
  if (profile.hasChart || suggested === 'chart') {
    types.add('chart');
  }
  if (profile.hasTable || suggested === 'table') {
    // Table layouts are catalog-typed as chart in seed data.
    types.add('chart');
  }
  if (
    profile.bulletCount >= 3 &&
    (profile.hasComparison || profile.contentStructure === 'comparison')
  ) {
    types.add('comparison');
  }
  if (suggested === 'stat' || profile.metricCount >= 2) {
    types.add('stat');
  }
  if (suggested === 'grid' || profile.allowPureImageGrid) {
    types.add('grid');
  }

  return [...types].filter(Boolean);
}

function templateKey(template) {
  return String(template?.schema?.layout_id || template?.variant || template?.id || '').trim();
}

/**
 * Load and dedupe templates across widened content types.
 * @param {string} primaryLayoutContentType
 * @param {{ profile?: object, outlineSlide?: object, resolveLayoutTemplates: Function, layoutIdWhitelist?: string[] }} options
 */
async function resolveLayoutCandidates(primaryLayoutContentType, options = {}) {
  const resolveFn = options.resolveLayoutTemplates;
  if (typeof resolveFn !== 'function') {
    throw new Error('resolveLayoutCandidates requires resolveLayoutTemplates');
  }
  const profile = options.profile || {};
  const outlineSlide = options.outlineSlide || {};
  const types = candidateContentTypes(profile, outlineSlide, primaryLayoutContentType);
  const whitelist = options.layoutIdWhitelist || null;
  const byId = new Map();

  for (const contentType of types) {
    const batch = await resolveFn(contentType, { layoutIdWhitelist: whitelist });
    for (const template of batch || []) {
      const id = templateKey(template);
      if (id && !byId.has(id)) byId.set(id, template);
    }
  }

  const templates = [...byId.values()];
  const primaryType = String(primaryLayoutContentType || types[0] || '')
    .trim()
    .toLowerCase();
  const primaryIds = new Set();
  const primaryTemplates = [];
  const widenedTemplates = [];

  for (const template of templates) {
    const id = templateKey(template);
    if (!id) continue;
    const ct = String(template?.contentType || template?.schema?.content_type || '')
      .trim()
      .toLowerCase();
    if (primaryType && ct === primaryType) {
      if (!primaryIds.has(id)) {
        primaryIds.add(id);
        primaryTemplates.push(template);
      }
    }
  }
  for (const template of templates) {
    const id = templateKey(template);
    if (!id || primaryIds.has(id)) continue;
    widenedTemplates.push(template);
  }

  return {
    templates,
    primaryTemplates,
    widenedTemplates,
    contentTypes: types,
  };
}

/**
 * Split an already-loaded template list by catalog content_type vs primary type.
 */
function splitPrimaryAndWidenedTemplates(templates, primaryLayoutContentType) {
  const list = Array.isArray(templates) ? templates : [];
  const primaryType = String(primaryLayoutContentType || '')
    .trim()
    .toLowerCase();
  const primaryIds = new Set();
  const primaryTemplates = [];
  const widenedTemplates = [];
  for (const template of list) {
    const id = templateKey(template);
    if (!id) continue;
    const ct = String(template?.contentType || template?.schema?.content_type || '')
      .trim()
      .toLowerCase();
    if (primaryType && ct === primaryType) {
      if (!primaryIds.has(id)) {
        primaryIds.add(id);
        primaryTemplates.push(template);
      }
    }
  }
  for (const template of list) {
    const id = templateKey(template);
    if (!id || primaryIds.has(id)) continue;
    widenedTemplates.push(template);
  }
  return { primaryTemplates, widenedTemplates };
}

function buildLayoutSearchText(ctx = {}, outlineSlide = {}, content = {}) {
  const parts = [
    ctx.userPrompt,
    ctx.sourceText,
    ctx.wizardBrief,
    ctx.outline?.title,
    ctx.outline?.sourcePrompt,
    outlineSlide?.title,
    outlineSlide?.summary,
    outlineSlide?.intent,
    outlineSlide?.purpose,
    Array.isArray(outlineSlide?.beats) ? outlineSlide.beats.join(' ') : '',
    content?.title,
    content?.summary,
    content?.body,
  ];
  return parts
    .filter(Boolean)
    .map((p) => String(p))
    .join(' ')
    .trim();
}

module.exports = {
  candidateContentTypes,
  resolveLayoutCandidates,
  splitPrimaryAndWidenedTemplates,
  buildLayoutSearchText,
  templateKey,
};
