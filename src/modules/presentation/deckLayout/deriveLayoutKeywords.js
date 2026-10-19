'use strict';

const { aliasesForTopics } = require('./layoutKeywordLexicon');

const NOISE = new Set(['v1', 'v2', 'layout', 'para', 'the', 'and', 'with']);
const KEYWORD_CAP = 50;

function idTokens(layoutId) {
  return String(layoutId || '')
    .replace(/_v\d+$/i, '')
    .split('_')
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length > 2 && !NOISE.has(t));
}

function slotTopicHints(slots) {
  const topics = new Set();
  const extra = new Set();
  for (const slot of slots || []) {
    const sid = String(slot?.id || '').toLowerCase();
    if (/milestone/.test(sid)) topics.add('roadmap');
    if (/^step_/.test(sid)) topics.add('process');
    if (/pros_|cons_/.test(sid)) topics.add('comparison');
    if (/^cell_/.test(sid)) topics.add('table');
    if (/^plan_/.test(sid)) topics.add('pricing');
    if (/^member_/.test(sid)) topics.add('team');
    if (/quote|statement/.test(sid)) topics.add('quote');
    if (/^bullet_/.test(sid)) topics.add('bullets');
    if (/^point_/.test(sid)) extra.add('point');
    if (/^metric_|^stat_/.test(sid)) topics.add('metrics');
  }
  return { topics: [...topics], extra: [...extra] };
}

function assignTopicsFromLayout({
  layoutId,
  contentType,
  category,
  slidePurposes,
  supportedElements,
  slots,
  keywordTopicsOverride,
}) {
  const id = String(layoutId || '').toLowerCase();
  const ct = String(contentType || '').toLowerCase();
  const topics = new Set(keywordTopicsOverride || []);

  if (ct === 'timeline' || /timeline/.test(id)) {
    topics.add('roadmap');
    topics.add('process');
  }
  if (/comparison|before_after|pros_cons/.test(id)) topics.add('comparison');
  if (/pricing|plan_/.test(id) || (slidePurposes || []).includes('pricing')) topics.add('pricing');
  if (/team|member_/.test(id) || ct === 'team') topics.add('team');
  if (/quote|testimonial|statement/.test(id) || ct === 'quote') topics.add('quote');
  if (/stat|metric_/.test(id) || ct === 'stat') topics.add('metrics');
  if (/chart|insight/.test(id) || ct === 'chart') topics.add('metrics');
  if (/table_/.test(id)) {
    topics.add('table');
    topics.add('metrics');
  }
  if (/funnel/.test(id)) topics.add('funnel');
  if (/swot|matrix/.test(id) && !/comparison_table/.test(id)) topics.add('swot');
  if (/grid_bento|grid_six|four_images|grid_three/.test(id) || ct === 'grid') topics.add('gallery');
  if (/closing|thank_you|contact/.test(id) || ct === 'closing') topics.add('closing');
  if (/title_hero|fullbleed|full_bg|title_full/.test(id) || ct === 'title') topics.add('hero');
  if (/agenda/.test(id) || ct === 'agenda') topics.add('agenda');
  if (/section_divider/.test(id) || ct === 'section_divider') topics.add('section');
  if (/device_/.test(id) || ct === 'device_frames') topics.add('device');
  if (/process_linear|diagram_process|process_step/.test(id) || ct === 'diagram') {
    topics.add('process');
    if (/diagram/.test(id)) topics.add('diagram');
  }
  if (ct === 'bullet_list' || /bullet_list|bullet_split/.test(id)) topics.add('bullets');
  if (ct === 'comparison') topics.add('comparison');
  if (ct === 'image+text' && !topics.size) topics.add('bullets');

  const slotHints = slotTopicHints(slots);
  for (const t of slotHints.topics) topics.add(t);

  if (supportedElements?.chart && !topics.has('table')) topics.add('metrics');
  if (supportedElements?.table) topics.add('table');
  if (supportedElements?.quote) topics.add('quote');
  if (supportedElements?.metrics) topics.add('metrics');
  if (supportedElements?.cards && topics.size === 0) topics.add('bullets');

  if (!topics.size) {
    if (ct) topics.add(ct.replace(/\+/g, '_'));
    else topics.add('bullets');
  }

  return [...topics].sort();
}

/**
 * @param {object} layout - partial or full DeckLayout-shaped object
 * @returns {{ layoutTopics: string[], keywords: string[] }}
 */
function deriveLayoutKeywords(layout) {
  const layoutId = layout?.id || layout?.schema?.layout_id || '';
  const slots = Array.isArray(layout?.schema?.slots)
    ? layout.schema.slots
    : Array.isArray(layout?.slots)
      ? layout.slots
      : [];

  const overlayTopics = layout?.keywordTopics;
  const layoutTopics = assignTopicsFromLayout({
    layoutId,
    contentType: layout.contentType || layout?.schema?.content_type,
    category: layout.category,
    slidePurposes: layout.slidePurposes,
    supportedElements: layout.supportedElements,
    slots,
    keywordTopicsOverride: Array.isArray(overlayTopics) ? overlayTopics : null,
  });

  const kw = new Set();
  for (const a of aliasesForTopics(layoutTopics)) kw.add(a);
  for (const t of idTokens(layoutId)) kw.add(t);
  for (const tag of layout.tags || []) {
    const x = String(tag || '').trim().toLowerCase();
    if (x && x.length > 2) kw.add(x);
  }
  for (const p of layout.slidePurposes || []) {
    const x = String(p || '').trim().toLowerCase();
    if (x) kw.add(x);
  }
  for (const hint of slotTopicHints(slots).extra) kw.add(hint);
  if (Array.isArray(layout.keywords)) {
    for (const k of layout.keywords) {
      const x = String(k || '').trim().toLowerCase();
      if (x) kw.add(x);
    }
  }

  const keywords = [...kw]
    .filter((k) => k && !NOISE.has(k))
    .sort()
    .slice(0, KEYWORD_CAP);

  return { layoutTopics, keywords };
}

module.exports = {
  deriveLayoutKeywords,
  assignTopicsFromLayout,
};
