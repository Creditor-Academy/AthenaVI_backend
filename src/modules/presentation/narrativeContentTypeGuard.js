'use strict';

const PROBLEM_NARRATIVE_ROLES = new Set(['problem_statement', 'pain_points']);
const QUANTITATIVE_NARRATIVE_ROLES = new Set([
  'research_data',
  'key_data',
  'results_impact',
  'market_overview',
  'key_insight',
]);

function normalizeNarrativeRole(role) {
  return String(role || '')
    .trim()
    .toLowerCase()
    .replace(/-/g, '_');
}

function isQuantitativeNarrativeRole(outlineSlide = {}) {
  const role = normalizeNarrativeRole(outlineSlide.narrativeRole || outlineSlide.narrative_role);
  return QUANTITATIVE_NARRATIVE_ROLES.has(role);
}

function isProblemNarrativeSlide(outlineSlide = {}) {
  if (isQuantitativeNarrativeRole(outlineSlide)) return false;
  const purpose = String(outlineSlide.purpose || '').trim().toLowerCase();
  if (purpose === 'problem') return true;
  const role = normalizeNarrativeRole(outlineSlide.narrativeRole || outlineSlide.narrative_role);
  return PROBLEM_NARRATIVE_ROLES.has(role);
}

function stripChartFieldsFromContent(content) {
  if (!content || typeof content !== 'object') return;
  delete content.chart;
  delete content.chart2;
  delete content.charts;
  delete content.stats;
  delete content.metrics;
}

/**
 * Keep outline narrative roles authoritative — problem beats must not become chart slides.
 */
function guardNarrativeContentType(outlineSlide = {}, contentType, content, opts = {}) {
  let next = String(contentType || 'bullet_list').toLowerCase();
  let adjusted = false;
  const outlineExplicit = Boolean(
    opts.outlineExplicit != null ? opts.outlineExplicit : outlineSlide?.suggestedContentType
  );
  const outlineType = String(outlineSlide?.suggestedContentType || '').toLowerCase();
  const visualNeed = String(opts.visualNeed || '').toLowerCase();
  const hasChartPayload =
    content &&
    typeof content === 'object' &&
    (content.chart || content.chart2 || (Array.isArray(content.charts) && content.charts.length));

  const problem = isProblemNarrativeSlide(outlineSlide);
  const chartish = next === 'chart' || visualNeed === 'chart' || hasChartPayload;

  if (problem && chartish) {
    const hasBullets =
      Array.isArray(content?.bullets) && content.bullets.filter(Boolean).length >= 2;
    if (outlineExplicit && outlineType && outlineType !== 'chart') {
      next = outlineType;
    } else if (hasBullets) {
      next = 'bullet_list';
    } else {
      next = 'bullet_list';
    }
    stripChartFieldsFromContent(content);
    adjusted = true;
  } else if (
    outlineExplicit &&
    outlineType === 'bullet_list' &&
    next === 'chart' &&
    !isQuantitativeNarrativeRole(outlineSlide)
  ) {
    next = 'bullet_list';
    stripChartFieldsFromContent(content);
    adjusted = true;
  }

  return { contentType: next, adjusted };
}

module.exports = {
  isProblemNarrativeSlide,
  isQuantitativeNarrativeRole,
  stripChartFieldsFromContent,
  guardNarrativeContentType,
};
